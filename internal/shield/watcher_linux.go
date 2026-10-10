//go:build linux

package shield

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Coverage is the honest state of real-time monitoring.
type Coverage struct {
	Mode           string   `json:"mode"` // inotify | none
	Roots          []string `json:"roots"`
	Watches        int      `json:"watches"`
	MaxUserWatches int      `json:"max_user_watches"`
	Degraded       bool     `json:"degraded"`
	Reasons        []string `json:"reasons,omitempty"`
	Overflows      int      `json:"overflows"`
}

// Watcher is a recursive inotify watcher. New directories get watches added
// and their existing contents are emitted (closing the mkdir→write race).
type Watcher struct {
	fd       int
	roots    []string
	OnEvent  func(FileEvent)          // set via NewWatcher; read-only afterwards
	Account  func(path string) string // set via NewWatcher; read-only afterwards
	mu       sync.Mutex
	wds      map[int]string
	byPath   map[string]int
	cov      Coverage
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
}

const watchMask = unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF

// NewWatcher starts watching roots recursively and calls onEvent per event.
// account maps a path to its owning account (may be nil).
func NewWatcher(roots []string, account func(path string) string, onEvent func(FileEvent)) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}
	w := &Watcher{fd: fd, OnEvent: onEvent, Account: account, wds: map[int]string{}, byPath: map[string]int{},
		stop: make(chan struct{}), done: make(chan struct{})}
	w.cov.Mode = "inotify"
	w.cov.MaxUserWatches = readProcInt("/proc/sys/fs/inotify/max_user_watches")
	for _, r := range roots {
		r = filepath.Clean(r)
		w.roots = append(w.roots, r)
		w.addRecursive(r, false)
	}
	w.cov.Roots = w.roots
	go w.loop()
	return w, nil
}

func readProcInt(p string) int {
	b, err := os.ReadFile(p)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

func (w *Watcher) degrade(reason string) {
	w.cov.Degraded = true
	for _, r := range w.cov.Reasons {
		if r == reason {
			return
		}
	}
	w.cov.Reasons = append(w.cov.Reasons, reason)
}

// addRecursive adds watches under dir; when emit is set, files already present
// are reported as "create" events (they may have been written before the watch).
func (w *Watcher) addRecursive(dir string, emit bool) {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow symlinks out of the tree
		}
		if d.IsDir() {
			w.mu.Lock()
			_, have := w.byPath[p]
			w.mu.Unlock()
			if have {
				return nil
			}
			wd, err := unix.InotifyAddWatch(w.fd, p, watchMask|unix.IN_DONT_FOLLOW)
			if err != nil {
				w.mu.Lock()
				if errors.Is(err, unix.ENOSPC) {
					w.degrade(fmt.Sprintf("max_user_watches reached (%d); %s and below not monitored", w.cov.MaxUserWatches, p))
				} else {
					w.degrade("watch failed for " + p + ": " + err.Error())
				}
				w.mu.Unlock()
				return fs.SkipDir
			}
			w.mu.Lock()
			w.wds[wd] = p
			w.byPath[p] = wd
			w.cov.Watches = len(w.wds)
			w.mu.Unlock()
			return nil
		}
		if emit && d.Type().IsRegular() {
			w.emit(p, "create")
		}
		return nil
	})
}

func (w *Watcher) emit(p, op string) {
	if w.OnEvent == nil {
		return
	}
	ev := FileEvent{Path: p, Op: op, TS: time.Now()}
	if w.Account != nil {
		ev.Account = w.Account(p)
	}
	base := filepath.Base(p)
	if base == ".htaccess" || IsCrontabPath(p) {
		if f, err := os.OpenFile(p, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0); err == nil {
			buf := make([]byte, 64<<10)
			n, _ := f.Read(buf)
			ev.Content = buf[:n]
			f.Close()
		}
	}
	w.OnEvent(ev)
}

func (w *Watcher) loop() {
	defer close(w.done)
	buf := make([]byte, 64*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))
	for {
		select {
		case <-w.stop:
			return
		default:
		}
		fds := []unix.PollFd{{Fd: int32(w.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, 200)
		if err != nil && !errors.Is(err, unix.EINTR) {
			return
		}
		if n <= 0 {
			continue
		}
		rn, err := unix.Read(w.fd, buf)
		if err != nil || rn <= 0 {
			continue
		}
		w.parse(buf[:rn])
	}
}

func (w *Watcher) parse(b []byte) {
	off := 0
	for off+unix.SizeofInotifyEvent <= len(b) {
		raw := (*unix.InotifyEvent)(unsafe.Pointer(&b[off]))
		nameLen := int(raw.Len)
		name := ""
		if nameLen > 0 && off+unix.SizeofInotifyEvent+nameLen <= len(b) {
			nb := b[off+unix.SizeofInotifyEvent : off+unix.SizeofInotifyEvent+nameLen]
			name = strings.TrimRight(string(nb), "\x00")
		}
		off += unix.SizeofInotifyEvent + nameLen
		mask := raw.Mask
		if mask&unix.IN_Q_OVERFLOW != 0 {
			w.mu.Lock()
			w.cov.Overflows++
			w.degrade("inotify queue overflowed; some events lost (full rescan recommended)")
			w.mu.Unlock()
			continue
		}
		w.mu.Lock()
		dir, ok := w.wds[int(raw.Wd)]
		if mask&unix.IN_IGNORED != 0 && ok {
			delete(w.wds, int(raw.Wd))
			delete(w.byPath, dir)
			w.cov.Watches = len(w.wds)
		}
		w.mu.Unlock()
		if !ok || name == "" {
			continue
		}
		p := filepath.Join(dir, name)
		isDir := mask&unix.IN_ISDIR != 0
		switch {
		case isDir && mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0:
			w.addRecursive(p, true)
		case isDir:
		case mask&unix.IN_CLOSE_WRITE != 0:
			w.emit(p, "write")
		case mask&unix.IN_MOVED_TO != 0:
			w.emit(p, "move")
		case mask&unix.IN_CREATE != 0:
			w.emit(p, "create")
		}
	}
}

// Coverage returns the current monitoring coverage.
func (w *Watcher) Coverage() Coverage {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.cov
	c.Reasons = append([]string(nil), w.cov.Reasons...)
	return c
}

// Close stops the watcher.
func (w *Watcher) Close() error {
	var err error
	w.stopOnce.Do(func() {
		close(w.stop)
		<-w.done
		err = unix.Close(w.fd)
	})
	return err
}

// FanotifyAvailable probes fanotify (needs CAP_SYS_ADMIN). It never keeps the fd.
func FanotifyAvailable() (bool, string) {
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_CLOEXEC, unix.O_RDONLY)
	if err != nil {
		switch {
		case errors.Is(err, unix.EPERM):
			return false, "fanotify needs CAP_SYS_ADMIN"
		case errors.Is(err, unix.ENOSYS):
			return false, "kernel built without fanotify"
		default:
			return false, "fanotify_init: " + err.Error()
		}
	}
	unix.Close(fd)
	return true, "fanotify available"
}

// FeedWatcher returns an OnEvent callback wiring events into q and b; alerts
// go to onAlert. Deletes are not queued for scanning.
func FeedWatcher(q *Queue, b *Behavior, onAlert func(Alert)) func(FileEvent) {
	return func(ev FileEvent) {
		if b != nil {
			for _, a := range b.Feed(ev) {
				if onAlert != nil {
					onAlert(a)
				}
			}
		}
		if q != nil && ev.Op != "delete" {
			_ = q.Enqueue(ev.Account, ev.Path)
		}
	}
}
