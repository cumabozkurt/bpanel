// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package devx

import (
	"errors"
	"os"
)

func OpenPTY() (*os.File, *os.File, error)        { return nil, nil, errors.New("pty: linux only") }
func SetWinsize(f *os.File, cols, rows int) error { return errors.New("pty: linux only") }
