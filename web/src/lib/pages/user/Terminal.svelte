<script>
	import { Terminal as TermIcon, Power } from '@lucide/svelte';
	import { onDestroy } from 'svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';

	// v0.4 devx: browser terminal. The panel bridges a WebSocket to a PTY the
	// agent runs as the account inside its cage. This is a plain-text
	// terminal (ANSI colours/cursor codes are stripped; full-screen programs
	// such as vim or top do not render).
	let st = $state(null);
	let ws = null;
	let connected = $state(false);
	let out = $state('');
	let reauth = $state(false);
	let pw = $state('');
	let screen;
	const dec = new TextDecoder();
	const MAX = 200000;
	async function load() {
		try { st = await api.get('/user/terminal'); } catch (e) { showErr(e); }
	}
	function clean(s) {
		return s.replace(/\x1b\][^\x07\x1b]*(\x07|\x1b\\)/g, '').replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '').replace(/\x1b[()][A-Za-z0-9]/g, '').replace(/\x1b[=>]/g, '').replace(/\r(?!\n)/g, '');
	}
	function append(s) {
		for (const ch of s.split(/(\x08)/)) {
			if (ch === '\x08') out = out.slice(0, -1); else out += ch;
		}
		if (out.length > MAX) out = out.slice(-MAX);
		queueMicrotask(() => { if (screen) screen.scrollTop = screen.scrollHeight; });
	}
	function connect() {
		if (!st?.recent_auth) { reauth = true; return; }
		const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
		ws = new WebSocket(`${proto}//${location.host}/api/v1/user/terminal/ws?cols=100&rows=30`);
		ws.binaryType = 'arraybuffer';
		ws.onopen = () => { connected = true; out = ''; screen?.focus(); };
		ws.onmessage = (m) => append(clean(typeof m.data === 'string' ? m.data : dec.decode(m.data, { stream: true })));
		ws.onclose = () => { connected = false; append('\n[' + $t('devx.term_closed') + ']\n'); load(); };
	}
	function send(d) { if (ws && connected) ws.send(JSON.stringify({ t: 'i', d })); }
	const keys = { Enter: '\r', Backspace: '\x7f', Tab: '\t', Escape: '\x1b', ArrowUp: '\x1b[A', ArrowDown: '\x1b[B', ArrowRight: '\x1b[C', ArrowLeft: '\x1b[D', Home: '\x1b[H', End: '\x1b[F', Delete: '\x1b[3~' };
	function onkey(e) {
		if (!connected) return;
		let d = null;
		if (e.ctrlKey && e.key.length === 1 && /[a-z]/i.test(e.key)) d = String.fromCharCode(e.key.toUpperCase().charCodeAt(0) - 64);
		else if (keys[e.key]) d = keys[e.key];
		else if (e.key.length === 1 && !e.metaKey) d = e.key;
		if (d !== null) { e.preventDefault(); send(d); }
	}
	function onpaste(e) { e.preventDefault(); send((e.clipboardData?.getData('text') || '').replace(/\r?\n/g, '\r')); }
	function disconnect() { ws?.close(); }
	async function confirmReauth(ev) {
		ev.preventDefault();
		try {
			await api.post('/account/reauth', /^\d{6}$/.test(pw) ? { totp: pw } : { password: pw });
			reauth = false; pw = '';
			await load();
			connect();
		} catch (e) { showErr(e); }
	}
	onDestroy(() => ws?.close());
	load();
</script>

<PageHead title={$t('devx.term_title')} desc={$t('devx.term_desc')} icon={TermIcon} />
{#if st}
	{#if !st.shell_access}
		<div class="card pad warn" role="status">{$t('devx.term_no_shell')}</div>
	{:else if !st.session}
		<div class="card pad warn" role="status">{$t('devx.term_no_token')}</div>
	{:else}
		<div class="row gap">
			{#if !connected}<button class="btn primary" onclick={connect}><TermIcon size={14} /> {$t('devx.term_connect')}</button>
			{:else}<button class="btn" onclick={disconnect}><Power size={14} /> {$t('devx.term_disconnect')}</button>{/if}
		</div>
		<!-- svelte-ignore a11y_no_noninteractive_tabindex -->
		<pre class="termscreen" bind:this={screen} tabindex="0" role="log" aria-live="off" aria-label={$t('devx.term_title')} onkeydown={onkey} onpaste={onpaste}>{out}</pre>
		<p class="small muted">{$t('devx.term_help', { minutes: Math.round(st.idle_timeout_seconds / 60) })}</p>
	{/if}
{/if}
<Modal bind:open={reauth} title={$t('devx.term_reauth')}>
	<form onsubmit={confirmReauth}>
		<p class="small">{$t('errors.reauth_required')}</p>
		<label class="field"><span>{$t('common.password')}</span><input type="password" bind:value={pw} required autocomplete="current-password" /></label>
		<button class="btn primary">{$t('usagex.confirm')}</button>
	</form>
</Modal>

<style>
	.termscreen { background: #0b0f14; color: #d7e0ea; min-height: 24rem; max-height: 70vh; overflow: auto; padding: .75rem; border-radius: 8px; white-space: pre-wrap; word-break: break-all; font-size: 13px; outline: none; }
	.termscreen:focus { box-shadow: 0 0 0 2px var(--accent, #4f8cff); }
</style>
