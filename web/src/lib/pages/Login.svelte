<script>
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import { LogIn, ShieldCheck, Loader2 } from '@lucide/svelte';
	import { api, setCSRF } from '$lib/api.js';
	import { loadSession, meta } from '$lib/stores.js';
	import { t, te } from '$lib/i18n/index.js';
	import Logo from '$lib/components/Logo.svelte';
	import LangSwitch from '$lib/components/LangSwitch.svelte';
	import { digitsOnly } from '$lib/a11y.js';

	let { realm } = $props();
	const focusNow = (node) => { setTimeout(() => node.focus(), 0); };
	let username = $state('');
	let password = $state('');
	let totp = $state('');
	let needTotp = $state(false);
	let busy = $state(false);
	let error = $state(null); // ApiError; rendered through $te so it follows the language switch
	// R2-UX-06: link to the other panel (2083 <-> 2087), built from /meta.ports
	let otherPanel = $derived.by(() => {
		const p = $meta?.ports;
		if (!p || typeof location === 'undefined') return '';
		const port = realm === 'admin' ? p.user : p.admin;
		return port ? `${location.protocol}//${location.hostname}:${port}/login` : '';
	});

	async function finish(res) {
		setCSRF(res.csrf);
		await loadSession();
		goto(page.url.searchParams.get('next') || '/', { replaceState: true });
	}

	onMount(async () => {
		const m = page.url.pathname.match(/^\/login\/once\/([a-f0-9]+)$/);
		if (m) {
			busy = true;
			try { await finish(await api.post('/auth/once', { token: m[1] })); }
			catch (e) { error = e; busy = false; goto('/login', { replaceState: true }); }
		}
	});

	async function submit(e) {
		e.preventDefault();
		error = null;
		busy = true;
		try {
			const res = await api.post('/auth/login', { username, password, totp: needTotp ? totp : undefined }, { noRedirect: true });
			if (res.totp_required) { needTotp = true; busy = false; return; }
			await finish(res);
		} catch (err) {
			error = err;
		}
		busy = false;
	}
</script>

<div class="wrap" class:admin={realm === 'admin'}>
	<div class="panel card">
		<div class="top">
			<Logo size={40} light={false} />
			<span class="realm badge {realm === 'admin' ? 'teal' : 'blue'}">{realm === 'admin' ? $t('login.admin_panel') : $t('login.user_panel')}</span>
		</div>
		<form onsubmit={submit} aria-label={$t('login.submit')}>
			{#if error}<div class="alert error" role="alert"><div>{$te(error.code)}
				{#if error.code === 'wrong_panel' && otherPanel}<div><a href={otherPanel}>{$t('login.open_other_panel')}</a></div>{/if}</div></div>{/if}
			{#if !needTotp}
				<label class="field"><span>{$t('login.username')}</span>
					<input bind:value={username} autocomplete="username" required autocapitalize="off" spellcheck="false" aria-invalid={error ? 'true' : undefined} /></label>
				<label class="field"><span>{$t('login.password')}</span>
					<input type="password" bind:value={password} autocomplete="current-password" required /></label>
			{:else}
				<div class="alert info"><ShieldCheck size={18} /> {$t('login.totp_prompt')}</div>
				<label class="field"><span>{$t('login.totp_code')}</span>
					<input bind:value={totp} inputmode="numeric" autocomplete="one-time-code" use:digitsOnly maxlength="12" pattern={'[0-9]{6}'} data-err="val.totp" required use:focusNow /></label>
			{/if}
			<button class="btn primary full" disabled={busy}>
				{#if busy}<Loader2 size={16} class="spin" />{:else}<LogIn size={16} />{/if} {$t('login.submit')}
			</button>
		</form>
		<div class="foot">
			<LangSwitch />
			<span class="muted small">{$meta?.hostname ?? ''}</span>
		</div>
	</div>
	<p class="legal small">BOZKURT PANEL {$meta?.version ?? ''} · Apache-2.0</p>
</div>

<style>
	.wrap { min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 24px; background:
		radial-gradient(1200px 500px at 10% -10%, color-mix(in srgb, var(--accent) 22%, transparent), transparent 60%),
		linear-gradient(160deg, var(--sidebar) 0%, #253150 100%); }
	.panel { width: 100%; max-width: 400px; padding: 28px 28px 18px; box-shadow: var(--shadow-lg); }
	.top { display: flex; flex-direction: column; align-items: center; gap: 12px; margin-bottom: 22px; }
	.full { width: 100%; height: 40px; margin-top: 4px; }
	.foot { display: flex; align-items: center; justify-content: space-between; margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--border); }
	.legal { color: #b8c2d6; margin-top: 16px; }
</style>
