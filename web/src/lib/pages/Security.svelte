<script>
	import { KeyRound, Smartphone, ShieldCheck } from '@lucide/svelte';
	import QRCode from 'qrcode';
	import { api } from '$lib/api.js';
	import { session, loadSession } from '$lib/stores.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import { digitsOnly } from '$lib/a11y.js';

	let current = $state('');
	let next = $state('');
	let setup = $state(null);
	let qr = $state('');
	let code = $state('');
	let offCode = $state('');
	let busy = $state(false);

	async function changePw(e) {
		e.preventDefault();
		busy = true;
		try { await api.post('/account/password', { current, new: next }); ok('security.password_changed'); current = next = ''; }
		// R2-UX-22: no username on this form — older servers answer invalid_credentials here
		catch (err) { showErr(err?.code === 'invalid_credentials' ? { code: 'wrong_current_password' } : err); }
		busy = false;
	}
	async function startTotp() {
		try {
			setup = await api.post('/account/totp/setup');
			qr = await QRCode.toDataURL(setup.url, { margin: 1, width: 200 });
		} catch (err) { showErr(err); }
	}
	async function enable(e) {
		e.preventDefault();
		try { await api.post('/account/totp/enable', { code }); ok('security.totp_enabled'); setup = null; code = ''; await loadSession(); }
		catch (err) { showErr(err); }
	}
	async function disable(e) {
		e.preventDefault();
		try { await api.post('/account/totp/disable', { code: offCode }); ok('security.totp_disabled'); offCode = ''; await loadSession(); }
		catch (err) { showErr(err); }
	}
</script>

<PageHead title={$t('security.title')} desc={$t('security.desc')} icon={KeyRound} />
<div class="grid2">
	<form class="card" onsubmit={changePw}>
		<div class="card-head"><KeyRound size={18} /><h2>{$t('security.change_password')}</h2></div>
		<div class="card-body">
			<label class="field"><span>{$t('security.current_password')}</span><input type="password" bind:value={current} autocomplete="current-password" required /></label>
			<PasswordField bind:value={next} label={$t('security.new_password')} id="newpw" />
			{#if $session?.user?.system_user}<p class="muted small">{$t('security.password_note')}</p>{/if}
			<button class="btn primary" disabled={busy}>{$t('security.change_password')}</button>
		</div>
	</form>
	<div class="card">
		<div class="card-head"><Smartphone size={18} /><h2 class="grow">{$t('security.two_factor')}</h2>
			{#if $session?.user?.totp_enabled}<span class="badge green"><ShieldCheck size={12} /> {$t('common.enabled')}</span>{:else}<span class="badge amber">{$t('common.disabled')}</span>{/if}
		</div>
		<div class="card-body">
			<p class="muted">{$t('security.two_factor_desc')}</p>
			{#if $session?.user?.totp_enabled}
				<form onsubmit={disable} class="row" style="flex-wrap:wrap">
					<input bind:value={offCode} inputmode="numeric" use:digitsOnly maxlength="12" pattern={'[0-9]{6}'} data-err="val.totp" autocomplete="one-time-code" placeholder="123456" aria-label={$t('login.totp_code')} style="max-width:140px" required />
					<button class="btn danger">{$t('security.disable_2fa')}</button>
				</form>
			{:else if setup}
				<div class="enroll">
					<img src={qr} alt={$t('security.qr_alt')} width="180" height="180" />
					<div>
						<ol class="small">
							<li>{$t('security.step1')}</li>
							<li>{$t('security.step2')}</li>
						</ol>
						<p class="small muted">{$t('security.manual_key')}</p>
						<code class="secret">{setup.secret}</code>
						<form onsubmit={enable} class="row" style="margin-top:12px">
							<input bind:value={code} inputmode="numeric" use:digitsOnly maxlength="12" pattern={'[0-9]{6}'} data-err="val.totp" autocomplete="one-time-code" placeholder="123456" aria-label={$t('login.totp_code')} style="max-width:140px" required />
							<button class="btn primary">{$t('security.verify_enable')}</button>
						</form>
					</div>
				</div>
			{:else}
				<button class="btn primary" onclick={startTotp}>{$t('security.setup_2fa')}</button>
			{/if}
		</div>
	</div>
</div>

<style>
	.enroll { display: flex; gap: 18px; align-items: flex-start; flex-wrap: wrap; }
	.enroll img { border: 1px solid var(--border); border-radius: 6px; background: #fff; }
	.secret { display: inline-block; padding: 6px 8px; background: var(--card-2); border: 1px solid var(--border); border-radius: 5px; word-break: break-all; }
	ol { padding-left: 18px; margin: 0 0 8px; }
</style>
