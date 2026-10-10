<script>
	import { Server, Plus, KeyRound, Trash2, Terminal } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PasswordField from '$lib/components/PasswordField.svelte';
	import { FTP_LOGIN_PATTERN, ftpLoginProblem, relPathProblem } from '$lib/validate.js';
	import { customValidity, maxLen } from '$lib/a11y.js';
	import { fromApi, toApi, showLimit, sendWithLimits, noteValues } from '$lib/limits.js';
	import LimitInput from '$lib/components/LimitInput.svelte';

	let data = $state({ accounts: [] });
	let domains = $state([]);
	let form = $state({ login: '', domain: '', password: '', dir: '', quota: { unl: true, n: 1024 } });
	// R2-UX-13: same rules as a document root (no ~/etc, ~/mail, … — they hold private files)
	let dirProblem = $derived(form.dir ? relPathProblem(form.dir, { allowHome: true }) : null);
	let pwOpen = $state(false);
	let cur = $state(null);
	let newPw = $state('');
	let busy = $state(false);
	async function load() {
		try {
			data = await api.get('/user/ftp');
			noteValues(data.accounts, ['quota_mb']);
			domains = (await api.get('/user/domains')).filter((d) => d.kind !== 'alias').map((d) => d.name);
			if (!form.domain) form.domain = domains[0] ?? '';
		} catch (e) { showErr(e); }
	}
	load();
	$effect(() => { if (form.login && !form.dirTouched) form.dir = 'public_html/' + form.login; });
	async function create(e) {
		e.preventDefault();
		if (dirProblem) return;
		busy = true;
		try {
			const r = await sendWithLimits((b) => api.post('/user/ftp', b), { login: form.login.trim(), domain: form.domain, password: form.password, dir: form.dir.trim().replace(/^\/+/, ''), quota_mb: toApi(form.quota) }, ['quota_mb']);
			ok('ftp.created', { login: r.login }); form = { ...form, login: '', password: '', dir: '', dirTouched: false }; load();
		}
		catch (err) { showErr(err); }
		busy = false;
	}
	async function del(a) { if (!ask('ftp.confirm_delete', { login: a.login })) return; try { await api.del('/user/ftp/' + a.id); ok('common.deleted'); load(); } catch (err) { showErr(err); } }
	async function setPw(e) { e.preventDefault(); busy = true; try { await api.put(`/user/ftp/${cur.id}/password`, { password: newPw }); ok('common.saved'); pwOpen = false; } catch (err) { showErr(err); } busy = false; }
</script>

<PageHead title={$t('ftp.title')} desc={$t('ftp.desc')} icon={Server} />
<div class="stack">
	<div class="grid2">
		<form class="card" onsubmit={create}>
			<div class="card-head"><Plus size={17} /><h2>{$t('ftp.add')}</h2></div>
			<div class="card-body">
				<label class="field"><span>{$t('ftp.login')}</span>
					<div class="input-group"><input id="ftp-login" bind:value={form.login} required pattern={FTP_LOGIN_PATTERN + '|.{33,}'} use:maxLen={32} data-err="errors.invalid_ftp_login" autocapitalize="off" spellcheck="false"
						use:customValidity={form.login && form.login.includes('..') ? ftpLoginProblem(form.login) : null} aria-label={$t('ftp.login')} /><span class="addon">@</span>
						<select bind:value={form.domain} style="width:auto;border-radius:0 6px 6px 0" aria-label={$t('domains.domain')}>{#each domains as d}<option>{d}</option>{/each}</select></div></label>
				<PasswordField bind:value={form.password} id="ftppw" />
				<label class="field"><span>{$t('ftp.directory')}</span><div class="input-group"><span class="addon">~/</span><input bind:value={form.dir} oninput={() => (form.dirTouched = true)} use:customValidity={dirProblem} aria-invalid={dirProblem ? 'true' : undefined} autocapitalize="off" spellcheck="false" /></div>
					{#if dirProblem}<small class="field-err">{$t(dirProblem)}</small>{/if}</label>
				<LimitInput id="ftp-quota" label={$t('ftp.quota')} unit="MB" min={1} max={1e9} bind:value={form.quota} help={$t('email.quota_help')} />
				<button class="btn primary" disabled={busy}>{$t('ftp.create')}</button>
			</div>
		</form>
		<section class="card">
			<div class="card-head"><Terminal size={17} /><h2>{$t('ftp.connection')}</h2></div>
			<div class="card-body">
				<div class="kv small">
					<div>{$t('ftp.server')}</div><div class="mono">{data.server}</div>
					<div>FTP / FTPS</div><div class="mono">{$t('ftp.port')} {data.ftp_port} · {$t('ftp.explicit_tls')}</div>
					<div>SFTP</div><div class="mono">{$t('ftp.port')} {data.sftp_port}</div>
					<div>{$t('ftp.sftp_user')}</div><div class="mono">{data.sftp_user}</div>
				</div>
				<p class="muted small" style="margin-top:12px">{$t('ftp.sftp_note')}</p>
			</div>
		</section>
	</div>
	<section class="card">
		<div class="card-head"><Server size={17} /><h2>{$t('ftp.accounts')}</h2></div>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('ftp.login')}</th><th>{$t('ftp.directory')}</th><th>{$t('ftp.quota')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each data.accounts as a}
					<tr><td><b>{a.login}</b></td><td class="mono">~/{a.dir}</td><td>{showLimit(a.quota_mb, 'MB')}</td>
						<td><div class="actions"><button class="linkbtn" onclick={() => { cur = a; newPw = ''; pwOpen = true; }}><KeyRound size={13} /> {$t('common.password')}</button><button class="linkbtn danger" onclick={() => del(a)} aria-label={$t('ftp.delete_named', { login: a.login })}><Trash2 size={13} /> {$t('common.delete')}</button></div></td></tr>
				{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table></div>
	</section>
</div>

<Modal bind:open={pwOpen} title={$t('ftp.change_password_for', { login: cur?.login ?? '' })}>
	<form id="ftpp" onsubmit={setPw}><PasswordField bind:value={newPw} id="ftppw2" /></form>
	{#snippet footer()}<button class="btn" onclick={() => (pwOpen = false)}>{$t('common.cancel')}</button><button class="btn primary" form="ftpp" disabled={busy}>{$t('common.save')}</button>{/snippet}
</Modal>
