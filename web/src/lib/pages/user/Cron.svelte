<script>
	import { Clock, Plus, Trash2, Mail } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	import { cronFieldProblem, cronCommandProblem, CRON_FIELDS } from '$lib/validate.js';
	import { customValidity, maxLen } from '$lib/a11y.js';

	let data = $state({ jobs: [], email: '' });
	let email = $state('');
	let form = $state({ minute: '0', hour: '*', dom: '*', month: '*', dow: '*', command: '' });
	let busy = $state(false);
	let tried = $state(false);
	// R2-UX-14: schedule fields are trimmed before the check (" 5 " is 5); a command pasted with line
	// breaks is not silently joined into a different command — it is flagged and can be joined with &&.
	let problems = $derived(Object.fromEntries(Object.keys(CRON_FIELDS).map((k) => [k, cronFieldProblem(String(form[k]).trim(), k)])));
	let multiline = $derived(/[\r\n]/.test(form.command.trim()));
	let cmdProblem = $derived(multiline ? 'cron.multiline' : cronCommandProblem(form.command));
	function joinLines() {
		form.command = form.command.split(/\r?\n/).map((l) => l.trim()).filter(Boolean).join(' && ');
		document.getElementById('cron-cmd')?.focus();
	}
	const hint = (k) => CRON_FIELDS[k].min + '–' + CRON_FIELDS[k].max + (CRON_FIELDS[k].names ? ', ' + CRON_FIELDS[k].names.slice(0, 3).join(', ') + '…' : '');
	const presets = [
		['once_minute', ['*', '*', '*', '*', '*']], ['every_5', ['*/5', '*', '*', '*', '*']], ['every_15', ['*/15', '*', '*', '*', '*']],
		['hourly', ['0', '*', '*', '*', '*']], ['twice_daily', ['0', '0,12', '*', '*', '*']], ['daily', ['0', '0', '*', '*', '*']],
		['weekly', ['0', '0', '*', '*', '0']], ['monthly', ['0', '0', '1', '*', '*']]
	];
	async function load() { try { data = await api.get('/user/cron'); email = data.email; } catch (e) { showErr(e); } }
	load();
	function preset(e) { const p = presets.find((x) => x[0] === e.currentTarget.value); if (p) [form.minute, form.hour, form.dom, form.month, form.dow] = p[1]; }
	async function add(e) { e.preventDefault(); tried = true; if (Object.values(problems).some(Boolean) || cmdProblem) return; busy = true; try { await api.post('/user/cron', { minute: String(form.minute).trim(), hour: String(form.hour).trim(), dom: String(form.dom).trim(), month: String(form.month).trim(), dow: String(form.dow).trim(), command: form.command.trim() }); ok('cron.added'); form.command = ''; tried = false; load(); } catch (err) { showErr(err); } busy = false; }
	async function del(j) { if (!ask('cron.confirm_delete')) return; try { await api.del('/user/cron/' + j.id); ok('common.deleted'); load(); } catch (err) { showErr(err); } }
	async function saveEmail(e) { e.preventDefault(); try { await api.put('/user/cron/email', { email }); ok('common.saved'); } catch (err) { showErr(err); } }
</script>

<PageHead title={$t('cron.title')} desc={$t('cron.desc')} icon={Clock} />
<div class="stack">
	<form class="card" onsubmit={saveEmail}>
		<div class="card-head"><Mail size={17} /><h2>{$t('cron.email')}</h2></div>
		<div class="card-body row wraprow"><input type="email" bind:value={email} placeholder="you@example.com" style="max-width:360px" aria-label={$t('cron.email')} /><button class="btn">{$t('cron.update_email')}</button><span class="muted small">{$t('cron.email_help')}</span></div>
	</form>
	<form class="card" onsubmit={add} novalidate>
		<div class="card-head"><Plus size={17} /><h2>{$t('cron.add')}</h2></div>
		<div class="card-body">
			<label class="field" style="max-width:360px"><span>{$t('cron.common')}</span>
				<select onchange={preset}><option value="">{$t('cron.choose')}</option>{#each presets as p}<option value={p[0]}>{$t('cron.p_' + p[0])}</option>{/each}</select></label>
			<div class="sched">
				{#each [['minute', 'cron.minute'], ['hour', 'cron.hour'], ['dom', 'cron.dom'], ['month', 'cron.month'], ['dow', 'cron.dow']] as [k, l]}
					<label class="field"><span>{$t(l)}</span><input bind:value={form[k]} class="mono" required data-max="40" autocapitalize="off" spellcheck="false"
						aria-invalid={tried && problems[k] ? 'true' : undefined} aria-describedby={'cron-' + k + '-h'} use:customValidity={problems[k] ? [problems[k], { range: hint(k) }] : null} />
						{#if tried && problems[k]}<small class="field-err" id={'cron-' + k + '-h'}>{$t(problems[k], { range: hint(k) })}</small>{:else}<small id={'cron-' + k + '-h'}>{hint(k)}</small>{/if}</label>
				{/each}
			</div>
			<label class="field"><span>{$t('cron.command')}</span><textarea id="cron-cmd" bind:value={form.command} class="mono cmdbox" rows="2" placeholder="/usr/bin/php /home/user/public_html/cron.php" required use:maxLen={1000}
				aria-invalid={(tried || multiline) && cmdProblem ? 'true' : undefined} use:customValidity={cmdProblem} onkeydown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); e.currentTarget.form?.requestSubmit(); } }}></textarea>
				{#if multiline}<small class="field-err" role="alert">{$t('cron.multiline')} <button type="button" class="linkbtn" onclick={joinLines}>{$t('cron.join_lines')}</button></small>
				{:else if tried && cmdProblem}<small class="field-err">{$t(cmdProblem)}</small>{:else}<small>{$t('cron.single_line')}</small>{/if}</label>
			<p class="muted small">{$t('cron.syntax_help')}</p>
			<button class="btn primary" disabled={busy}>{$t('cron.add')}</button>
		</div>
	</form>
	<section class="card">
		<div class="card-head"><Clock size={17} /><h2>{$t('cron.current')}</h2></div>
		<div class="tw">
		<table class="table">
			<thead><tr><th>{$t('cron.minute')}</th><th>{$t('cron.hour')}</th><th>{$t('cron.dom')}</th><th>{$t('cron.month')}</th><th>{$t('cron.dow')}</th><th>{$t('cron.command')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
			<tbody>
				{#each data.jobs as j}
					<tr><td class="mono">{j.minute}</td><td class="mono">{j.hour}</td><td class="mono">{j.dom}</td><td class="mono">{j.month}</td><td class="mono">{j.dow}</td><td class="mono cmd">{j.command}</td>
						<td><div class="actions"><button class="linkbtn danger" onclick={() => del(j)} aria-label={$t('cron.delete_named', { cmd: j.command })}><Trash2 size={13} /> {$t('common.delete')}</button></div></td></tr>
				{:else}<tr><td colspan="7" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table>
		</div>
	</section>
</div>

<style>
	.sched { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
	.cmd { word-break: break-all; }
	.cmdbox { resize: vertical; min-height: 34px; }
	.sched small { display: block; color: var(--muted); font-size: 11.5px; margin-top: 3px; }
	.sched small.field-err { color: var(--red-text); }
	.wraprow { flex-wrap: wrap; }
	@media (max-width: 760px) { .sched { grid-template-columns: repeat(2, 1fr); } }
</style>
