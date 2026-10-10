<script>
	import { Code2 } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let busy = $state(false);
	async function load() { try { data = await api.get('/user/php'); } catch (e) { showErr(e); } }
	load();
	async function set(row, v) {
		busy = true;
		try { await api.put('/user/domains/' + row.id, { php_version: v }); ok('php.changed', { domain: row.domain, v: v || data.default }); load(); }
		catch (e) { showErr(e); }
		busy = false;
	}
</script>

<PageHead title={$t('php.title')} desc={$t('php.desc')} icon={Code2} />
{#if data}
	<div class="alert info">{$t('php.default_is', { v: data.default })}</div>
	<div class="card">
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('domains.domain')}</th><th>{$t('php.version')}</th><th style="width:240px">{$t('php.change')}</th></tr></thead>
			<tbody>
				{#each data.domains as r}
					<tr><td><b>{r.domain}</b></td><td>PHP {r.version} {#if r.inherited}<span class="badge">{$t('php.inherited')}</span>{/if}</td>
						<td><select disabled={busy} value={r.inherited ? '' : r.version} onchange={(e) => set(r, e.currentTarget.value)} aria-label={$t('php.change')}>
							<option value="">{$t('domains.inherit')} ({data.default})</option>
							{#each data.versions.filter((v) => v.installed) as v}<option value={v.version}>PHP {v.version}</option>{/each}
						</select></td></tr>
				{/each}
			</tbody>
		</table></div>
	</div>
{/if}
