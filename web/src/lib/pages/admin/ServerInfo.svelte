<script>
	import { Info } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let d = $state(null);
	api.get('/admin/server').then((r) => (d = r)).catch(showErr);
</script>

<PageHead title={$t('tools.server_info')} desc={$t('srv.desc')} icon={Info} />
{#if d}
	<div class="grid2">
		<section class="card"><div class="card-head"><h2>{$t('srv.system')}</h2></div><div class="card-body kv">
			<div>{$t('shell.hostname')}</div><div>{d.sys.hostname}</div>
			<div>{$t('shell.os')}</div><div>{d.sys.os}</div>
			<div>{$t('srv.kernel')}</div><div class="mono">{d.sys.kernel}</div>
			<div>{$t('srv.arch')}</div><div>{d.sys.arch}</div>
			<div>{$t('adash.uptime')}</div><div>{$fmt.duration(d.sys.uptime_sec)}</div>
			<div>{$t('srv.panel')}</div><div>BOZKURT PANEL {d.panel_version}</div>
			<div>{$t('srv.agent')}</div><div>{d.agent?.version} · {d.agent?.distro}</div>
		</div></section>
		<section class="card"><div class="card-head"><h2>{$t('srv.resources')}</h2></div><div class="card-body kv">
			<div>CPU</div><div>{d.sys.cpus} × {d.sys.cpu_model || '—'}</div>
			<div>{$t('srv.cpu_usage')}</div><div>{d.sys.cpu_percent}%</div>
			<div>{$t('shell.load')}</div><div class="mono">{d.sys.load.map((x) => x.toFixed(2)).join(' / ')}</div>
			<div>{$t('adash.memory')}</div><div>{$fmt.bytes(d.sys.mem_used)} / {$fmt.bytes(d.sys.mem_total)}</div>
			<div>{$t('srv.swap')}</div><div>{$fmt.bytes(d.sys.swap_used)} / {$fmt.bytes(d.sys.swap_total)}</div>
			<div>{$t('adash.disk')} (/)</div><div>{$fmt.bytes(d.sys.disk_used)} / {$fmt.bytes(d.sys.disk_total)}</div>
			<div>{$t('srv.processes')}</div><div>{d.sys.processes}</div>
			<div>IPv4</div><div class="mono">{(d.sys.ipv4 ?? []).join(', ') || '—'}</div>
			<div>IPv6</div><div class="mono">{(d.sys.ipv6 ?? []).join(', ') || '—'}</div>
		</div></section>
	</div>
{/if}
