<script>
	import { ChevronUp, ChevronDown, ShieldCheck, ShieldAlert, ChevronRight } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { visibleGroups } from '$lib/tools.js';
	import { session } from '$lib/stores.js';
	import { openTool } from '$lib/actions.js';
	import ToolIcon from '$lib/components/ToolIcon.svelte';
	import Stat from '$lib/components/Stat.svelte';
	import { pageTitle } from '$lib/stores.js';
	$effect(() => { pageTitle.set($t('dash.tools')); return () => pageTitle.set(''); });
	// R2-SYS-16: tools of features this server does not run (mail, DNS, FTP) are not shown
	let userGroups = $derived(visibleGroups('user', $session?.user?.role, $session?.features));

	let sum = $state(null);
	let collapsed = $state(JSON.parse(localStorage.getItem('bp_collapsed') || '[]'));
	api.get('/user/summary').then((s) => (sum = s)).catch(() => {});

	function toggle(id) {
		collapsed = collapsed.includes(id) ? collapsed.filter((x) => x !== id) : [...collapsed, id];
		localStorage.setItem('bp_collapsed', JSON.stringify(collapsed));
	}
	const bytesKeys = ['disk', 'db_disk', 'bandwidth'];
</script>

<h1 class="title">{$t('dash.tools')}</h1>
<div class="layout">
	<div class="groups">
		{#each userGroups as g}
			{@const open = !collapsed.includes(g.id)}
			<section class="card group">
				<button class="card-head gh" aria-expanded={open} onclick={() => toggle(g.id)}>
					<ToolIcon icon={g.icon} size={24} />
					<h2 class="grow">{$t('groups.' + g.id)}</h2>
					{#if open}<ChevronUp size={18} />{:else}<ChevronDown size={18} />{/if}
				</button>
				{#if open}
					<div class="tools">
						{#each g.tools as tool}
							<button class="tool" onclick={() => openTool(tool)}>
								<ToolIcon icon={tool.icon} size={32} />
								<span>{$t('tools.' + tool.id)}</span>
							</button>
						{/each}
					</div>
				{/if}
			</section>
		{/each}
	</div>
	<aside class="side">
		<section class="card">
			<div class="card-head"><h2>{$t('dash.general_info')}</h2></div>
			<div class="card-body info">
				{#if sum}
					<div class="kv">
						<div>{$t('dash.current_user')}</div><div>{sum.username}</div>
						<div>{$t('dash.primary_domain')}</div>
						<div>
							{sum.primary_domain}
							{#if sum.ssl_status === 'active'}<span class="badge green"><ShieldCheck size={11} /> SSL</span>{:else}<span class="badge amber"><ShieldAlert size={11} /> SSL</span>{/if}
						</div>
						<div>{$t('dash.shared_ip')}</div><div class="mono">{sum.shared_ip}</div>
						<div>{$t('dash.home_dir')}</div><div class="mono">{sum.home}</div>
						<div>{$t('dash.last_login')}</div><div class="mono">{sum.last_login_ip || '—'}</div>
						<div>{$t('dash.package')}</div><div>{sum.package}</div>
						<div>{$t('dash.php_version')}</div><div>PHP {sum.php_version}</div>
					</div>
					<a class="btn outline sm ssl" href="/ssl"><ShieldCheck size={14} /> {$t('dash.ssl_status')}</a>
					<a class="srv" href="/disk">{$t('dash.server_info')} <ChevronRight size={14} /></a>
				{:else}
					<p class="muted">{$t('common.loading')}</p>
				{/if}
			</div>
		</section>
		<section class="card">
			<div class="card-head"><h2>{$t('dash.statistics')}</h2></div>
			<div class="card-body">
				{#each sum?.stats ?? [] as s}
					<Stat label={$t('stats.' + s.key)} used={s.used} limit={s.limit} bytes={bytesKeys.includes(s.key)} />
				{/each}
			</div>
		</section>
	</aside>
</div>

<style>
	.title { margin-bottom: 16px; }
	.layout { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 20px; align-items: start; }
	.groups { display: flex; flex-direction: column; gap: 16px; }
	.gh { width: 100%; background: none; border: 0; border-bottom: 1px solid var(--border); color: var(--text); font: inherit; cursor: pointer; text-align: left; }
	.group:has(.gh[aria-expanded='false']) .gh { border-bottom: 0; }
	.tools { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 2px 12px; padding: 10px 14px 12px; }
	.tool { display: flex; align-items: center; gap: 12px; padding: 9px 8px; background: none; border: 0; border-radius: 6px; color: var(--link); font: inherit; text-align: left; cursor: pointer; min-height: 50px; }
	.tool:hover { background: var(--card-2); }
	.tool:hover span { text-decoration: underline; }
	.side { display: flex; flex-direction: column; gap: 16px; position: sticky; top: 76px; }
	.info .kv { font-size: 13px; }
	.ssl { margin-top: 12px; width: 100%; }
	.srv { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; font-size: 13px; }
	@media (max-width: 1180px) { .tools { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
	@media (max-width: 980px) { .layout { grid-template-columns: 1fr; } .side { position: static; } }
	@media (max-width: 560px) { .tools { grid-template-columns: 1fr; } }
</style>
