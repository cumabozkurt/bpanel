<script>
	import { Cpu, RotateCw, Play, Square, RefreshCw } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t, fmt } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let list = $state(null);
	let busy = $state('');
	async function load() { try { list = await api.get('/admin/services'); } catch (e) { showErr(e); } }
	load();
	async function act(s, a) {
		if (a === 'stop' && !ask('svc.confirm_stop', { name: s.name })) return;
		busy = s.unit + a;
		try { await api.post(`/admin/services/${s.unit}/${a}`); ok('svc.done_' + a, { name: s.name }); load(); } catch (e) { showErr(e); }
		busy = '';
	}
</script>

<PageHead title={$t('svc.title')} desc={$t('svc.desc')} icon={Cpu}>
	{#snippet actions()}<button class="btn" onclick={load}><RefreshCw size={15} /> {$t('fm.reload')}</button>{/snippet}
</PageHead>
<div class="card tw">
	<table class="table">
		<thead><tr><th>{$t('svc.service')}</th><th>{$t('svc.unit')}</th><th>{$t('svc.status')}</th><th>{$t('svc.memory')}</th><th>{$t('svc.since')}</th><th><span class="sr-only">{$t('common.actions')}</span></th></tr></thead>
		<tbody>
			{#each list ?? [] as s}
				<tr>
					<td><b>{s.name}</b></td><td class="mono small">{s.unit}</td>
					<td>{#if s.active === 'active'}<span class="badge green"><span aria-hidden="true">●</span> {$t('svc.running')}</span>{:else if s.active === 'failed'}<span class="badge red"><span aria-hidden="true">●</span> {$t('svc.failed')}</span>{:else}<span class="badge amber">● {$t('svc.state_' + s.active) === 'svc.state_' + s.active ? $t('svc.state_unknown', { state: s.active }) : $t('svc.state_' + s.active)}</span>{/if}</td>
					<td>{s.memory_bytes ? $fmt.bytes(s.memory_bytes) : '—'}</td>
					<td class="small">{s.since_unix ? $fmt.date(s.since_unix) : '—'}</td>
					<td><div class="actions">
						{#if s.active === 'active'}
							<button class="btn sm" disabled={!!busy} onclick={() => act(s, 'restart')} aria-label={$t('svc.restart') + ': ' + s.name}><RotateCw size={13} class={busy === s.unit + 'restart' ? 'spin' : ''} /> {$t('svc.restart')}</button>
							{#if s.unit !== 'bpanel-api'}<button class="btn sm danger" disabled={!!busy} onclick={() => act(s, 'stop')} aria-label={$t('svc.stop') + ': ' + s.name}><Square size={13} /> {$t('svc.stop')}</button>{/if}
						{:else}
							<button class="btn sm" disabled={!!busy} onclick={() => act(s, 'start')} aria-label={$t('svc.start') + ': ' + s.name}><Play size={13} /> {$t('svc.start')}</button>
						{/if}
					</div></td>
				</tr>
			{:else}<tr><td colspan="6" class="empty">{$t('common.loading')}</td></tr>{/each}
		</tbody>
	</table>
</div>
