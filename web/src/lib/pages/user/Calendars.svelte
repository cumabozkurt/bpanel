<script>
	// v1.1: Calendars & Contacts — CalDAV/CardDAV (Radicale) for the account's mailboxes, at /dav/ of this panel.
	import { CalendarDays, Trash2, KeyRound } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, ask } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let data = $state(null);
	let pw = $state({});
	async function load() { try { data = await api.get('/user/calendars'); } catch (e) { showErr(e); } }
	async function enable(b) {
		try { await api.put('/user/calendars/' + b.mailbox_id, { password: pw[b.mailbox_id] ?? '' }); pw[b.mailbox_id] = ''; ok('v11.dav_enabled', { email: b.email }); load(); } catch (e) { showErr(e); }
	}
	async function disable(b) {
		if (!ask('v11.dav_disable_confirm', { email: b.email })) return;
		try { await api.del('/user/calendars/' + b.mailbox_id); ok('v11.dav_disabled'); load(); } catch (e) { showErr(e); }
	}
	load();
</script>

<PageHead title={$t('tools.calendars')} desc={$t('v11.dav_desc')} icon={CalendarDays} />
{#if data}
	<div class="stack">
		<div class="card"><div class="card-body kv small">
			<div>{$t('v11.status')}</div><div><span class="badge" class:green={data.status === 'active'} class:amber={data.status !== 'active'}>{$t('v11.dav_' + (data.status || 'inactive'))}</span> {data.reason ?? ''}</div>
			<div>{$t('v11.server_url')}</div><div class="mono">{data.url}</div>
		</div></div>
		<div class="card tw"><table class="table">
			<thead><tr><th>{$t('mailx.mailbox')}</th><th>{$t('v11.dav_url')}</th><th>{$t('v11.dav_password')}</th><th></th></tr></thead>
			<tbody>
				{#each data.mailboxes as b (b.mailbox_id)}
					<tr><td>{b.email} {#if b.enabled}<span class="badge green">{$t('v11.on')}</span>{/if}</td>
						<td class="mono small">{b.enabled ? b.calendar_url : '—'}</td>
						<td><input type="password" bind:value={pw[b.mailbox_id]} minlength="10" maxlength="72" autocomplete="new-password" placeholder={$t('v11.min10')} aria-label={$t('v11.dav_password')} /></td>
						<td class="right"><button class="btn sm" onclick={() => enable(b)}><KeyRound size={14} /> {b.enabled ? $t('v11.change_password') : $t('v11.enable')}</button>
							{#if b.enabled}<button class="btn ghost sm" aria-label={$t('common.delete')} onclick={() => disable(b)}><Trash2 size={14} /></button>{/if}</td></tr>
				{:else}<tr><td colspan="4" class="empty">{$t('v11.no_mailboxes')}</td></tr>{/each}
			</tbody></table></div>
		<p class="muted small">{$t('v11.dav_help')}</p>
	</div>
{/if}
