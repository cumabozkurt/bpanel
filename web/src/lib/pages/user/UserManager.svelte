<script>
	// v0.4 adminx: User Manager — unified read-only view of the account's mailboxes and FTP accounts.
	import { Users } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let d = $state(null);
	api.get('/user/user-manager').then((r) => (d = r)).catch(showErr);
</script>

<PageHead title={$t('tools.user_manager')} desc={$t('adminx.um_desc')} icon={Users} />
{#if d}
	<div class="card">
		<a class="btn" href={d.create.email}>{$t('adminx.um_new_email')}</a>
		<a class="btn" href={d.create.ftp}>{$t('adminx.um_new_ftp')}</a>
		<div class="tw"><table class="table">
			<thead><tr><th>{$t('adminx.um_login')}</th><th>{$t('adminx.um_services')}</th><th>{$t('adminx.um_quota')}</th><th></th></tr></thead>
			<tbody>
				{#each d.users as u}
					<tr><td class="mono">{u.login}</td><td>{#each u.services as s}<span class="badge">{$t('adminx.svc_' + s)}</span> {/each}{#if u.detail}<span class="muted small">{u.detail}</span>{/if}</td>
						<td>{u.quota_mb > 0 ? u.quota_mb + ' MB' : $t('adminx.unlimited')}</td><td><a class="btn small" href={u.manage}>{$t('adminx.um_manage')}</a></td></tr>
				{:else}<tr><td colspan="4" class="empty">{$t('common.none')}</td></tr>{/each}
			</tbody>
		</table></div>
		<p class="muted small">{$t('adminx.um_webdisk_na')}</p>
	</div>
{/if}
