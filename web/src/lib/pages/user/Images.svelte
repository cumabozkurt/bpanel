<script>
	// v1.1: Images — thumbnailer, scaler and converter (JPEG/PNG/GIF) for files in the account home.
	import { Image } from '@lucide/svelte';
	import { api } from '$lib/api.js';
	import { t } from '$lib/i18n/index.js';
	import { showErr, ok, qs } from '$lib/util.js';
	import PageHead from '$lib/components/PageHead.svelte';
	let f = $state({ path: qs('path') ?? '', op: 'thumbnail', width: 200, height: 0, percent: 50, format: '', quality: 85 });
	let res = $state(null);
	let busy = $state(false);
	async function run(e) {
		e.preventDefault(); busy = true;
		const body = { path: f.path, op: f.op };
		if (f.op === 'thumbnail') { body.width = Number(f.width) || 0; body.height = Number(f.height) || 0; }
		if (f.op === 'scale') { if (Number(f.width) || Number(f.height)) { body.width = Number(f.width) || 0; body.height = Number(f.height) || 0; } else body.percent = Number(f.percent); }
		if (f.format) body.format = f.format;
		if ((f.format || '') === 'jpeg') body.quality = Number(f.quality);
		try { res = await api.post('/user/images', body); ok('v11.image_done'); } catch (err) { showErr(err); }
		busy = false;
	}
</script>

<PageHead title={$t('tools.images')} desc={$t('v11.images_desc')} icon={Image} />
<form class="card" onsubmit={run}><div class="card-body stack">
	<label class="field"><span>{$t('v11.image_path')}</span><input class="mono" bind:value={f.path} required placeholder="public_html/images/photo.jpg" maxlength="1024" /></label>
	<div class="row wraprow">
		<label class="field"><span>{$t('v11.operation')}</span><select bind:value={f.op}><option value="thumbnail">{$t('v11.op_thumbnail')}</option><option value="scale">{$t('v11.op_scale')}</option><option value="convert">{$t('v11.op_convert')}</option></select></label>
		{#if f.op !== 'convert'}
			<label class="field"><span>{$t('v11.width')}</span><input type="number" min="0" max="8000" bind:value={f.width} /></label>
			<label class="field"><span>{$t('v11.height')}</span><input type="number" min="0" max="8000" bind:value={f.height} /></label>
		{/if}
		{#if f.op === 'scale'}<label class="field"><span>{$t('v11.percent')}</span><input type="number" min="1" max="400" bind:value={f.percent} /></label>{/if}
		<label class="field"><span>{$t('v11.format')}</span><select bind:value={f.format}><option value="">{f.op === 'convert' ? '—' : $t('v11.keep')}</option><option value="jpeg">JPEG</option><option value="png">PNG</option><option value="gif">GIF</option></select></label>
		{#if f.format === 'jpeg'}<label class="field"><span>{$t('v11.quality')}</span><input type="number" min="1" max="100" bind:value={f.quality} /></label>{/if}
	</div>
	<p class="muted small">{$t('v11.images_help')}</p>
	<div><button class="btn primary" disabled={busy}>{$t('v11.run')}</button></div>
	{#if res}<p class="small">{$t('v11.image_result', { path: res.path, w: res.width, h: res.height })}</p>{/if}
</div></form>

<style>.wraprow { flex-wrap: wrap; align-items: flex-end; gap: 12px; }</style>
