<script>
	// G1: a limit as WHM shows it — a number (0 = none) plus an explicit "Unlimited" checkbox.
	// value is { unl: boolean, n: number }; see $lib/limits.js for the API encoding.
	import { t } from '$lib/i18n/index.js';
	let { label, value = $bindable({ unl: false, n: 0 }), unit = '', min = 0, max = undefined, help = '', id, allowUnlimited = true } = $props();
</script>

<div class="lim">
	<label class="lbl" for={id}>{label}</label>
	<div class="limit">
		<div class="input-group">
			<input {id} type="number" {min} {max} step="1" bind:value={value.n} disabled={value.unl} required={!value.unl} aria-describedby={help ? id + '-h' : undefined} />
			{#if unit}<span class="addon">{unit}</span>{/if}
		</div>
		{#if allowUnlimited}
			<label class="unl"><input type="checkbox" bind:checked={value.unl} aria-label={$t('common.unlimited_named', { name: label })} /> {$t('common.unlimited')}</label>
		{/if}
	</div>
	{#if help}<small id={id + '-h'}>{help}</small>{/if}
</div>

<style>
	.lim { margin-bottom: 14px; }
	.lbl { display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; }
	small { display: block; color: var(--muted); font-size: 12px; margin-top: 4px; }
</style>
