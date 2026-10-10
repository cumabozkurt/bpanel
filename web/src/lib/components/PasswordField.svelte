<script>
	import { Eye, EyeOff, Wand2 } from '@lucide/svelte';
	import { t } from '$lib/i18n/index.js';
	import { passwordProblem } from '$lib/validate.js';
	import { customValidity } from '$lib/a11y.js';
	let { value = $bindable(''), label = '', id = 'pw', autocomplete = 'new-password', generate = true } = $props();
	let show = $state(false);
	let touched = $state(false);
	function gen() {
		// No ':' (rejected by the backend); always mixes lower, upper and digits.
		const set = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_+=!';
		const a = new Uint32Array(18);
		crypto.getRandomValues(a);
		value = 'Bp' + Array.from(a, (x) => set[x % set.length]).join('') + '7';
		show = true;
		touched = true;
	}
	let problem = $derived(passwordProblem(value));
	let strength = $derived.by(() => {
		if (problem) return 1;
		let s = 1;
		if (value.length >= 14) s++;
		if (/[a-z]/.test(value) && /[A-Z]/.test(value) && /\d/.test(value)) s++;
		if (/[^A-Za-z0-9]/.test(value)) s++;
		return s;
	});
</script>

<div class="field pwf">
	<label for={id}>{label || $t('common.password')}</label>
	<div class="input-group">
		<input {id} type={show ? 'text' : 'password'} bind:value {autocomplete} required minlength="10" data-max="256"
			use:customValidity={value ? problem : null} onblur={() => (touched = true)}
			aria-describedby={id + '-help'} aria-invalid={touched && value && problem ? 'true' : undefined} />
		<button type="button" class="addon iconbtn" aria-label={show ? $t('common.hide_password') : $t('common.show_password')} aria-pressed={show} onclick={() => (show = !show)}>
			{#if show}<EyeOff size={15} />{:else}<Eye size={15} />{/if}
		</button>
		{#if generate}
			<button type="button" class="addon iconbtn gen" onclick={gen}><Wand2 size={15} /> <span class="gtxt">{$t('common.generate')}</span></button>
		{/if}
	</div>
	<div id={id + '-help'}>
		{#if value}
			<div class="meter" aria-hidden="true"><div style="width:{strength * 25}%" class="s{strength}"></div></div>
			{#if problem && touched}
				<small class="err">{$t(problem)}</small>
			{:else}
				<small>{$t('common.strength')}: {$t('common.strength_' + strength)}</small>
			{/if}
		{:else}
			<small>{$t('common.password_rules')}</small>
		{/if}
	</div>
</div>

<style>
	.pwf { margin-bottom: 14px; }
	.pwf > label { display: block; font-weight: 600; font-size: 13px; margin-bottom: 5px; }
	.pwf small { display: block; color: var(--muted); font-size: 12px; margin-top: 4px; }
	.pwf small.err { color: var(--red-text); }
	.iconbtn { cursor: pointer; gap: 4px; font: inherit; font-size: 12.5px; color: var(--text-2); }
	.input-group > .iconbtn { border-left: 0; border-radius: 0; }
	.input-group > .iconbtn:last-child { border-radius: 0 var(--radius) var(--radius) 0; }
	.input-group > input { min-width: 0; }
	.meter { height: 4px; background: var(--border); border-radius: 4px; margin-top: 6px; overflow: hidden; }
	.meter div { height: 100%; background: var(--red); }
	.meter .s2 { background: var(--amber); }
	.meter .s3, .meter .s4 { background: var(--green); }
	@media (max-width: 420px) { .gtxt { display: none; } }
</style>
