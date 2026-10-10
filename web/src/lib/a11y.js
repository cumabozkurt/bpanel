// Accessibility helpers: focus trap for dialogs and translated form validation.
import { translate, locale } from './i18n/index.js';
import { charLen } from './validate.js';

const FOCUSABLE =
	'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function focusables(root) {
	return [...root.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null || el === document.activeElement);
}

const trapStack = [];
/**
 * use:trapFocus — keeps Tab/Shift+Tab inside the node (even if focus fell back to <body>, e.g. after the
 * focused button became disabled), focuses the first field (or opts.initial) when mounted and gives focus
 * back to the opener when destroyed. opts.onEscape is called for Esc while this is the topmost trap.
 */
export function trapFocus(node, opts = {}) {
	const opener = document.activeElement;
	trapStack.push(node);
	queueMicrotask(() => {
		if (node.contains(document.activeElement)) return;
		const first = (opts?.initial && node.querySelector(opts.initial)) ||
			node.querySelector('[autofocus]') ||
			focusables(node).find((el) => !el.closest('[data-skip-autofocus]')) ||
			node;
		first?.focus?.();
	});
	function onKey(e) {
		if (trapStack[trapStack.length - 1] !== node) return;
		if (e.key === 'Escape' && opts?.onEscape) { e.preventDefault(); e.stopPropagation(); opts.onEscape(); return; }
		if (e.key !== 'Tab') return;
		e.preventDefault();
		const els = focusables(node);
		if (!els.length) { node.focus(); return; }
		const i = els.indexOf(document.activeElement);
		const n = i === -1 ? (e.shiftKey ? els.length - 1 : 0) : (i + (e.shiftKey ? -1 : 1) + els.length) % els.length;
		els[n].focus();
	}
	document.addEventListener('keydown', onKey, true);
	return {
		update(o) { opts = o; },
		destroy() {
			document.removeEventListener('keydown', onKey, true);
			const k = trapStack.lastIndexOf(node);
			if (k >= 0) trapStack.splice(k, 1);
			// Give focus back to the opener, unless another dialog or page has taken it meanwhile
			// (palette -> wizard: the new dialog keeps its first field focused, R2-UX-07).
			if (opener && opener instanceof HTMLElement && document.contains(opener)) setTimeout(() => {
				const a = document.activeElement;
				if (trapStack.length && a && trapStack[trapStack.length - 1].contains(a)) return;
				if (a && a !== document.body && a !== opener && !node.contains(a) && document.contains(a) && a.id !== 'main-content') return;
				opener.focus?.();
			}, 0);
		}
	};
}

/**
 * Global translated validation messages: replaces the browser's own (English/OS-language)
 * bubbles with ours. An input may name its own message with data-err="key".
 */
function messageFor(el) {
	const v = el.validity;
	if (v.valueMissing) return el.type === 'file' ? translate('val.file_required') : el.type === 'checkbox' ? translate('val.check_required') : translate('val.required');
	if ((v.patternMismatch || v.typeMismatch || v.badInput) && el.dataset.err) return translate(el.dataset.err, { max: el.maxLength > 0 ? el.maxLength : '' });
	if (v.typeMismatch && el.type === 'email') return translate('errors.invalid_email');
	if (v.typeMismatch && el.type === 'url') return translate('val.url');
	if (v.patternMismatch) return translate('val.pattern');
	if (v.tooShort) return translate('val.too_short', { n: el.minLength });
	if (v.tooLong) return translate('val.too_long', { n: el.maxLength });
	if (v.rangeUnderflow) return translate('val.min', { n: el.min });
	if (v.rangeOverflow) return translate('val.max', { n: el.max });
	if (v.stepMismatch || v.badInput) return translate('val.number');
	return '';
}

export function installValidationMessages() {
	const onInvalid = (e) => {
		const el = e.target;
		if (!(el instanceof HTMLInputElement || el instanceof HTMLSelectElement || el instanceof HTMLTextAreaElement)) return;
		if (el.validity.customError && !el.dataset.autoMsg) return; // component-managed message
		el.setCustomValidity('');
		if (el.validity.valid) return;
		const msg = messageFor(el);
		if (msg) { el.setCustomValidity(msg); el.dataset.autoMsg = '1'; }
		el.setAttribute('aria-invalid', 'true');
	};
	const onInput = (e) => {
		const el = e.target;
		if (el?.dataset?.autoMsg) { el.setCustomValidity(''); delete el.dataset.autoMsg; }
		if (el?.getAttribute?.('aria-invalid') === 'true' && el.validity?.valid) el.removeAttribute('aria-invalid');
	};
	document.addEventListener('invalid', onInvalid, true);
	document.addEventListener('input', onInput, true);
	document.addEventListener('change', onInput, true);
}

// A field can carry two component-managed problems: its own rule (customValidity) and the
// length limit (maxLen). The length problem wins, so a too-long paste is never hidden.
function applyValidity(node) {
	const st = node.__bp ?? {};
	node.setCustomValidity(st.len || st.custom || '');
	delete node.dataset.autoMsg;
	if (st.len) node.setAttribute('aria-invalid', 'true');
	else if (st.lenWas) { node.removeAttribute('aria-invalid'); st.lenWas = false; }
}

/** use:customValidity={key|null} — component-managed rule (e.g. cron fields, passwords). */
export function customValidity(node, problem) {
	function set(p) {
		const [key, params] = Array.isArray(p) ? p : [p, undefined];
		node.__bp = { ...(node.__bp ?? {}), custom: key ? translate(key, params) : '' };
		applyValidity(node);
	}
	set(problem);
	return { update: set };
}

/**
 * use:maxLen={max} — R2-UX-10: instead of a hard maxlength (which silently cuts pasted text and
 * then saves the cut value) the field accepts any length, shows a live "n / max" counter from 75 %
 * of the limit and blocks submit with "Too long: n characters, at most max." The counter is
 * inserted after the field (or its .input-group) and linked with aria-describedby; data-max
 * carries the limit for tests and scripts.
 */
let cntSeq = 0;
export function maxLen(node, max) {
	const c = document.createElement('small');
	c.className = 'counter';
	c.id = (node.id || 'fld') + '-cnt-' + ++cntSeq;
	(node.closest('.input-group') ?? node).after(c);
	node.setAttribute('aria-describedby', [node.getAttribute('aria-describedby'), c.id].filter(Boolean).join(' '));
	function upd() {
		node.dataset.max = String(max);
		const n = charLen(node.value);
		const over = n > max;
		c.textContent = n ? translate('val.counter', { n, max }) : '';
		c.classList.toggle('over', over);
		c.hidden = !n || (n < max * 0.75 && !over);
		const st = (node.__bp ??= {});
		if (over) { st.len = translate('val.too_long_n', { n, max }); st.lenWas = true; } else st.len = '';
		applyValidity(node);
	}
	const unsub = locale.subscribe(() => upd());
	node.addEventListener('input', upd);
	queueMicrotask(upd);
	return {
		update(m) { max = m; upd(); },
		destroy() { unsub(); node.removeEventListener('input', upd); c.remove(); }
	};
}

/** use:digitsOnly — TOTP fields (R2-UX-23): "123 456", " 123456 " and "123-456" become 123456. */
export function digitsOnly(node) {
	function clean() {
		const v = node.value.replace(/[\s\-\u00a0\u2007\u202f]/g, '');
		if (v !== node.value) { node.value = v; node.dispatchEvent(new Event('input', { bubbles: true })); }
	}
	node.addEventListener('input', clean);
	node.addEventListener('change', clean);
	return { destroy() { node.removeEventListener('input', clean); node.removeEventListener('change', clean); } };
}
