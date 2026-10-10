// Sortable + paginated view over a reactive list. Usage:
//   const tbl = new TableState(() => rows, { key: 'name', size: 25, get: { size: (r) => r.size_bytes } });
//   {#each tbl.page as r} … <SortTh {tbl} key="name" label=… /> … <Pager {tbl} />
import { norm } from './search.js';

export class TableState {
	key = $state('');
	dir = $state(1);
	pageNo = $state(1);
	size = $state(25);

	constructor(rows, opts = {}) {
		this.rows = rows;
		this.key = opts.key ?? '';
		this.dir = opts.dir ?? 1;
		this.size = opts.size ?? 25;
		this.get = opts.get ?? {};
		this.pin = opts.pin; // (row) => number: rows with a lower pin always sort first (e.g. folders)
		this.paged = opts.paged ?? true;
	}

	value(r, k) {
		const v = this.get[k] ? this.get[k](r) : r?.[k];
		return v;
	}

	sorted = $derived.by(() => {
		const list = [...(this.rows() ?? [])];
		const k = this.key, d = this.dir;
		if (!k) return list;
		const col = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
		return list.sort((a, b) => {
			if (this.pin) { const p = this.pin(a) - this.pin(b); if (p) return p; }
			const x = this.value(a, k), y = this.value(b, k);
			if (x == null && y == null) return 0;
			if (x == null) return 1;
			if (y == null) return -1;
			if (typeof x === 'number' && typeof y === 'number') return (x - y) * d;
			return col.compare(norm(x), norm(y)) * d;
		});
	});

	total = $derived(this.sorted.length);
	pages = $derived(this.paged ? Math.max(1, Math.ceil(this.sorted.length / this.size)) : 1);
	page = $derived.by(() => {
		if (!this.paged) return this.sorted;
		const p = Math.min(this.pageNo, this.pages);
		return this.sorted.slice((p - 1) * this.size, p * this.size);
	});
	from = $derived(this.total ? (Math.min(this.pageNo, this.pages) - 1) * this.size + 1 : 0);
	to = $derived(Math.min(this.total, this.from - 1 + this.size));

	toggle(k) {
		if (this.key === k) this.dir = -this.dir;
		else { this.key = k; this.dir = 1; }
		this.pageNo = 1;
	}
	go(n) { this.pageNo = Math.max(1, Math.min(this.pages, n)); }
	setSize(n) { this.size = n; this.pageNo = 1; }
	reset() { this.pageNo = 1; }
}
