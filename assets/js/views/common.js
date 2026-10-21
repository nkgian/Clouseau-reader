(function () {
  'use strict';

  const C = window.C = window.C || {};
  const U = {};
  const D = C.dom;

  function isDefang() {
    return Boolean(C.state && C.state.prefs && C.state.prefs.defang);
  }

  function displayValue(value, type) {
    const text = String(value == null ? '' : value);
    return isDefang() ? C.format.defang(text, type) : text;
  }

  function badge(text, variant, icon) {
    return D.el('span', { class: 'badge badge-' + (variant || 'muted') },
      icon ? D.icon(icon) : null,
      text
    );
  }

  function taskStatusBadge(status) {
    const map = {
      ok: ['ok', 'check', 'Complete'],
      partial: ['warning', 'alert-triangle', 'Partial'],
      error: ['critical', 'x-circle', 'Error'],
      missing: ['muted', 'minus', 'Not run']
    };
    const item = map[status] || ['muted', 'info', C.format.humanize(status)];
    return badge(item[2], item[0], item[1]);
  }

  function httpStatusBadge(status) {
    const code = Number(status);
    if (!Number.isFinite(code)) return badge('No status', 'muted');
    let variant = 'info';
    if (code >= 200 && code < 300) variant = 'ok';
    else if (code >= 300 && code < 400) variant = 'info';
    else if (code >= 400 && code < 500) variant = 'warning';
    else if (code >= 500) variant = 'critical';
    return badge(String(code), variant);
  }

  function sourceStatusBadge(status) {
    const text = String(status || '').toLowerCase();
    const map = {
      found: ['critical', 'shield-alert', 'Found'],
      clear: ['ok', 'check', 'Clear'],
      error: ['warning', 'alert-triangle', 'Error'],
      ok: ['ok', 'check', 'OK'],
      weak: ['warning', 'alert-triangle', 'Weak'],
      missing: ['warning', 'x-circle', 'Missing']
    };
    const item = map[text] || ['muted', 'info', C.format.humanize(text || 'unknown')];
    return badge(item[2], item[0], item[1]);
  }

  function boolBadge(value, trueLabel, falseLabel, trueVariant, falseVariant) {
    return value
      ? badge(trueLabel || 'Yes', trueVariant || 'ok', 'check')
      : badge(falseLabel || 'No', falseVariant || 'muted', 'x');
  }

  function copyButton(value, label, options) {
    const text = String(value == null ? '' : value);
    if (!text) return null;
    return D.el('button', {
      class: 'copy-btn',
      type: 'button',
      title: 'Copy ' + (label || 'value'),
      'aria-label': 'Copy ' + (label || 'value'),
      onClick: function (event) {
        event.stopPropagation();
        D.copyText(text, label, options);
      }
    }, D.icon('copy'));
  }

  function externalButton(url, options) {
    const opts = options || {};
    if (!url) return null;
    return D.el('button', {
      class: 'copy-btn',
      type: 'button',
      title: opts.warn ? 'Open URL (warning)' : 'Open in a new tab',
      'aria-label': opts.warn ? 'Open potentially malicious URL' : 'Open in a new tab',
      onClick: function (event) {
        event.stopPropagation();
        D.externalUrl(url, { warn: Boolean(opts.warn), source: opts.source });
      }
    }, D.icon(opts.warn ? 'alert-triangle' : 'external'));
  }

  function valueSpan(value, type, className) {
    return D.el('span', { class: className || '' }, D.el('bdi', { text: displayValue(value, type) }));
  }

  function copyable(value, label, type, options) {
    const text = String(value == null ? '' : value);
    if (!text) return D.el('span', { class: 'muted', text: '—' });
    const wrap = D.el('span', { class: 'row' });
    wrap.appendChild(valueSpan(text, type, options && options.mono ? 'mono' : ''));
    const button = copyButton(text, label || type || 'value');
    if (button) wrap.appendChild(button);
    return wrap;
  }

  function hashValue(hash, label) {
    const text = String(hash == null ? '' : hash);
    if (!text) return D.el('span', { class: 'muted', text: '—' });
    return D.el('span', { class: 'hash', title: text },
      D.el('code', { text: C.format.shortHash(text) }),
      copyButton(text, label || 'hash')
    );
  }

  function urlValue(url, options) {
    const opts = options || {};
    if (!url) return D.el('span', { class: 'muted', text: '—' });
    const wrap = D.el('span', { class: 'row-wrap' });
    wrap.appendChild(D.el('span', { class: 'url-text' }, D.el('bdi', { text: displayValue(url, 'url') })));
    const copy = copyButton(url, 'URL');
    if (copy) wrap.appendChild(copy);
    if (opts.open !== false) {
      const ext = externalButton(url, { warn: opts.warn !== false, source: opts.source });
      if (ext) wrap.appendChild(ext);
    }
    if (opts.pivot) wrap.appendChild(pivotBtn('url', url, opts.ctx));
    return wrap;
  }

  function pivotBtn(type, value, ctx, label) {
    if (!C.integrations) return null;
    return D.el('button', {
      class: 'copy-btn',
      type: 'button',
      title: 'Pivot on this value',
      'aria-label': 'Pivot on this value',
      onClick: function (event) {
        event.stopPropagation();
        C.integrations.openPivot(type, value, ctx);
      }
    }, D.icon('crosshair'));
  }

  function chipValue(value, options) {
    const opts = options || {};
    const text = String(value == null ? '' : value);
    if (!text) return null;
    const chip = D.el('span', { class: 'chip ' + (opts.variant || '') + (opts.title ? '' : '') });
    chip.appendChild(D.el('bdi', { text: displayValue(text, opts.type) }));
    const copy = copyButton(text, opts.label || opts.type || 'value');
    if (copy) chip.appendChild(copy);
    if (opts.pivot) {
      const pivot = pivotBtn(opts.type, text, opts.ctx);
      if (pivot) chip.appendChild(pivot);
    }
    return chip;
  }

  function chipList(values, options) {
    const opts = options || {};
    const list = Array.isArray(values) ? values.filter(function (value) { return value != null && String(value).trim(); }) : [];
    if (!list.length) {
      return D.el('div', { class: 'inline-empty', text: opts.empty || 'None found.' });
    }
    const wrap = D.el('div', { class: 'chip-list' });
    list.forEach(function (value) {
      const chip = chipValue(value, opts);
      if (chip) wrap.appendChild(chip);
    });
    return wrap;
  }

  function stat(label, value, sub, options) {
    const opts = options || {};
    const node = D.el('div', { class: 'stat' + (opts.class ? ' ' + opts.class : '') });
    const labelNode = D.el('div', { class: 'stat-label' }, opts.icon ? D.icon(opts.icon) : null, label);
    node.appendChild(labelNode);
    const valueNode = D.el('div', { class: 'stat-value' + (typeof value === 'string' ? ' small' : '') });
    if (value instanceof Node) valueNode.appendChild(value);
    else valueNode.textContent = value == null || value === '' ? '—' : String(value);
    node.appendChild(valueNode);
    if (sub) node.appendChild(D.el('div', { class: 'stat-sub', text: sub }));
    return node;
  }

  function statGrid(items) {
    const grid = D.el('div', { class: 'stat-grid' });
    items.forEach(function (item) { if (item) grid.appendChild(item); });
    return grid;
  }

  function kvRow(label, value, options) {
    const opts = options || {};
    const row = D.el('div', { class: 'kv-row' });
    row.appendChild(D.el('div', { class: 'kv-label', text: label }));
    const cell = D.el('div', { class: 'kv-value' + (opts.strong ? ' strong' : '') + (opts.mono ? ' mono' : '') });
    if (value instanceof Node) cell.appendChild(value);
    else cell.textContent = value == null || value === '' ? (opts.fallback || '—') : String(value);
    row.appendChild(cell);
    return row;
  }

  function kvList(rows) {
    const list = D.el('div', { class: 'kv-list' });
    rows.forEach(function (row) {
      if (!row) return;
      if (row instanceof Node) {
        list.appendChild(row);
      } else if (Array.isArray(row)) {
        list.appendChild(kvRow(row[0], row[1], row[2] || {}));
      } else {
        list.appendChild(kvRow(row.label, row.value, row));
      }
    });
    return list;
  }

  function kvGrid(items) {
    const grid = D.el('div', { class: 'kv-grid' });
    items.forEach(function (item) {
      if (!item) return;
      const block = D.el('div', { class: 'kv-item' });
      block.appendChild(D.el('div', { class: 'kv-label', text: item.label }));
      const value = D.el('div', { class: 'kv-value' + (item.mono ? ' mono' : '') });
      if (item.value instanceof Node) value.appendChild(item.value);
      else value.textContent = item.value == null || item.value === '' ? '—' : String(item.value);
      block.appendChild(value);
      grid.appendChild(block);
    });
    return grid;
  }

  function card(title, content, options) {
    const opts = options || {};
    const node = D.el('section', { class: 'card' + (opts.class ? ' ' + opts.class : '') });
    if (title || opts.actions || opts.subtitle) {
      const head = D.el('div', { class: 'card-head' });
      const text = D.el('div');
      if (title) {
        text.appendChild(D.el('div', { class: 'card-title' }, opts.icon ? D.icon(opts.icon) : null, title));
      }
      if (opts.subtitle) text.appendChild(D.el('div', { class: 'card-subtitle', text: opts.subtitle }));
      head.appendChild(text);
      if (opts.actions) {
        const actions = D.el('div', { class: 'card-actions' });
        D.append(actions, opts.actions);
        head.appendChild(actions);
      }
      node.appendChild(head);
    }
    const body = D.el('div', { class: 'card-body' + (opts.flush ? ' flush' : '') });
    D.append(body, content);
    node.appendChild(body);
    return node;
  }

  function section(title, id, content, options) {
    const opts = options || {};
    const node = D.el('section', { class: 'section', id: id || null });
    const head = D.el('div', { class: 'section-head' });
    const titleWrap = D.el('div');
    const h2 = D.el('h2', { class: 'section-title' }, opts.icon ? D.icon(opts.icon) : null, title);
    if (opts.count != null) h2.appendChild(D.el('span', { class: 'section-count', text: String(opts.count) }));
    titleWrap.appendChild(h2);
    if (opts.subtitle) titleWrap.appendChild(D.el('div', { class: 'section-sub', text: opts.subtitle }));
    head.appendChild(titleWrap);
    if (opts.actions) {
      const actions = D.el('div', { class: 'toolbar' });
      D.append(actions, opts.actions);
      head.appendChild(actions);
    }
    node.appendChild(head);
    const body = D.el('div', { class: 'stack' });
    D.append(body, content);
    node.appendChild(body);
    return node;
  }

  function sectionNav(items) {
    if (!items || items.length < 2) return null;
    const nav = D.el('nav', { class: 'section-nav', 'aria-label': 'Jump to section' });
    items.forEach(function (item) {
      nav.appendChild(D.el('button', {
        type: 'button',
        onClick: function () {
          const target = document.getElementById(item.id);
          if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
      }, item.label, item.count != null ? ' ' + item.count : ''));
    });
    return nav;
  }

  function notice(kind, icon, title, detail) {
    const node = D.el('div', { class: 'notice ' + (kind || '') });
    node.appendChild(D.icon(icon || 'info'));
    const body = D.el('div');
    if (title) body.appendChild(D.el('strong', { text: title }));
    if (detail) body.appendChild(D.el('div', { text: detail }));
    node.appendChild(body);
    return node;
  }

  function errorList(errors, options) {
    const opts = options || {};
    if (!errors || !errors.length) return null;
    const list = D.el('div', { class: 'error-list' });
    errors.forEach(function (item) {
      const entry = D.el('div', { class: 'error-item' });
      entry.appendChild(D.el('div', { class: 'error-task', text: item.task || 'unknown task' }));
      entry.appendChild(D.el('div', { class: 'error-msg', text: String(item.error || '') }));
      if (opts.onOpen) {
        entry.appendChild(D.el('button', {
          class: 'obs-link',
          type: 'button',
          onClick: function () { opts.onOpen(item); }
        }, 'Open raw data'));
      }
      list.appendChild(entry);
    });
    return list;
  }

  function collapsible(title, content, open) {
    const details = D.el('details', { class: 'collapse', open: Boolean(open) });
    details.appendChild(D.el('summary', {}, title));
    const body = D.el('div', { class: 'collapse-body' });
    D.append(body, content);
    details.appendChild(body);
    return details;
  }

  function codeBlock(text, options) {
    const opts = options || {};
    const wrap = D.el('div', { class: 'stack' });
    if (opts.actions) {
      const bar = D.el('div', { class: 'toolbar' });
      D.append(bar, opts.actions);
      wrap.appendChild(bar);
    }
    const pre = D.el('pre', { class: 'code-block' + (opts.nowrap ? ' nowrap' : '') + (opts.class ? ' ' + opts.class : '') });
    pre.textContent = String(text == null ? '' : text);
    wrap.appendChild(pre);
    return wrap;
  }

  function detailBlock(title, content, icon) {
    const block = D.el('div', { class: 'detail-block' });
    block.appendChild(D.el('div', { class: 'detail-block-title' }, icon ? D.icon(icon) : null, title));
    D.append(block, content);
    return block;
  }

  function dataTable(columns, rows, options) {
    const opts = options || {};
    const state = {
      query: '',
      sortKey: opts.sortKey || null,
      sortDir: opts.sortDir || 1,
      limit: opts.pageSize || 50
    };
    const root = D.el('div', { class: 'table-component' + (opts.class ? ' ' + opts.class : '') });
    const toolbar = D.el('div', { class: 'table-toolbar' });
    const search = D.el('input', {
      type: 'search',
      class: 'input input-sm',
      placeholder: opts.filterPlaceholder || 'Filter rows…',
      'aria-label': opts.filterPlaceholder || 'Filter table rows'
    });
    const count = D.el('span', { class: 'row-count' });
    toolbar.appendChild(search);
    toolbar.appendChild(count);
    root.appendChild(toolbar);

    const wrap = D.el('div', { class: 'table-wrap' });
    const hasWidths = columns.some(function (col) { return Boolean(col.width); });
    const table = D.el('table', { class: 'data-table' + (hasWidths ? ' wide' : '') });
    const thead = D.el('thead');
    const tbody = D.el('tbody');
    table.appendChild(thead);
    table.appendChild(tbody);
    wrap.appendChild(table);
    root.appendChild(wrap);

    const moreWrap = D.el('div', { class: 'table-more' });
    const moreButton = D.el('button', { class: 'btn btn-ghost btn-sm', type: 'button' }, 'Show more');
    moreWrap.appendChild(moreButton);
    root.appendChild(moreWrap);

    const textCache = new Map();
    function rowText(row) {
      if (textCache.has(row)) return textCache.get(row);
      let text = '';
      if (typeof opts.searchText === 'function') {
        text = String(opts.searchText(row) || '');
      } else {
        text = columns.map(function (col) {
          const value = col.value ? col.value(row) : row[col.key];
          return value == null ? '' : String(value);
        }).join(' ');
      }
      text = text.toLowerCase();
      textCache.set(row, text);
      return text;
    }

    function filteredRows() {
      const query = state.query.trim().toLowerCase();
      let list = rows;
      if (query) list = rows.filter(function (row) { return rowText(row).indexOf(query) !== -1; });
      if (state.sortKey) {
        const column = columns.find(function (col) { return col.key === state.sortKey; });
        if (column) {
          list = list.slice().sort(function (a, b) {
            const av = column.value ? column.value(a) : a[column.key];
            const bv = column.value ? column.value(b) : b[column.key];
            if (typeof av === 'number' && typeof bv === 'number') return (av - bv) * state.sortDir;
            return String(av == null ? '' : av).localeCompare(String(bv == null ? '' : bv)) * state.sortDir;
          });
        }
      }
      return list;
    }

    function renderHead() {
      D.clear(thead);
      const tr = D.el('tr');
      columns.forEach(function (col) {
        const sortable = opts.sortable !== false && col.sortable !== false;
        const th = D.el('th', {
          class: (sortable ? 'sortable' : '') + (col.class ? ' ' + col.class : ''),
          style: col.width ? { width: col.width } : null
        });
        if (!sortable) {
          th.textContent = col.label;
        } else {
          const isActive = state.sortKey === col.key;
          th.appendChild(D.el('span', { text: col.label }));
          if (isActive) th.appendChild(D.el('span', { class: 'sort-ind', text: state.sortDir > 0 ? '↑' : '↓' }));
          th.addEventListener('click', function () {
            if (state.sortKey === col.key) state.sortDir *= -1;
            else {
              state.sortKey = col.key;
              state.sortDir = 1;
            }
            renderHead();
            renderBody();
          });
        }
        tr.appendChild(th);
      });
      thead.appendChild(tr);
    }

    function renderBody() {
      D.clear(tbody);
      const list = filteredRows();
      const visible = list.slice(0, state.limit);
      if (!list.length) {
        const tr = D.el('tr');
        tr.appendChild(D.el('td', { colspan: String(columns.length) }, D.el('div', { class: 'table-empty', text: opts.empty || 'No rows match this filter.' })));
        tbody.appendChild(tr);
      } else {
        visible.forEach(function (row, index) {
          const tr = D.el('tr', { class: opts.rowClass ? opts.rowClass(row, index) : null });
          columns.forEach(function (col) {
            const td = D.el('td', { class: (col.cellClass || '') + (col.align === 'right' ? ' num' : '') });
            const rendered = col.render ? col.render(row, index) : (row[col.key] == null ? '' : String(row[col.key]));
            if (rendered instanceof Node) td.appendChild(rendered);
            else td.textContent = rendered == null ? '' : String(rendered);
            tr.appendChild(td);
          });
          tbody.appendChild(tr);
        });
      }
      count.textContent = list.length + ' of ' + rows.length + ' ' + (opts.rowLabel || 'rows');
      moreWrap.hidden = list.length <= state.limit;
      if (!moreWrap.hidden) {
        moreButton.textContent = 'Show ' + Math.min(opts.pageSize || 50, list.length - state.limit) + ' more';
      }
    }

    search.addEventListener('input', function () {
      state.query = search.value;
      state.limit = opts.pageSize || 50;
      renderBody();
    });
    moreButton.addEventListener('click', function () {
      state.limit += opts.pageSize || 50;
      renderBody();
    });

    renderHead();
    renderBody();
    return root;
  }

  function sourceTag(label, icon) {
    return D.el('span', { class: 'source-tag' }, icon ? D.icon(icon) : null, label);
  }

  function emptyInline(text) {
    return D.el('div', { class: 'inline-empty', text: text || 'No data.' });
  }

  function notRun(label) {
    return D.el('div', { class: 'inline-empty', text: (label || 'This module') + ' was not part of this scan.' });
  }

  function profileCard(title, rows, mismatch) {
    const node = D.el('div', { class: 'profile' + (mismatch ? ' mismatch' : '') });
    node.appendChild(D.el('div', { class: 'profile-name' }, D.el('span', { text: title }), mismatch ? badge('Differs', 'critical', 'alert-triangle') : null));
    rows.forEach(function (row) {
      const line = D.el('div', { class: 'profile-row' });
      line.appendChild(D.el('span', { text: row[0] }));
      const value = D.el('span');
      if (row[1] instanceof Node) value.appendChild(row[1]);
      else value.textContent = row[1] == null || row[1] === '' ? '—' : String(row[1]);
      line.appendChild(value);
      node.appendChild(line);
    });
    return node;
  }

  function redirectChain(redirects) {
    const list = Array.isArray(redirects) ? redirects : [];
    if (!list.length) return emptyInline('No redirects reported.');
    const chain = D.el('div', { class: 'redirect-chain' });
    list.forEach(function (hop, index) {
      const row = D.el('div', { class: 'redirect-hop' });
      row.appendChild(httpStatusBadge(hop.status));
      row.appendChild(urlValue(hop.url, { open: false }));
      if (index < list.length - 1) row.appendChild(D.icon('arrow-right'));
      chain.appendChild(row);
    });
    return chain;
  }

  function checkRows(checks) {
    const list = Array.isArray(checks) ? checks : [];
    if (!list.length) return emptyInline('No header checks reported.');
    const box = D.el('div', { class: 'check-list' });
    list.forEach(function (check) {
      const row = D.el('div', { class: 'check-row' });
      const text = D.el('div');
      text.appendChild(D.el('div', { class: 'check-name', text: check.name || 'Unnamed check' }));
      if (check.note) text.appendChild(D.el('div', { class: 'check-note', text: check.note }));
      row.appendChild(text);
      row.appendChild(sourceStatusBadge(check.status));
      box.appendChild(row);
    });
    return box;
  }

  function cookieTable(cookies) {
    const list = Array.isArray(cookies) ? cookies : [];
    if (!list.length) return emptyInline('No cookies reported.');
    return dataTable([
      { key: 'name', label: 'Cookie', render: function (row) { return D.el('span', { class: 'mono', text: row.name }); }, value: function (row) { return row.name; } },
      { key: 'secure', label: 'Secure', render: function (row) { return boolBadge(row.secure, 'Secure', 'Not secure', 'ok', 'warning'); }, value: function (row) { return row.secure ? '1' : '0'; } },
      { key: 'http_only', label: 'HttpOnly', render: function (row) { return boolBadge(row.http_only, 'HttpOnly', 'Readable', 'ok', 'warning'); }, value: function (row) { return row.http_only ? '1' : '0'; } },
      { key: 'same_site', label: 'SameSite', render: function (row) { return row.same_site ? badge(row.same_site, 'info') : badge('Not set', 'muted'); }, value: function (row) { return row.same_site || ''; } }
    ], list, { pageSize: 25, filterPlaceholder: 'Filter cookies…', rowLabel: 'cookies' });
  }

  function portsList(ports) {
    const list = Array.isArray(ports) ? ports : [];
    if (!list.length) return D.el('span', { class: 'muted small', text: 'No open ports reported' });
    const wrap = D.el('div', { class: 'port-list' });
    list.forEach(function (port) { wrap.appendChild(D.el('span', { class: 'port', text: String(port) })); });
    return wrap;
  }

  function defangNote() {
    return D.el('div', { class: 'notice info' },
      D.icon('shield'),
      D.el('div', {}, D.el('strong', { text: 'Values are displayed defanged.' }), D.el('div', { text: 'Raw values are preserved for copy actions, pivot links, and exports.' }))
    );
  }

  C.ui = {
    isDefang: isDefang,
    displayValue: displayValue,
    badge: badge,
    taskStatusBadge: taskStatusBadge,
    httpStatusBadge: httpStatusBadge,
    sourceStatusBadge: sourceStatusBadge,
    boolBadge: boolBadge,
    copyButton: copyButton,
    externalButton: externalButton,
    valueSpan: valueSpan,
    copyable: copyable,
    hashValue: hashValue,
    urlValue: urlValue,
    pivotBtn: pivotBtn,
    chipValue: chipValue,
    chipList: chipList,
    stat: stat,
    statGrid: statGrid,
    kvRow: kvRow,
    kvList: kvList,
    kvGrid: kvGrid,
    card: card,
    section: section,
    sectionNav: sectionNav,
    notice: notice,
    errorList: errorList,
    collapsible: collapsible,
    codeBlock: codeBlock,
    detailBlock: detailBlock,
    dataTable: dataTable,
    sourceTag: sourceTag,
    emptyInline: emptyInline,
    notRun: notRun,
    profileCard: profileCard,
    redirectChain: redirectChain,
    checkRows: checkRows,
    cookieTable: cookieTable,
    portsList: portsList,
    defangNote: defangNote
  };

})();
