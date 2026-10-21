(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function typeLabel(type) {
    const meta = C.iocs.TYPES[type];
    return meta ? meta.label : C.format.humanize(type);
  }

  function typeIcon(type) {
    const meta = C.iocs.TYPES[type];
    return meta ? meta.icon : 'hash';
  }

  C.views = C.views || {};
  C.views.iocs = function (model) {
    const items = model.iocs && model.iocs.length ? model.iocs : C.iocs.extract(model);
    const counts = C.iocs.counts(items);
    const types = Object.keys(counts).sort(function (a, b) {
      const orderA = C.iocs.TYPES[a] ? C.iocs.TYPES[a].order : 99;
      const orderB = C.iocs.TYPES[b] ? C.iocs.TYPES[b].order : 99;
      return orderA - orderB;
    });
    let activeType = 'all';
    let query = '';
    const sourceCount = new Set();
    items.forEach(function (item) { asArray(item.sources).forEach(function (source) { sourceCount.add(source); }); });

    const view = D.el('div', { class: 'view' });
    view.appendChild(UI.statGrid([
      UI.stat('Indicators', items.length, 'Deduplicated across modules', { icon: 'crosshair' }),
      UI.stat('Types', types.length, types.slice(0, 3).map(typeLabel).join(' · ') || 'No values', { icon: 'layers' }),
      UI.stat('Sources', sourceCount.size, 'Extraction sources', { icon: 'database' }),
      UI.stat('URLs', counts.url || 0, 'Crawled, threat, and form URLs', { icon: 'link' })
    ]));

    const toolbar = D.el('div', { class: 'toolbar' });
    const search = D.el('input', {
      class: 'input input-sm',
      type: 'search',
      placeholder: 'Search indicators or sources…',
      'aria-label': 'Search indicators'
    });
    toolbar.appendChild(search);
    const exportGroup = D.el('div', { class: 'row' });
    exportGroup.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        const filtered = current();
        D.downloadFile(C.iocs.filename(model, 'json'), C.iocs.exportJson(model, filtered, C.state.prefs.defang), 'application/json');
      }
    }, D.icon('download'), 'JSON'));
    exportGroup.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        const filtered = current();
        D.downloadFile(C.iocs.filename(model, 'csv'), C.iocs.exportCsv(filtered, C.state.prefs.defang), 'text/csv');
      }
    }, D.icon('download'), 'CSV'));
    exportGroup.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        const filtered = current();
        D.downloadFile(C.iocs.filename(model, 'md'), C.iocs.exportMarkdown(model, filtered, C.state.prefs.defang), 'text/markdown');
      }
    }, D.icon('download'), 'Markdown'));
    exportGroup.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () { D.copyText(C.iocs.copyAll(current(), C.state.prefs.defang), 'indicators'); }
    }, D.icon('copy'), 'Copy'));
    toolbar.appendChild(exportGroup);
view.appendChild(UI.card('Filters & export', D.el('div', { class: 'stack' }, toolbar, D.el('p', { class: 'tiny muted', text: 'Exports include the current filter. Values are ' + (C.state.prefs.defang ? 'defanged' : 'raw') + '.' })), {
    icon: 'filter'
  }));

    const filterRow = D.el('div', { class: 'ioc-summary' });
    const filterButtons = [];
    const makeFilter = function (id, label, count) {
      const button = D.el('button', {
        class: 'ioc-filter' + (id === activeType ? ' active' : ''),
        type: 'button',
        onClick: function () {
          activeType = id;
          filterButtons.forEach(function (entry) { entry.node.classList.toggle('active', entry.id === id); });
          drawRows();
        }
      }, label, count != null ? D.el('span', { class: 'tab-count', text: String(count) }) : null);
      filterButtons.push({ id: id, node: button });
      filterRow.appendChild(button);
    };
    makeFilter('all', 'All', items.length);
    types.forEach(function (type) { makeFilter(type, typeLabel(type), counts[type]); });
    view.appendChild(filterRow);

    const tableHost = D.el('div');
    const resultCount = D.el('span', { class: 'tiny muted' });
    const tableSection = UI.section('Indicators', 'iocs-table', [
      UI.card('Extracted values', D.el('div', { class: 'stack' }, D.el('div', { class: 'toolbar' }, resultCount), tableHost), {
        icon: 'crosshair',
        flush: false,
        subtitle: 'Unique indicators grouped by type, with their source tasks.'
      })
    ], {
      icon: 'crosshair',
      count: items.length,
      subtitle: 'Normalized indicators extracted from every module in the report.'
    });
    view.appendChild(tableSection);

    function current() {
      const q = query.trim().toLowerCase();
      return items.filter(function (item) {
        if (activeType !== 'all' && item.type !== activeType) return false;
        if (!q) return true;
        return (item.value + ' ' + asArray(item.sources).join(' ') + ' ' + typeLabel(item.type)).toLowerCase().indexOf(q) !== -1;
      });
    }

    function drawRows() {
      const list = current();
      D.clear(tableHost);
      resultCount.textContent = list.length + ' of ' + items.length + ' indicators';
      if (!list.length) {
        tableHost.appendChild(UI.emptyInline('No indicators match the current filter.'));
        return;
      }
      const wrap = D.el('div', { class: 'table-wrap' });
      const table = D.el('table', { class: 'data-table wide' });
      const thead = D.el('thead');
      thead.appendChild(D.el('tr', {},
        D.el('th', { text: 'Type', style: { width: '100px' } }),
        D.el('th', { text: 'Value' }),
        D.el('th', { text: 'Sources', style: { width: '22%' } }),
        D.el('th', { text: 'View', style: { width: '160px' } })
      ));
      const tbody = D.el('tbody');
      list.forEach(function (item) {
        const tr = D.el('tr');
        tr.appendChild(D.el('td', { class: 'nowrap' }, D.el('span', { class: 'ioc-type' }, D.icon(typeIcon(item.type)), typeLabel(item.type))));
        const valueCell = D.el('td');
        const valueRow = D.el('div', { class: 'row-wrap' });
        valueRow.appendChild(D.el('span', { class: 'ioc-value' }, D.el('bdi', { text: C.iocs.displayValue(item, C.state.prefs.defang) })));
        const copy = UI.copyButton(item.value, 'indicator');
        if (copy) valueRow.appendChild(copy);
        const pivot = UI.pivotBtn(item.type, item.value, { model: model });
        if (pivot) valueRow.appendChild(pivot);
        valueCell.appendChild(valueRow);
        tr.appendChild(valueCell);

        const sources = D.el('td');
        const sourceWrap = D.el('div', { class: 'row-wrap' });
        asArray(item.sources).forEach(function (source) { sourceWrap.appendChild(UI.sourceTag(source, 'database')); });
        sources.appendChild(sourceWrap);
        tr.appendChild(sources);

        const viewCell = D.el('td', { class: 'nowrap' });
        asArray(item.tabs).forEach(function (tab, index) {
          if (index) viewCell.appendChild(D.el('span', { class: 'muted', text: ' · ' }));
          viewCell.appendChild(D.el('button', {
            class: 'obs-link',
            type: 'button',
            onClick: function () { C.router.go(model.id, tab); }
          }, C.format.humanize(tab)));
        });
        if (!asArray(item.tabs).length) viewCell.appendChild(D.el('span', { class: 'muted', text: '—' }));
        tr.appendChild(viewCell);
        tbody.appendChild(tr);
      });
      table.appendChild(thead);
      table.appendChild(tbody);
      wrap.appendChild(table);
      tableHost.appendChild(wrap);
    }

    search.addEventListener('input', function () {
      query = search.value;
      drawRows();
    });
    drawRows();
    return view;
  };
})();
