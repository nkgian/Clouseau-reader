(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;
  const handlers = {};

  function searchButton() {
    const shortcut = C.search && C.search.shortcutLabel ? C.search.shortcutLabel() : 'Ctrl K';
    return D.el('button', {
      class: 'btn btn-ghost btn-sm search-top-btn',
      type: 'button',
      title: 'Search report fields (' + shortcut + ')',
      'aria-haspopup': 'dialog',
      onClick: function () {
        if (C.search) C.search.open();
      }
    }, D.icon('search'), D.el('span', { text: 'Search' }), D.el('kbd', { class: 'search-shortcut', text: shortcut }));
  }

  function byId(id) {
    return document.getElementById(id);
  }

  function formatBytes(bytes) {
    const n = Number(bytes);
    if (!Number.isFinite(n) || n <= 0) return '';
    const units = ['B', 'KB', 'MB', 'GB'];
    let value = n;
    let index = 0;
    while (value >= 1024 && index < units.length - 1) {
      value /= 1024;
      index += 1;
    }
    return value.toFixed(value >= 10 || index === 0 ? 0 : 1) + ' ' + units[index];
  }

  function openSidebar() {
    const sidebar = byId('sidebar');
    const backdrop = byId('sidebar-backdrop');
    if (sidebar) sidebar.classList.add('open');
    if (backdrop) backdrop.hidden = false;
  }

  function closeSidebar() {
    const sidebar = byId('sidebar');
    const backdrop = byId('sidebar-backdrop');
    if (sidebar) sidebar.classList.remove('open');
    if (backdrop) backdrop.hidden = true;
  }

  function syncPrefs() {
    const toggle = byId('defang-toggle');
    if (toggle) toggle.checked = Boolean(C.state.prefs.defang);
    const themeLabel = byId('theme-label');
    if (themeLabel) themeLabel.textContent = C.state.prefs.theme === 'dark' ? 'Light theme' : 'Dark theme';
    const use = document.querySelector('#theme-toggle use');
    if (use) use.setAttribute('href', C.state.prefs.theme === 'dark' ? '#i-sun' : '#i-moon');
  }

  function renderLibrary() {
    const list = byId('report-list');
    if (!list) return;
    D.clear(list);
    const reports = C.state.sortedReports();
    const query = String(C.state.query || '').trim().toLowerCase();
    const filtered = query
      ? reports.filter(function (report) {
        return (report.target + ' ' + report.path + ' ' + (report.host || '')).toLowerCase().indexOf(query) !== -1;
      })
      : reports;

    if (!reports.length) {
      list.appendChild(D.el('div', { class: 'library-empty', text: 'No reports loaded.' }));
      return;
    }

    if (!filtered.length) {
      list.appendChild(D.el('div', { class: 'library-empty', text: 'No reports match “' + C.state.query + '”.' }));
      return;
    }

    filtered.forEach(function (report) {
      const active = report.id === C.state.activeId;
      const button = D.el('button', {
        class: 'report-item' + (active ? ' active' : ''),
        type: 'button',
        title: report.target,
        'aria-current': active ? 'true' : null,
        onClick: function () {
          const tab = active ? C.state.activeTab || 'overview' : 'overview';
          C.router.go(report.id, tab);
          closeSidebar();
        }
      });
      button.appendChild(D.el('div', { class: 'report-item-target', text: UI.displayValue(report.target, 'url') }));
      const meta = D.el('div', { class: 'report-item-meta' });
      meta.appendChild(D.el('span', { text: report.generatedAt ? C.format.fmtDate(report.generatedAt) : 'Unknown date' }));
      meta.appendChild(D.el('span', { text: '·' }));
      meta.appendChild(D.el('span', { text: report.taskCount + ' ' + C.format.plural(report.taskCount, 'task') }));
      if (report.errorCount) {
        meta.appendChild(D.el('span', { class: 'warn-link', text: report.errorCount + ' ' + C.format.plural(report.errorCount, 'error') }));
      }
      button.appendChild(meta);
      button.appendChild(D.el('div', { class: 'report-item-path', text: report.path }));
      list.appendChild(button);
    });
  }

  function tabDefs(model) {
    const cov = new Map(model.coverage.map(function (item) { return [item.task, item]; }));
    const available = function (task) {
      const item = cov.get(task);
      return Boolean(item && item.status !== 'missing');
    };
    const html = model.getResult('html_scan') || {};
    const threat = model.getResult('threat_lookup') || {};
    const ip = model.getResult('ip_lookup') || {};
    const pages = Array.isArray(html.pages) ? html.pages : [];
    const sources = Array.isArray(threat.sources) ? threat.sources : [];
    const addresses = Array.isArray(ip.addresses) ? ip.addresses : [];
    const threatHits = sources.filter(C.signals.isThreatHit).length;

    const tabs = [{ id: 'overview', label: 'Overview', icon: 'layers', count: null }];
    if (available('html_scan') || available('robots_scan') || available('headers_scan')) {
      tabs.push({ id: 'website', label: 'Website', icon: 'globe', count: pages.length || null });
    }
    if (available('infra_scan') || available('ip_lookup')) {
      tabs.push({ id: 'network', label: 'Network', icon: 'network', count: addresses.length || null });
    }
    if (available('domain_scan') || available('whois_lookup')) {
      tabs.push({ id: 'domain', label: 'Domain', icon: 'server', count: null });
    }
    if (available('threat_lookup')) {
      tabs.push({ id: 'threats', label: 'Threats', icon: 'shield-alert', count: threatHits || null });
    }
    tabs.push({ id: 'iocs', label: 'IOCs', icon: 'crosshair', count: model.iocs.length || null });
    (model.unknownTasks || []).forEach(function (task) {
      const item = cov.get(task);
      tabs.push({
        id: 'task:' + task,
        label: item ? item.label : C.format.humanize(task),
        icon: item ? item.icon : 'file-text',
        count: item ? item.ok : null
      });
    });
    tabs.push({ id: 'raw', label: 'Raw', icon: 'code', count: null });
    return tabs;
  }

  function renderTabbar(model, activeTab) {
    const tabbar = byId('tabbar');
    if (!tabbar) return;
    D.clear(tabbar);
    tabDefs(model).forEach(function (tab) {
      const button = D.el('button', {
        class: 'tab' + (tab.id === activeTab ? ' active' : ''),
        type: 'button',
        'aria-current': tab.id === activeTab ? 'page' : null,
        onClick: function () { C.router.go(model.id, tab.id); }
      }, D.icon(tab.icon), tab.label);
      if (tab.count != null) button.appendChild(D.el('span', { class: 'tab-count', text: String(tab.count) }));
      tabbar.appendChild(button);
    });
    tabbar.hidden = false;
  }

  function renderHeader(model) {
    const header = byId('report-header');
    if (!header) return;
    D.clear(header);
    const inner = D.el('div', { class: 'report-header-inner' });

    const top = D.el('div', { class: 'report-topline' });
    top.appendChild(D.el('button', {
      class: 'icon-btn mobile-menu-btn',
      type: 'button',
      'aria-label': 'Open report library',
      onClick: openSidebar
    }, D.icon('menu')));
    top.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () { C.router.home(); }
    }, D.icon('arrow-left'), 'All reports'));
    top.appendChild(D.el('span', { class: 'dot' }));
    top.appendChild(D.el('span', { text: 'Scan report' }));
    top.appendChild(D.el('span', { class: 'dot' }));
    top.appendChild(D.el('span', { text: model.taskCount + ' ' + C.format.plural(model.taskCount, 'result') }));
    inner.appendChild(top);

    const titleRow = D.el('div', { class: 'report-title-row' });
    const title = D.el('div', { class: 'report-title' });
    title.appendChild(D.el('h1', {}, D.el('bdi', { text: UI.displayValue(model.target, 'url') })));
    const copy = UI.copyButton(model.target, 'target URL');
    if (copy) title.appendChild(copy);
    const ext = UI.externalButton(model.target, { warn: true, source: 'Target URL' });
    if (ext) title.appendChild(ext);
    if (model.unicodeHost && model.unicodeHost.toLowerCase() !== String(model.host || '').toLowerCase()) {
      title.appendChild(D.el('span', {
        class: 'unicode-host',
        title: 'Unicode display form of the hostname'
      }, D.icon('alert-triangle'), D.el('bdi', { text: model.unicodeHost })));
    }
    if (model.errorCount) {
      title.appendChild(UI.badge(model.errorCount + ' ' + C.format.plural(model.errorCount, 'error'), 'critical', 'alert-triangle'));
    }
    titleRow.appendChild(title);

    const actions = D.el('div', { class: 'header-actions' });
    actions.appendChild(searchButton());
    actions.appendChild(D.el('button', {
      class: 'btn btn-primary btn-sm',
      type: 'button',
      onClick: function () {
        if (handlers.print) handlers.print(model);
        else window.print();
      }
    }, D.icon('printer'), 'Print / PDF'));
    actions.appendChild(D.el('button', {
      class: 'icon-btn',
      type: 'button',
      title: 'Copy report JSON',
      'aria-label': 'Copy report JSON',
      onClick: function () {
        if (handlers.copyReport) handlers.copyReport(model);
        else D.copyText(JSON.stringify(model.raw, null, 2), 'report JSON');
      }
    }, D.icon('copy')));
    actions.appendChild(D.el('button', {
      class: 'icon-btn',
      type: 'button',
      title: 'Open raw report',
      'aria-label': 'Open raw report',
      onClick: function () { C.router.go(model.id, 'raw'); }
    }, D.icon('code')));
    titleRow.appendChild(actions);
    inner.appendChild(titleRow);

    const meta = D.el('div', { class: 'report-meta' });
    meta.appendChild(D.el('span', { class: 'meta-item' },
      D.icon('clock'),
      model.generatedAt ? C.format.fmtDateTime(model.generatedAt) : 'Unknown scan time'
    ));
    meta.appendChild(D.el('span', { class: 'meta-item' },
      D.icon('layers'),
      model.taskCount + ' ' + C.format.plural(model.taskCount, 'task') + ' run'
    ));
    if (model.errorCount) {
      meta.appendChild(D.el('span', { class: 'meta-item warn-link' },
        D.icon('alert-triangle'),
        model.errorCount + ' ' + C.format.plural(model.errorCount, 'module error')
      ));
    }
    if (model.size) {
      meta.appendChild(D.el('span', { class: 'meta-item' }, D.icon('file-text'), formatBytes(model.size)));
    }
    meta.appendChild(D.el('span', { class: 'source-path', title: model.path, text: model.path }));
    inner.appendChild(meta);

    header.appendChild(inner);
    header.hidden = false;
  }

  function renderHome() {
    const reports = C.state.sortedReports();
    const view = D.el('div', { class: 'view home-view' });
    const head = D.el('div', { class: 'home-head' });
    const titleRow = D.el('div', { class: 'home-title-row' });
    titleRow.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm mobile-menu-btn',
      type: 'button',
      onClick: openSidebar
    }, D.icon('menu'), 'Library'));
    titleRow.appendChild(D.el('h1', { class: 'page-title', text: 'Reports' }));
    titleRow.appendChild(D.el('span', { class: 'page-count', text: String(reports.length) }));
    head.appendChild(titleRow);

    const actions = D.el('div', { class: 'home-actions' });
    actions.appendChild(searchButton());
    actions.appendChild(D.el('button', {
      class: 'btn btn-primary btn-sm',
      type: 'button',
      onClick: function () { if (handlers.openFiles) handlers.openFiles(); }
    }, D.icon('file-plus'), 'Open JSON'));
    head.appendChild(actions);
    view.appendChild(head);

    if (!reports.length) {
      view.appendChild(D.el('button', {
        class: 'ingest-drop',
        type: 'button',
        onClick: function () { if (handlers.openFiles) handlers.openFiles(); }
      },
      D.icon('file-plus'),
      D.el('span', { class: 'ingest-title', text: 'Drop a report JSON' }),
      D.el('span', { class: 'ingest-hint', text: 'Click to browse JSON files' })
      ));
      return view;
    }

    const wrap = D.el('div', { class: 'reports-table-wrap' });
    const table = D.el('table', { class: 'report-table' });
    const thead = D.el('thead');
    const headRow = D.el('tr');
    [
      ['Report', 'col-report'],
      ['Scanned', 'col-date'],
      ['Modules', 'col-tasks'],
      ['Errors', 'col-errors'],
      ['', 'col-open']
    ].forEach(function (item) {
      headRow.appendChild(D.el('th', { class: item[1], scope: 'col', text: item[0] }));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    const tbody = D.el('tbody');
    reports.forEach(function (report) {
      const row = D.el('tr');
      const subject = D.el('td', { class: 'col-report' });
      subject.appendChild(D.el('button', {
        class: 'report-target',
        type: 'button',
        onClick: function () { C.router.go(report.id, 'overview'); }
      }, UI.displayValue(report.target, 'url')));
      subject.appendChild(D.el('div', { class: 'report-path', text: report.path }));
      row.appendChild(subject);
      row.appendChild(D.el('td', {
        class: 'col-date',
        text: report.generatedAt ? C.format.fmtDateTime(report.generatedAt) : 'Unknown'
      }));
      row.appendChild(D.el('td', { class: 'col-tasks', text: String(report.taskCount) }));
      row.appendChild(D.el('td', { class: 'col-errors' },
        report.errorCount ? UI.badge(String(report.errorCount), 'critical') : D.el('span', { class: 'faint', text: '—' })
      ));
      row.appendChild(D.el('td', { class: 'col-open' },
        D.el('button', {
          class: 'btn btn-ghost btn-sm',
          type: 'button',
          onClick: function () { C.router.go(report.id, 'overview'); }
        }, 'Open', D.icon('chevron-right'))
      ));
      tbody.appendChild(row);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    view.appendChild(wrap);
    return view;
  }

  function setMain(content, options) {
    const main = byId('main');
    if (!main) return;
    D.clear(main);
    D.append(main, content);
    if (!options || options.scroll !== false) window.scrollTo(0, 0);
  }

  function showHome() {
    const header = byId('report-header');
    const tabbar = byId('tabbar');
    if (header) header.hidden = true;
    if (tabbar) tabbar.hidden = true;
    setMain(renderHome());
  }

  function showReport(model, activeTab, content, options) {
    renderHeader(model);
    renderTabbar(model, activeTab);
    setMain(content, options);
  }

  function setLoading(loading) {
    const progress = byId('progress');
    if (progress) progress.hidden = !loading;
    const main = byId('main');
    if (main) main.setAttribute('aria-busy', loading ? 'true' : 'false');
  }

  function init(nextHandlers) {
    Object.assign(handlers, nextHandlers || {});
    const openFiles = byId('open-files');
    const clear = byId('clear-library');
    const defang = byId('defang-toggle');
    const theme = byId('theme-toggle');
    const search = byId('library-search');
    const sidebarClose = byId('sidebar-close');
    const backdrop = byId('sidebar-backdrop');

    if (openFiles) openFiles.addEventListener('click', function () { if (handlers.openFiles) handlers.openFiles(); });
    if (clear) clear.addEventListener('click', function () {
      if (handlers.clear) handlers.clear();
      else C.state.clearReports();
    });
    if (defang) defang.addEventListener('change', function () {
      C.state.setPrefs({ defang: defang.checked });
    });
    if (theme) theme.addEventListener('click', C.state.toggleTheme);
    if (search) {
      search.value = C.state.query || '';
      search.addEventListener('input', function () {
        C.state.query = search.value;
        renderLibrary();
      });
    }
    if (sidebarClose) sidebarClose.addEventListener('click', closeSidebar);
    if (backdrop) backdrop.addEventListener('click', closeSidebar);
    window.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') closeSidebar();
    });
    window.addEventListener('resize', function () {
      if (window.innerWidth > 900 && byId('sidebar')) closeSidebar();
    });

    C.state.subscribe(function (event) {
      if (event.type === 'reports') renderLibrary();
      if (event.type === 'prefs') syncPrefs();
    });
    syncPrefs();
    renderLibrary();
  }

  C.shell = {
    init: init,
    renderHome: renderHome,
    renderHeader: renderHeader,
    renderTabbar: renderTabbar,
    renderLibrary: renderLibrary,
    tabDefs: tabDefs,
    showHome: showHome,
    showReport: showReport,
    setMain: setMain,
    setLoading: setLoading,
    openSidebar: openSidebar,
    closeSidebar: closeSidebar,
    syncPrefs: syncPrefs,
    formatBytes: formatBytes
  };
})();
