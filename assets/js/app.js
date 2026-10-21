(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;
  const signatures = new Map();
  let ingestQueue = Promise.resolve();

  function modelById(id) {
    const exact = C.state.getReport(id);
    if (exact) return exact;
    const lower = String(id || '').toLowerCase();
    return C.state.sortedReports().find(function (report) {
      return String(report.id).toLowerCase() === lower || String(report.path).toLowerCase() === lower;
    }) || null;
  }

  function hashFor(id, tab) {
    return '#/r/' + encodeURIComponent(id) + '/' + encodeURIComponent(tab || 'overview');
  }

  function setTitle(model) {
    document.title = model ? model.target + ' · Clouseau Reader' : 'Clouseau Reader';
  }

  function renderError(model, error) {
    console.error(error);
    return D.el('div', { class: 'view' }, UI.card('Could not render this view', UI.notice('warning', 'alert-triangle',
      'The report is loaded, but this section threw an error while rendering.',
      error && error.message ? error.message : String(error)
    ), { icon: 'alert-triangle' }));
  }

  function renderTab(model, tab) {
    const key = tab.indexOf('task:') === 0 ? 'generic' : tab;
    const render = C.views[key] || C.views.generic;
    if (!render) return renderError(model, new Error('No renderer for ' + key));
    try {
      return render(model);
    } catch (error) {
      return renderError(model, error);
    }
  }

  function showMissing(route) {
    C.state.activeId = null;
    C.state.activeTab = 'overview';
    const header = document.getElementById('report-header');
    const tabbar = document.getElementById('tabbar');
    if (header) header.hidden = true;
    if (tabbar) tabbar.hidden = true;
    const view = D.el('div', { class: 'empty-state' });
    const menu = D.el('button', {
      class: 'btn btn-ghost btn-sm mobile-menu-btn',
      type: 'button',
      onClick: C.shell.openSidebar
    }, D.icon('menu'), 'Library');
    view.appendChild(menu);
    view.appendChild(D.el('div', { class: 'empty-art' }, D.icon('file-text')));
    view.appendChild(D.el('h1', { text: 'Report not loaded' }));
    view.appendChild(D.el('p', { class: 'lede', text: 'Open the report JSON to load this report again.' }));
    view.appendChild(D.el('div', { class: 'modal-url', style: { marginTop: '12px' }, text: route.id || '' }));
    const actions = D.el('div', { class: 'empty-actions' });
    actions.appendChild(D.el('button', {
      class: 'btn btn-primary',
      type: 'button',
      onClick: openFiles
    }, D.icon('file-plus'), 'Open report JSON'));
    actions.appendChild(D.el('button', {
      class: 'btn btn-ghost',
      type: 'button',
      onClick: function () { C.router.home(); }
    }, D.icon('arrow-left'), 'Back to library'));
    view.appendChild(actions);
    C.shell.setMain(view);
    setTitle(null);
    C.shell.renderLibrary();
  }

  function renderRoute(route, options) {
    const opts = options || {};
    C.shell.closeSidebar();
    if (!route || route.view === 'home') {
      C.state.activeId = null;
      C.state.activeTab = 'overview';
      C.shell.showHome();
      C.shell.renderLibrary();
      setTitle(null);
      return;
    }

    const model = modelById(route.id);
    if (!model) {
      showMissing(route);
      return;
    }

    const defs = C.shell.tabDefs(model);
    const ids = new Set(defs.map(function (tab) { return tab.id; }));
    let tab = route.tab || 'overview';
    if (!ids.has(tab)) {
      tab = ids.has('overview') ? 'overview' : defs[0].id;
    }
    if (tab !== route.tab) {
      const nextHash = hashFor(model.id, tab);
      if (window.location.hash !== nextHash) history.replaceState(null, '', nextHash);
    }

    C.state.activeId = model.id;
    C.state.activeTab = tab;
    const scrollY = window.scrollY;
    C.shell.showReport(model, tab, renderTab(model, tab), { scroll: !opts.preserveScroll });
    if (opts.preserveScroll) window.scrollTo(0, scrollY);
    C.shell.renderLibrary();
    setTitle(model);
  }

  async function ingest(options) {
    const opts = options || {};
    C.shell.setLoading(true);
    let loaded = 0;
    let skipped = 0;
    try {
      const candidates = C.files.reportCandidates();
      for (const record of candidates) {
        const signature = record.key + '|' + record.size + '|' + record.lastModified;
        if (signatures.get(record.key) === signature) continue;
        let text;
        try {
          text = await C.files.readText(record);
        } catch (error) {
          signatures.set(record.key, signature);
          skipped += 1;
          continue;
        }
        const parsed = C.reports.parseReportText(text);
        if (!parsed.ok) {
          signatures.set(record.key, signature);
          skipped += 1;
          continue;
        }
        try {
          const model = C.reports.buildReport(parsed.raw, {
            id: record.path,
            path: record.path,
            size: record.size,
            lastModified: record.lastModified
          });
          model.record = record;
          model.observations = C.signals.derive(model);
          model.iocs = C.iocs.extract(model);
          C.state.addReport(model);
          signatures.set(record.key, signature);
          loaded += 1;
        } catch (error) {
          console.error('Could not build report', record.path, error);
          signatures.set(record.key, signature);
          skipped += 1;
        }
      }
    } finally {
      C.shell.setLoading(false);
    }

    if (loaded) {
      D.toast('Loaded ' + loaded + ' ' + C.format.plural(loaded, 'report') + (skipped ? ' · skipped ' + skipped + ' JSON file(s)' : ''), 'ok');
    } else if (skipped && opts.fileCount) {
      D.toast('No Clouseau reports found.', 'warning');
    }

    const route = C.router.parse();
    if (route.view === 'report') {
      if (modelById(route.id)) {
        renderRoute(route, { preserveScroll: true });
      } else if (loaded) {
        const newest = C.state.newestReport();
        if (newest) C.router.go(newest.id, 'overview');
      } else {
        renderRoute(route, { preserveScroll: true });
      }
    } else if (loaded && !C.state.activeId) {
      const newest = C.state.newestReport();
      if (newest) C.router.go(newest.id, 'overview');
      else {
        C.shell.showHome();
        C.shell.renderLibrary();
      }
    } else {
      C.shell.renderLibrary();
    }
  }

  function requestIngest(options) {
    ingestQueue = ingestQueue.then(function () { return ingest(options); }).catch(function (error) {
      C.shell.setLoading(false);
      console.error(error);
      D.toast('Could not read the selected files.', 'error');
    });
    return ingestQueue;
  }

  function openFiles() {
    const input = document.getElementById('files-input');
    if (!input) return;
    input.value = '';
    input.click();
  }

  function clearSession() {
    const summary = C.files.summary();
    if (!C.state.reports.size && !summary.files) return;
    const body = D.el('div');
    body.appendChild(D.el('p', { text: 'Clear all loaded reports?' }));
    D.modal({
      title: 'Clear session',
      icon: 'trash',
      body: body,
      actions: [
        { label: 'Cancel', variant: 'btn-ghost' },
        {
          label: 'Clear session',
          variant: 'btn-danger',
          icon: 'trash',
          onClick: function () {
            C.state.clearReports();
            C.files.clear();
            signatures.clear();
            C.router.home();
            D.toast('Session cleared', 'ok');
          }
        }
      ]
    });
  }

  function buildPrintRoot(model) {
    let root = document.getElementById('print-root');
    if (!root) {
      root = D.el('div', { class: 'print-root', id: 'print-root' });
      document.body.appendChild(root);
    }
    D.clear(root);
    const doc = D.el('div', { class: 'print-doc' });
    const cover = D.el('div', { class: 'print-cover' });
    cover.appendChild(D.el('div', { class: 'print-kicker', text: 'Clouseau scan report' }));
    cover.appendChild(D.el('h1', {}, D.el('bdi', { text: model.target })));
    const meta = D.el('div', { class: 'print-meta' });
    if (model.generatedAt) meta.appendChild(D.el('span', { text: C.format.fmtDateTime(model.generatedAt) }));
    if (model.host) meta.appendChild(D.el('span', { text: model.host }));
    meta.appendChild(D.el('span', { text: model.taskCount + ' ' + C.format.plural(model.taskCount, 'task') }));
    if (model.errorCount) meta.appendChild(D.el('span', { text: model.errorCount + ' ' + C.format.plural(model.errorCount, 'error') }));
    cover.appendChild(meta);
    cover.appendChild(D.el('div', { class: 'source-path', text: model.path }));
    doc.appendChild(cover);

    const tabs = C.shell.tabDefs(model).filter(function (tab) {
      return tab.id !== 'raw' && tab.id.indexOf('task:') !== 0;
    });
    tabs.forEach(function (tab, index) {
      const render = C.views[tab.id];
      if (!render) return;
      let view;
      try {
        view = render(model);
      } catch (error) {
        console.error('Print render failed for ' + tab.id, error);
        return;
      }
      const section = D.el('section', { class: 'print-tab' + (index ? ' print-page-break' : '') });
      section.appendChild(D.el('h2', { class: 'section-title', text: tab.label }));
      section.appendChild(view);
      doc.appendChild(section);
    });
    doc.appendChild(D.el('div', { class: 'print-footer', text: 'Generated by Clouseau Reader · ' + model.path }));
    root.appendChild(doc);
    document.body.classList.add('has-print-doc');
    return root;
  }

  function removePrintRoot() {
    const root = document.getElementById('print-root');
    if (root && root.parentNode) root.parentNode.removeChild(root);
    document.body.classList.remove('has-print-doc');
  }

  function printReport(model) {
    if (!model) return;
    buildPrintRoot(model);
    setTimeout(function () { window.print(); }, 80);
  }

  function preparePrint() {
    const model = C.state.activeReport();
    if (model) buildPrintRoot(model);
    else removePrintRoot();
  }

  function bindPrint() {
    window.addEventListener('beforeprint', preparePrint);
    window.addEventListener('afterprint', removePrintRoot);
  }

  function copyReport(model) {
    if (model) D.copyText(JSON.stringify(model.raw, null, 2), 'report JSON');
  }

  function bindFileInputs() {
    const files = document.getElementById('files-input');
    if (!files) return;
    files.addEventListener('change', function () {
      const added = C.files.addFileList(files.files, 'file');
      files.value = '';
      if (added.length) requestIngest({ source: 'files', fileCount: added.length });
      else D.toast('No JSON files selected', 'warning');
    });
  }

  function bindDrop() {
    const overlay = document.getElementById('drop-overlay');
    let depth = 0;
    const hasFiles = function (event) {
      const transfer = event.dataTransfer;
      if (!transfer) return false;
      if (transfer.files && transfer.files.length) return true;
      if (Array.prototype.indexOf.call(transfer.types || [], 'Files') !== -1) return true;
      return Array.prototype.some.call(transfer.items || [], function (item) {
        return item.kind === 'file';
      });
    };
    const show = function () { if (overlay) overlay.hidden = false; };
    const hide = function () { if (overlay) overlay.hidden = true; depth = 0; };

    document.addEventListener('dragenter', function (event) {
      if (!hasFiles(event)) return;
      event.preventDefault();
      depth += 1;
      show();
    });
    document.addEventListener('dragover', function (event) {
      if (!hasFiles(event)) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = 'copy';
    });
    document.addEventListener('dragleave', function () {
      if (!depth) return;
      depth = Math.max(0, depth - 1);
      if (!depth) hide();
    });
    document.addEventListener('drop', function (event) {
      if (!hasFiles(event)) return;
      event.preventDefault();
      hide();
      C.files.addDataTransfer(event.dataTransfer).then(function (added) {
        if (added.length) requestIngest({ source: 'drop', fileCount: added.length });
        else D.toast('No JSON reports in the drop', 'warning');
      }).catch(function (error) {
        console.error(error);
        D.toast('Could not read the dropped report', 'error');
      });
    });
    window.addEventListener('blur', hide);
  }

  function init() {
    C.shell.init({
      openFiles: openFiles,
      clear: clearSession,
      print: printReport,
      copyReport: copyReport
    });
    bindFileInputs();
    bindDrop();
    bindPrint();

    C.router.onChange(function (route) { renderRoute(route); });
    C.state.subscribe(function (event) {
      if (event.type !== 'prefs') return;
      const route = C.router.parse();
      if (route.view === 'report' && C.state.activeId) renderRoute(route, { preserveScroll: true });
    });

    renderRoute(C.router.parse());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
