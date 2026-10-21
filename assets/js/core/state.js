(function () {
  'use strict';

  const C = window.C = window.C || {};
  const STORAGE_KEY = 'clouseau.prefs';
  const listeners = new Set();

  function readPrefs() {
    const defaults = { theme: 'dark', defang: false };
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return defaults;
      const parsed = JSON.parse(raw);
      return {
        theme: parsed.theme === 'light' ? 'light' : 'dark',
        defang: Boolean(parsed.defang)
      };
    } catch (error) {
      return defaults;
    }
  }

  const state = {
    prefs: readPrefs(),
    reports: new Map(),
    activeId: null,
    activeTab: 'overview',
    query: '',
    lastError: null
  };

  function savePrefs() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(state.prefs));
      localStorage.setItem('clouseau.theme', state.prefs.theme);
    } catch (error) {}
  }

  function applyTheme() {
    document.documentElement.dataset.theme = state.prefs.theme;
  }

  function emit(event) {
    listeners.forEach(function (listener) {
      try { listener(event, state); } catch (error) { console.error(error); }
    });
  }

  function subscribe(listener) {
    listeners.add(listener);
    return function () { listeners.delete(listener); };
  }

  function setPrefs(patch) {
    Object.assign(state.prefs, patch || {});
    savePrefs();
    applyTheme();
    emit({ type: 'prefs', patch: patch });
  }

  function toggleDefang() {
    setPrefs({ defang: !state.prefs.defang });
  }

  function toggleTheme() {
    setPrefs({ theme: state.prefs.theme === 'dark' ? 'light' : 'dark' });
  }

  function addReport(report) {
    state.reports.set(report.id, report);
    emit({ type: 'reports', report: report });
  }

  function removeReport(id) {
    state.reports.delete(id);
    if (state.activeId === id) state.activeId = null;
    emit({ type: 'reports' });
  }

  function clearReports() {
    state.reports.clear();
    state.activeId = null;
    state.activeTab = 'overview';
    state.query = '';
    emit({ type: 'reports' });
  }

  function getReport(id) {
    return state.reports.get(id) || null;
  }

  function activeReport() {
    return state.activeId ? getReport(state.activeId) : null;
  }

  function sortedReports() {
    return Array.from(state.reports.values()).sort(function (a, b) {
      const aTime = a.generatedAt ? a.generatedAt.getTime() : 0;
      const bTime = b.generatedAt ? b.generatedAt.getTime() : 0;
      if (aTime !== bTime) return bTime - aTime;
      return a.path.localeCompare(b.path);
    });
  }

  function newestReport() {
    return sortedReports()[0] || null;
  }

  applyTheme();

  C.state = state;
  C.state.setPrefs = setPrefs;
  C.state.toggleDefang = toggleDefang;
  C.state.toggleTheme = toggleTheme;
  C.state.addReport = addReport;
  C.state.removeReport = removeReport;
  C.state.clearReports = clearReports;
  C.state.getReport = getReport;
  C.state.activeReport = activeReport;
  C.state.sortedReports = sortedReports;
  C.state.newestReport = newestReport;
  C.state.subscribe = subscribe;
  C.state.emit = emit;
  C.state.applyTheme = applyTheme;
})();
