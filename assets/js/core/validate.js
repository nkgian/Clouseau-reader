(function () {
  'use strict';

  const C = window.C = window.C || {};

  const MODULES = [
    { id: 'whois_lookup', label: 'WHOIS', icon: 'key' },
    { id: 'html_scan', label: 'Website scan', icon: 'globe' },
    { id: 'robots_scan', label: 'Robots & sitemaps', icon: 'file-text' },
    { id: 'headers_scan', label: 'HTTP headers', icon: 'server' },
    { id: 'domain_scan', label: 'Domain analysis', icon: 'globe' },
    { id: 'threat_lookup', label: 'Threat intelligence', icon: 'shield-alert' },
    { id: 'infra_scan', label: 'Infrastructure', icon: 'layers' },
    { id: 'ip_lookup', label: 'IP, DNS & TLS', icon: 'network' }
  ];

  const MODULE_BY_ID = new Map(MODULES.map(function (module) { return [module.id, module]; }));

  function stripBom(text) {
    return String(text == null ? '' : text).replace(/^\uFEFF/, '');
  }

  function validate(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
      return { ok: false, reason: 'Top-level JSON is not an object.' };
    }
    if (typeof raw.target !== 'string' || !raw.target.trim()) {
      return { ok: false, reason: 'Missing a target URL.' };
    }
    if (!Array.isArray(raw.results)) {
      return { ok: false, reason: 'Missing a results array.' };
    }
    const bad = raw.results.find(function (entry) {
      return !entry || typeof entry !== 'object' || typeof entry.task !== 'string';
    });
    if (bad) {
      return { ok: false, reason: 'A result entry is missing its task name.' };
    }
    return { ok: true };
  }

  function isReport(raw) {
    return validate(raw).ok;
  }

  function parseReportText(text) {
    let raw;
    try {
      raw = JSON.parse(stripBom(text));
    } catch (error) {
      return { ok: false, error: 'Invalid JSON: ' + error.message };
    }
    const check = validate(raw);
    if (!check.ok) return { ok: false, error: check.reason, raw: raw };
    return { ok: true, raw: raw };
  }

  function coverageFor(taskId, entries) {
    const module = MODULE_BY_ID.get(taskId);
    if (!entries || !entries.length) {
      return {
        task: taskId,
        label: module ? module.label : C.format.humanize(taskId),
        icon: module ? module.icon : 'file-text',
        known: Boolean(module),
        status: 'missing',
        total: 0,
        ok: 0,
        errors: 0
      };
    }
    const withResult = entries.filter(function (entry) { return entry.result != null; });
    const withError = entries.filter(function (entry) { return entry.error; });
    let status = 'ok';
    if (!withResult.length && withError.length) status = 'error';
    else if (withResult.length && withError.length) status = 'partial';
    else if (!withResult.length) status = 'error';
    return {
      task: taskId,
      label: module ? module.label : C.format.humanize(taskId),
      icon: module ? module.icon : 'file-text',
      known: Boolean(module),
      status: status,
      total: entries.length,
      ok: withResult.length,
      errors: withError.length
    };
  }

  function buildReport(raw, meta) {
    const info = meta || {};
    const results = raw.results.filter(function (entry) {
      return entry && typeof entry === 'object' && typeof entry.task === 'string';
    });

    const byTask = new Map();
    results.forEach(function (entry) {
      if (!byTask.has(entry.task)) byTask.set(entry.task, []);
      byTask.get(entry.task).push(entry);
    });

    const getEntries = function (task) {
      return byTask.get(task) || [];
    };

    const getEntry = function (task) {
      const entries = getEntries(task);
      return entries.find(function (entry) { return entry.result != null; }) || entries[0] || null;
    };

    const getResult = function (task) {
      const entry = getEntry(task);
      return entry && entry.result != null ? entry.result : null;
    };

    const getError = function (task) {
      const entries = getEntries(task);
      const found = entries.find(function (entry) { return Boolean(entry.error); });
      return found ? found.error : null;
    };

    const target = String(raw.target || '').trim();
    const domainResult = getResult('domain_scan') || {};
    const ipResult = getResult('ip_lookup') || {};
    const threatResult = getResult('threat_lookup') || {};
    const whoisResult = getResult('whois_lookup') || {};
    const host = String(
      domainResult.host ||
      ipResult.host ||
      threatResult.host ||
      whoisResult.domain ||
      C.format.hostFromUrl(target) ||
      ''
    ).trim();

    const errors = results
      .filter(function (entry) { return Boolean(entry.error); })
      .map(function (entry) { return { task: entry.task, error: String(entry.error) }; });

    const knownIds = new Set(MODULES.map(function (module) { return module.id; }));
    const unknownTasks = Array.from(byTask.keys()).filter(function (task) { return !knownIds.has(task); });

    const coverage = MODULES.map(function (module) {
      return coverageFor(module.id, byTask.get(module.id));
    }).concat(unknownTasks.map(function (task) {
      return coverageFor(task, byTask.get(task));
    }));

    const model = {
      id: info.id || info.path || target,
      path: info.path || info.id || target,
      size: info.size || 0,
      lastModified: info.lastModified || 0,
      raw: raw,
      target: target,
      host: host,
      unicodeHost: String(domainResult.unicode_host || '').trim(),
      generatedAt: C.format.parseDate(raw.generated_at),
      results: results,
      byTask: byTask,
      errors: errors,
      coverage: coverage,
      unknownTasks: unknownTasks,
      taskCount: results.length,
      errorCount: errors.length,
      getEntries: getEntries,
      getEntry: getEntry,
      getResult: getResult,
      getError: getError,
      hasTask: function (task) { return byTask.has(task); },
      observations: [],
      iocs: []
    };

    return model;
  }

  C.reports = {
    MODULES: MODULES,
    MODULE_BY_ID: MODULE_BY_ID,
    stripBom: stripBom,
    validate: validate,
    isReport: isReport,
    parseReportText: parseReportText,
    buildReport: buildReport
  };
})();
