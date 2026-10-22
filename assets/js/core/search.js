(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;

  const MAX_ENTRIES_PER_REPORT = 20000;
  const MAX_TOTAL_ENTRIES = 60000;
  const MAX_VALUE_LENGTH = 4000;
  const MAX_RESULTS = 80;

  const TAB_LABELS = {
    overview: 'Overview',
    website: 'Website',
    network: 'Network',
    domain: 'Domain',
    threats: 'Threats',
    iocs: 'IOCs',
    raw: 'Raw'
  };

  const SECTION_LABELS = {
    'overview-observations': 'Observations',
    'overview-profile': 'Target profile',
    'overview-timeline': 'Timeline',
    'overview-pivots': 'External pivots',
    'overview-coverage': 'Coverage',
    'website-pages': 'Pages',
    'website-cloaking': 'Cloaking',
    'website-forms': 'Forms',
    'website-identifiers': 'Identifiers',
    'website-wordpress': 'WordPress',
    'website-robots': 'Robots & sitemaps',
    'website-headers': 'HTTP headers',
    'network-dns': 'DNS records',
    'network-addresses': 'Addresses',
    'network-tls': 'TLS',
    'network-email': 'Email security',
    'network-cloudflare': 'Cloudflare origin',
    'network-infra': 'Infrastructure',
    'domain-analysis': 'Domain',
    'domain-whois': 'WHOIS',
    'domain-pivots': 'Domain pivots',
    'threats-wayback': 'Archive history',
    'threats-sources': 'Sources',
    'iocs-table': 'Indicators',
    'raw-json': 'Raw JSON',
    'generic-result': 'Module output'
  };

  const indexCache = new WeakMap();
  const routeCache = new Map();
  let initialized = false;
  let overlay = null;
  let input = null;
  let resultsNode = null;
  let countNode = null;
  let allEntries = [];
  let currentResults = [];
  let activeIndex = 0;
  let lastFocus = null;
  let targetTimer = null;

  function shortcutLabel() {
    return /Mac|iPhone|iPad|iPod/.test(navigator.platform || '') ? 'Cmd K' : 'Ctrl K';
  }

  function moduleLabel(task) {
    const module = C.reports && C.reports.MODULE_BY_ID ? C.reports.MODULE_BY_ID.get(task) : null;
    return module ? module.label : C.format.humanize(task);
  }

  function makeRoute(tab, sectionId) {
    const label = TAB_LABELS[tab] || (tab.indexOf('task:') === 0 ? C.format.humanize(tab.slice(5)) : C.format.humanize(tab));
    return {
      tab: tab,
      sectionId: sectionId,
      tabLabel: label,
      sectionLabel: SECTION_LABELS[sectionId] || C.format.humanize(sectionId.replace(/^task:/, ''))
    };
  }

  function routeForTask(task, keys) {
    const first = keys && keys.length ? String(keys[0]) : '';
    const cacheKey = task + '|' + first;
    if (routeCache.has(cacheKey)) return routeCache.get(cacheKey);

    let tab = 'task:' + task;
    let sectionId = 'generic-result';

    if (task === 'html_scan') {
      tab = 'website';
      if (first === 'forms') sectionId = 'website-forms';
      else if (first === 'cloaking') sectionId = 'website-cloaking';
      else if (first === 'identifiers') sectionId = 'website-identifiers';
      else if (first === 'wordpress') sectionId = 'website-wordpress';
      else sectionId = 'website-pages';
    } else if (task === 'robots_scan') {
      tab = 'website';
      sectionId = 'website-robots';
    } else if (task === 'headers_scan') {
      tab = 'website';
      sectionId = 'website-headers';
    } else if (task === 'ip_lookup') {
      tab = 'network';
      if (first === 'records') sectionId = 'network-dns';
      else if (first === 'tls') sectionId = 'network-tls';
      else if (first === 'email_security') sectionId = 'network-email';
      else if (first === 'cloudflare_origin') sectionId = 'network-cloudflare';
      else sectionId = 'network-addresses';
    } else if (task === 'infra_scan') {
      tab = 'network';
      sectionId = 'network-infra';
    } else if (task === 'domain_scan') {
      tab = 'domain';
      sectionId = 'domain-analysis';
    } else if (task === 'whois_lookup') {
      tab = 'domain';
      sectionId = 'domain-whois';
    } else if (task === 'threat_lookup') {
      tab = 'threats';
      sectionId = first === 'wayback_first_seen' ? 'threats-wayback' : 'threats-sources';
    }

    const route = makeRoute(tab, sectionId);
    routeCache.set(cacheKey, route);
    return route;
  }

  function topRoute(tab, sectionId) {
    const cacheKey = 'top|' + tab + '|' + sectionId;
    if (!routeCache.has(cacheKey)) routeCache.set(cacheKey, makeRoute(tab, sectionId));
    return routeCache.get(cacheKey);
  }

  function addEntry(entries, model, reportInfo, labels, route, value, matchExtra) {
    if (entries.length >= MAX_ENTRIES_PER_REPORT) return;
    if (value == null) return;

    let text;
    if (typeof value === 'boolean') text = value ? 'Yes' : 'No';
    else text = String(value).trim();
    if (!text) return;
    if (text.length > MAX_VALUE_LENGTH) text = text.slice(0, MAX_VALUE_LENGTH);

    const pathLabel = labels.join(' \u203a ');
    const valueLower = (text + (matchExtra ? ' ' + matchExtra : '')).toLowerCase();
    entries.push({
      reportId: model.id,
      reportTarget: model.target,
      reportPath: model.path,
      order: reportInfo.order,
      position: entries.length,
      pathLabel: pathLabel,
      pathLower: pathLabel.toLowerCase(),
      sectionId: route.sectionId,
      tab: route.tab,
      tabLabel: route.tabLabel,
      sectionLabel: route.sectionLabel,
      sectionLower: route.sectionLabel.toLowerCase(),
      value: text,
      valueLower: valueLower
    });
  }

  function walk(value, keys, labels, task, entries, model, reportInfo) {
    if (entries.length >= MAX_ENTRIES_PER_REPORT || value == null) return;

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i += 1) {
        if (entries.length >= MAX_ENTRIES_PER_REPORT) return;
        walk(value[i], keys.concat(i), labels.concat('#' + (i + 1)), task, entries, model, reportInfo);
      }
      return;
    }

    if (typeof value === 'object') {
      const objectKeys = Object.keys(value);
      for (let i = 0; i < objectKeys.length; i += 1) {
        if (entries.length >= MAX_ENTRIES_PER_REPORT) return;
        const key = objectKeys[i];
        walk(value[key], keys.concat(key), labels.concat(C.format.humanize(key)), task, entries, model, reportInfo);
      }
      return;
    }

    const route = task ? routeForTask(task, keys) : topRoute('overview', 'overview-profile');
    addEntry(entries, model, reportInfo, labels, route, value);
  }

  function entriesForReport(model, order) {
    if (!model || !model.raw) return [];
    if (indexCache.has(model)) return indexCache.get(model);

    const entries = [];
    const reportInfo = { order: order || 0 };
    const add = function (labels, route, value, extra) {
      addEntry(entries, model, reportInfo, labels, route, value, extra);
    };

    add(['Target'], topRoute('overview', 'overview-profile'), model.target);
    if (model.raw.generated_at != null) {
      add(['Generated at'], topRoute('overview', 'overview-timeline'), model.raw.generated_at);
    }

    model.results.forEach(function (entry) {
      const task = entry.task;
      const label = moduleLabel(task);
      if (entry.error) {
        add([label, 'Error'], routeForTask(task, []), entry.error);
      }
      if (entry.result != null) {
        walk(entry.result, [], [label], task, entries, model, reportInfo);
      }
    });

    indexCache.set(model, entries);
    return entries;
  }

  function buildIndex(reports) {
    const list = reports || (C.state ? C.state.sortedReports() : []);
    const entries = [];
    for (let i = 0; i < list.length; i += 1) {
      if (entries.length >= MAX_TOTAL_ENTRIES) break;
      const reportEntries = entriesForReport(list[i], i);
      for (let j = 0; j < reportEntries.length && entries.length < MAX_TOTAL_ENTRIES; j += 1) {
        reportEntries[j].order = i;
        entries.push(reportEntries[j]);
      }
    }
    return entries;
  }

  function tokensFor(query) {
    return String(query == null ? '' : query).trim().toLowerCase().split(/\s+/).filter(Boolean);
  }

  function matchesEntry(entry, tokens) {
    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (entry.pathLower.indexOf(token) === -1 &&
          entry.sectionLower.indexOf(token) === -1 &&
          entry.valueLower.indexOf(token) === -1) {
        return false;
      }
    }
    return true;
  }

  function scoreEntry(entry, tokens, fullQuery, activeId) {
    let score = 0;
    if (entry.reportId === activeId) score += 24;
    if (entry.valueLower === fullQuery) score += 220;
    else if (entry.valueLower.indexOf(fullQuery) === 0) score += 140;
    else if (entry.valueLower.indexOf(fullQuery) !== -1) score += 70;
    if (entry.pathLower === fullQuery) score += 180;
    else if (entry.pathLower.indexOf(fullQuery) === 0) score += 100;
    else if (entry.pathLower.indexOf(fullQuery) !== -1) score += 55;

    for (let i = 0; i < tokens.length; i += 1) {
      const token = tokens[i];
      if (entry.pathLower.indexOf(token) !== -1) score += 9;
      if (entry.valueLower.indexOf(token) !== -1) score += 5;
    }
    return score + Math.max(0, 30 - Math.min(30, Math.floor(entry.value.length / 8)));
  }

  function filter(entries, query, options) {
    const tokens = tokensFor(query);
    if (!tokens.length) return [];
    const fullQuery = tokens.join(' ');
    const activeId = options && options.activeId;
    const scored = [];
    for (let i = 0; i < entries.length; i += 1) {
      const entry = entries[i];
      if (matchesEntry(entry, tokens)) {
        scored.push({ entry: entry, score: scoreEntry(entry, tokens, fullQuery, activeId) });
      }
    }
    scored.sort(function (a, b) {
      if (a.score !== b.score) return b.score - a.score;
      if (a.entry.order !== b.entry.order) return a.entry.order - b.entry.order;
      if (a.entry.position !== b.entry.position) return a.entry.position - b.entry.position;
      return a.entry.pathLabel.localeCompare(b.entry.pathLabel);
    });
    return scored.map(function (item) { return item.entry; });
  }

  function escapeRegExp(text) {
    return String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  function appendHighlighted(parent, text, tokens) {
    const value = String(text == null ? '' : text);
    if (!tokens.length) {
      parent.appendChild(document.createTextNode(value));
      return;
    }
    const pattern = new RegExp('(' + tokens.map(escapeRegExp).join('|') + ')', 'gi');
    let last = 0;
    const matches = value.matchAll(pattern);
    for (const match of matches) {
      if (match.index > last) parent.appendChild(document.createTextNode(value.slice(last, match.index)));
      parent.appendChild(D.el('mark', { text: match[0] }));
      last = match.index + match[0].length;
    }
    if (last < value.length) parent.appendChild(document.createTextNode(value.slice(last)));
  }

  function snippet(value, tokens) {
    const text = C.ui ? C.ui.displayValue(value) : value;
    const limit = 220;
    if (text.length <= limit) return text;
    const lower = text.toLowerCase();
    let position = -1;
    for (let i = 0; i < tokens.length; i += 1) {
      const found = lower.indexOf(tokens[i]);
      if (found !== -1 && (position === -1 || found < position)) position = found;
    }
    if (position === -1) return text.slice(0, limit - 3) + '...';
    const start = Math.max(0, Math.min(text.length - limit, position - Math.floor(limit / 3)));
    return (start > 0 ? '...' : '') + text.slice(start, start + limit - 6) + (start + limit - 6 < text.length ? '...' : '');
  }

  function renderEmpty(title, detail) {
    resultsNode.appendChild(D.el('div', { class: 'spotlight-empty' },
      D.icon('search'),
      D.el('strong', { text: title }),
      D.el('span', { text: detail })
    ));
  }

  function setActive(index, scroll) {
    if (!currentResults.length) {
      activeIndex = -1;
      if (input) input.removeAttribute('aria-activedescendant');
      return;
    }
    activeIndex = (index + currentResults.length) % currentResults.length;
    const items = D.qsa('.spotlight-result', resultsNode);
    items.forEach(function (item, i) {
      const active = i === activeIndex;
      item.classList.toggle('active', active);
      item.setAttribute('aria-selected', active ? 'true' : 'false');
    });
    if (input) input.setAttribute('aria-activedescendant', 'spotlight-option-' + activeIndex);
    if (scroll) {
      const node = items[activeIndex];
      if (node) node.scrollIntoView({ block: 'nearest' });
    }
  }

  function renderResults() {
    if (!resultsNode) return;
    D.clear(resultsNode);
    const query = input ? input.value.trim() : '';
    const tokens = tokensFor(query);
    currentResults = query ? filter(allEntries, query, { activeId: C.state.activeId }) : [];
    activeIndex = currentResults.length ? 0 : -1;

    if (!allEntries.length) {
      renderEmpty('No reports loaded', 'Open a Clouseau report JSON to search its fields.');
      if (countNode) countNode.textContent = '0 fields';
      input.removeAttribute('aria-activedescendant');
      return;
    }

    if (!query) {
      const reports = C.state.sortedReports().length;
      renderEmpty(
        'Search every field',
        'Find page titles, DNS records, WHOIS fields, headers, IOCs, and more across ' +
        C.format.formatNumber(reports) + ' loaded ' + C.format.plural(reports, 'report') + '.'
      );
      if (countNode) countNode.textContent = C.format.formatNumber(allEntries.length) + ' ' + C.format.plural(allEntries.length, 'field');
      input.removeAttribute('aria-activedescendant');
      return;
    }

    if (!currentResults.length) {
      renderEmpty('No matches for "' + query + '"',
        'Try a shorter term or search for a value such as a domain, IP, header, or page title.');
      if (countNode) countNode.textContent = '0 matches';
      input.removeAttribute('aria-activedescendant');
      return;
    }

    const shown = currentResults.slice(0, MAX_RESULTS);
    shown.forEach(function (entry, index) {
      const item = D.el('button', {
        class: 'spotlight-result',
        type: 'button',
        id: 'spotlight-option-' + index,
        role: 'option',
        'aria-selected': 'false',
        title: entry.pathLabel + ': ' + entry.value,
        onClick: function () { choose(entry); },
        onMouseenter: function () { setActive(index, false); }
      });
      const path = D.el('span', { class: 'spotlight-result-path' });
      appendHighlighted(path, entry.pathLabel, tokens);
      item.appendChild(path);
      const value = D.el('span', { class: 'spotlight-result-value' });
      appendHighlighted(value, snippet(entry.value, tokens), tokens);
      item.appendChild(value);
      const meta = D.el('span', { class: 'spotlight-result-meta' });
      meta.appendChild(D.el('span', { class: 'spotlight-result-location', text: entry.tabLabel + ' \u203a ' + entry.sectionLabel }));
      const report = D.el('span', {
        class: 'spotlight-result-report',
        title: entry.reportTarget,
        text: C.ui ? C.ui.displayValue(entry.reportTarget, 'url') : entry.reportTarget
      });
      meta.appendChild(report);
      item.appendChild(meta);
      resultsNode.appendChild(item);
    });

    if (countNode) {
      const matchLabel = currentResults.length === 1 ? 'match' : 'matches';
      countNode.textContent = currentResults.length > shown.length
        ? C.format.formatNumber(shown.length) + ' of ' + C.format.formatNumber(currentResults.length) + ' ' + matchLabel
        : C.format.formatNumber(currentResults.length) + ' ' + matchLabel;
    }
    setActive(0, false);
  }

  function ensureDom() {
    if (overlay) return;

    overlay = D.el('div', {
      class: 'spotlight-backdrop',
      hidden: true,
      onMousedown: function (event) {
        if (event.target === overlay) close();
      }
    });

    const panel = D.el('div', {
      class: 'spotlight',
      role: 'dialog',
      'aria-modal': 'true',
      'aria-labelledby': 'spotlight-label'
    });
    panel.appendChild(D.el('span', { class: 'visually-hidden', id: 'spotlight-label', text: 'Search report fields' }));

    const head = D.el('div', { class: 'spotlight-head' });
    head.appendChild(D.icon('search'));
    input = D.el('input', {
      class: 'spotlight-input',
      id: 'spotlight-input',
      type: 'text',
      placeholder: 'Search every field in loaded reports...',
      autocomplete: 'off',
      spellcheck: 'false',
      role: 'combobox',
      'aria-label': 'Search report fields',
      'aria-autocomplete': 'list',
      'aria-controls': 'spotlight-results',
      'aria-expanded': 'true'
    });
    head.appendChild(input);
    head.appendChild(D.el('kbd', { class: 'spotlight-key', text: 'Esc' }));
    panel.appendChild(head);

    resultsNode = D.el('div', {
      class: 'spotlight-results',
      id: 'spotlight-results',
      role: 'listbox',
      'aria-label': 'Matching report fields'
    });
    panel.appendChild(resultsNode);

    const foot = D.el('div', { class: 'spotlight-foot' });
    const hints = D.el('span', { class: 'spotlight-hints' });
    [
      { keys: ['\u2191', '\u2193'], label: 'navigate' },
      { keys: ['Enter'], label: 'open' },
      { keys: ['Esc'], label: 'close' }
    ].forEach(function (hint, index) {
      if (index) hints.appendChild(D.el('span', { class: 'spotlight-hint-sep', text: '\u00b7' }));
      hint.keys.forEach(function (key) {
        hints.appendChild(D.el('kbd', { text: key }));
      });
      hints.appendChild(D.el('span', { text: hint.label }));
    });
    foot.appendChild(hints);
    countNode = D.el('span', { class: 'spotlight-count', 'aria-live': 'polite' });
    foot.appendChild(countNode);
    panel.appendChild(foot);
    overlay.appendChild(panel);
    document.body.appendChild(overlay);

    input.addEventListener('input', renderResults);
    input.addEventListener('keydown', function (event) {
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setActive(activeIndex + 1, true);
      } else if (event.key === 'ArrowUp') {
        event.preventDefault();
        setActive(activeIndex - 1, true);
      } else if (event.key === 'Enter') {
        if (currentResults.length && activeIndex >= 0) {
          event.preventDefault();
          choose(currentResults[activeIndex]);
        }
      } else if (event.key === 'Tab') {
        event.preventDefault();
        input.focus();
      }
    });
    overlay.addEventListener('keydown', function (event) {
      if (event.key === 'Tab') {
        event.preventDefault();
        input.focus();
      }
    });
  }

  function open() {
    ensureDom();
    if (!overlay.hidden) {
      input.focus();
      input.select();
      return;
    }
    if (D.closeModal) D.closeModal();
    if (C.shell && C.shell.closeSidebar) C.shell.closeSidebar();
    lastFocus = document.activeElement;

    allEntries = buildIndex(C.state.sortedReports());
    input.value = '';
    currentResults = [];
    activeIndex = 0;
    overlay.hidden = false;
    document.body.classList.add('modal-open');
    renderResults();
    input.focus();
  }

  function close(options) {
    if (!overlay || overlay.hidden) return;
    overlay.hidden = true;
    if (!document.querySelector('.modal-backdrop')) document.body.classList.remove('modal-open');
    const restore = !options || options.restoreFocus !== false;
    if (restore && lastFocus && document.documentElement.contains(lastFocus) && typeof lastFocus.focus === 'function') {
      lastFocus.focus();
    }
    lastFocus = null;
  }

  function reveal(entry, attempt) {
    const section = document.getElementById(entry.sectionId);
    if (!section) {
      if (attempt < 30) setTimeout(function () { reveal(entry, attempt + 1); }, 50);
      return;
    }
    D.qsa('.section.spotlight-target').forEach(function (node) { node.classList.remove('spotlight-target'); });
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    section.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    section.classList.add('spotlight-target');
    clearTimeout(targetTimer);
    targetTimer = setTimeout(function () { section.classList.remove('spotlight-target'); }, 2400);
  }

  function choose(entry) {
    if (!entry) return;
    close({ restoreFocus: false });
    const route = C.router.parse();
    if (route.view !== 'report' || route.id !== entry.reportId || route.tab !== entry.tab) {
      C.router.go(entry.reportId, entry.tab);
    }
    reveal(entry, 0);
  }

  function onKeydown(event) {
    const key = String(event.key || '').toLowerCase();
    if ((event.ctrlKey || event.metaKey) && !event.altKey && !event.shiftKey && key === 'k') {
      event.preventDefault();
      event.stopPropagation();
      open();
      return;
    }
    if (overlay && !overlay.hidden && event.key === 'Escape') {
      event.preventDefault();
      event.stopPropagation();
      close();
    }
  }

  function init() {
    if (initialized) return;
    initialized = true;
    const trigger = document.getElementById('open-search');
    if (trigger) {
      trigger.addEventListener('click', open);
      const key = trigger.querySelector('.spotlight-trigger-key');
      if (key) key.textContent = shortcutLabel();
    }
    window.addEventListener('keydown', onKeydown, true);
  }

  C.search = {
    init: init,
    open: open,
    close: close,
    buildIndex: buildIndex,
    filter: filter,
    routeForTask: routeForTask,
    entriesForReport: entriesForReport,
    shortcutLabel: shortcutLabel,
    isOpen: function () { return Boolean(overlay && !overlay.hidden); }
  };
})();

