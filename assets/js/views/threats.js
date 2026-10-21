(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function sourceCard(model, source) {
    const status = String(source.status || '').toLowerCase();
    const urls = asArray(source.urls);
    const content = [];
    if (source.detail) {
      content.push(D.el('div', { class: 'small ' + (status === 'error' ? 'warn-link' : 'muted'), text: source.detail }));
    }
    if (urls.length) {
      const list = D.el('div', { class: 'stack' });
      urls.forEach(function (url) {
        list.appendChild(UI.urlValue(url, { open: true, warn: true, source: C.format.humanize(source.source) + ' match' }));
      });
      content.push(list);
    }
    if (!content.length) content.push(UI.emptyInline('No matching URLs were returned.'));
    return UI.card(C.format.humanize(source.source || 'Unknown source'), content, {
      icon: status === 'found' ? 'shield-alert' : status === 'error' ? 'alert-triangle' : 'shield',
      actions: UI.sourceStatusBadge(source.status)
    });
  }

  function waybackDays(model, firstSeen) {
    const date = C.format.parseDate(firstSeen);
    if (!date) return null;
    const generated = model.generatedAt || new Date();
    return Math.round((generated.getTime() - date.getTime()) / 86400000);
  }

  function overviewCard(model, sources) {
    const found = sources.filter(function (source) { return String(source.status || '').toLowerCase() === 'found'; });
    const errors = sources.filter(function (source) { return String(source.status || '').toLowerCase() === 'error'; });
    const urlCount = found.reduce(function (total, source) { return total + asArray(source.urls).length; }, 0);
    if (found.length) {
      return UI.notice('critical', 'shield-alert', 'Target appears in threat intelligence',
        'Listed by ' + found.map(function (source) { return C.format.humanize(source.source); }).join(', ') +
        (urlCount ? ' · ' + urlCount + ' matching ' + C.format.plural(urlCount, 'URL') : '') +
        (errors.length ? ' · ' + errors.length + ' source(s) could not be checked.' : '.'));
    }
    if (errors.length === sources.length && sources.length) {
      return UI.notice('warning', 'alert-triangle', 'Threat checks could not complete',
        'All sources returned errors. The target has not been cleared.');
    }
    return UI.notice('ok', 'check', 'No threat listings reported',
      'Checked sources did not return a listing' + (errors.length ? ', but some sources failed.' : '.'));
  }

  function stats(model) {
    const threat = model.getResult('threat_lookup') || {};
    const sources = asArray(threat.sources);
    const found = sources.filter(function (source) { return String(source.status || '').toLowerCase() === 'found'; });
    const errors = sources.filter(function (source) { return String(source.status || '').toLowerCase() === 'error'; });
    const urls = found.reduce(function (total, source) { return total + asArray(source.urls).length; }, 0);
    const days = waybackDays(model, threat.wayback_first_seen);
    return UI.statGrid([
      UI.stat('Sources', sources.length, found.length + ' listed · ' + errors.length + ' error', { icon: 'database' }),
      UI.stat('Listings', found.length, found.length ? found.map(function (source) { return C.format.humanize(source.source); }).join(', ') : 'None reported', { icon: 'shield-alert' }),
      UI.stat('Matching URLs', urls, urls ? 'Returned by threat sources' : 'No URLs returned', { icon: 'link' }),
      UI.stat('First archived', threat.wayback_first_seen ? C.format.fmtDate(threat.wayback_first_seen) : '—', days != null ? (days >= 0 ? days + ' days before this scan' : Math.abs(days) + ' days after this scan') : 'No Wayback date', { icon: 'archive' })
    ]);
  }

  function waybackSection(model) {
    const threat = model.getResult('threat_lookup') || {};
    const ctx = { model: model };
    const firstSeen = threat.wayback_first_seen;
    const days = waybackDays(model, firstSeen);
    const rows = [
      threat.host ? UI.kvRow('Host', UI.copyable(threat.host, 'host', 'domain', { mono: true })) : null,
      UI.kvRow('First seen', firstSeen ? C.format.fmtDate(firstSeen) + (days != null ? ' · ' + (days >= 0 ? days + ' days before scan' : Math.abs(days) + ' days after scan') : '') : 'No date reported'),
      UI.kvRow('Target capture', C.integrations.renderStrip('url', model.target, ctx, { ids: ['wayback-first', 'wayback-calendar', 'archive-today'], limit: 5 })),
      model.host ? UI.kvRow('Host history', C.integrations.renderStrip('domain', model.host, ctx, { ids: ['wayback-host', 'wayback-cdx'], limit: 3 })) : null
    ];
  return UI.section('Archive history', 'threats-wayback', UI.card('Wayback Machine', UI.kvList(rows), {
    icon: 'archive'
  }), { icon: 'archive' });
  }

  function sourceSection(model) {
    const threat = model.getResult('threat_lookup');
    if (!threat) {
      const error = model.getError('threat_lookup');
      return UI.section('Sources', 'threats-sources', UI.card('Threat intelligence', error ? UI.notice('warning', 'alert-triangle', 'Threat lookup failed', error) : UI.notRun('Threat lookup'), { icon: 'shield-alert' }), { icon: 'shield-alert' });
    }
    const sources = asArray(threat.sources);
    if (!sources.length) {
      return UI.section('Sources', 'threats-sources', UI.card('Threat intelligence', UI.emptyInline('No threat sources were reported.'), { icon: 'shield-alert' }), { icon: 'shield-alert' });
    }
    const grid = D.el('div', { class: 'card-grid' });
    sources.forEach(function (source) { grid.appendChild(sourceCard(model, source)); });
    const errors = sources.filter(function (source) { return String(source.status || '').toLowerCase() === 'error'; });
    const content = [grid];
    if (errors.length) {
      content.push(UI.notice('warning', 'alert-triangle', 'Unchecked sources',
        errors.map(function (source) { return C.format.humanize(source.source) + ': ' + (source.detail || 'error'); }).join(' · ')));
    }
    return UI.section('Sources', 'threats-sources', content, {
      icon: 'shield-alert',
      count: sources.length
    });
  }

  C.views = C.views || {};
  C.views.threats = function (model) {
    const view = D.el('div', { class: 'view' });
    const threat = model.getResult('threat_lookup') || {};
    const sources = asArray(threat.sources);
    view.appendChild(stats(model));
    if (sources.length) view.appendChild(overviewCard(model, sources));

    const nav = UI.sectionNav([
      { id: 'threats-sources', label: 'Sources', count: sources.length },
      { id: 'threats-wayback', label: 'Archive' }
    ]);
    if (nav) view.appendChild(nav);
    view.appendChild(sourceSection(model));
    view.appendChild(waybackSection(model));
    return view;
  };
})();
