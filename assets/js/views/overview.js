(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function go(model, tab) {
    C.router.go(model.id, tab);
  }

  function viewLink(model, tab, label) {
    return D.el('button', {
      class: 'obs-link',
      type: 'button',
      onClick: function () { go(model, tab); }
    }, label || 'View details →');
  }

  function fieldMap(fields) {
    const map = new Map();
    Object.keys(fields || {}).forEach(function (key) {
      map.set(key.toLowerCase(), fields[key]);
    });
    return map;
  }

  function fieldValue(map, names) {
    for (const name of names) {
      const value = map.get(name.toLowerCase());
      if (value != null && String(value).trim()) return String(value);
    }
    return '';
  }

  function firstIp(ip) {
    const addresses = asArray(ip.addresses);
    if (addresses.length && addresses[0].ip) return addresses[0].ip;
    return (asArray((ip.records || {}).a)[0]) || '';
  }

  function observationCard(model, observation) {
    const node = D.el('article', { class: 'obs ' + observation.severity });
    node.appendChild(D.el('div', { class: 'obs-icon' }, D.icon(observation.icon)));
    const body = D.el('div', { class: 'obs-body' });
    body.appendChild(D.el('div', { class: 'obs-title', text: observation.title }));
    if (observation.detail) body.appendChild(D.el('div', { class: 'obs-detail', text: observation.detail }));
    const foot = D.el('div', { class: 'obs-foot' });
    if (observation.source) foot.appendChild(UI.sourceTag(C.format.humanize(observation.source), 'database'));
    if (observation.tab && observation.tab !== 'overview') {
      foot.appendChild(viewLink(model, observation.tab, 'Inspect →'));
    }
    body.appendChild(foot);
    node.appendChild(body);
    return node;
  }

  function observationsSection(model) {
    const observations = model.observations || [];
    const summary = C.signals.summarise(observations);
    const content = [];
    if (!observations.length) {
      content.push(UI.notice('ok', 'check', 'No notable observations', 'No tracked signals were flagged.'));
    } else {
      const grid = D.el('div', { class: 'obs-grid' });
      observations.forEach(function (observation) { grid.appendChild(observationCard(model, observation)); });
      content.push(grid);
    }
    const actions = [];
    if (observations.length) {
      actions.push(UI.badge(summary.critical + ' critical', 'critical'));
      actions.push(UI.badge(summary.warning + ' warning', 'warning'));
      actions.push(UI.badge(summary.info + ' info', 'info'));
    }
    return UI.section('Observations', 'overview-observations', content, {
      icon: 'activity',
      count: observations.length,
      actions: actions,
      subtitle: 'Prioritized findings derived from the scan, ordered by severity.'
    });
  }

  function coverageSummary(model) {
    const counts = { ok: 0, partial: 0, error: 0, missing: 0 };
    model.coverage.forEach(function (item) { counts[item.status] = (counts[item.status] || 0) + 1; });
    return counts;
  }

  function statsSection(model) {
    const html = model.getResult('html_scan') || {};
    const pages = asArray(html.pages);
    const labels = C.iocs.counts(model.iocs || []);
    const labelParts = Object.keys(labels).slice(0, 3).map(function (type) {
      return (C.iocs.TYPES[type] ? C.iocs.TYPES[type].label : C.format.humanize(type)) + ' ' + labels[type];
    });
    const obs = C.signals.summarise(model.observations || []);
    const cov = coverageSummary(model);
    const complete = cov.ok;
    const total = model.coverage.filter(function (item) { return item.known; }).length;

    return UI.statGrid([
      UI.stat('Observations', obs.total, obs.total ? obs.critical + ' critical · ' + obs.warning + ' warning · ' + obs.info + ' info' : 'Nothing flagged', { icon: 'activity' }),
      UI.stat('Coverage', complete + ' / ' + total, (cov.partial ? cov.partial + ' partial · ' : '') + (cov.error ? cov.error + ' failed · ' : '') + (cov.missing ? cov.missing + ' not run' : 'All modules ran'), { icon: 'layers' }),
      UI.stat('Pages scanned', pages.length, pages.length ? (asArray(html.links).length + ' links collected') : 'No website scan', { icon: 'globe' }),
      UI.stat('IOCs', (model.iocs || []).length, labelParts.join(' · ') || 'None extracted', { icon: 'crosshair' })
    ]);
  }

  function identityCard(model) {
    const html = model.getResult('html_scan') || {};
    const headers = model.getResult('headers_scan') || {};
    const page = asArray(html.pages)[0] || {};
    const rows = [
      UI.kvRow('Target', UI.copyable(model.target, 'target URL', 'url', { mono: true })),
      model.host ? UI.kvRow('Host', UI.copyable(model.host, 'host', 'domain', { mono: true })) : null,
      model.unicodeHost && model.unicodeHost !== model.host ? UI.kvRow('Unicode host', UI.copyable(model.unicodeHost, 'Unicode host', 'domain', { mono: true })) : null,
      page.url && page.url !== model.target ? UI.kvRow('Scanned page', UI.urlValue(page.url, { open: true, source: 'Scanned page' })) : null,
      page.title ? UI.kvRow('Page title', page.title) : null,
      page.status != null ? UI.kvRow('HTTP status', UI.httpStatusBadge(page.status)) : null,
      headers.server ? UI.kvRow('Server', headers.server) : null,
      headers.powered_by ? UI.kvRow('Powered by', headers.powered_by) : null
    ];
    return UI.card('Identity', UI.kvList(rows), {
      icon: 'globe',
      subtitle: 'Target URL, host, page title, and server information.'
    });
  }

  function registrationCard(model) {
    const whois = model.getResult('whois_lookup') || {};
    const fields = fieldMap(whois.fields);
    const nameservers = asArray((model.getResult('ip_lookup') || {}).records && (model.getResult('ip_lookup') || {}).records.ns);
    const nsValue = nameservers.length ? nameservers : fieldValue(fields, ['Name Server', 'Name Servers', 'nameservers']);
    const expires = fieldValue(fields, ['Registry Expiry Date', 'Expiry Date', 'Expiration Date', 'paid-till']);
    const rows = [
      whois.domain ? UI.kvRow('Domain', UI.copyable(whois.domain, 'domain', 'domain', { mono: true })) : null,
      fieldValue(fields, ['Registrar']) ? UI.kvRow('Registrar', fieldValue(fields, ['Registrar'])) : null,
      whois.created_at || fieldValue(fields, ['Creation Date', 'Created']) ? UI.kvRow('Created', C.format.fmtDate(whois.created_at || fieldValue(fields, ['Creation Date', 'Created']))) : null,
      Number.isFinite(Number(whois.domain_age_days)) ? UI.kvRow('Domain age', C.format.formatDays(Number(whois.domain_age_days))) : null,
      expires ? UI.kvRow('Expires', C.format.fmtDate(expires)) : null,
      nsValue ? UI.kvRow('Name servers', Array.isArray(nsValue) ? UI.chipList(nsValue, { type: 'domain' }) : nsValue) : null,
      whois.new_domain ? UI.kvRow('Flag', UI.badge('Recently registered', 'warning', 'calendar')) : null
    ];
    return UI.card('Registration', UI.kvList(rows), {
      icon: 'key',
      subtitle: 'Domain age, registrar, expiry, and name-server details.'
    });
  }

  function hostingCard(model) {
    const ip = model.getResult('ip_lookup') || {};
    const addresses = asArray(ip.addresses);
    const address = addresses[0] || {};
    const records = ip.records || {};
    const allIps = addresses.length
      ? addresses.map(function (item) { return item.ip; })
      : asArray(records.a).concat(asArray(records.aaaa));
    const rows = [
      allIps.length ? UI.kvRow('Addresses', UI.chipList(allIps, { type: 'ip', pivot: true, ctx: { model: model } })) : null,
      address.asn ? UI.kvRow('ASN', D.el('span', {}, address.asn + (address.as_name ? ' · ' + address.as_name : ''))) : null,
      address.country ? UI.kvRow('Country', address.country) : null,
      address.provider ? UI.kvRow('Provider', address.provider) : null,
      address.ptr && asArray(address.ptr).length ? UI.kvRow('Reverse DNS', UI.chipList(address.ptr, { type: 'domain' })) : null,
      asArray(records.ns).length ? UI.kvRow('DNS NS', UI.chipList(records.ns, { type: 'domain' })) : null,
      asArray(records.mx).length ? UI.kvRow('Mail exchangers', UI.chipList(records.mx, { type: 'domain' })) : null,
      address.tor_exit ? UI.kvRow('Tor exit', UI.badge('Listed', 'warning', 'network')) : null,
      asArray(address.dnsbl).length ? UI.kvRow('Blocklists', UI.chipList(address.dnsbl, { type: 'text' })) : null
    ];
    return UI.card('Hosting & DNS', UI.kvList(rows), {
      icon: 'network',
      subtitle: 'Resolved addresses, network ownership, DNS records, and reputation signals.'
    });
  }

  function tlsCard(model) {
    const ip = model.getResult('ip_lookup') || {};
    const tls = ip.tls || {};
    const infra = model.getResult('infra_scan') || {};
    if (!tls || !Object.keys(tls).length) {
      return UI.card('TLS & assets', UI.emptyInline('No TLS details reported.'), {
        icon: 'lock',
        subtitle: 'Certificate status, validity, names, and related infrastructure.'
      });
    }
    const status = tls.self_signed
      ? UI.badge('Self-signed', 'critical', 'alert-triangle')
      : tls.verified === false
        ? UI.badge('Not verified', 'warning', 'alert-triangle')
        : UI.badge('Verified', 'ok', 'check');
    const rows = [
      UI.kvRow('Certificate status', status),
      tls.version ? UI.kvRow('Protocol', tls.version) : null,
      tls.issuer ? UI.kvRow('Issuer', tls.issuer) : null,
      tls.subject ? UI.kvRow('Subject', tls.subject) : null,
      tls.not_before ? UI.kvRow('Valid from', C.format.fmtDate(tls.not_before)) : null,
      tls.not_after ? UI.kvRow('Expires', C.format.fmtDate(tls.not_after) + (Number.isFinite(Number(tls.days_left)) ? ' · ' + tls.days_left + ' days left' : '')) : null,
      asArray(tls.dns_names).length ? UI.kvRow('SANs', UI.chipList(tls.dns_names, { type: 'domain' })) : null,
      tls.verify_error ? UI.kvRow('Verification error', D.el('span', { class: 'warn-link', text: tls.verify_error })) : null,
      infra.favicon && infra.favicon.mmh3 != null ? UI.kvRow('Favicon hash', UI.copyable(infra.favicon.mmh3, 'favicon mmh3 hash', 'text', { mono: true })) : null,
      asArray(infra.certificate_domains).length ? UI.kvRow('Related domains', UI.chipList(infra.certificate_domains.slice(0, 8), { type: 'domain', empty: 'None' })) : null
    ];
    return UI.card('TLS & assets', UI.kvList(rows), {
      icon: 'lock',
      subtitle: 'Certificate status, validity, names, and related infrastructure.'
    });
  }

  function coverageSection(model) {
    const list = D.el('div', { class: 'check-list' });
    model.coverage.forEach(function (item) {
      const row = D.el('div', { class: 'check-row' });
      const text = D.el('div');
      text.appendChild(D.el('div', { class: 'check-name' }, D.icon(item.icon), item.label));
      const notes = [];
      if (item.ok) notes.push(item.ok + ' ' + C.format.plural(item.ok, 'result'));
      if (item.errors) notes.push(item.errors + ' ' + C.format.plural(item.errors, 'error'));
      if (item.status === 'missing') notes.push('Not included in this scan');
      text.appendChild(D.el('div', { class: 'check-note', text: notes.join(' · ') }));
      row.appendChild(text);
      row.appendChild(UI.taskStatusBadge(item.status));
      list.appendChild(row);
    });
    return UI.card('Module coverage', list, {
      icon: 'layers',
      subtitle: 'Modules included in this report and their completion status.'
    });
  }

  function timelineSection(model) {
    const whois = model.getResult('whois_lookup') || {};
    const threat = model.getResult('threat_lookup') || {};
    const tls = (model.getResult('ip_lookup') || {}).tls || {};
    const events = [];
    const add = function (value, title, detail, className) {
      const date = C.format.parseDate(value);
      if (!date) return;
      events.push({ date: date, title: title, detail: detail || '', className: className || '' });
    };
    add(whois.created_at, 'Domain registered', whois.domain || model.host, '');
    add(threat.wayback_first_seen, 'First Wayback capture', 'Earliest snapshot indexed by the Wayback Machine.', '');
    add(tls.not_before, 'TLS certificate issued', tls.issuer || '', '');
    add(tls.not_after, 'TLS certificate expires', tls.subject || '', '');
    add(model.generatedAt, 'Scan completed', model.path, '');
    if (!events.length) return null;
    events.sort(function (a, b) { return a.date - b.date; });
    const list = D.el('ul', { class: 'timeline' });
    events.forEach(function (event) {
      const item = D.el('li', { class: event.className });
      item.appendChild(D.el('div', { class: 'timeline-date', text: C.format.fmtDate(event.date) }));
      item.appendChild(D.el('div', { class: 'timeline-title', text: event.title }));
      if (event.detail) item.appendChild(D.el('div', { class: 'timeline-detail', text: event.detail }));
      list.appendChild(item);
    });
    return UI.section('Timeline', 'overview-timeline', UI.card('Chronology', list, {
      icon: 'clock',
      subtitle: 'Dated events assembled from registration, archive, certificate, and scan data.'
    }), {
      icon: 'clock',
      subtitle: 'Dated events assembled from the report and related lookups.'
    });
  }

  function integrationsSection(model) {
    const ip = model.getResult('ip_lookup') || {};
    const address = firstIp(ip);
    const ctx = { model: model };
    const rows = [];
    rows.push(UI.detailBlock('Target URL', C.integrations.renderStrip('url', model.target, ctx, { limit: 4 }), 'link'));
    if (model.host) {
      rows.push(UI.detailBlock('Host', C.integrations.renderStrip('domain', model.host, ctx, { limit: 4 }), 'globe'));
    }
    if (address) {
      rows.push(UI.detailBlock('Resolved address', C.integrations.renderStrip('ip', address, ctx, { limit: 4 }), 'network'));
    }
    const body = D.el('div', { class: 'stack' }, rows);
    return UI.section('External pivots', 'overview-pivots', UI.card('Investigate further', body, {
      icon: 'crosshair',
      subtitle: 'External services that can extend the investigation.'
    }), {
      icon: 'crosshair',
      subtitle: 'Open external lookups for the target and related indicators.'
    });
  }

  C.views = C.views || {};
  C.views.overview = function (model) {
    const view = D.el('div', { class: 'view' });
    view.appendChild(statsSection(model));

    const nav = UI.sectionNav([
      { id: 'overview-observations', label: 'Observations', count: (model.observations || []).length },
      { id: 'overview-profile', label: 'Profile' },
      { id: 'overview-coverage', label: 'Coverage' },
      { id: 'overview-timeline', label: 'Timeline' },
      { id: 'overview-pivots', label: 'Pivots' }
    ]);
    if (nav) view.appendChild(nav);

    view.appendChild(observationsSection(model));

    const profile = UI.section('Target profile', 'overview-profile', [
      D.el('div', { class: 'card-grid' }, identityCard(model), registrationCard(model), hostingCard(model), tlsCard(model))
    ], {
      icon: 'file-text',
      subtitle: 'Core identity, registration, hosting, and certificate details.'
    });
    view.appendChild(profile);

    view.appendChild(UI.section('Coverage', 'overview-coverage', coverageSection(model), {
      icon: 'layers',
      count: model.coverage.filter(function (item) { return item.status !== 'missing'; }).length,
      subtitle: 'Which scanner modules ran, partially completed, or failed.'
    }));

    const timeline = timelineSection(model);
    if (timeline) view.appendChild(timeline);

    view.appendChild(integrationsSection(model));
    return view;
  };
})();
