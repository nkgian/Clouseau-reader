(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
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

  function errorBanner(model) {
    const errors = model.errors.filter(function (entry) {
      return entry.task === 'whois_lookup' || entry.task === 'domain_scan';
    });
    if (!errors.length) return null;
    return UI.card('Module errors', UI.errorList(errors, {
      onOpen: function () { C.router.go(model.id, 'raw'); }
    }), { icon: 'alert-triangle' });
  }

  function stats(model) {
    const whois = model.getResult('whois_lookup') || {};
    const domain = model.getResult('domain_scan') || {};
    const age = Number(whois.domain_age_days);
    const nameservers = whois.fields ? fieldValue(fieldMap(whois.fields), ['Name Server', 'Name Servers']) : '';
    return UI.statGrid([
      UI.stat('Domain age', Number.isFinite(age) ? C.format.formatDays(age) : '—', whois.created_at ? 'Registered ' + C.format.fmtDate(whois.created_at) : 'No creation date', { icon: 'calendar' }),
      UI.stat('IDN status', domain.punycode ? 'Punycode' : domain.host ? 'ASCII' : '—', domain.unicode_host || 'No Unicode form', { icon: 'globe' }),
      UI.stat('Scripts', asArray(domain.scripts).length || '—', asArray(domain.scripts).join(' + ') || 'No script data', { icon: 'code' }),
      UI.stat('Registrar', whois.fields ? fieldValue(fieldMap(whois.fields), ['Registrar']) || '—' : '—', nameservers ? 'Nameservers present' : 'No WHOIS fields', { icon: 'key' })
    ]);
  }

  function domainSection(model) {
    const domain = model.getResult('domain_scan');
    if (!domain) return null;
    const scripts = asArray(domain.scripts);
    const content = [];
    if (domain.mixed_script) {
      content.push(UI.notice('critical', 'shield-alert', 'Mixed-script host',
        'The host mixes ' + (scripts.join(' + ') || 'multiple scripts') + '. This can indicate a homoglyph impersonation. Treat the Unicode form with caution.'));
    } else if (domain.punycode) {
      content.push(UI.notice('warning', 'globe', 'Internationalised host',
        'The host uses punycode. Verify that the decoded form is expected before acting on it.'));
    }
    const facts = UI.kvList([
      UI.kvRow('Host', UI.copyable(domain.host || model.host, 'host', 'domain', { mono: true })),
      domain.unicode_host ? UI.kvRow('Unicode form', D.el('span', { class: 'row' }, D.el('bdi', { class: 'unicode-host', text: UI.displayValue(domain.unicode_host, 'domain') }), UI.copyButton(domain.unicode_host, 'Unicode host'))) : null,
      UI.kvRow('Punycode', UI.boolBadge(domain.punycode, 'Yes', 'No', 'warning', 'ok')),
      UI.kvRow('Mixed script', UI.boolBadge(domain.mixed_script, 'Yes', 'No', 'critical', 'ok')),
      scripts.length ? UI.kvRow('Scripts', UI.chipList(scripts, { type: 'text', variant: domain.mixed_script ? 'warning' : '' })) : null,
      asArray(domain.warnings).length ? UI.kvRow('Warnings', D.el('div', { class: 'stack' }, asArray(domain.warnings).map(function (warning) { return D.el('div', { class: 'small', text: warning }); }))) : null
    ]);
    content.push(UI.card('Domain analysis', facts, { icon: 'globe' }));
  return UI.section('Domain', 'domain-analysis', content, {
    icon: 'globe',
    subtitle: domain.host || ''
  });
  }

  function whoisSection(model) {
    const whois = model.getResult('whois_lookup');
    if (!whois) {
      const error = model.getError('whois_lookup');
      return UI.section('WHOIS', 'domain-whois', UI.card('WHOIS', error ? UI.notice('warning', 'alert-triangle', 'WHOIS failed', error) : UI.notRun('WHOIS lookup'), { icon: 'key' }), { icon: 'key' });
    }
    const map = fieldMap(whois.fields);
    const registrar = fieldValue(map, ['Registrar']);
    const nameservers = fieldValue(map, ['Name Server', 'Name Servers']);
    const expires = fieldValue(map, ['Registry Expiry Date', 'Expiry Date', 'Expiration Date', 'paid-till']);
    const rows = [
      whois.domain ? UI.kvRow('Domain', UI.copyable(whois.domain, 'domain', 'domain', { mono: true })) : null,
      registrar ? UI.kvRow('Registrar', registrar) : null,
      whois.created_at ? UI.kvRow('Created', C.format.fmtDate(whois.created_at)) : null,
      Number.isFinite(Number(whois.domain_age_days)) ? UI.kvRow('Age', C.format.formatDays(Number(whois.domain_age_days))) : null,
      expires ? UI.kvRow('Expires', C.format.fmtDate(expires)) : null,
      nameservers ? UI.kvRow('Name servers', UI.chipList(nameservers.split(',').map(function (value) { return value.trim().replace(/\.$/, ''); }), { type: 'domain', pivot: true, ctx: { model: model } })) : null,
      whois.server ? UI.kvRow('WHOIS server', whois.server) : null,
      whois.new_domain ? UI.kvRow('Flag', UI.badge('Recently registered', 'warning', 'calendar')) : null
    ];
    const content = [UI.card('Registration record', UI.kvList(rows), { icon: 'key' })];

    const fields = Object.keys(whois.fields || {});
    if (fields.length) {
      const table = UI.dataTable([
        { key: 'label', label: 'Field', render: function (row) { return D.el('span', { class: 'check-name', text: row.label }); }, value: function (row) { return row.label; } },
        { key: 'value', label: 'Value', render: function (row) { return UI.copyable(row.value, row.label, 'text'); }, value: function (row) { return row.value; } }
      ], fields.map(function (key) { return { label: key, value: whois.fields[key] }; }), {
        pageSize: 25,
        rowLabel: 'fields',
        filterPlaceholder: 'Filter WHOIS fields…'
      });
      content.push(UI.card('WHOIS fields', table, { flush: true, icon: 'database' }));
    }
    if (whois.raw) {
      content.push(UI.collapsible('Raw WHOIS response', [
        UI.codeBlock(whois.raw, { actions: D.el('button', { class: 'btn btn-ghost btn-sm', type: 'button', onClick: function () { D.copyText(whois.raw, 'raw WHOIS'); } }, D.icon('copy'), 'Copy raw') })
      ], false));
    }
  return UI.section('WHOIS', 'domain-whois', content, {
    icon: 'key',
    subtitle: whois.server || ''
  });
  }

  function integrationSection(model) {
    const values = [];
    if (model.host) values.push({ type: 'domain', value: model.host, label: 'Host' });
    const unicodeHost = (model.getResult('domain_scan') || {}).unicode_host;
    if (unicodeHost && unicodeHost !== model.host) values.push({ type: 'domain', value: unicodeHost, label: 'Unicode host' });
    const whoisDomain = (model.getResult('whois_lookup') || {}).domain;
    if (whoisDomain && !values.some(function (item) { return item.value.toLowerCase() === whoisDomain.toLowerCase(); })) {
      values.push({ type: 'domain', value: whoisDomain, label: 'WHOIS domain' });
    }
    if (!values.length) return null;
    const blocks = values.map(function (item) {
      return UI.detailBlock(item.label, C.integrations.renderStrip(item.type, item.value, { model: model }, { limit: 5 }), 'external');
    });
  return UI.section('Domain pivots', 'domain-pivots', UI.card('Investigate this domain', D.el('div', { class: 'stack' }, blocks), {
    icon: 'crosshair'
  }), { icon: 'crosshair' });
  }

  C.views = C.views || {};
  C.views.domain = function (model) {
    const view = D.el('div', { class: 'view' });
    const banner = errorBanner(model);
    if (banner) view.appendChild(banner);
    view.appendChild(stats(model));

    const sections = [];
    const nav = [];
    const add = function (section, id, label) {
      if (!section) return;
      sections.push(section);
      nav.push({ id: id, label: label });
    };
    add(domainSection(model), 'domain-analysis', 'Analysis');
    add(whoisSection(model), 'domain-whois', 'WHOIS');
    add(integrationSection(model), 'domain-pivots', 'Pivots');

    if (nav.length > 2) {
      const sectionNav = UI.sectionNav(nav);
      if (sectionNav) view.appendChild(sectionNav);
    }
    sections.forEach(function (section) { view.appendChild(section); });
    return view;
  };
})();
