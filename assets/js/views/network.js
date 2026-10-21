(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function stripDot(value) {
    return String(value == null ? '' : value).replace(/\.$/, '');
  }

  function cleanMx(value) {
    return String(value == null ? '' : value).replace(/^\d+\s+/, '').replace(/\.$/, '');
  }

  function mxPriority(value) {
    const match = String(value == null ? '' : value).match(/^(\d+)\s+/);
    return match ? match[1] : '';
  }

  function errorBanner(model) {
    const errors = model.errors.filter(function (entry) {
      return entry.task === 'ip_lookup' || entry.task === 'infra_scan';
    });
    if (!errors.length) return null;
    return UI.card('Module errors', UI.errorList(errors, {
      onOpen: function () { C.router.go(model.id, 'raw'); }
    }), { icon: 'alert-triangle' });
  }

  function stats(model) {
    const ip = model.getResult('ip_lookup') || {};
    const addresses = asArray(ip.addresses);
    const first = addresses[0] || {};
    const tls = ip.tls || {};
    const blocklisted = addresses.filter(function (address) { return asArray(address.dnsbl).length; }).length;
    return UI.statGrid([
      UI.stat('Addresses', addresses.length, addresses.length ? asArray(ip.records && ip.records.a).length + ' A · ' + asArray(ip.records && ip.records.aaaa).length + ' AAAA' : 'No addresses resolved', { icon: 'network' }),
      UI.stat('Network', first.asn ? 'AS' + first.asn : '—', first.as_name || first.provider && asArray(first.provider).join(', ') || 'No ASN data', { icon: 'server' }),
      UI.stat('Reputation', blocklisted ? blocklisted + ' listed' : addresses.length ? 'No listings' : '—', first.tor_exit ? 'Tor exit node' : 'Not a Tor exit', { icon: 'shield' }),
      UI.stat('TLS', tls.version || '—', tls.verified === false ? 'Certificate not verified' : tls.not_after ? 'Expires ' + C.format.fmtDate(tls.not_after) : 'No certificate data', { icon: 'lock' })
    ]);
  }

  function dnsSection(model) {
    const ip = model.getResult('ip_lookup');
    if (!ip) return null;
    const records = ip.records || {};
    const known = ['a', 'aaaa', 'mx', 'ns', 'txt', 'cname'];
    const keys = known.filter(function (key) { return records[key] != null; }).concat(Object.keys(records).filter(function (key) { return known.indexOf(key) === -1; }));
    if (!keys.length) {
      return UI.section('DNS records', 'network-dns', UI.card('DNS', UI.emptyInline('No DNS records were reported.'), { icon: 'database' }), { icon: 'database' });
    }
    const rows = keys.map(function (key) {
      const value = records[key];
      const values = Array.isArray(value) ? value : [value];
      let rendered;
      if (key === 'a' || key === 'aaaa') {
        rendered = UI.chipList(values, { type: 'ip', pivot: true, ctx: { model: model } });
      } else if (key === 'mx') {
        rendered = D.el('div', { class: 'stack' }, values.map(function (entry) {
          const row = D.el('div', { class: 'row' });
          const priority = mxPriority(entry);
          if (priority) row.appendChild(UI.badge('P' + priority, 'muted'));
          row.appendChild(UI.copyable(cleanMx(entry), 'mail exchanger', 'domain', { mono: true }));
          return row;
        }));
      } else if (key === 'ns') {
        rendered = UI.chipList(values.map(stripDot), { type: 'domain', pivot: true, ctx: { model: model } });
      } else if (key === 'cname') {
        rendered = UI.chipList(values.map(stripDot), { type: 'domain', pivot: true, ctx: { model: model } });
      } else if (key === 'txt') {
        rendered = D.el('div', { class: 'stack' }, values.map(function (entry) {
          return UI.copyable(entry, 'TXT value', 'text');
        }));
      } else {
        rendered = D.el('div', { class: 'stack' }, values.map(function (entry) {
          return UI.copyable(typeof entry === 'object' ? JSON.stringify(entry) : entry, key.toUpperCase() + ' record', 'text');
        }));
      }
      return UI.kvRow(key.toUpperCase(), rendered);
    });
    return UI.section('DNS records', 'network-dns', UI.card('Resolver output', UI.kvList(rows), {
      icon: 'database',
      subtitle: ip.host ? 'Records for ' + ip.host : ''
    }), { icon: 'database', count: keys.length });
  }

  function portsList(ports) {
    const risky = [21, 22, 23, 25, 3306, 3389, 5432, 6379, 9200, 11211];
    const list = asArray(ports);
    if (!list.length) return D.el('span', { class: 'muted small', text: 'No open ports reported' });
    const wrap = D.el('div', { class: 'port-list' });
    list.forEach(function (port) {
      wrap.appendChild(D.el('span', { class: 'port' + (risky.indexOf(Number(port)) !== -1 ? ' warn-link' : ''), text: String(port) }));
    });
    return wrap;
  }

  function addressCard(model, address) {
    const card = D.el('div', { class: 'address-card' });
    const head = D.el('div', { class: 'address-head' });
    head.appendChild(D.el('div', { class: 'address-ip' }, D.el('bdi', { text: UI.displayValue(address.ip, 'ip') })));
    const badges = D.el('div', { class: 'row' });
    badges.appendChild(UI.badge('IPv' + (address.version || 4), 'muted'));
    if (address.scope) badges.appendChild(UI.badge(address.scope, address.scope === 'public' ? 'info' : 'muted'));
    if (address.tor_exit) badges.appendChild(UI.badge('Tor exit', 'warning', 'network'));
    if (asArray(address.dnsbl).length) badges.appendChild(UI.badge(asArray(address.dnsbl).length + ' DNSBL', 'warning', 'shield-alert'));
    const pivot = UI.pivotBtn('ip', address.ip, { model: model });
    if (pivot) badges.appendChild(pivot);
    head.appendChild(badges);
    card.appendChild(head);

    const provider = asArray(address.provider).join(', ');
    const netblock = address.netblock || {};
    const rows = [
      asArray(address.ptr).length ? UI.kvRow('PTR', UI.chipList(address.ptr.map(stripDot), { type: 'domain' })) : null,
      address.asn ? UI.kvRow('ASN', D.el('span', {}, 'AS' + address.asn + (address.as_name ? ' · ' + address.as_name : ''))) : null,
      address.country ? UI.kvRow('Country', address.country) : null,
      address.prefix ? UI.kvRow('Prefix', UI.copyable(address.prefix, 'network prefix', 'text', { mono: true })) : null,
      provider ? UI.kvRow('Provider', provider) : null,
      address.forward_confirmed != null ? UI.kvRow('Forward-confirmed', UI.boolBadge(address.forward_confirmed, 'Confirmed', 'Unconfirmed', 'ok', 'warning')) : null,
      UI.kvRow('Open ports', portsList(address.open_ports)),
      asArray(address.dnsbl).length ? UI.kvRow('DNS blocklists', UI.chipList(address.dnsbl, { type: 'text', variant: 'warning' })) : null,
      netblock.organization ? UI.kvRow('Netblock', netblock.organization) : null,
      asArray(netblock.abuse_emails).length ? UI.kvRow('Abuse contact', UI.chipList(netblock.abuse_emails, { type: 'email' })) : null
    ];
    card.appendChild(UI.kvList(rows));
    return card;
  }

  function addressesSection(model) {
    const ip = model.getResult('ip_lookup');
    if (!ip) return null;
    const addresses = asArray(ip.addresses);
    const content = [];
    if (!addresses.length) {
      content.push(UI.emptyInline('No resolved addresses were enriched.'));
    } else {
      const grid = D.el('div', { class: 'address-grid' });
      addresses.forEach(function (address) { grid.appendChild(addressCard(model, address)); });
      content.push(grid);
    }
    if (asArray(ip.warnings).length) {
      content.push(UI.notice('warning', 'alert-triangle', 'Resolver warnings', asArray(ip.warnings).join(' · ')));
    }
    return UI.section('Addresses', 'network-addresses', content, {
      icon: 'network',
      count: addresses.length
    });
  }

  function tlsSection(model) {
    const ip = model.getResult('ip_lookup');
    if (!ip) return null;
    const tls = ip.tls;
    if (!tls) return null;
    const notBefore = C.format.parseDate(tls.not_before);
    const notAfter = C.format.parseDate(tls.not_after);
    let percent = null;
    if (notBefore && notAfter && notAfter > notBefore) {
      percent = Math.max(0, Math.min(100, ((Date.now() - notBefore.getTime()) / (notAfter.getTime() - notBefore.getTime())) * 100));
    }
    const status = tls.self_signed
      ? UI.badge('Self-signed', 'critical', 'alert-triangle')
      : tls.verified === false
        ? UI.badge('Not verified', 'warning', 'alert-triangle')
        : UI.badge('Verified', 'ok', 'check');
    const rows = [
      UI.kvRow('Status', status),
      tls.version ? UI.kvRow('Protocol', tls.version) : null,
      tls.cipher_suite ? UI.kvRow('Cipher suite', D.el('span', { class: 'mono small', text: tls.cipher_suite })) : null,
      tls.subject ? UI.kvRow('Subject', D.el('span', { class: 'mono small break', text: tls.subject })) : null,
      tls.issuer ? UI.kvRow('Issuer', tls.issuer) : null,
      tls.not_before ? UI.kvRow('Valid from', C.format.fmtDateTime(tls.not_before)) : null,
      tls.not_after ? UI.kvRow('Valid until', C.format.fmtDateTime(tls.not_after) + (Number.isFinite(Number(tls.days_left)) ? ' · ' + tls.days_left + ' days left' : '')) : null,
      asArray(tls.dns_names).length ? UI.kvRow('SANs', UI.chipList(tls.dns_names, { type: 'domain', pivot: true, ctx: { model: model } })) : null,
      tls.verify_error ? UI.kvRow('Verification', D.el('span', { class: 'warn-link', text: tls.verify_error })) : null
    ];
    const card = UI.card('Certificate', D.el('div', { class: 'stack' }, [
      percent != null ? D.el('div', {}, D.el('div', { class: 'validity-bar', title: Math.round(percent) + '% of validity window elapsed' }, D.el('span', { style: { width: percent + '%' } }))) : null,
      UI.kvList(rows)
    ]), { icon: 'lock' });
  return UI.section('TLS', 'network-tls', [card], {
    icon: 'lock',
    subtitle: tls.server_name || ''
  });
  }

  function emailSection(model) {
    const ip = model.getResult('ip_lookup');
    if (!ip) return null;
    const email = ip.email_security;
    if (!email) return null;
    const policy = String(email.dmarc_policy || '').toLowerCase();
    const dmarcBadge = policy === 'reject'
      ? UI.badge('reject', 'ok', 'shield')
      : policy === 'quarantine'
        ? UI.badge('quarantine', 'info', 'shield')
        : policy === 'none'
          ? UI.badge('none', 'warning', 'alert-triangle')
          : email.dmarc ? UI.badge('present', 'info', 'shield') : UI.badge('Missing', 'warning', 'alert-triangle');
    const rows = [
      asArray(email.spf).length ? UI.kvRow('SPF', D.el('div', { class: 'stack' }, asArray(email.spf).map(function (record) { return UI.copyable(record, 'SPF record', 'text'); }))) : UI.kvRow('SPF', UI.badge('Missing', 'warning', 'alert-triangle')),
      UI.kvRow('DMARC policy', dmarcBadge),
      email.dmarc ? UI.kvRow('DMARC record', UI.copyable(email.dmarc, 'DMARC record', 'text')) : null,
      email.bimi ? UI.kvRow('BIMI', UI.copyable(email.bimi, 'BIMI record', 'text')) : null
    ];
  return UI.section('Email security', 'network-email', UI.card('SPF, DMARC & BIMI', UI.kvList(rows), {
    icon: 'mail'
  }), { icon: 'mail' });
  }

  function cloudflareSection(model) {
    const ip = model.getResult('ip_lookup');
    if (!ip) return null;
    const cf = ip.cloudflare_origin;
    if (!cf) return null;
    const candidates = asArray(cf.candidates);
    const content = [];
    content.push(UI.kvList([
      UI.kvRow('Domain', cf.domain || model.host),
      UI.kvRow('Subdomains checked', String(cf.checked || 0)),
      UI.kvRow('Candidates', String(candidates.length))
    ]));
    if (candidates.length) {
      const table = UI.dataTable([
        { key: 'subdomain', label: 'Subdomain', render: function (row) { return UI.urlValue('https://' + row.subdomain, { open: false }); }, value: function (row) { return row.subdomain || ''; } },
        { key: 'ips', label: 'Addresses', render: function (row) { return UI.chipList(row.ips, { type: 'ip', pivot: true, ctx: { model: model } }); }, value: function (row) { return asArray(row.ips).join(' '); } }
      ], candidates, { pageSize: 20, rowLabel: 'candidates', filterPlaceholder: 'Filter candidates…' });
      content.push(UI.card('Origin candidates', table, { flush: true, icon: 'crosshair' }));
      content.push(UI.notice('warning', 'crosshair', 'Potential origin exposure', 'These subdomains resolve to addresses that may bypass the CDN. Verify before drawing conclusions.'));
    } else {
      content.push(UI.emptyInline('No origin candidates were found.'));
    }
    return UI.section('Cloudflare origin', 'network-cloudflare', [
      UI.card('CDN bypass check', content, { icon: 'crosshair' })
    ], { icon: 'crosshair', count: candidates.length });
  }

  function infraSection(model) {
    const infra = model.getResult('infra_scan');
    if (!infra) return null;
    const content = [];
    const domains = asArray(infra.certificate_domains);
    content.push(UI.kvList([
      UI.kvRow('Host', infra.host || model.host),
      UI.kvRow('Certificate domains', String(infra.certificate_domain_total || domains.length)),
      domains.length ? UI.kvRow('Domains', UI.chipList(domains, { type: 'domain', pivot: true, ctx: { model: model } })) : null,
      infra.certificate_error ? UI.kvRow('Certificate lookup', D.el('span', { class: 'warn-link', text: infra.certificate_error })) : null
    ]));
    if (domains.length > 1) {
      content.push(UI.notice('info', 'layers', 'Shared certificate',
        'The certificate covers ' + domains.length + ' domains, which can reveal related infrastructure.'));
    }
    const favicon = infra.favicon;
    if (favicon) {
      const rows = [
        favicon.url ? UI.kvRow('URL', UI.urlValue(favicon.url, { open: false })) : null,
        favicon.bytes ? UI.kvRow('Size', C.dom.formatBytes(favicon.bytes)) : null,
        favicon.sha256 ? UI.kvRow('SHA-256', UI.hashValue(favicon.sha256, 'favicon SHA-256')) : null,
        favicon.mmh3 != null ? UI.kvRow('mmh3', D.el('span', { class: 'row' }, UI.copyable(favicon.mmh3, 'favicon mmh3', 'text', { mono: true }), UI.pivotBtn('mmh3', String(favicon.mmh3), { model: model }))) : null,
        favicon.error ? UI.kvRow('Fetch', D.el('span', { class: 'warn-link', text: favicon.error })) : null
      ];
      content.push(UI.card('Favicon', UI.kvList(rows), { icon: 'eye' }));
    }
    return UI.section('Infrastructure', 'network-infra', [
      UI.card('Certificate transparency & favicon', content, { icon: 'layers' })
    ], { icon: 'layers' });
  }

  C.views = C.views || {};
  C.views.network = function (model) {
    const view = D.el('div', { class: 'view' });
    const banner = errorBanner(model);
    if (banner) view.appendChild(banner);
    view.appendChild(stats(model));

    const sections = [];
    const nav = [];
    const add = function (section, id, label, count) {
      if (!section) return;
      sections.push(section);
      nav.push({ id: id, label: label, count: count });
    };
    const ip = model.getResult('ip_lookup') || {};
    add(dnsSection(model), 'network-dns', 'DNS');
    add(addressesSection(model), 'network-addresses', 'Addresses', asArray(ip.addresses).length);
    add(tlsSection(model), 'network-tls', 'TLS');
    add(emailSection(model), 'network-email', 'Email');
    add(cloudflareSection(model), 'network-cloudflare', 'Cloudflare');
    add(infraSection(model), 'network-infra', 'Infrastructure');

    if (nav.length > 2) {
      const sectionNav = UI.sectionNav(nav);
      if (sectionNav) view.appendChild(sectionNav);
    }
    sections.forEach(function (section) { view.appendChild(section); });
    if (!sections.length) {
      view.appendChild(UI.card('No network data', UI.notRun('The network modules'), { icon: 'network' }));
    }
    return view;
  };
})();
