(function () {
  'use strict';

  const C = window.C = window.C || {};
  const TYPES = {
    url: { label: 'URL', icon: 'link', order: 1 },
    domain: { label: 'Domain', icon: 'globe', order: 2 },
    ip: { label: 'IP address', icon: 'network', order: 3 },
    email: { label: 'Email', icon: 'mail', order: 4 },
    wallet: { label: 'Wallet', icon: 'wallet', order: 5 },
    telegram: { label: 'Telegram', icon: 'send', order: 6 },
    whatsapp: { label: 'WhatsApp', icon: 'phone', order: 7 },
    analytics: { label: 'Analytics ID', icon: 'activity', order: 8 },
    username: { label: 'Username', icon: 'message', order: 9 },
    sha256: { label: 'SHA-256', icon: 'hash', order: 10 },
    mmh3: { label: 'Favicon hash', icon: 'hash', order: 11 }
  };

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function clean(value) {
    if (value == null) return '';
    let text = String(value).trim();
    if (text.length > 2048) text = text.slice(0, 2048);
    return text;
  }

  function normaliseKey(type, value) {
    if (type === 'url') return value;
    return value.toLowerCase();
  }

  function valid(type, value) {
    if (!value) return false;
    if (type === 'url') return /^https?:\/\//i.test(value);
    if (type === 'domain') return /^[^\s\/]+$/.test(value) && value.indexOf('.') !== -1;
    if (type === 'ip') return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || /^[0-9a-f:]+$/i.test(value);
    if (type === 'email') return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
    if (type === 'wallet') return /^0x[a-fA-F0-9]{40}$/.test(value) || /^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(value);
    if (type === 'sha256') return /^[a-f0-9]{64}$/i.test(value);
    if (type === 'mmh3') return /^-?\d+$/.test(value);
    return true;
  }

  function extract(model) {
    const items = [];
    const index = new Map();

    const add = function (type, rawValue, source, tab) {
      if (!TYPES[type]) return;
      let value = clean(rawValue);
      if (!value) return;
      if (type === 'domain') value = value.replace(/\.$/, '');
      if (type === 'telegram') value = value.replace(/^@/, '').replace(/^https?:\/\/t\.me\//i, '');
      if (type === 'whatsapp') value = value.replace(/^tel:/i, '');
      if (!valid(type, value)) return;
      const key = type + '|' + normaliseKey(type, value);
      const existing = index.get(key);
      if (existing) {
        if (source && existing.sources.indexOf(source) === -1) existing.sources.push(source);
        if (tab && existing.tabs.indexOf(tab) === -1) existing.tabs.push(tab);
        return;
      }
      const item = {
        type: type,
        value: value,
        sources: source ? [source] : [],
        tabs: tab ? [tab] : []
      };
      index.set(key, item);
      items.push(item);
    };

    const addEmailText = function (text, source, tab) {
      const matches = String(text || '').match(/[^\s@<>()]+@[^\s@<>()]+\.[a-zA-Z]{2,}/g) || [];
      matches.forEach(function (email) { add('email', email, source, tab); });
    };

    if (model.target) add('url', model.target, 'Target', 'overview');
    if (model.host) add('domain', model.host, 'Target host', 'overview');
    if (model.unicodeHost && model.unicodeHost !== model.host) {
      add('domain', model.unicodeHost, 'Unicode host', 'domain');
    }

    const whois = model.getResult('whois_lookup') || {};
    if (whois.domain) add('domain', whois.domain, 'WHOIS', 'domain');
    asArray(Object.values(whois.fields || {})).forEach(function (value) {
      addEmailText(value, 'WHOIS', 'domain');
    });

    const html = model.getResult('html_scan') || {};
    if (html.start_url) add('url', html.start_url, 'Website scan', 'website');
    asArray(html.pages).forEach(function (page) {
      add('url', page.url, 'Crawled page', 'website');
      add('sha256', page.sha256, 'Page body hash', 'website');
      asArray(page.links).forEach(function (link) { add('url', link, 'Page links', 'website'); });
    });
    asArray(html.links).forEach(function (link) { add('url', link, 'Crawled links', 'website'); });
    const forms = html.forms || {};
    asArray(forms.forms).forEach(function (form) {
      add('url', form.action, 'Form action', 'website');
    });
    const identifiers = html.identifiers || {};
    asArray(identifiers.analytics).forEach(function (value) { add('analytics', value, 'HTML identifiers', 'website'); });
    asArray(identifiers.telegram).forEach(function (value) { add('telegram', value, 'HTML identifiers', 'website'); });
    asArray(identifiers.whatsapp).forEach(function (value) { add('whatsapp', value, 'HTML identifiers', 'website'); });
    asArray(identifiers.wallets).forEach(function (value) { add('wallet', value, 'HTML identifiers', 'website'); });
    asArray(identifiers.emails).forEach(function (value) { add('email', value, 'HTML identifiers', 'website'); });
    const wordpress = html.wordpress || {};
    const userName = function (user) {
      return typeof user === 'string' ? user : (user && (user.name || user.slug || user.id));
    };
    asArray(wordpress.authors).forEach(function (value) { add('username', userName(value), 'WordPress author', 'website'); });
    asArray(wordpress.users).forEach(function (user) { add('username', userName(user), 'WordPress user', 'website'); });

    const robots = model.getResult('robots_scan') || {};
    asArray(robots.sitemaps).forEach(function (value) { add('url', value, 'robots.txt sitemap', 'website'); });
    asArray(robots.sitemap_files).forEach(function (file) { add('url', file.url, 'Sitemap file', 'website'); });

    const headers = model.getResult('headers_scan') || {};
    asArray(headers.redirects).forEach(function (hop) { add('url', hop.url, 'Redirect chain', 'website'); });

    const threat = model.getResult('threat_lookup') || {};
    asArray(threat.sources).forEach(function (source) {
      const sourceLabel = (C.signals.isArchiveSource(source) ? 'Archive: ' : 'Threat intel: ') + source.source;
      asArray(source.urls).forEach(function (value) { add('url', value, sourceLabel, 'threats'); });
    });

    const ip = model.getResult('ip_lookup') || {};
    const records = ip.records || {};
    ['a', 'aaaa'].forEach(function (key) {
      asArray(records[key]).forEach(function (value) { add('ip', value, 'DNS ' + key.toUpperCase(), 'network'); });
    });
    ['ns', 'mx'].forEach(function (key) {
      asArray(records[key]).forEach(function (value) {
        const host = String(value || '').replace(/^\d+\s+/, '').replace(/\.$/, '');
        add('domain', host, 'DNS ' + key.toUpperCase(), 'network');
      });
    });
    asArray(ip.addresses).forEach(function (address) {
      add('ip', address.ip, 'Resolved address', 'network');
      asArray(address.ptr).forEach(function (ptr) { add('domain', String(ptr || '').replace(/\.$/, ''), 'Reverse DNS', 'network'); });
      if (address.netblock) {
        asArray(address.netblock.abuse_emails).forEach(function (email) { add('email', email, 'Netblock abuse contact', 'network'); });
      }
    });
    const emailSecurity = ip.email_security || {};
    addEmailText(emailSecurity.dmarc, 'DMARC record', 'network');
    asArray(emailSecurity.spf).forEach(function (value) { addEmailText(value, 'SPF record', 'network'); });
    const tls = ip.tls || {};
    asArray(tls.dns_names).forEach(function (value) { add('domain', value, 'TLS SAN', 'network'); });
    const cloudflare = ip.cloudflare_origin || {};
    asArray(cloudflare.candidates).forEach(function (candidate) {
      add('domain', candidate.subdomain, 'Cloudflare origin candidate', 'network');
      asArray(candidate.ips).forEach(function (value) { add('ip', value, 'Cloudflare origin candidate', 'network'); });
    });

    const infra = model.getResult('infra_scan') || {};
    asArray(infra.certificate_domains).forEach(function (value) { add('domain', value, 'Certificate transparency', 'network'); });
    if (infra.favicon) {
      add('sha256', infra.favicon.sha256, 'Favicon hash', 'network');
      if (infra.favicon.mmh3 != null) add('mmh3', infra.favicon.mmh3, 'Favicon hash', 'network');
    }

    items.sort(function (a, b) {
      const orderA = TYPES[a.type] ? TYPES[a.type].order : 99;
      const orderB = TYPES[b.type] ? TYPES[b.type].order : 99;
      if (orderA !== orderB) return orderA - orderB;
      return a.value.localeCompare(b.value);
    });

    return items;
  }

  function counts(items) {
    const out = {};
    items.forEach(function (item) { out[item.type] = (out[item.type] || 0) + 1; });
    return out;
  }

  function displayValue(item, defanged) {
    return defanged ? C.format.defang(item.value, item.type) : item.value;
  }

  function csvCell(value) {
    return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
  }

  function exportCsv(items, defanged) {
    const rows = [['type', 'value', 'defanged', 'sources'].map(csvCell).join(',')];
    items.forEach(function (item) {
      rows.push([
        TYPES[item.type] ? TYPES[item.type].label : item.type,
        item.value,
        C.format.defang(item.value, item.type),
        item.sources.join('; ')
      ].map(csvCell).join(','));
    });
    return rows.join('\r\n');
  }

  function exportJson(model, items, defanged) {
    return JSON.stringify({
      target: model.target,
      generated_at: model.raw.generated_at,
      exported_at: new Date().toISOString(),
      defanged: Boolean(defanged),
      indicators: items.map(function (item) {
        return {
          type: item.type,
          label: TYPES[item.type] ? TYPES[item.type].label : item.type,
          value: item.value,
          defanged: C.format.defang(item.value, item.type),
          sources: item.sources
        };
      })
    }, null, 2);
  }

  function mdCell(value) {
    return String(value == null ? '' : value).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  }

  function exportMarkdown(model, items, defanged) {
    const lines = [];
    lines.push('# Indicators — ' + model.target);
    lines.push('');
    lines.push('- Generated: ' + (model.raw.generated_at || 'unknown'));
    lines.push('- Exported: ' + new Date().toISOString());
    lines.push('- Total: ' + items.length);
    lines.push('');
    lines.push('| Type | Value | Sources |');
    lines.push('| --- | --- | --- |');
    items.forEach(function (item) {
      const value = displayValue(item, defanged);
      lines.push('| ' + mdCell(TYPES[item.type] ? TYPES[item.type].label : item.type) + ' | `' + mdCell(value) + '` | ' + mdCell(item.sources.join(', ')) + ' |');
    });
    return lines.join('\n');
  }

  function copyAll(items, defanged) {
    return items.map(function (item) { return displayValue(item, defanged); }).join('\n');
  }

  function filename(model, extension) {
    const host = model.host || C.format.hostFromUrl(model.target) || 'report';
    const date = model.generatedAt ? model.generatedAt.toISOString().slice(0, 10) : new Date().toISOString().slice(0, 10);
    return host.replace(/[^a-z0-9.-]+/gi, '_') + '_indicators_' + date + '.' + extension;
  }

  C.iocs = {
    TYPES: TYPES,
    extract: extract,
    counts: counts,
    displayValue: displayValue,
    exportCsv: exportCsv,
    exportJson: exportJson,
    exportMarkdown: exportMarkdown,
    copyAll: copyAll,
    filename: filename
  };
})();
