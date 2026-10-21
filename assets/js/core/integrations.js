(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;

  function enc(value) {
    return encodeURIComponent(String(value == null ? '' : value));
  }

  function firstSeenOf(ctx) {
    if (!ctx) return '';
    if (ctx.firstSeen) return ctx.firstSeen;
    if (ctx.model && ctx.model.getResult) {
      const threat = ctx.model.getResult('threat_lookup') || {};
      return threat.wayback_first_seen || '';
    }
    return '';
  }

  function compactFirstSeen(ctx) {
    return C.format.compactDate(firstSeenOf(ctx));
  }

  function isEth(value) {
    return /^0x[a-fA-F0-9]{40}$/.test(value);
  }

  function isBtc(value) {
    return /^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(value);
  }

  const PROVIDERS = [
    {
      id: 'wayback-first',
      label: 'Wayback snapshot',
      group: 'Archive',
      supports: ['url'],
      description: 'First archived capture',
      build: function (value, ctx) {
        const date = compactFirstSeen(ctx);
        return date ? 'https://web.archive.org/web/' + date + '/' + value : null;
      }
    },
    {
      id: 'wayback-calendar',
      label: 'Wayback calendar',
      group: 'Archive',
      supports: ['url'],
      description: 'All captures of this URL',
      build: function (value) { return 'https://web.archive.org/web/*/' + value; }
    },
    {
      id: 'wayback-host',
      label: 'Wayback host calendar',
      group: 'Archive',
      supports: ['domain'],
      description: 'All captures of this host',
      build: function (value) { return 'https://web.archive.org/web/*/' + value + '/*'; }
    },
    {
      id: 'wayback-cdx',
      label: 'Wayback CDX query',
      group: 'Archive',
      supports: ['domain'],
      description: 'Raw CDX index JSON',
      build: function (value) {
        return 'https://web.archive.org/cdx/search/cdx?url=' + enc(value) + '&matchType=domain&output=json&collapse=urlkey&fl=timestamp,original,statuscode,mimetype';
      }
    },
    {
      id: 'archive-today',
      label: 'archive.today',
      group: 'Archive',
      supports: ['url'],
      description: 'Newest archive.today capture',
      build: function (value) { return 'https://archive.ph/newest/' + value; }
    },
    {
      id: 'virustotal',
      label: 'VirusTotal',
      group: 'Reputation',
      supports: ['url', 'domain', 'ip', 'sha256', 'email'],
      description: 'Reputation and relations',
      build: function (value) { return 'https://www.virustotal.com/gui/search/' + enc(value); }
    },
    {
      id: 'urlscan',
      label: 'urlscan.io',
      group: 'Reputation',
      supports: ['url', 'domain', 'ip', 'sha256'],
      description: 'Public scan history',
      build: function (value) { return 'https://urlscan.io/search/#' + enc(value); }
    },
    {
      id: 'gsb',
      label: 'Safe Browsing',
      group: 'Reputation',
      supports: ['url'],
      description: 'Google transparency report',
      build: function (value) { return 'https://transparencyreport.google.com/safe-browsing/search?url=' + enc(value); }
    },
    {
      id: 'urlhaus-search',
      label: 'URLhaus search',
      group: 'Reputation',
      supports: ['url', 'domain'],
      description: 'Abuse.ch URLhaus lookup',
      build: function (value) { return 'https://urlhaus.abuse.ch/browse/?search=' + enc(value); }
    },
    {
      id: 'shodan-ip',
      label: 'Shodan host',
      group: 'Infrastructure',
      supports: ['ip'],
      description: 'Open ports and services',
      build: function (value) { return 'https://www.shodan.io/host/' + enc(value); }
    },
    {
      id: 'shodan-domain',
      label: 'Shodan hostname',
      group: 'Infrastructure',
      supports: ['domain'],
      description: 'Search by hostname',
      build: function (value) { return 'https://www.shodan.io/search?query=' + enc('hostname:' + value); }
    },
    {
      id: 'shodan-favicon',
      label: 'Shodan favicon hash',
      group: 'Infrastructure',
      supports: ['mmh3'],
      description: 'Pivot on favicon hash',
      build: function (value) { return 'https://www.shodan.io/search?query=' + enc('http.favicon.hash:' + value); }
    },
    {
      id: 'censys',
      label: 'Censys',
      group: 'Infrastructure',
      supports: ['ip', 'domain'],
      description: 'Host and certificate search',
      build: function (value) { return 'https://search.censys.io/search?resource=hosts&q=' + enc(value); }
    },
    {
      id: 'abuseipdb',
      label: 'AbuseIPDB',
      group: 'Infrastructure',
      supports: ['ip'],
      description: 'IP abuse reports',
      build: function (value) { return 'https://www.abuseipdb.com/check/' + enc(value); }
    },
    {
      id: 'crtsh',
      label: 'crt.sh',
      group: 'Certificates',
      supports: ['domain'],
      description: 'Certificate transparency',
      build: function (value) { return 'https://crt.sh/?q=' + enc('%.' + value); }
    },
    {
      id: 'domaintools',
      label: 'DomainTools WHOIS',
      group: 'Registration',
      supports: ['domain'],
      description: 'WHOIS history',
      build: function (value) { return 'https://whois.domaintools.com/' + enc(value); }
    },
    {
      id: 'icann',
      label: 'ICANN Lookup',
      group: 'Registration',
      supports: ['domain'],
      description: 'Registration data',
      build: function (value) { return 'https://lookup.icann.org/en/lookup?q=' + enc(value); }
    },
    {
      id: 'spyonweb',
      label: 'SpyOnWeb',
      group: 'Clustering',
      supports: ['analytics'],
      description: 'Find sites sharing an ID',
      build: function (value) { return 'https://spyonweb.com/' + enc(value); }
    },
    {
      id: 'publicwww',
      label: 'PublicWWW',
      group: 'Clustering',
      supports: ['analytics'],
      description: 'Source-code search',
      build: function (value) { return 'https://publicwww.com/websites/' + enc('"' + value + '"') + '/'; }
    },
    {
      id: 'google-search',
      label: 'Search the web',
      group: 'Clustering',
      supports: ['analytics', 'email', 'telegram', 'wallet'],
      description: 'Exact-value web search',
      build: function (value) { return 'https://www.google.com/search?q=' + enc('"' + value + '"'); }
    },
    {
      id: 'etherscan',
      label: 'Etherscan',
      group: 'Wallets',
      supports: ['wallet'],
      description: 'Ethereum address',
      build: function (value) { return isEth(value) ? 'https://etherscan.io/address/' + enc(value) : null; }
    },
    {
      id: 'blockchain',
      label: 'Blockchain.com',
      group: 'Wallets',
      supports: ['wallet'],
      description: 'Bitcoin address',
      build: function (value) { return isBtc(value) ? 'https://www.blockchain.com/btc/address/' + enc(value) : null; }
    },
    {
      id: 'telegram',
      label: 'Open Telegram',
      group: 'Contacts',
      supports: ['telegram'],
      description: 'Contact handle',
      build: function (value) { return 'https://t.me/' + enc(String(value).replace(/^@/, '')); }
    },
    {
      id: 'whatsapp',
      label: 'Open WhatsApp',
      group: 'Contacts',
      supports: ['whatsapp'],
      description: 'Contact number',
      build: function (value) { return 'https://wa.me/' + enc(String(value).replace(/[^\d]/g, '')); }
    }
  ];

  function linksFor(type, value, ctx) {
    if (!value) return [];
    const results = [];
    PROVIDERS.forEach(function (provider) {
      if (provider.supports.indexOf(type) === -1) return;
      let url = null;
      try { url = provider.build(String(value), ctx || {}); } catch (error) { url = null; }
      if (!url) return;
      results.push({ provider: provider.id, label: provider.label, group: provider.group, description: provider.description, url: url });
    });
    return results;
  }

  function targetLinks(model) {
    const ctx = {
      model: model,
      firstSeen: (model.getResult('threat_lookup') || {}).wayback_first_seen || ''
    };
    const out = [];
    const add = function (type, value, ids) {
      if (!value) return;
      linksFor(type, value, ctx).forEach(function (link) {
        if (ids && ids.indexOf(link.provider) === -1) return;
        out.push({ type: type, value: value, link: link });
      });
    };
    add('url', model.target, ['wayback-first', 'wayback-calendar', 'virustotal', 'urlscan', 'gsb', 'archive-today']);
    add('domain', model.host, ['wayback-host', 'crtsh', 'icann', 'domaintools']);
    const ip = model.getResult('ip_lookup') || {};
    const firstIp = ((ip.addresses || [])[0] || {}).ip;
    if (firstIp) add('ip', firstIp, ['shodan-ip', 'abuseipdb', 'censys']);
    return out;
  }

  function grouped(links) {
    const groups = new Map();
    links.forEach(function (link) {
      if (!groups.has(link.group)) groups.set(link.group, []);
      groups.get(link.group).push(link);
    });
    return groups;
  }

  function anchor(link, options) {
    const opts = options || {};
    const node = D.el('a', {
      class: 'integration-link' + (opts.primary ? ' primary' : ''),
      href: link.url,
      target: '_blank',
      rel: 'noopener noreferrer',
      title: link.description || link.label
    }, D.icon(opts.icon || 'external'), link.label);
    return node;
  }

  function renderStrip(type, value, ctx, options) {
    const opts = options || {};
    const links = linksFor(type, value, ctx);
    const filtered = opts.ids ? links.filter(function (link) { return opts.ids.indexOf(link.provider) !== -1; }) : links;
    const strip = D.el('div', { class: 'integration-strip' });
    const limited = opts.limit ? filtered.slice(0, opts.limit) : filtered;
    limited.forEach(function (link, index) {
      strip.appendChild(anchor(link, { primary: index === 0 }));
    });
    if (filtered.length > limited.length) {
      strip.appendChild(D.el('button', {
        class: 'integration-link',
        type: 'button',
        onClick: function () { openPivot(type, value, ctx); }
      }, D.icon('more'), 'More'));
    }
    if (!strip.childNodes.length) {
      strip.appendChild(D.el('span', { class: 'muted small', text: 'No integrations available.' }));
    }
    return strip;
  }

  function openPivot(type, value, ctx) {
    const links = linksFor(type, value, ctx);
    const body = D.el('div');
    body.appendChild(D.el('p', { class: 'small muted', text: 'Pivot on this value with external services. No data is sent until you open a link.' }));
    body.appendChild(D.el('div', { class: 'modal-url' }, D.el('bdi', { text: ctx && ctx.model && C.state.prefs.defang ? C.format.defang(value, type) : value })));
    const groups = grouped(links);
    if (!groups.size) {
      body.appendChild(D.el('div', { class: 'inline-empty mt-14', text: 'No integration providers support this value type.' }));
    }
    groups.forEach(function (groupLinks, groupName) {
      const group = D.el('div', { class: 'modal-list-group' });
      group.appendChild(D.el('h3', { text: groupName }));
      const list = D.el('div', { class: 'modal-list' });
      groupLinks.forEach(function (link) {
        const node = D.el('a', {
          class: 'pivot-link',
          href: link.url,
          target: '_blank',
          rel: 'noopener noreferrer'
        }, D.icon('external'), D.el('span', { text: link.label }), D.el('span', { class: 'pivot-desc', text: link.description || '' }));
        list.appendChild(node);
      });
      group.appendChild(list);
      body.appendChild(group);
    });
    D.modal({
      title: 'Pivot on value',
      icon: 'crosshair',
      wide: true,
      body: body,
      actions: [
        {
          label: 'Copy value',
          variant: 'btn-ghost',
          icon: 'copy',
          close: false,
          onClick: function () { D.copyText(value, 'value'); }
        },
        { label: 'Close', variant: 'btn-ghost' }
      ]
    });
  }

  function pivotButton(type, value, ctx, label) {
    return D.el('button', {
      class: 'btn btn-ghost btn-sm pivot-btn',
      type: 'button',
      title: 'Pivot on this value',
      onClick: function () { openPivot(type, value, ctx); }
    }, D.icon('crosshair'), label == null ? 'Pivot' : label);
  }

  C.integrations = {
    PROVIDERS: PROVIDERS,
    linksFor: linksFor,
    targetLinks: targetLinks,
    renderStrip: renderStrip,
    openPivot: openPivot,
    pivotButton: pivotButton,
    anchor: anchor
  };
})();
