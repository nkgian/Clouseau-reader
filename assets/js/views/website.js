(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function errorBanner(model) {
    const errors = model.errors.filter(function (entry) {
      return entry.task === 'html_scan' || entry.task === 'robots_scan' || entry.task === 'headers_scan';
    });
    if (!errors.length) return null;
    return UI.card('Module errors', UI.errorList(errors, {
      onOpen: function (entry) { C.router.go(model.id, 'raw'); }
    }), { icon: 'alert-triangle' });
  }

  function stats(model) {
    const html = model.getResult('html_scan') || {};
    const pages = asArray(html.pages);
    const forms = html.forms || {};
    const checks = asArray((model.getResult('headers_scan') || {}).checks);
    const missing = checks.filter(function (check) { return check.status === 'missing'; }).length;
    const weak = checks.filter(function (check) { return check.status === 'weak'; }).length;
    const cloaking = html.cloaking || null;
    const links = extractedLinks(html);
    return UI.statGrid([
      UI.stat('Pages', pages.length, pages.length ? (C.format.formatNumber(links.length) + ' extracted links') : 'No pages reported', { icon: 'file-text' }),
      UI.stat('Forms', asArray(forms.forms).length, (forms.cross_origin_forms || 0) + ' cross-origin · ' + (forms.password_forms || 0) + ' password', { icon: 'send' }),
      UI.stat('Cloaking', cloaking ? UI.badge(cloaking.differs ? 'Differs' : 'Consistent', cloaking.differs ? 'critical' : 'ok', cloaking.differs ? 'eye' : 'check') : '—', cloaking ? asArray(cloaking.reasons).join(' · ') || 'Profiles compared' : 'No probe data', { icon: 'eye' }),
      UI.stat('Security headers', missing + ' missing', weak + ' weak · ' + checks.length + ' checked', { icon: 'shield' })
    ]);
  }

  function normalizedHost(host) {
    return String(host || '').toLowerCase().replace(/\.$/, '');
  }

  function isIpLiteral(host) {
    return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || /^\[[0-9a-f:.]+\]$/i.test(host);
  }

  function isPunycodeHost(host) {
    return String(host || '').split('.').some(function (label) { return label.indexOf('xn--') === 0; });
  }

  function extractedLinks(html) {
    const allLinks = asArray(html.links).slice();
    asArray(html.pages).forEach(function (page) {
      allLinks.push.apply(allLinks, asArray(page.links));
    });
    return C.format.unique(allLinks);
  }

  function destinationData(links, base) {
    let baseUrl = null;
    try {
      baseUrl = new URL(base);
    } catch (error) {
      baseUrl = null;
    }
    const baseHost = baseUrl ? normalizedHost(baseUrl.hostname) : '';
    return links.map(function (value) {
      let url = null;
      try {
        url = baseUrl ? new URL(value, baseUrl) : new URL(value);
      } catch (error) {
        url = null;
      }
      const web = Boolean(url && (url.protocol === 'http:' || url.protocol === 'https:') && url.hostname);
      const host = web ? normalizedHost(url.hostname) : '';
      const internal = Boolean(host && baseHost &&
        (host === baseHost || host === 'www.' + baseHost || baseHost === 'www.' + host));
      return {
        value: value,
        host: host,
        internal: internal,
        ip: Boolean(host && isIpLiteral(host)),
        punycode: Boolean(host && isPunycodeHost(host))
      };
    });
  }

  function linkMetric(value, label, title) {
    return D.el('div', { class: 'link-metric', title: title || null },
      D.el('strong', { text: C.format.formatNumber(value) }),
      D.el('span', { text: label })
    );
  }

  function linkDestinationsCard(model, links, html) {
    const data = destinationData(links, html.start_url || model.target);
    const hostCounts = new Map();
    const internalHosts = new Set();
    data.forEach(function (entry) {
      if (!entry.host) return;
      hostCounts.set(entry.host, (hostCounts.get(entry.host) || 0) + 1);
      if (entry.internal) internalHosts.add(entry.host);
    });

    const hosts = Array.from(hostCounts.keys()).sort(function (a, b) {
      const difference = hostCounts.get(b) - hostCounts.get(a);
      return difference || a.localeCompare(b);
    });
    const topHosts = hosts.slice(0, 8);
    const topHostSet = new Set(topHosts);
    const rows = topHosts.map(function (host) {
      return {
        key: 'host:' + host,
        host: host,
        label: host,
        count: hostCounts.get(host),
        internal: internalHosts.has(host),
        ip: isIpLiteral(host),
        punycode: isPunycodeHost(host)
      };
    });
    const shownCount = rows.reduce(function (total, row) { return total + row.count; }, 0);
    if (data.length > shownCount) {
      rows.push({
        key: 'other',
        host: '',
        label: 'Other destinations',
        count: data.length - shownCount,
        other: true
      });
    }

    const externalHosts = hosts.filter(function (host) { return !internalHosts.has(host); }).length;
    const ipLinks = data.filter(function (entry) { return entry.ip; }).length;
    const punycodeLinks = data.filter(function (entry) { return entry.punycode; }).length;
    const metrics = D.el('div', { class: 'link-metrics' },
      linkMetric(data.length, 'unique links', 'Unique URLs extracted from crawled pages.'),
      linkMetric(externalHosts, 'external hosts', 'Distinct hosts outside the scanned site.'),
      linkMetric(ipLinks, 'IP-literal URLs', 'Unique URLs whose hostname is an IP address.'),
      linkMetric(punycodeLinks, 'punycode URLs', 'Unique URLs whose hostname contains a punycode label.')
    );

    const legend = D.el('div', { class: 'link-legend' },
      D.el('span', { class: 'link-legend-item' }, D.el('i', { class: 'link-swatch internal' }), 'Internal'),
      D.el('span', { class: 'link-legend-item' }, D.el('i', { class: 'link-swatch external' }), 'External'),
      D.el('span', { class: 'link-legend-item' }, D.el('i', { class: 'link-swatch other' }), 'Other')
    );

    let selectedKey = null;
    const barNodes = new Map();
    const chart = D.el('div', { class: 'link-chart', role: 'group', 'aria-label': 'Link destinations by host' });
    const maxCount = rows.reduce(function (maximum, row) { return Math.max(maximum, row.count); }, 0);

    const listDetails = D.el('details', { class: 'collapse link-list' });
    const listSummary = D.el('summary');
    const listBody = D.el('div', { class: 'collapse-body' });
    listDetails.appendChild(listSummary);
    listDetails.appendChild(listBody);

    const filterStatus = D.el('div', { class: 'link-filter-status' });
    const filterText = D.el('span', { 'aria-live': 'polite' });
    const clearButton = D.el('button', {
      class: 'link-clear',
      type: 'button',
      hidden: true,
      onClick: function () {
        selectedKey = null;
        draw();
      }
    }, 'Clear filter');
    filterStatus.appendChild(filterText);
    filterStatus.appendChild(clearButton);

    function selectedRow() {
      return rows.find(function (row) { return row.key === selectedKey; }) || null;
    }

    function filteredData() {
      const selected = selectedRow();
      if (!selected) return data;
      if (selected.other) {
        return data.filter(function (entry) { return !entry.host || !topHostSet.has(entry.host); });
      }
      return data.filter(function (entry) { return entry.host === selected.host; });
    }

    function draw() {
      const selected = selectedRow();
      barNodes.forEach(function (node, key) {
        const active = key === selectedKey;
        node.classList.toggle('active', active);
        node.setAttribute('aria-pressed', active ? 'true' : 'false');
      });

      const filtered = filteredData();
      D.clear(listBody);
      listBody.appendChild(UI.chipList(filtered.map(function (entry) { return entry.value; }), {
        type: 'url',
        pivot: true,
        ctx: { model: model },
        empty: 'No links match this destination.'
      }));

      if (!selected) {
        listSummary.textContent = 'All extracted links (' + data.length + ')';
        filterText.textContent = 'Click a destination bar to filter the URL list.';
        clearButton.hidden = true;
        return;
      }

      const label = selected.other
        ? 'other destinations'
        : (C.ui ? C.ui.displayValue(selected.host, 'domain') : selected.host);
      listSummary.textContent = (selected.other ? 'Other destination links' : 'Links to ' + label) +
        ' (' + filtered.length + ' of ' + data.length + ')';
      filterText.textContent = 'Showing ' + C.format.formatNumber(filtered.length) + ' of ' +
        C.format.formatNumber(data.length) + ' links ' +
        (selected.other ? 'in other destinations' : 'to ' + label);
      clearButton.hidden = false;
      listDetails.open = true;
    }

    rows.forEach(function (row) {
      const label = row.other
        ? row.label
        : (C.ui ? C.ui.displayValue(row.host, 'domain') : row.host);
      const button = D.el('button', {
        class: 'link-bar-row ' + (row.other ? 'other' : (row.internal ? 'internal' : 'external')),
        type: 'button',
        'aria-pressed': 'false',
        dataset: { key: row.key, host: row.host },
        title: label + ': ' + row.count + ' ' + C.format.plural(row.count, 'link'),
        onClick: function () {
          selectedKey = selectedKey === row.key ? null : row.key;
          draw();
        }
      });
      button.setAttribute('aria-label', 'Filter links to ' + label + ' (' + row.count + ')');
      const text = D.el('span', { class: 'link-bar-label' }, D.el('bdi', { text: label }));
      if (row.ip) text.appendChild(D.el('span', { class: 'link-flag', text: 'IP' }));
      if (row.punycode) text.appendChild(D.el('span', { class: 'link-flag', text: 'punycode' }));
      button.appendChild(text);
      button.appendChild(D.el('span', { class: 'link-bar-count', text: C.format.formatNumber(row.count) }));
      const track = D.el('span', { class: 'link-bar-track', 'aria-hidden': 'true' });
      const width = maxCount ? Math.max(3, Math.round((row.count / maxCount) * 100)) : 0;
      track.appendChild(D.el('span', { class: 'link-bar-fill', style: { width: width + '%' } }));
      button.appendChild(track);
      barNodes.set(row.key, button);
      chart.appendChild(button);
    });

    draw();

    const body = D.el('div', { class: 'stack link-destinations' },
      metrics,
      D.el('div', { class: 'link-chart-head' },
        D.el('div', { class: 'link-chart-title', text: 'Destinations by host' }),
        legend
      ),
      chart,
      filterStatus,
      listDetails
    );

    return UI.card('Link destinations', body, {
      icon: 'link',
      subtitle: 'Unique hosts linked from crawled pages. Click a bar to filter the URL list.'
    });
  }

  function pagesSection(model) {
    const html = model.getResult('html_scan');
    if (!html) {
      return UI.section('Pages', 'website-pages', UI.card('Website scan', UI.notRun('The website scan'), {
        icon: 'globe',
        subtitle: 'Crawled pages, titles, and response metadata.'
      }), {
        icon: 'globe',
        subtitle: 'Crawled pages and response details for each URL.'
      });
    }
    const pages = asArray(html.pages);

    const table = UI.dataTable([
      {
        key: 'url', label: 'URL', width: '38%',
        render: function (page) { return UI.urlValue(page.url, { open: true, source: 'Scanned page' }); },
        value: function (page) { return page.url; }
      },
      {
        key: 'status', label: 'Status', width: '70px',
        render: function (page) { return UI.httpStatusBadge(page.status); },
        value: function (page) { return Number(page.status) || 0; }
      },
      {
        key: 'title', label: 'Title', width: '18%',
        render: function (page) { return page.title || D.el('span', { class: 'muted', text: '—' }); },
        value: function (page) { return page.title || ''; }
      },
      {
        key: 'bytes', label: 'Size', width: '80px', align: 'right',
        render: function (page) { return page.bytes ? C.dom.formatBytes(page.bytes) : '—'; },
        value: function (page) { return Number(page.bytes) || 0; }
      },
      {
        key: 'links', label: 'Links', width: '60px', align: 'right',
        render: function (page) { return asArray(page.links).length; },
        value: function (page) { return asArray(page.links).length; }
      }
    ], pages, {
      pageSize: 20,
      rowLabel: 'pages',
      filterPlaceholder: 'Filter pages…',
      empty: 'No pages were recorded.'
    });

    const content = [UI.card('Crawled pages', table, {
      flush: true,
      icon: 'globe',
      subtitle: html.start_url ? 'Start URL: ' + html.start_url : 'Pages returned by the scanner.'
    })];
    const links = extractedLinks(html);
    if (links.length) content.push(linkDestinationsCard(model, links, html));
    return UI.section('Pages', 'website-pages', content, {
      icon: 'globe',
      count: pages.length,
      subtitle: 'Responses recorded during the crawl, including status, size, and extracted links.'
    });
  }

  function cloakingSection(model) {
    const html = model.getResult('html_scan');
    if (!html) return null;
    const cloaking = html.cloaking;
    if (!cloaking) return null;
    const probes = asArray(cloaking.probes);
    const header = D.el('div', { class: 'status-line' },
      UI.badge(cloaking.differs ? 'Cloaking detected' : 'No differences', cloaking.differs ? 'critical' : 'ok', cloaking.differs ? 'eye' : 'check'),
      cloaking.reasons && asArray(cloaking.reasons).length
        ? D.el('span', { class: 'small muted', text: asArray(cloaking.reasons).join(' · ') })
        : null
    );
    const table = UI.dataTable([
      { key: 'profile', label: 'Profile', render: function (row) { return D.el('span', { class: 'mono', text: row.profile }); } },
      { key: 'status', label: 'Status', width: '80px', render: function (row) { return UI.httpStatusBadge(row.status); } },
      { key: 'title', label: 'Title', render: function (row) { return row.title || D.el('span', { class: 'muted', text: '—' }); }, value: function (row) { return row.title || ''; } },
      { key: 'bytes', label: 'Size', width: '80px', align: 'right', render: function (row) { return row.bytes ? C.dom.formatBytes(row.bytes) : '—'; }, value: function (row) { return Number(row.bytes) || 0; } },
      { key: 'final_url', label: 'Final URL', render: function (row) { return row.final_url ? UI.urlValue(row.final_url, { open: true, source: 'Cloaking probe' }) : '—'; }, value: function (row) { return row.final_url || ''; } },
      { key: 'sha256', label: 'SHA-256', width: '110px', render: function (row) { return row.sha256 ? UI.hashValue(row.sha256, 'body hash') : '—'; }, value: function (row) { return row.sha256 || ''; } },
      { key: 'error', label: 'Error', render: function (row) { return row.error ? D.el('span', { class: 'warn-link tiny', text: row.error }) : D.el('span', { class: 'muted', text: '—' }); }, value: function (row) { return row.error || ''; } }
    ], probes, { pageSize: 20, rowLabel: 'profiles', filterPlaceholder: 'Filter profiles…', sortable: false });
    return UI.section('Cloaking', 'website-cloaking', [
      D.el('div', { class: 'stack' }, header, UI.card('Response comparison', table, {
        flush: true,
        icon: 'eye',
        subtitle: 'Status, title, size, final URL, and body hash for each probe profile.'
      }))
    ], {
      icon: 'eye',
      subtitle: 'Compares what a browser and a plain HTTP client receive, looking for content served selectively.'
    });
  }

  function formsSection(model) {
    const html = model.getResult('html_scan');
    if (!html) return null;
    const forms = html.forms || {};
    const entries = asArray(forms.forms);
    const content = [];
    const summary = D.el('div', { class: 'status-line' },
      UI.badge((forms.cross_origin_forms || 0) + ' cross-origin', forms.cross_origin_forms ? 'critical' : 'ok', 'send'),
      UI.badge((forms.password_forms || 0) + ' password', forms.password_forms ? 'warning' : 'ok', 'lock'),
      forms.meta_refresh ? UI.badge('Meta refresh', 'info', 'refresh') : null
    );
    content.push(summary);
    if (!entries.length) {
      content.push(UI.card('Forms', UI.emptyInline('No forms found on the scanned pages.'), {
        icon: 'send',
        subtitle: 'Submission targets and field counts for each form found on the crawled pages.'
      }));
    } else {
      const table = UI.dataTable([
        { key: 'action', label: 'Action', render: function (row) { return UI.urlValue(row.action, { open: true, source: 'Form action', pivot: true, ctx: { model: model } }); }, value: function (row) { return row.action || ''; } },
        { key: 'method', label: 'Method', width: '80px', render: function (row) { return D.el('span', { class: 'mono tiny', text: String(row.method || '').toUpperCase() }); }, value: function (row) { return row.method || ''; } },
        { key: 'cross_origin', label: 'Origin', width: '100px', render: function (row) { return row.cross_origin ? UI.badge('Cross-origin', 'critical', 'alert-triangle') : UI.badge('Same origin', 'ok', 'check'); }, value: function (row) { return row.cross_origin ? '1' : '0'; } },
        { key: 'password_fields', label: 'Passwords', width: '90px', align: 'right', value: function (row) { return Number(row.password_fields) || 0; } },
        { key: 'hidden_fields', label: 'Hidden', width: '90px', align: 'right', value: function (row) { return Number(row.hidden_fields) || 0; } }
      ], entries, { pageSize: 20, rowLabel: 'forms', filterPlaceholder: 'Filter forms…', wide: false });
      content.push(UI.card('Detected forms', table, {
        flush: true,
        icon: 'send',
        subtitle: 'Submission targets and field counts for each form found on the crawled pages.'
      }));
    }
    if (forms.meta_refresh) {
      content.push(UI.notice('info', 'refresh', 'Meta refresh redirect', 'At least one scanned page uses a meta refresh redirect.'));
    }
    return UI.section('Forms', 'website-forms', content, {
      icon: 'send',
      count: entries.length,
      subtitle: 'Forms found on crawled pages, where they submit, and whether they use cross-origin targets or password fields.'
    });
  }

  function identifierGroup(label, values, type, icon, ctx) {
    const list = asArray(values).filter(Boolean);
    if (!list.length) return null;
    return UI.detailBlock(label, UI.chipList(list, {
      type: type,
      pivot: true,
      ctx: ctx,
      empty: 'None found.'
    }), icon);
  }

  function identifiersSection(model) {
    const html = model.getResult('html_scan');
    if (!html) return null;
    const ids = html.identifiers || {};
    const groups = [
      identifierGroup('Analytics & ad IDs', ids.analytics, 'analytics', 'activity', { model: model }),
      identifierGroup('Telegram', ids.telegram, 'telegram', 'send', { model: model }),
      identifierGroup('WhatsApp', ids.whatsapp, 'whatsapp', 'phone', { model: model }),
      identifierGroup('Wallets', ids.wallets, 'wallet', 'wallet', { model: model }),
      identifierGroup('Email addresses', ids.emails, 'email', 'mail', { model: model })
    ].filter(Boolean);
    if (!groups.length) return null;
    return UI.section('Identifiers', 'website-identifiers', [
      UI.card('Tracking, contact, and payment identifiers', D.el('div', { class: 'stack' }, groups), {
        icon: 'hash',
        subtitle: 'Identifiers extracted from page content and grouped by type.'
      })
    ], {
      icon: 'hash',
      subtitle: 'Analytics IDs, messaging handles, wallets, and email addresses found on the site.'
    });
  }

  function wordpressSection(model) {
    const html = model.getResult('html_scan');
    if (!html) return null;
    const wp = html.wordpress;
    if (!wp || !Object.keys(wp).length) return null;
    const flags = D.el('div', { class: 'status-line' },
      UI.badge(wp.login ? 'Login exposed' : 'No login', wp.login ? 'warning' : 'muted', 'lock'),
      UI.badge(wp.rest ? 'REST API' : 'No REST', wp.rest ? 'info' : 'muted', 'code'),
      UI.badge(wp.xmlrpc ? 'XML-RPC' : 'No XML-RPC', wp.xmlrpc ? 'warning' : 'muted', 'server'),
      UI.badge(wp.sitemap ? 'Sitemap' : 'No sitemap', wp.sitemap ? 'ok' : 'muted', 'map-pin')
    );
    const facts = UI.kvList([
      wp.version ? UI.kvRow('Version', wp.version + (wp.version_source ? ' · ' + wp.version_source : '')) : null,
      wp.site_name ? UI.kvRow('Site name', wp.site_name) : null,
      asArray(wp.rest_namespaces).length ? UI.kvRow('REST namespaces', UI.chipList(wp.rest_namespaces, { type: 'text' })) : null,
      asArray(wp.themes).length ? UI.kvRow('Themes', UI.chipList(wp.themes, { type: 'text' })) : null,
      asArray(wp.plugins).length ? UI.kvRow('Plugins', UI.chipList(wp.plugins, { type: 'text' })) : null,
      asArray(wp.users).length ? UI.kvRow('Users', UI.chipList(wp.users.map(function (user) {
        return typeof user === 'string' ? user : (user.name || user.slug || user.id);
      }).filter(Boolean), { type: 'username', label: 'username' })) : null,
      asArray(wp.authors).length ? UI.kvRow('Authors', UI.chipList(wp.authors, { type: 'username', label: 'username' })) : null,
      asArray(wp.evidence).length ? UI.kvRow('Fingerprints', UI.chipList(wp.evidence, { type: 'text' })) : null
    ]);
    const content = [UI.card('WordPress fingerprints', D.el('div', { class: 'stack' }, flags, facts), {
      icon: 'globe',
      subtitle: 'Detected features, version clues, users, plugins, and exposed endpoints.'
    })];
    const endpoints = asArray(wp.endpoints);
    if (endpoints.length) {
      const table = UI.dataTable([
        { key: 'path', label: 'Path', render: function (row) { return D.el('span', { class: 'mono', text: row.path }); }, value: function (row) { return row.path || ''; } },
        { key: 'status', label: 'Status', width: '80px', render: function (row) { return UI.httpStatusBadge(row.status); }, value: function (row) { return Number(row.status) || 0; } }
      ], endpoints, { pageSize: 20, rowLabel: 'endpoints', filterPlaceholder: 'Filter endpoints…' });
      content.push(UI.card('Endpoints', table, { flush: true, icon: 'list' }));
    }
    return UI.section('WordPress', 'website-wordpress', content, {
      icon: 'globe',
      subtitle: 'WordPress version, plugins, users, and common endpoints inferred from page markup and probe paths.'
    });
  }

  function robotsSection(model) {
    const robots = model.getResult('robots_scan');
    if (!robots) return null;
    const groups = asArray(robots.groups);
    const groupNodes = groups.map(function (group) {
      const rows = [
        UI.kvRow('User agents', asArray(group.user_agents).join(', ') || '*'),
        asArray(group.allow).length ? UI.kvRow('Allow', UI.chipList(group.allow, { type: 'text' })) : null,
        asArray(group.disallow).length ? UI.kvRow('Disallow', UI.chipList(group.disallow, { type: 'text' })) : null,
        group.crawl_delay ? UI.kvRow('Crawl delay', String(group.crawl_delay) + 's') : null
      ];
      return UI.card('Robots group', UI.kvList(rows), { icon: 'file-text' });
    });
    const content = [];
    content.push(UI.card('robots.txt', UI.kvList([
      UI.kvRow('URL', UI.urlValue(robots.url, { open: true, source: 'robots.txt' })),
      UI.kvRow('Status', UI.httpStatusBadge(robots.status)),
      UI.kvRow('Sitemap URLs', String(robots.total_urls || 0)),
      asArray(robots.sensitive).length ? UI.kvRow('Sensitive paths', UI.chipList(robots.sensitive, { type: 'text' })) : null
    ]), {
      icon: 'file-text',
      subtitle: 'Crawler directives and exposed paths advertised by the site.'
    }));
    const sitemaps = asArray(robots.sitemap_files);
    if (sitemaps.length) {
      const table = UI.dataTable([
        { key: 'url', label: 'Sitemap', render: function (row) { return UI.urlValue(row.url, { open: true, source: 'Sitemap' }); }, value: function (row) { return row.url || ''; } },
        { key: 'status', label: 'Status', width: '80px', render: function (row) { return UI.httpStatusBadge(row.status); }, value: function (row) { return Number(row.status) || 0; } },
        { key: 'urls', label: 'URLs', width: '70px', align: 'right', value: function (row) { return Number(row.urls) || 0; } },
        { key: 'error', label: 'Error', render: function (row) { return row.error ? D.el('span', { class: 'warn-link tiny', text: row.error }) : D.el('span', { class: 'muted', text: '—' }); }, value: function (row) { return row.error || ''; } }
      ], sitemaps, { pageSize: 20, rowLabel: 'sitemaps', filterPlaceholder: 'Filter sitemaps…' });
      content.push(UI.card('Sitemap files', table, { flush: true, icon: 'map-pin' }));
    }
    if (groups.length) content.push(D.el('div', { class: 'card-grid' }, groupNodes));
    return UI.section('Robots & sitemaps', 'website-robots', content, {
      icon: 'file-text',
      count: sitemaps.length,
      subtitle: 'Crawler rules and sitemap locations advertised by the site.'
    });
  }

  function headersSection(model) {
    const headers = model.getResult('headers_scan');
    if (!headers) return null;
    const content = [];
    const facts = UI.kvList([
      UI.kvRow('URL', UI.urlValue(headers.url, { open: true, source: 'Headers scan' })),
      UI.kvRow('Status', UI.httpStatusBadge(headers.status)),
      headers.server ? UI.kvRow('Server', headers.server) : null,
      headers.powered_by ? UI.kvRow('Powered by', headers.powered_by) : null
    ]);
    content.push(UI.card('Response', facts, {
      icon: 'server',
      subtitle: 'Final URL and basic server information from the header scan.'
    }));

    if (asArray(headers.redirects).length) {
      content.push(UI.card('Redirect chain', UI.redirectChain(headers.redirects), {
        icon: 'git-branch',
        subtitle: 'Each hop from the requested URL to the final response.'
      }));
    }
    if (asArray(headers.checks).length) {
      content.push(UI.card('Security headers', UI.checkRows(headers.checks), {
        icon: 'shield',
        subtitle: 'Browser hardening headers and whether each is missing, weak, or present.'
      }));
    }

    const cors = headers.cors;
    if (cors) {
      const reflected = Boolean(cors.reflects_origin);
      const status = reflected
        ? UI.badge(cors.allow_credentials ? 'Reflected with credentials' : 'Reflected', cors.allow_credentials ? 'critical' : 'warning', 'alert-triangle')
        : UI.badge('No reflection', 'ok', 'check');
      const corsFacts = UI.kvList([
        UI.kvRow('Status', status),
        cors.probe_origin ? UI.kvRow('Probe origin', cors.probe_origin) : null,
        cors.allow_origin ? UI.kvRow('Allow-Origin', cors.allow_origin) : null,
        UI.kvRow('Credentials', cors.allow_credentials ? 'Allowed' : 'Not allowed')
      ]);
      content.push(UI.card('CORS', corsFacts, {
        icon: 'link',
        subtitle: 'Controls which origins may read responses in a browser. A reflected origin with credentials can expose authenticated data.'
      }));
    }

    if (asArray(headers.cookies).length) {
      content.push(UI.card('Cookies', UI.cookieTable(headers.cookies), {
        flush: true,
        icon: 'key',
        subtitle: 'Cookie names and attributes that affect browser exposure and cross-site behavior.'
      }));
    }

    return UI.section('HTTP headers', 'website-headers', content, {
      icon: 'server',
      subtitle: 'Response headers, redirects, cookie flags, security-header checks, and CORS behavior.'
    });
  }

  C.views = C.views || {};
  C.views.website = function (model) {
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

    const pages = pagesSection(model);
    add(pages, 'website-pages', 'Pages', asArray((model.getResult('html_scan') || {}).pages).length);
    add(cloakingSection(model), 'website-cloaking', 'Cloaking');
    add(formsSection(model), 'website-forms', 'Forms');
    add(identifiersSection(model), 'website-identifiers', 'Identifiers');
    add(wordpressSection(model), 'website-wordpress', 'WordPress');
    add(robotsSection(model), 'website-robots', 'Robots');
    add(headersSection(model), 'website-headers', 'Headers');

    if (nav.length > 2) {
      const sectionNav = UI.sectionNav(nav);
      if (sectionNav) view.appendChild(sectionNav);
    }
    sections.forEach(function (section) { view.appendChild(section); });
    if (!sections.length) {
      view.appendChild(UI.card('No website data', UI.notRun('The website modules'), { icon: 'globe' }));
    }
    return view;
  };
})();
