(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function openEvidence(model, ref) {
    C.state.evidenceFocus = ref || '';
    C.router.go(model.id, 'evidence');
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
    return UI.statGrid([
      UI.stat('Pages', pages.length, pages.length ? (asArray(html.links).length + ' extracted links') : 'No pages reported', { icon: 'file-text' }),
      UI.stat('Forms', asArray(forms.forms).length, (forms.cross_origin_forms || 0) + ' cross-origin · ' + (forms.password_forms || 0) + ' password', { icon: 'send' }),
      UI.stat('Cloaking', cloaking ? UI.badge(cloaking.differs ? 'Differs' : 'Consistent', cloaking.differs ? 'critical' : 'ok', cloaking.differs ? 'eye' : 'check') : '—', cloaking ? asArray(cloaking.reasons).join(' · ') || 'Profiles compared' : 'No probe data', { icon: 'eye' }),
      UI.stat('Security headers', missing + ' missing', weak + ' weak · ' + checks.length + ' checked', { icon: 'shield' })
    ]);
  }

  function pagesSection(model) {
    const html = model.getResult('html_scan');
    if (!html) {
      return UI.section('Pages', 'website-pages', UI.card('Website scan', UI.notRun('The website scan'), { icon: 'globe' }), { icon: 'globe' });
    }
    const pages = asArray(html.pages);
    const evidence = model.evidence && model.evidence.length ? model.evidence : C.evidence.resolveAll(model);
    const evidenceByRef = new Map();
    evidence.forEach(function (item) {
      evidenceByRef.set(item.ref, item);
    });

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
      },
      {
        key: 'evidence', label: 'Evidence', width: '110px', sortable: false,
        render: function (page) {
          if (!page.evidence_file) return D.el('span', { class: 'muted tiny', text: 'Not saved' });
          const item = evidenceByRef.get(page.evidence_file);
          const button = D.el('button', {
            class: 'btn btn-ghost btn-sm',
            type: 'button',
            title: item && item.record ? 'Open saved page evidence' : 'Evidence file is missing',
            onClick: function () { openEvidence(model, page.evidence_file); }
          }, D.icon('archive'), item && item.record ? 'Open' : 'Missing');
          return button;
        }
      }
    ], pages, {
      pageSize: 20,
      rowLabel: 'pages',
      filterPlaceholder: 'Filter pages…',
      empty: 'No pages were recorded.'
    });

    const content = [UI.card('Crawled pages', table, { flush: true, icon: 'globe', subtitle: html.start_url || '' })];
    const links = C.format.unique(asArray(html.links).concat.apply(asArray(html.links), pages.map(function (page) { return asArray(page.links); })));
    if (links.length) {
      content.push(UI.collapsible('All extracted links (' + links.length + ')', UI.chipList(links, {
        type: 'url',
        pivot: true,
        ctx: { model: model },
        empty: 'No links extracted.'
      })));
    }
    if (model.evidenceErrors && model.evidenceErrors.length) {
      content.push(UI.notice('warning', 'archive', 'Some evidence files are missing',
        model.evidenceErrors.join(' · ')));
    }
    return UI.section('Pages', 'website-pages', content, {
      icon: 'globe',
      count: pages.length
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
      D.el('div', { class: 'stack' }, header, UI.card('Response comparison', table, { flush: true, icon: 'eye' }))
    ], {
      icon: 'eye'
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
      content.push(UI.card('Forms', UI.emptyInline('No forms found on the scanned pages.'), { icon: 'send' }));
    } else {
      const table = UI.dataTable([
        { key: 'action', label: 'Action', render: function (row) { return UI.urlValue(row.action, { open: true, source: 'Form action', pivot: true, ctx: { model: model } }); }, value: function (row) { return row.action || ''; } },
        { key: 'method', label: 'Method', width: '80px', render: function (row) { return D.el('span', { class: 'mono tiny', text: String(row.method || '').toUpperCase() }); }, value: function (row) { return row.method || ''; } },
        { key: 'cross_origin', label: 'Origin', width: '100px', render: function (row) { return row.cross_origin ? UI.badge('Cross-origin', 'critical', 'alert-triangle') : UI.badge('Same origin', 'ok', 'check'); }, value: function (row) { return row.cross_origin ? '1' : '0'; } },
        { key: 'password_fields', label: 'Password fields', width: '90px', align: 'right', value: function (row) { return Number(row.password_fields) || 0; } },
        { key: 'hidden_fields', label: 'Hidden fields', width: '90px', align: 'right', value: function (row) { return Number(row.hidden_fields) || 0; } }
      ], entries, { pageSize: 20, rowLabel: 'forms', filterPlaceholder: 'Filter forms…' });
      content.push(UI.card('Detected forms', table, { flush: true, icon: 'send' }));
    }
    if (forms.meta_refresh) {
      content.push(UI.notice('info', 'refresh', 'Meta refresh redirect', 'At least one scanned page uses a meta refresh redirect.'));
    }
    return UI.section('Forms', 'website-forms', content, {
      icon: 'send',
      count: entries.length
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
      UI.card('Tracking, contact, and payment identifiers', D.el('div', { class: 'stack' }, groups), { icon: 'hash' })
    ], {
      icon: 'hash'
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
      asArray(wp.evidence).length ? UI.kvRow('Evidence', UI.chipList(wp.evidence, { type: 'text' })) : null
    ]);
    const content = [UI.card('WordPress fingerprints', D.el('div', { class: 'stack' }, flags, facts), { icon: 'globe' })];
    const endpoints = asArray(wp.endpoints);
    if (endpoints.length) {
      const table = UI.dataTable([
        { key: 'path', label: 'Path', render: function (row) { return D.el('span', { class: 'mono', text: row.path }); }, value: function (row) { return row.path || ''; } },
        { key: 'status', label: 'Status', width: '80px', render: function (row) { return UI.httpStatusBadge(row.status); }, value: function (row) { return Number(row.status) || 0; } }
      ], endpoints, { pageSize: 20, rowLabel: 'endpoints', filterPlaceholder: 'Filter endpoints…' });
      content.push(UI.card('Endpoints', table, { flush: true, icon: 'list' }));
    }
    return UI.section('WordPress', 'website-wordpress', content, {
      icon: 'globe'
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
    ]), { icon: 'file-text' }));
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
      count: sitemaps.length
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
    content.push(UI.card('Response', facts, { icon: 'server' }));

    if (asArray(headers.redirects).length) {
      content.push(UI.card('Redirect chain', UI.redirectChain(headers.redirects), { icon: 'git-branch' }));
    }
    if (asArray(headers.checks).length) {
  content.push(UI.card('Security headers', UI.checkRows(headers.checks), {
    icon: 'shield'
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
      content.push(UI.card('CORS', corsFacts, { icon: 'link' }));
    }

    if (asArray(headers.cookies).length) {
      content.push(UI.card('Cookies', UI.cookieTable(headers.cookies), { flush: true, icon: 'key' }));
    }

  return UI.section('HTTP headers', 'website-headers', content, {
    icon: 'server'
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
