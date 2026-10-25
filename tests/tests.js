(function () {
  'use strict';

  const C = window.C;
  const tests = [];

  function test(name, fn) {
    tests.push({ name: name, fn: fn });
  }

  function assert(condition, message) {
    if (!condition) throw new Error(message || 'Assertion failed');
  }

  function equal(actual, expected, message) {
    if (actual !== expected) {
      throw new Error((message || 'Values differ') + ': expected ' + JSON.stringify(expected) + ', got ' + JSON.stringify(actual));
    }
  }

  function includes(text, needle, message) {
    if (String(text).indexOf(needle) === -1) {
      throw new Error((message || 'Missing text') + ': ' + JSON.stringify(needle));
    }
  }

  function fixtureRaw() {
    const host = 'xn--pple-43d.com';
    return {
      target: 'https://' + host + '/login',
      generated_at: '2026-10-20T09:12:07.123456789+00:00',
      results: [
        {
          task: 'whois_lookup',
          result: {
            domain: host,
            created_at: '2026-09-25',
            domain_age_days: 25,
            new_domain: true,
            fields: {
              Registrar: 'Example Registrar, Inc.',
              'Abuse Email': 'abuse@example.test'
            },
            raw: 'Domain Name: ' + host
          }
        },
        { task: 'whois_lookup', error: 'whois server timeout' },
        {
          task: 'html_scan',
          result: {
            host: host,
            start_url: 'https://' + host + '/login',
            pages: [{
              url: 'https://' + host + '/login',
              status: 200,
              title: 'Sign in to your account',
              content_type: 'text/html',
              bytes: 47104,
              sha256: 'a'.repeat(64),
              links: ['https://' + host + '/help']
            }],
            links: ['https://' + host + '/help'],
            forms: {
              password_forms: 1,
              cross_origin_forms: 1,
              meta_refresh: true,
              forms: [{
                action: 'https://collect.example.test/login.php',
                method: 'post',
                cross_origin: true,
                password_fields: 1,
                hidden_fields: 2
              }]
            },
            identifiers: {
              analytics: ['G-TEST123'],
              telegram: ['@clouseau_test'],
              whatsapp: ['+15551234567'],
              wallets: ['0x' + 'a'.repeat(40)],
              emails: ['collector@example.test']
            },
            wordpress: {
              login: true,
              rest: true,
              xmlrpc: false,
              version: '6.5',
              plugins: ['contact-form-7'],
              authors: ['admin'],
              users: ['editor', { name: 'writer' }]
            },
            cloaking: {
              differs: true,
              reasons: ['status differs between browser (200) and curl (403)'],
              profiles: [
                { profile: 'browser', status: 200, title: 'Sign in', bytes: 47104, final_url: 'https://' + host + '/login', sha256: 'b'.repeat(64) },
                { profile: 'curl', status: 403, error: 'forbidden' }
              ]
            }
          }
        },
        {
          task: 'robots_scan',
          result: {
            groups: [{ user_agents: ['*'], allow: ['/'], disallow: ['/admin'] }],
            sitemaps: ['https://' + host + '/sitemap.xml'],
            sitemap_files: [{ url: 'https://' + host + '/sitemap.xml', status: 200, urls: 3 }]
          }
        },
        {
          task: 'headers_scan',
          result: {
            url: 'https://' + host + '/login',
            status: 200,
            powered_by: 'PHP/8.2.18',
            headers: { 'content-type': 'text/html' },
            checks: [
              { name: 'Content-Security-Policy', status: 'missing' },
              { name: 'Strict-Transport-Security', status: 'weak' }
            ],
            cors: { reflects_origin: true, allow_credentials: true, probe_origin: 'https://probe.test' },
            cookies: [{ name: 'session', secure: false, http_only: false }],
            redirects: [{ url: 'https://' + host + '/login', status: 200 }]
          }
        },
        {
          task: 'domain_scan',
          result: {
            host: host,
            unicode_host: '\u0430pple.com',
            punycode: true,
            mixed_script: true,
            scripts: ['Cyrillic', 'Latin'],
            warnings: ['internationalized domain name (punycode)']
          }
        },
        {
          task: 'threat_lookup',
          result: {
            host: host,
            sources: [
              { source: 'OpenPhish', status: 'found', urls: ['https://' + host + '/login'] },
              { source: 'Urlhaus', status: 'error', detail: 'rate_limited' },
              { source: 'Wayback', status: 'found', urls: [] }
            ],
            wayback_first_seen: '2026-10-01'
          }
        },
        {
          task: 'ip_lookup',
          result: {
            host: host,
            records: {
              a: ['104.16.1.1', '104.16.1.2'],
              aaaa: ['2606:4700::6810:101'],
              mx: ['10 mail.' + host + '.'],
              ns: ['elliott.ns.cloudflare.com.', 'hera.ns.cloudflare.com.'],
              txt: ['v=spf1 include:_spf.example.test -all'],
              cname: [host + '.cdn.cloudflare.net.']
            },
            addresses: [{
              ip: '104.16.1.1',
              version: 4,
              scope: 'public',
              asn: 13335,
              as_name: 'CLOUDFLARENET',
              country: 'US',
              prefix: '104.16.0.0/13',
              ptr: [host + '.'],
              provider: ['Cloudflare'],
              forward_confirmed: true,
              open_ports: [443, 8443],
              dnsbl: ['zen.spamhaus.org'],
              tor_exit: true,
              netblock: { organization: 'Cloudflare', abuse_emails: ['abuse@cloudflare.test'] }
            }],
            tls: {
              version: 'TLS 1.3',
              verified: false,
              verify_error: 'x509: certificate signed by unknown authority',
              not_after: '2026-12-01T00:00:00Z',
              days_left: 41,
              dns_names: [host, 'www.' + host]
            },
            email_security: {
              spf: ['v=spf1 -all'],
              dmarc: 'v=DMARC1; p=reject',
              dmarc_policy: 'reject'
            },
            cloudflare_origin: {
              domain: host,
              checked: 12,
              candidates: [{ subdomain: 'direct.' + host, ips: ['203.0.113.10'] }]
            }
          }
        },
        {
          task: 'infra_scan',
          result: {
            host: host,
            certificate_domains: [host, 'www.' + host],
            certificate_domain_total: 2,
            favicon: {
              url: 'https://' + host + '/favicon.ico',
              bytes: 1150,
              sha256: 'c'.repeat(64),
              mmh3: -123456
            }
          }
        },
        {
          task: 'custom_task',
          result: {
            note: 'hello custom output',
            nested: { flag: true, count: 2 },
            list: ['one', 'two']
          }
        }
      ]
    };
  }

  function fixtureModel() {
    const model = C.reports.buildReport(fixtureRaw(), {
      id: 'scan/report.json',
      path: 'scan/report.json',
      size: 2048,
      lastModified: 0
    });
    model.observations = C.signals.derive(model);
    model.iocs = C.iocs.extract(model);
    return model;
  }

  test('format: parses nanosecond RFC3339 timestamps and date-only values', function () {
    const parsed = C.format.parseDate('2026-10-20T09:12:07.123456789+00:00');
    assert(parsed instanceof Date, 'expected a Date');
    equal(parsed.getUTCFullYear(), 2026, 'year');
    equal(parsed.getUTCMonth(), 9, 'month index');
    equal(parsed.getUTCDate(), 20, 'day');
    equal(parsed.getUTCMilliseconds(), 123, 'milliseconds should be preserved');
    equal(C.format.dateOnly('2026-09-25'), '2026-09-25', 'date-only value');
    equal(C.format.parseDate('not a date'), null, 'invalid date');
  });

  test('format: detects, defangs, and refangs URLs, domains, and emails', function () {
    equal(C.format.detectType('https://example.test/a'), 'url', 'URL type');
    equal(C.format.detectType('example.test'), 'domain', 'domain type');
    equal(C.format.detectType('104.16.1.1'), 'ip', 'IP type');
    equal(C.format.detectType('a'.repeat(64)), 'sha256', 'hash type');
    const url = C.format.defang('https://xn--pple-43d.com/login');
    equal(url, 'hxxps://xn--pple-43d[.]com/login', 'defanged URL');
    equal(C.format.refang(url), 'https://xn--pple-43d.com/login', 'round trip');
    equal(C.format.defang('abuse@example.test'), 'abuse[@]example[.]test', 'defanged email');
  });

  test('format: humanizes keys and truncates long values', function () {
    equal(C.format.humanize('ip_lookup'), 'IP Lookup', 'humanized key');
    equal(C.format.plural(1, 'task'), 'task', 'singular');
    equal(C.format.plural(2, 'task'), 'tasks', 'plural');
    assert(C.format.truncateMiddle('abcdefghijklmnopqrstuvwxyz', 10).indexOf('\u2026') !== -1, 'middle ellipsis');
    equal(C.format.hostFromUrl('https://example.test/a/b'), 'example.test', 'host extraction');
  });

  test('validate: rejects malformed reports and accepts BOM-prefixed JSON', function () {
    assert(!C.reports.validate(null).ok, 'null rejected');
    assert(C.reports.validate({ target: 'x', results: [] }).ok, 'target with no host is still structurally valid');
    assert(!C.reports.validate({ results: [] }).ok, 'missing target rejected');
    assert(!C.reports.validate({ target: 'https://example.test' }).ok, 'missing results rejected');
    assert(!C.reports.validate({ target: 'https://example.test', results: [{}] }).ok, 'entry without task rejected');
    const text = '\uFEFF' + JSON.stringify(fixtureRaw());
    const parsed = C.reports.parseReportText(text);
    assert(parsed.ok, 'valid report parsed');
    assert(!C.reports.parseReportText('{').ok, 'invalid JSON rejected');
    assert(!C.reports.parseReportText('[]').ok, 'array rejected');
  });

  test('buildReport: models duplicate tasks, errors, coverage, and unknown tasks', function () {
    const model = fixtureModel();
    equal(model.host, 'xn--pple-43d.com', 'host');
    equal(model.unicodeHost, '\u0430pple.com', 'unicode host');
    equal(model.taskCount, 10, 'task entry count');
    equal(model.errorCount, 1, 'error count');
    equal(model.getError('whois_lookup'), 'whois server timeout', 'kept duplicate task error');
    assert(model.getResult('whois_lookup').new_domain === true, 'kept successful duplicate task result');
    assert(model.unknownTasks.indexOf('custom_task') !== -1, 'unknown task retained');
    const whoisCoverage = model.coverage.find(function (item) { return item.task === 'whois_lookup'; });
    equal(whoisCoverage.status, 'partial', 'partial WHOIS coverage');
    assert(model.generatedAt instanceof Date, 'generatedAt parsed');
  });

  test('files: adds JSON reports and ignores other files', function () {
    C.files.clear();
    const report = C.files.addFile(new File(['{}'], 'report.json', { type: 'application/json' }), 'file');
    const page = C.files.addFile(new File(['<html></html>'], 'page.html', { type: 'text/html' }), 'file');
    assert(report, 'JSON report added');
    equal(page, null, 'non-JSON file ignored');
    equal(report.path, 'report.json', 'path from file name');
    equal(C.files.reportCandidates().length, 1, 'one report candidate');
    equal(C.files.summary().files, 1, 'one file in summary');
    C.files.clear();
    equal(C.files.summary().files, 0, 'cleared');
  });

  test('files: adds JSON reports from dropped files', async function () {
    C.files.clear();
    const transfer = new DataTransfer();
    transfer.items.add(new File(['{"target":"https://drop.test","results":[]}'], 'dropped.json', { type: 'application/json' }));
    transfer.items.add(new File(['<html></html>'], 'page.html', { type: 'text/html' }));
    const added = await C.files.addDataTransfer(transfer);
    equal(added.length, 1, 'one JSON file added');
    equal(added[0].path, 'dropped.json', 'path from file name');
    equal(C.files.reportCandidates().length, 1, 'report candidate');
    C.files.clear();
  });

  test('indicators: extracts, deduplicates, and exports indicators', function () {
    const model = fixtureModel();
    const items = model.iocs;
    assert(items.length > 10, 'expected a useful indicator set');
    assert(items.every(function (item) { return item.value && typeof item.value === 'string'; }), 'all values defined');
    const usernameItems = items.filter(function (item) { return item.type === 'username'; });
    equal(usernameItems.length, 3, 'WordPress string users and authors become usernames');
    assert(items.some(function (item) { return item.type === 'ip' && item.value === '104.16.1.1'; }), 'IP extracted');
    assert(items.some(function (item) { return item.type === 'sha256' && item.value === 'a'.repeat(64); }), 'page hash extracted');
    assert(items.some(function (item) { return item.type === 'mmh3' && item.value === '-123456'; }), 'favicon hash extracted');
    const counts = C.iocs.counts(items);
    assert(counts.url >= 4, 'URL count');
    const csv = C.iocs.exportCsv(items, false);
    includes(csv, '"type","value","defanged","sources"', 'CSV header');
    const json = JSON.parse(C.iocs.exportJson(model, items, true));
    equal(json.indicators.length, items.length, 'JSON export count');
    assert(json.indicators[0].defanged.indexOf('[') !== -1 || json.indicators[0].defanged.indexOf('hxxp') !== -1, 'JSON export includes defanged values');
    const markdown = C.iocs.exportMarkdown(model, items, false);
    includes(markdown, '# Indicators — ', 'Markdown heading');
    includes(markdown, '| Type | Value | Sources |', 'Markdown table');
    equal(C.iocs.copyAll(items, false).split('\n').length, items.length, 'copy-all line count');
    assert(C.iocs.filename(model, 'csv').endsWith('_indicators_2026-10-20.csv'), 'export filename');
  });

  test('signals: derives expected observations and summary counts', function () {
    const model = fixtureModel();
    const ids = model.observations.map(function (item) { return item.id; });
    [
      'punycode-host', 'mixed-script-host', 'new-domain', 'cloaking', 'cross-origin-form',
      'password-form', 'meta-refresh', 'missing-headers', 'weak-headers',
      'cors-reflection', 'insecure-cookies', 'threat-listing', 'threat-source-errors',
      'recent-archive', 'tor-exit', 'dnsbl', 'unverified-tls', 'origin-leak',
      'shared-certificate', 'task-error-whois_lookup', 'unknown-modules'
    ].forEach(function (id) {
      assert(ids.indexOf(id) !== -1, 'missing observation ' + id);
    });
    const summary = C.signals.summarise(model.observations);
    equal(summary.total, model.observations.length, 'summary total');
    equal(summary.critical + summary.warning + summary.info, summary.total, 'severity buckets');
    const cors = model.observations.find(function (item) { return item.id === 'cors-reflection'; });
    equal(cors.severity, 'critical', 'credentialed CORS is critical');
    const puny = model.observations.find(function (item) { return item.id === 'punycode-host'; });
    equal(puny.tab, 'domain', 'punycode observation routes to domain');
    const listing = model.observations.find(function (item) { return item.id === 'threat-listing'; });
    assert(listing.detail.indexOf('Wayback') === -1, 'archive source is not a threat listing');
    assert(C.signals.isArchiveSource({ source: 'Wayback Machine' }), 'Wayback is an archive source');
    assert(C.signals.isArchiveSource({ source: 'archive.today' }), 'archive.today is an archive source');
    assert(!C.signals.isArchiveSource({ source: 'OpenPhish' }), 'OpenPhish is not an archive source');
  });

  test('shell: exposes only available tabs and adds unknown-task tabs', function () {
    const model = fixtureModel();
    const tabs = C.shell.tabDefs(model);
    const ids = tabs.map(function (tab) { return tab.id; });
    ['overview', 'website', 'network', 'domain', 'threats', 'iocs', 'task:custom_task', 'raw'].forEach(function (id) {
      assert(ids.indexOf(id) !== -1, 'missing tab ' + id);
    });
    assert(ids.indexOf('evidence') === -1, 'evidence tab removed');
    const threatsTab = tabs.find(function (tab) { return tab.id === 'threats'; });
    equal(threatsTab.count, 1, 'archive source excluded from threat count');
    const indicatorsTab = tabs.find(function (tab) { return tab.id === 'iocs'; });
    equal(indicatorsTab.label, 'Indicators', 'indicator tab label');
    const customTab = tabs.find(function (tab) { return tab.id === 'task:custom_task'; });
    equal(customTab.label, 'Custom Task', 'unknown task label');
  });

  test('views: every tab renders with the fixture model', function () {
    const model = fixtureModel();
    C.state.addReport(model);
    ['overview', 'website', 'network', 'domain', 'threats', 'iocs', 'raw'].forEach(function (id) {
      const node = C.views[id](model);
      assert(node instanceof Node, id + ' did not return a node');
      assert(node.textContent.trim().length > 0, id + ' rendered no text');
      assert(node.textContent.indexOf('Could not render this view') === -1, id + ' rendered an error state');
    });
  });

  test('website: groups link destinations and filters the URL list', function () {
    const raw = fixtureRaw();
    const html = raw.results.find(function (entry) { return entry.task === 'html_scan'; }).result;
    html.links = [
      'https://' + html.host + '/help',
      'https://' + html.host + '/security',
      'https://collect.example.test/login.php',
      'http://104.16.1.1/pixel',
      'https://xn--pple-43d.com.evil.test/landing',
      'mailto:test@example.test'
    ];
    const model = C.reports.buildReport(raw, {
      id: 'scan/link-chart.json',
      path: 'scan/link-chart.json',
      size: 2048,
      lastModified: 0
    });
    const view = C.views.website(model);
    const chart = view.querySelector('.link-chart');
    assert(chart, 'link chart missing');
    equal(chart.querySelectorAll('.link-bar-row').length, 5, 'chart row count');

    const metrics = Array.prototype.map.call(view.querySelectorAll('.link-metric strong'), function (node) {
      return node.textContent;
    });
    equal(metrics.join(','), '6,3,1,3', 'link chart metrics');

    const details = view.querySelector('.link-list');
    const external = chart.querySelector('.link-bar-row[data-host="collect.example.test"]');
    assert(external, 'external destination bar missing');
    external.click();
    assert(details.open, 'link list should open when filtering');
    includes(details.querySelector('summary').textContent, 'Links to collect.example.test', 'filtered list title');
    equal(details.querySelectorAll('.chip').length, 1, 'filtered link count');

    chart.querySelector('.link-bar-row[data-key="other"]').click();
    includes(details.querySelector('summary').textContent, 'Other destination links', 'other destination title');
    equal(details.querySelectorAll('.chip').length, 1, 'other destination link count');

    external.click();
    external.click();
    includes(details.querySelector('summary').textContent, 'All extracted links (6)', 'cleared list title');
  });

  test('website: links WordPress and powered-by versions to CVE lookups', function () {
    const model = fixtureModel();
    const view = C.views.website(model);
    const links = Array.prototype.slice.call(view.querySelectorAll('.cve-lookup'));
    equal(links.length, 2, 'CVE lookup count');

    const wordpress = links.find(function (link) { return link.href.indexOf('wpscan.com') !== -1; });
    assert(wordpress, 'WordPress CVE lookup missing');
    equal(wordpress.getAttribute('href'), 'https://wpscan.com/wordpress/65/', 'WordPress lookup URL');
    includes(wordpress.getAttribute('title'), 'WordPress 6.5', 'WordPress lookup title');

    const powered = links.find(function (link) { return link.href.indexOf('cve.org') !== -1; });
    assert(powered, 'powered-by CVE lookup missing');
    includes(powered.getAttribute('href'), 'CVERecord/SearchResults?query=PHP%208.2.18', 'powered-by lookup URL');
    includes(powered.getAttribute('title'), 'PHP 8.2.18', 'powered-by lookup title');
    equal(powered.getAttribute('target'), '_blank', 'lookup opens in a new tab');

    const overview = C.views.overview(model);
    assert(overview.querySelector('.cve-lookup'), 'overview powered-by lookup missing');
  });

  test('threats: archive sources are separate from threat listings', function () {
    const model = fixtureModel();
    const view = C.views.threats(model);
    const alert = view.querySelector('.notice.critical');
    assert(alert, 'threat notice missing');
    includes(alert.textContent, 'Threat listing found', 'neutral threat title');
    assert(alert.textContent.indexOf('Wayback') === -1, 'archive source appears in threat notice');
    const sources = view.querySelector('#threats-sources');
    const wayback = Array.prototype.slice.call(sources.querySelectorAll('.card')).find(function (card) {
      return card.textContent.indexOf('Wayback') !== -1;
    });
    assert(wayback, 'archive source card missing');
    includes(wayback.textContent, 'Archived', 'archive source badge');
    assert(wayback.textContent.indexOf('Found') === -1, 'archive source marked as found');
  });

  test('views: generic renderer handles unknown task output and escapes untrusted text', function () {
    const model = fixtureModel();
    const previousHash = window.location.hash;
    window.location.hash = '#/r/' + encodeURIComponent(model.id) + '/' + encodeURIComponent('task:custom_task');
    const node = C.views.generic(model);
    includes(node.textContent, 'hello custom output', 'custom scalar value rendered');
    includes(node.textContent, 'nested', 'nested object rendered');

    const raw = fixtureRaw();
    raw.results[2].result.pages[0].title = '<img src=x onerror=alert(1)>';
    const hostile = C.reports.buildReport(raw, { id: 'scan/hostile.json', path: 'scan/hostile.json' });
    hostile.observations = C.signals.derive(hostile);
    hostile.iocs = C.iocs.extract(hostile);
    const website = C.views.website(hostile);
    equal(website.querySelector('img'), null, 'untrusted title did not create an image element');
    window.location.hash = previousHash;
  });

  test('search: indexes fields with the right tab and section targets', function () {
    const model = fixtureModel();
    const entries = C.search.buildIndex([model]);
    const find = function (value) {
      return entries.find(function (entry) { return entry.value === value; });
    };
    assert(entries.length > 50, 'expected a useful search index');
    equal(find('Sign in to your account').tab, 'website', 'page title tab');
    equal(find('Sign in to your account').sectionId, 'website-pages', 'page title section');
    equal(find('104.16.1.1').sectionId, 'network-dns', 'DNS record section');
    equal(find('abuse@example.test').sectionId, 'domain-whois', 'WHOIS field section');
    equal(find('hello custom output').tab, 'task:custom_task', 'unknown task tab');
    equal(find('hello custom output').sectionId, 'generic-result', 'unknown task section');
    equal(find('whois server timeout').sectionId, 'domain-whois', 'task error section');
    const target = entries.find(function (entry) { return entry.pathLabel === 'Target'; });
    assert(target, 'target entry missing');
    equal(target.sectionId, 'overview-profile', 'target section');
  });

  test('search: maps task fields to the correct sections', function () {
    equal(C.search.routeForTask('html_scan', ['forms', 'forms']).sectionId, 'website-forms', 'forms');
    equal(C.search.routeForTask('html_scan', ['cloaking', 'probes']).sectionId, 'website-cloaking', 'cloaking');
    equal(C.search.routeForTask('headers_scan', ['checks']).sectionId, 'website-headers', 'headers');
    equal(C.search.routeForTask('ip_lookup', ['records', 'a']).sectionId, 'network-dns', 'DNS');
    equal(C.search.routeForTask('ip_lookup', ['tls', 'issuer']).sectionId, 'network-tls', 'TLS');
    equal(C.search.routeForTask('ip_lookup', ['email_security', 'spf']).sectionId, 'network-email', 'email');
    equal(C.search.routeForTask('threat_lookup', ['wayback_first_seen']).sectionId, 'threats-wayback', 'archive');
    equal(C.search.routeForTask('threat_lookup', ['sources']).sectionId, 'threats-sources', 'sources');
    equal(C.search.routeForTask('custom_task', ['note']).tab, 'task:custom_task', 'unknown task');
  });

  test('search: filters by every token and ranks matching values', function () {
    const model = fixtureModel();
    const entries = C.search.buildIndex([model]);
    const account = C.search.filter(entries, 'account');
    assert(account.length > 0, 'expected a page-title match');
    equal(account[0].value, 'Sign in to your account', 'title should rank first');
    assert(C.search.filter(entries, 'sign account').length > 0, 'all tokens should match');
    equal(C.search.filter(entries, 'sign missingtoken').length, 0, 'missing token should exclude the field');
    assert(C.search.filter(entries, 'DNS records').some(function (entry) {
      return entry.sectionId === 'network-dns';
    }), 'section labels should be searchable');
  });

  async function run() {
    const results = document.getElementById('results');
    const summary = document.getElementById('summary');
    let passed = 0;
    let failed = 0;

    for (const item of tests) {
      const li = document.createElement('li');
      const strong = document.createElement('strong');
      strong.textContent = item.name;
      li.appendChild(strong);
      try {
        await item.fn();
        li.className = 'pass';
        passed += 1;
      } catch (error) {
        li.className = 'fail';
        failed += 1;
        const message = document.createElement('span');
        message.className = 'msg';
        message.textContent = error && error.stack ? error.stack : String(error);
        li.appendChild(message);
      }
      results.appendChild(li);
    }

    summary.textContent = '';
    const passPill = document.createElement('span');
    passPill.className = 'pill pass';
    passPill.textContent = passed + ' passed';
    const failPill = document.createElement('span');
    failPill.className = 'pill fail';
    failPill.textContent = failed + ' failed';
    summary.appendChild(passPill);
    summary.appendChild(failPill);
    summary.appendChild(document.createElement('span')).className = 'pill';

    window.__testResults = { passed: passed, failed: failed, total: tests.length };
    document.body.setAttribute('data-tests', JSON.stringify(window.__testResults));
    document.title = (failed ? 'FAIL' : 'PASS') + ' (' + passed + '/' + tests.length + ') - Clouseau Reader tests';
    if (failed) {
      const errors = document.getElementById('errors');
      errors.textContent = failed + ' test(s) failed. See the messages above.';
    }
  }

  run();
})();
