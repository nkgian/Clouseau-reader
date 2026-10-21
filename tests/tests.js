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
              evidence_file: 'evidence/20261020-091207-page-001.html',
              links: ['https://' + host + '/help']
            }],
            evidence_errors: ['evidence/20261020-091207-page-002.html: permission denied'],
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
    model.evidence = C.evidence.resolveAll(model);
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
    equal(model.evidenceErrors.length, 1, 'evidence errors retained');
    assert(model.generatedAt instanceof Date, 'generatedAt parsed');
  });

  test('files: resolves report-relative and unique basename evidence references', function () {
    C.files.clear();
    C.files.addFile('scan/report.json', new File(['{}'], 'report.json', { type: 'application/json' }), 'folder');
    const record = C.files.addFile(
      'scan/evidence/20261020-091207-page-001.html',
      new File(['<html>saved</html>'], '20261020-091207-page-001.html', { type: 'text/html' }),
      'folder'
    );
    const resolved = C.files.resolveReference('evidence/20261020-091207-page-001.html', 'scan/report.json');
    equal(resolved.record && resolved.record.key, record.key, 'record resolved');
    equal(resolved.method, 'report-relative', 'resolution method');
    const byName = C.files.resolveReference('20261020-091207-page-001.html', 'scan/report.json');
    assert(byName.record === record, 'basename lookup resolved');
    equal(C.files.reportCandidates().length, 1, 'one report candidate');
    equal(C.files.summary().evidenceCount, 1, 'evidence count');
    C.files.clear();
    equal(C.files.summary().files, 0, 'cleared');
  });

  test('files: falls back to FileList when dragged entries are unavailable', async function () {
    C.files.clear();
    const transfer = new DataTransfer();
    transfer.items.add(new File(['{"target":"https://drop.test","results":[]}'], 'dropped.json', { type: 'application/json' }));
    const added = await C.files.addDataTransfer(transfer);
    equal(added.length, 1, 'one file added');
    equal(added[0].path, 'dropped.json', 'path from file name');
    equal(C.files.reportCandidates().length, 1, 'report candidate');
    C.files.clear();
  });

  test('files: keeps FileList snapshot when entry reads fail', async function () {
    C.files.clear();
    const file = new File(['{"target":"https://late.test","results":[]}'], 'late.json', { type: 'application/json' });
    let reads = 0;
    const transfer = {
      items: [{
        kind: 'file',
        webkitGetAsEntry: function () {
          return {
            isFile: true,
            name: 'late.json',
            file: function (resolve, reject) {
              setTimeout(function () { reject(new Error('expired')); }, 0);
            }
          };
        }
      }],
      get files() {
        reads += 1;
        return reads === 1 ? [file] : [];
      }
    };
    const added = await C.files.addDataTransfer(transfer);
    equal(reads, 1, 'files snapshotted before async reads');
    equal(added.length, 1, 'fallback file added');
    equal(added[0].path, 'late.json', 'fallback path');
    C.files.clear();
  });

  test('iocs: extracts, deduplicates, and exports indicators', function () {
    const model = fixtureModel();
    const items = model.iocs;
    assert(items.length > 10, 'expected a useful IOC set');
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
    equal(json.iocs.length, items.length, 'JSON export count');
    assert(json.iocs[0].defanged.indexOf('[') !== -1 || json.iocs[0].defanged.indexOf('hxxp') !== -1, 'JSON export includes defanged values');
    includes(C.iocs.exportMarkdown(model, items, false), '| Type | Value | Sources |', 'Markdown table');
    equal(C.iocs.copyAll(items, false).split('\n').length, items.length, 'copy-all line count');
    assert(C.iocs.filename(model, 'csv').endsWith('_iocs_2026-10-20.csv'), 'export filename');
  });

  test('signals: derives expected observations and summary counts', function () {
    const model = fixtureModel();
    const ids = model.observations.map(function (item) { return item.id; });
    [
      'punycode-host', 'mixed-script-host', 'new-domain', 'cloaking', 'cross-origin-form',
      'password-form', 'meta-refresh', 'evidence-missing', 'missing-headers', 'weak-headers',
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
  });

  test('evidence: resolves saved files, reports missing files, hashes content, and sanitizes previews', async function () {
    C.files.clear();
    const model = fixtureModel();
    equal(C.evidence.summary(model).total, 1, 'one reference collected');
    equal(C.evidence.summary(model).found, 0, 'missing before file is added');
    const record = C.files.addFile(
      'scan/evidence/20261020-091207-page-001.html',
      new File(['abc'], '20261020-091207-page-001.html', { type: 'text/html' }),
      'folder'
    );
    model.evidence = C.evidence.resolveAll(model);
    equal(C.evidence.summary(model).found, 1, 'resolved after file is added');
    assert(C.evidence.isHtml(record, model.evidence[0].page), 'HTML detected');
    assert(!C.evidence.isImage(record, model.evidence[0].page), 'HTML is not an image');

    if (window.crypto && window.crypto.subtle) {
      const digest = await C.evidence.sha256(record);
      equal(digest, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', 'SHA-256 digest');
    }

    const preview = C.evidence.buildPreviewHtml(
      '<html><head><script>alert(1)</script></head><body onload="alert(2)">' +
      '<a href="javascript:alert(3)">click</a><img src="x" onerror="alert(4)"></body></html>'
    );
    assert(preview.indexOf('<script') === -1, 'script nodes removed');
    assert(preview.indexOf('onerror') === -1, 'inline handlers removed');
    assert(preview.indexOf('javascript:') === -1, 'javascript URLs removed');
    includes(preview, 'Content-Security-Policy', 'CSP injected');
    includes(preview, 'default-src \'none\'', 'restrictive CSP');
    C.files.clear();
  });

  test('shell: exposes only available tabs and adds unknown-task tabs', function () {
    const model = fixtureModel();
    const tabs = C.shell.tabDefs(model);
    const ids = tabs.map(function (tab) { return tab.id; });
    ['overview', 'website', 'network', 'domain', 'threats', 'evidence', 'iocs', 'task:custom_task', 'raw'].forEach(function (id) {
      assert(ids.indexOf(id) !== -1, 'missing tab ' + id);
    });
    const evidenceTab = tabs.find(function (tab) { return tab.id === 'evidence'; });
    equal(evidenceTab.count, '0/1', 'evidence tab count');
    const customTab = tabs.find(function (tab) { return tab.id === 'task:custom_task'; });
    equal(customTab.label, 'Custom Task', 'unknown task label');
  });

  test('views: every tab renders with the fixture model', function () {
    const model = fixtureModel();
    C.state.addReport(model);
    ['overview', 'website', 'network', 'domain', 'threats', 'evidence', 'iocs', 'raw'].forEach(function (id) {
      const node = C.views[id](model);
      assert(node instanceof Node, id + ' did not return a node');
      assert(node.textContent.trim().length > 0, id + ' rendered no text');
      assert(node.textContent.indexOf('Could not render this view') === -1, id + ' rendered an error state');
    });
  });

  test('views: generic renderer handles unknown task output and escapes untrusted text', function () {
    const model = fixtureModel();
    model.evidence = C.evidence.resolveAll(model);
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
    hostile.evidence = [];
    const website = C.views.website(hostile);
    equal(website.querySelector('img'), null, 'untrusted title did not create an image element');
    window.location.hash = previousHash;
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
