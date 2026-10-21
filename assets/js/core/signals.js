(function () {
  'use strict';

  const C = window.C = window.C || {};
  const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 };

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function sourceName(source) {
    if (source && typeof source === 'object') return String(source.source == null ? '' : source.source);
    return String(source == null ? '' : source);
  }

  function isArchiveSource(source) {
    return /wayback|archive/i.test(sourceName(source));
  }

  function isThreatHit(source) {
    return Boolean(source) &&
      String(source.status || '').toLowerCase() === 'found' &&
      !isArchiveSource(source);
  }

  function list(values) {
    return values.filter(Boolean).join(', ');
  }

  function tabForTask(task) {
    if (task === 'whois_lookup' || task === 'domain_scan') return 'domain';
    if (task === 'html_scan' || task === 'robots_scan' || task === 'headers_scan') return 'website';
    if (task === 'threat_lookup') return 'threats';
    if (task === 'ip_lookup' || task === 'infra_scan') return 'network';
    return 'raw';
  }

  function derive(model) {
    const observations = [];
    const add = function (item) {
      if (!item || !item.title) return;
      observations.push({
        id: item.id || item.title.toLowerCase().replace(/\s+/g, '-'),
        severity: item.severity || 'info',
        title: item.title,
        detail: item.detail || '',
        tab: item.tab || 'overview',
        source: item.source || '',
        icon: item.icon || (item.severity === 'critical' ? 'shield-alert' : item.severity === 'warning' ? 'alert-triangle' : 'info')
      });
    };

    const domain = model.getResult('domain_scan') || {};
    const whois = model.getResult('whois_lookup') || {};
    const html = model.getResult('html_scan') || {};
    const forms = html.forms || {};
    const headers = model.getResult('headers_scan') || {};
    const threat = model.getResult('threat_lookup') || {};
    const ip = model.getResult('ip_lookup') || {};
    const infra = model.getResult('infra_scan') || {};

    if (domain.punycode) {
      add({
        id: 'punycode-host',
        severity: 'warning',
        title: 'Internationalised (punycode) host',
        detail: domain.unicode_host ? 'The host decodes to ' + domain.unicode_host + '.' : 'The host contains punycode encoding.',
        tab: 'domain',
        source: 'domain_scan',
        icon: 'globe'
      });
    }

    if (domain.mixed_script) {
      add({
        id: 'mixed-script-host',
        severity: 'critical',
        title: 'Mixed-script host',
        detail: 'The host mixes ' + (asArray(domain.scripts).join(' + ') || 'multiple scripts') + ', which can indicate a homoglyph impersonation.',
        tab: 'domain',
        source: 'domain_scan',
        icon: 'shield-alert'
      });
    }

    if (asArray(domain.warnings).length && !domain.punycode && !domain.mixed_script) {
      add({
        severity: 'info',
        title: 'Domain warnings',
        detail: asArray(domain.warnings).join(' · '),
        tab: 'domain',
        source: 'domain_scan'
      });
    }

    const ageDays = Number(whois.domain_age_days);
    if (whois.new_domain) {
      add({
        id: 'new-domain',
        severity: 'warning',
        title: 'Recently registered domain',
        detail: 'Registered ' + (whois.created_at || 'recently') + (Number.isFinite(ageDays) ? ' · ' + C.format.formatDays(ageDays) + ' old' : '') + '.',
        tab: 'domain',
        source: 'whois_lookup',
        icon: 'calendar'
      });
    } else if (Number.isFinite(ageDays) && ageDays >= 0 && ageDays <= 30) {
      add({
        id: 'young-domain',
        severity: 'warning',
        title: 'Young domain',
        detail: 'Registered ' + ageDays + ' days ago' + (whois.created_at ? ' (' + whois.created_at + ')' : '') + '.',
        tab: 'domain',
        source: 'whois_lookup',
        icon: 'calendar'
      });
    }

    if (html.cloaking && html.cloaking.differs) {
      add({
        id: 'cloaking',
        severity: 'critical',
        title: 'Cloaking detected',
        detail: asArray(html.cloaking.reasons).join(' · ') || 'Responses differ between browser, Googlebot, and curl profiles.',
        tab: 'website',
        source: 'html_scan',
        icon: 'eye'
      });
    }

    if (Number(forms.cross_origin_forms) > 0) {
      const actions = asArray(forms.forms).filter(function (form) { return form.cross_origin; }).map(function (form) { return form.action; });
      add({
        id: 'cross-origin-form',
        severity: 'critical',
        title: 'Cross-origin form submission',
        detail: forms.cross_origin_forms + ' form(s) submit to another origin' + (actions.length ? ': ' + actions.slice(0, 2).join(', ') : '') + '.',
        tab: 'website',
        source: 'html_scan',
        icon: 'send'
      });
    }

    if (Number(forms.password_forms) > 0) {
      add({
        id: 'password-form',
        severity: 'warning',
        title: 'Password field detected',
        detail: forms.password_forms + ' form(s) contain a password field.',
        tab: 'website',
        source: 'html_scan',
        icon: 'lock'
      });
    }

    if (forms.meta_refresh) {
      add({
        id: 'meta-refresh',
        severity: 'info',
        title: 'Meta refresh redirect',
        detail: 'The page includes a meta refresh redirect.',
        tab: 'website',
        source: 'html_scan'
      });
    }

    if (asArray(html.evidence_errors).length) {
      add({
        id: 'evidence-missing',
        severity: 'warning',
        title: 'Evidence files are missing',
        detail: html.evidence_errors.length + ' evidence reference(s) could not be saved or found.',
        tab: 'evidence',
        source: 'html_scan',
        icon: 'file-text'
      });
    }

    const checks = asArray(headers.checks);
    const missingHeaders = checks.filter(function (check) { return check.status === 'missing'; }).map(function (check) { return check.name; });
    const weakHeaders = checks.filter(function (check) { return check.status === 'weak'; }).map(function (check) { return check.name; });
    if (missingHeaders.length) {
      add({
        id: 'missing-headers',
        severity: 'warning',
        title: 'Missing security headers',
        detail: list(missingHeaders) + '.',
        tab: 'website',
        source: 'headers_scan',
        icon: 'shield'
      });
    }
    if (weakHeaders.length) {
      add({
        id: 'weak-headers',
        severity: 'info',
        title: 'Weak security headers',
        detail: list(weakHeaders) + '.',
        tab: 'website',
        source: 'headers_scan',
        icon: 'shield'
      });
    }

    const cors = headers.cors;
    if (cors && cors.reflects_origin) {
      add({
        id: 'cors-reflection',
        severity: cors.allow_credentials ? 'critical' : 'warning',
        title: cors.allow_credentials ? 'CORS reflects origin with credentials' : 'CORS reflects arbitrary origin',
        detail: 'Probe origin ' + (cors.probe_origin || 'unknown') + ' was allowed' + (cors.allow_credentials ? ' with credentials.' : '.'),
        tab: 'website',
        source: 'headers_scan',
        icon: 'link'
      });
    }

    const insecureCookies = asArray(headers.cookies).filter(function (cookie) {
      return cookie.secure === false || cookie.http_only === false;
    });
    if (insecureCookies.length) {
      add({
        id: 'insecure-cookies',
        severity: 'warning',
        title: 'Cookies missing security flags',
        detail: insecureCookies.map(function (cookie) {
          const flags = [];
          if (cookie.secure === false) flags.push('Secure');
          if (cookie.http_only === false) flags.push('HttpOnly');
          return cookie.name + ' (missing ' + flags.join(' / ') + ')';
        }).join(' · ') + '.',
        tab: 'website',
        source: 'headers_scan',
        icon: 'key'
      });
    }

    const sources = asArray(threat.sources);
    const foundSources = sources.filter(isThreatHit);
    if (foundSources.length) {
      const urlCount = foundSources.reduce(function (total, source) {
        return total + asArray(source.urls).length;
      }, 0);
      add({
        id: 'threat-listing',
        severity: 'critical',
        title: 'Threat listing found',
        detail: 'Listed by ' + foundSources.map(function (source) { return C.format.humanize(sourceName(source)); }).join(', ') + (urlCount ? ' · ' + urlCount + ' matching ' + C.format.plural(urlCount, 'URL') : '') + '.',
        tab: 'threats',
        source: 'threat_lookup',
        icon: 'shield-alert'
      });
    }

    const threatErrors = sources.filter(function (source) { return source.status === 'error'; });
    if (threatErrors.length) {
      add({
        id: 'threat-source-errors',
        severity: 'info',
        title: 'Some sources could not be checked',
        detail: threatErrors.map(function (source) { return C.format.humanize(sourceName(source)) + ': ' + (source.detail || 'error'); }).join(' · '),
        tab: 'threats',
        source: 'threat_lookup'
      });
    }

    if (threat.wayback_first_seen) {
      const firstSeen = C.format.parseDate(threat.wayback_first_seen);
      const generated = model.generatedAt || new Date();
      if (firstSeen) {
        const days = Math.round((generated.getTime() - firstSeen.getTime()) / 86400000);
        if (days >= 0 && days <= 90) {
          add({
            id: 'recent-archive',
            severity: 'warning',
            title: 'First archived recently',
            detail: 'The Wayback Machine first saw this host on ' + C.format.fmtDate(firstSeen) + ', ' + days + ' days before this scan.',
            tab: 'threats',
            source: 'threat_lookup',
            icon: 'archive'
          });
        }
      }
    }

    const addresses = asArray(ip.addresses);
    const torAddresses = addresses.filter(function (address) { return address.tor_exit; });
    if (torAddresses.length) {
      add({
        id: 'tor-exit',
        severity: 'warning',
        title: 'Tor exit node',
        detail: torAddresses.map(function (address) { return address.ip; }).join(', ') + ' is listed as a Tor exit node.',
        tab: 'network',
        source: 'ip_lookup',
        icon: 'network'
      });
    }

    const blocklisted = addresses.filter(function (address) { return asArray(address.dnsbl).length; });
    if (blocklisted.length) {
      add({
        id: 'dnsbl',
        severity: 'warning',
        title: 'IPs on DNS blocklists',
        detail: blocklisted.map(function (address) {
          return address.ip + ' (' + asArray(address.dnsbl).join(', ') + ')';
        }).join(' · ') + '.',
        tab: 'network',
        source: 'ip_lookup',
        icon: 'shield-alert'
      });
    }

    const riskyPorts = [21, 22, 23, 25, 3306, 3389, 5432, 6379, 9200, 11211];
    const exposed = [];
    addresses.forEach(function (address) {
      asArray(address.open_ports).forEach(function (port) {
        if (riskyPorts.indexOf(port) !== -1) exposed.push(address.ip + ':' + port);
      });
    });
    if (exposed.length) {
      add({
        id: 'exposed-ports',
        severity: 'info',
        title: 'Uncommon ports exposed',
        detail: exposed.join(', ') + '.',
        tab: 'network',
        source: 'ip_lookup',
        icon: 'server'
      });
    }

    const tls = ip.tls;
    if (tls) {
      if (tls.self_signed) {
        add({
          id: 'self-signed-tls',
          severity: 'critical',
          title: 'Self-signed TLS certificate',
          detail: 'The TLS certificate is self-signed.',
          tab: 'network',
          source: 'ip_lookup',
          icon: 'lock'
        });
      } else if (tls.verified === false) {
        add({
          id: 'unverified-tls',
          severity: 'warning',
          title: 'TLS certificate not verified',
          detail: tls.verify_error || 'The certificate chain could not be verified.',
          tab: 'network',
          source: 'ip_lookup',
          icon: 'lock'
        });
      }
      const daysLeft = Number(tls.days_left);
      if (Number.isFinite(daysLeft)) {
        if (daysLeft < 0) {
          add({
            id: 'expired-tls',
            severity: 'warning',
            title: 'TLS certificate expired',
            detail: 'Expired ' + Math.abs(daysLeft) + ' days before this scan.',
            tab: 'network',
            source: 'ip_lookup',
            icon: 'clock'
          });
        } else if (daysLeft <= 14) {
          add({
            id: 'expiring-tls',
            severity: 'info',
            title: 'TLS certificate expires soon',
            detail: 'The certificate expires in ' + daysLeft + ' days.',
            tab: 'network',
            source: 'ip_lookup',
            icon: 'clock'
          });
        }
      }
    }

    const origin = ip.cloudflare_origin;
    if (origin && asArray(origin.candidates).length) {
      add({
        id: 'origin-leak',
        severity: 'warning',
        title: 'Potential Cloudflare origin leak',
        detail: 'Checked ' + (origin.checked || 0) + ' subdomain(s) and found ' + origin.candidates.length + ' candidate(s): ' + origin.candidates.map(function (candidate) { return candidate.subdomain; }).join(', ') + '.',
        tab: 'network',
        source: 'ip_lookup',
        icon: 'crosshair'
      });
    }

    const certDomains = asArray(infra.certificate_domains);
    if (certDomains.length > 1) {
      add({
        id: 'shared-certificate',
        severity: 'info',
        title: 'Shared certificate exposes related domains',
        detail: certDomains.length + ' domains appear on the certificate: ' + certDomains.slice(0, 6).join(', ') + (certDomains.length > 6 ? '…' : '') + '.',
        tab: 'network',
        source: 'infra_scan',
        icon: 'layers'
      });
    }

    model.errors.forEach(function (entry) {
      add({
        id: 'task-error-' + entry.task,
        severity: 'info',
        title: 'Module failed: ' + entry.task,
        detail: entry.error,
        tab: tabForTask(entry.task),
        source: 'scan output',
        icon: 'alert-triangle'
      });
    });

    const missingModules = model.coverage.filter(function (item) {
      return item.known && item.status === 'missing';
    });
    if (missingModules.length && missingModules.length < C.reports.MODULES.length) {
      add({
        id: 'partial-coverage',
        severity: 'info',
        title: 'Partial scan coverage',
        detail: 'Not run: ' + missingModules.map(function (item) { return item.label; }).join(', ') + '.',
        tab: 'overview',
        source: 'scan output'
      });
    }

    if (model.unknownTasks.length) {
      add({
        id: 'unknown-modules',
        severity: 'info',
        title: 'Unrecognised module output',
        detail: 'Generic rendering is available for: ' + model.unknownTasks.join(', ') + '.',
        tab: 'raw',
        source: 'scan output'
      });
    }

    observations.sort(function (a, b) {
      const severityDiff = (SEVERITY_ORDER[a.severity] || 9) - (SEVERITY_ORDER[b.severity] || 9);
      return severityDiff;
    });

    return observations;
  }

  function summarise(observations) {
    const counts = { critical: 0, warning: 0, info: 0 };
    observations.forEach(function (item) { counts[item.severity] = (counts[item.severity] || 0) + 1; });
    return {
      total: observations.length,
      critical: counts.critical,
      warning: counts.warning,
      info: counts.info
    };
  }

  C.signals = {
    derive: derive,
    summarise: summarise,
    isArchiveSource: isArchiveSource,
    isThreatHit: isThreatHit,
    SEVERITY_ORDER: SEVERITY_ORDER
  };
})();
