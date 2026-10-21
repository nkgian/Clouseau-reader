(function () {
  'use strict';

  const C = window.C = window.C || {};
  const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' });
  const dateTimeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  const numberFmt = new Intl.NumberFormat();
  const relativeFmt = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

  function parseDate(value) {
    if (value == null || value === '') return null;
    if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value;
    if (typeof value === 'number') {
      const fromMs = new Date(value);
      return Number.isNaN(fromMs.getTime()) ? null : fromMs;
    }
    let text = String(value).trim();
    if (!text) return null;
    if (/^\d{4}-\d{2}-\d{2}$/.test(text)) {
      const dateOnly = new Date(text + 'T00:00:00Z');
      return Number.isNaN(dateOnly.getTime()) ? null : dateOnly;
    }
    text = text.replace(/(\.\d{3})\d+/, '$1');
    let date = new Date(text);
    if (Number.isNaN(date.getTime())) {
      date = new Date(text.replace(' ', 'T'));
    }
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function fmtDate(value, fallback) {
    const date = parseDate(value);
    if (!date) return fallback == null ? '—' : fallback;
    return dateFmt.format(date);
  }

  function fmtDateTime(value, fallback) {
    const date = parseDate(value);
    if (!date) return fallback == null ? '—' : fallback;
    return dateTimeFmt.format(date);
  }

  function relativeTime(value) {
    const date = parseDate(value);
    if (!date) return '';
    const diffSeconds = (date.getTime() - Date.now()) / 1000;
    const abs = Math.abs(diffSeconds);
    if (abs < 45) return 'just now';
    if (abs < 3600) return relativeFmt.format(Math.round(diffSeconds / 60), 'minute');
    if (abs < 86400) return relativeFmt.format(Math.round(diffSeconds / 3600), 'hour');
    if (abs < 2592000) return relativeFmt.format(Math.round(diffSeconds / 86400), 'day');
    if (abs < 31536000) return relativeFmt.format(Math.round(diffSeconds / 2592000), 'month');
    return relativeFmt.format(Math.round(diffSeconds / 31536000), 'year');
  }

  function dateOnly(value) {
    const date = parseDate(value);
    if (!date) return '';
    return date.toISOString().slice(0, 10);
  }

  function compactDate(value) {
    const date = parseDate(value);
    if (!date) return '';
    return date.toISOString().slice(0, 10).replace(/-/g, '');
  }

  function formatNumber(value) {
    const n = Number(value);
    return Number.isFinite(n) ? numberFmt.format(n) : '—';
  }

  function plural(count, singular, pluralWord) {
    return count === 1 ? singular : (pluralWord || singular + 's');
  }

  function formatDays(days) {
    const n = Number(days);
    if (!Number.isFinite(n)) return '—';
    if (n < 0) return Math.abs(n) + ' ' + plural(Math.abs(n), 'day') + ' ago';
    return n + ' ' + plural(n, 'day');
  }

  function detectType(value) {
    const text = String(value == null ? '' : value).trim();
    if (/^https?:\/\//i.test(text)) return 'url';
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(text)) return 'email';
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(text)) return 'ip';
    if (/^[a-f0-9]{64}$/i.test(text)) return 'sha256';
    if (/^[a-f0-9]{32}$/i.test(text)) return 'md5';
    if (/^0x[a-f0-9]{40}$/i.test(text)) return 'wallet';
    if (/^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(text)) return 'wallet';
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(text)) return 'domain';
    return 'text';
  }

  function defang(value, type) {
    const text = String(value == null ? '' : value);
    if (!text) return text;
    const kind = type || detectType(text);
    if (kind === 'url') {
      return text
        .replace(/^https:\/\//i, 'hxxps://')
        .replace(/^http:\/\//i, 'hxxp://')
        .replace(/\./g, '[.]');
    }
    if (kind === 'email') {
      return text.replace(/\./g, '[.]').replace(/@/g, '[@]');
    }
    if (kind === 'domain' || kind === 'ip' || kind === 'host') {
      return text.replace(/\./g, '[.]');
    }
    return text;
  }

  function refang(value) {
    return String(value == null ? '' : value)
      .replace(/hxxps:\/\//gi, 'https://')
      .replace(/hxxp:\/\//gi, 'http://')
      .replace(/\[\.\]/g, '.')
      .replace(/\[@\]/g, '@');
  }

  function hostFromUrl(value) {
    const text = String(value == null ? '' : value).trim();
    if (!text) return '';
    try {
      const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : 'https://' + text);
      return url.hostname;
    } catch (error) {
      const match = text.match(/^(?:https?:\/\/)?([^\/?#:]+)/i);
      return match ? match[1] : text;
    }
  }

  function normaliseUrl(value) {
    const text = String(value == null ? '' : value).trim();
    if (!text) return '';
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return text;
    return 'https://' + text;
  }

  function absoluteUrl(value, base) {
    try {
      return new URL(String(value), base || document.baseURI).href;
    } catch (error) {
      return String(value == null ? '' : value);
    }
  }

  function shorten(value, max) {
    const text = String(value == null ? '' : value);
    const limit = max || 12;
    return text.length > limit ? text.slice(0, limit) + '…' : text;
  }

  function shortHash(value, max) {
    const text = String(value == null ? '' : value);
    const limit = max || 12;
    return text.length > limit ? text.slice(0, limit) + '…' : text;
  }

  function humanize(key) {
    const acronyms = {
      ip: 'IP', tls: 'TLS', dns: 'DNS', cdn: 'CDN', whois: 'WHOIS', url: 'URL',
      urls: 'URLs', http: 'HTTP', https: 'HTTPS', wp: 'WP', cors: 'CORS', spf: 'SPF',
      dmarc: 'DMARC', bimi: 'BIMI', asn: 'ASN', ptr: 'PTR', mx: 'MX', ns: 'NS',
      txt: 'TXT', idn: 'IDN', csp: 'CSP', hsts: 'HSTS', sha256: 'SHA-256',
      sha1: 'SHA-1', mmh3: 'mmh3', btc: 'BTC', eth: 'ETH', id: 'ID', ids: 'IDs',
      api: 'API', ui: 'UI', pdf: 'PDF', html: 'HTML', js: 'JS', css: 'CSS'
    };
    return String(key == null ? '' : key)
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .split(' ')
      .map(function (word) {
        const lower = word.toLowerCase();
        if (acronyms[lower]) return acronyms[lower];
        return lower.charAt(0).toUpperCase() + lower.slice(1);
      })
      .join(' ');
  }

  function stripProtocol(value) {
    return String(value == null ? '' : value).replace(/^[a-z][a-z0-9+.-]*:\/\//i, '');
  }

  function titleForStatus(status) {
    const text = String(status == null ? '' : status).toLowerCase();
    if (text === 'ok' || text === 'found' || text === 'clear' || text === 'match') return humanize(text);
    return humanize(text);
  }

  function unique(values) {
    const seen = new Set();
    const out = [];
    (values || []).forEach(function (value) {
      const key = typeof value === 'string' ? value.toLowerCase() : JSON.stringify(value);
      if (seen.has(key)) return;
      seen.add(key);
      out.push(value);
    });
    return out;
  }

  function truncateMiddle(value, max) {
    const text = String(value == null ? '' : value);
    const limit = max || 60;
    if (text.length <= limit) return text;
    const half = Math.floor((limit - 1) / 2);
    return text.slice(0, half) + '…' + text.slice(text.length - half);
  }

  function isPlainObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  C.format = {
    parseDate: parseDate,
    fmtDate: fmtDate,
    fmtDateTime: fmtDateTime,
    dateOnly: dateOnly,
    compactDate: compactDate,
    relativeTime: relativeTime,
    formatNumber: formatNumber,
    formatDays: formatDays,
    plural: plural,
    detectType: detectType,
    defang: defang,
    refang: refang,
    hostFromUrl: hostFromUrl,
    normaliseUrl: normaliseUrl,
    absoluteUrl: absoluteUrl,
    shorten: shorten,
    shortHash: shortHash,
    humanize: humanize,
    stripProtocol: stripProtocol,
    unique: unique,
    truncateMiddle: truncateMiddle,
    isPlainObject: isPlainObject
  };
})();
