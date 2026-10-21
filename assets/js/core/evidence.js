(function () {
  'use strict';

  const C = window.C = window.C || {};
  const MAX_HASH_BYTES = 50 * 1024 * 1024;

  function collect(model) {
    const html = model.getResult('html_scan') || {};
    const pages = Array.isArray(html.pages) ? html.pages : [];
    const refs = [];
    pages.forEach(function (page) {
      if (page && page.evidence_file) {
        refs.push({ page: page, ref: page.evidence_file });
      }
    });
    return refs;
  }

  function resolveAll(model) {
    return collect(model).map(function (item) {
      const resolved = C.files.resolveReference(item.ref, model.path);
      return {
        page: item.page,
        ref: item.ref,
        record: resolved.record,
        method: resolved.method,
        candidates: resolved.candidates,
        ambiguous: resolved.ambiguous || []
      };
    });
  }

  function refresh(model) {
    model.evidence = resolveAll(model);
    return model.evidence;
  }

  function summary(model) {
    const items = model.evidence && model.evidence.length ? model.evidence : resolveAll(model);
    const found = items.filter(function (item) { return Boolean(item.record); }).length;
    return {
      total: items.length,
      found: found,
      missing: items.length - found,
      ambiguous: items.filter(function (item) { return item.ambiguous && item.ambiguous.length; }).length
    };
  }

  async function sha256(record) {
    if (!record || !record.file) return null;
    if (record._sha256) return record._sha256;
    if (record._sha256Promise) return record._sha256Promise;
    if (!window.crypto || !window.crypto.subtle) return null;
    if (record.size > MAX_HASH_BYTES) return null;
    record._sha256Promise = (async function () {
      try {
        const buffer = await record.file.arrayBuffer();
        const digest = await window.crypto.subtle.digest('SHA-256', buffer);
        const hex = Array.from(new Uint8Array(digest)).map(function (byte) {
          return byte.toString(16).padStart(2, '0');
        }).join('');
        record._sha256 = hex;
        return hex;
      } catch (error) {
        return null;
      }
    })();
    return record._sha256Promise;
  }

  function removeDangerousNodes(doc) {
    const selectors = 'script,base,iframe,frame,frameset,object,embed,applet,form';
    doc.querySelectorAll(selectors).forEach(function (node) {
      if (node.parentNode) node.parentNode.removeChild(node);
    });
    doc.querySelectorAll('meta').forEach(function (meta) {
      const equiv = (meta.getAttribute('http-equiv') || '').toLowerCase();
      if (equiv === 'refresh' || equiv === 'set-cookie') {
        if (meta.parentNode) meta.parentNode.removeChild(meta);
      }
    });
    doc.querySelectorAll('link').forEach(function (link) {
      const rel = (link.getAttribute('rel') || '').toLowerCase();
      if (rel === 'preload' || rel === 'prefetch' || rel === 'preconnect' || rel === 'dns-prefetch') {
        if (link.parentNode) link.parentNode.removeChild(link);
      }
    });
  }

  function scrubAttributes(doc) {
    doc.querySelectorAll('*').forEach(function (node) {
      Array.from(node.attributes || []).forEach(function (attr) {
        const name = attr.name.toLowerCase();
        const value = String(attr.value || '');
        if (name.indexOf('on') === 0 || name === 'srcdoc' || name === 'formaction') {
          node.removeAttribute(attr.name);
          return;
        }
        if ((name === 'href' || name === 'src' || name === 'xlink:href') && /^\s*(?:javascript|vbscript|data:text\/html|data:application\/xhtml)/i.test(value)) {
          node.removeAttribute(attr.name);
          return;
        }
        if (name === 'style' && /(?:expression\s*\(|url\s*\(\s*['"]?\s*(?:javascript|vbscript))/i.test(value)) {
          node.removeAttribute(attr.name);
        }
      });
    });
  }

  function buildPreviewHtml(html, options) {
    const opts = options || {};
    const doc = new DOMParser().parseFromString(String(html == null ? '' : html), 'text/html');
    removeDangerousNodes(doc);
    scrubAttributes(doc);

    const head = doc.head || doc.createElement('head');
    if (!doc.head) {
      doc.documentElement.insertBefore(head, doc.documentElement.firstChild);
    }

    const csp = opts.remote
      ? "default-src 'none'; script-src 'none'; connect-src 'none'; img-src data: blob: https: http:; style-src 'unsafe-inline' https: http:; font-src data: https: http:; media-src data: blob: https: http:; object-src 'none'; frame-src 'none'; form-action 'none'"
      : "default-src 'none'; script-src 'none'; connect-src 'none'; img-src data: blob:; style-src 'unsafe-inline'; font-src data:; media-src data: blob:; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'";

    const meta = doc.createElement('meta');
    meta.setAttribute('http-equiv', 'Content-Security-Policy');
    meta.setAttribute('content', csp);
    head.insertBefore(meta, head.firstChild);

    const referrer = doc.createElement('meta');
    referrer.setAttribute('name', 'referrer');
    referrer.setAttribute('content', 'no-referrer');
    head.insertBefore(referrer, head.firstChild);

    if (!doc.querySelector('meta[charset]')) {
      const charset = doc.createElement('meta');
      charset.setAttribute('charset', 'utf-8');
      head.insertBefore(charset, head.firstChild);
    }

    if (opts.remote && opts.baseUrl) {
      const base = doc.createElement('base');
      base.setAttribute('href', opts.baseUrl);
      head.insertBefore(base, head.firstChild);
    }

    return '<!doctype html>' + doc.documentElement.outerHTML;
  }

  function isImage(record, page) {
    if (!record) return false;
    const type = String((page && page.content_type) || '');
    if (/^image\//i.test(type)) return true;
    return /\.(?:png|jpe?g|gif|webp|bmp|svg|avif)$/i.test(record.name);
  }

  function isHtml(record, page) {
    if (!record) return false;
    const type = String((page && page.content_type) || '');
    if (/html/i.test(type)) return true;
    return /\.(?:html?|xhtml)$/i.test(record.name);
  }

  C.evidence = {
    collect: collect,
    resolveAll: resolveAll,
    refresh: refresh,
    summary: summary,
    sha256: sha256,
    buildPreviewHtml: buildPreviewHtml,
    isImage: isImage,
    isHtml: isHtml,
    MAX_HASH_BYTES: MAX_HASH_BYTES
  };
})();
