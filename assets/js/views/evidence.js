(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  let selectedRef = '';
  let previewMode = 'rendered';
  let allowRemote = false;
  let previewToken = 0;
  let activeObjectUrl = '';

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function findItem(items, ref) {
    return items.find(function (item) { return item.ref === ref; }) || null;
  }

  function statusFor(item) {
    if (item.record) return UI.badge('Found', 'ok', 'check');
    if (item.ambiguous && item.ambiguous.length) return UI.badge('Ambiguous', 'warning', 'alert-triangle');
    return UI.badge('Missing', 'warning', 'x-circle');
  }

  function evidenceSummary(items, model) {
    const found = items.filter(function (item) { return Boolean(item.record); }).length;
    return {
      total: items.length,
      found: found,
      missing: items.length - found,
      declaredErrors: asArray(model.evidenceErrors).length
    };
  }

  function stats(items, model) {
    const summary = evidenceSummary(items, model);
    return UI.statGrid([
      UI.stat('References', summary.total, 'Linked from page scans', { icon: 'archive' }),
      UI.stat('Resolved', summary.found, summary.found === summary.total && summary.total ? 'All files matched' : summary.missing + ' still missing', { icon: 'check' }),
      UI.stat('Missing', summary.missing, summary.missing ? 'Add the scan folder to resolve' : 'Nothing missing', { icon: 'x-circle' }),
      UI.stat('Declared errors', summary.declaredErrors, 'Reported by the scanner', { icon: 'alert-triangle' })
    ]);
  }

  function evidenceErrorsCard(model) {
    const errors = asArray(model.evidenceErrors);
    if (!errors.length) return null;
    const list = D.el('div', { class: 'stack' });
    errors.forEach(function (error) {
      list.appendChild(D.el('div', { class: 'error-item' },
        D.el('div', { class: 'error-task', text: 'evidence_errors' }),
        D.el('div', { class: 'error-msg', text: String(error) })
      ));
    });
  return UI.card('Scanner evidence errors', list, {
    icon: 'alert-triangle'
  });
  }

  function locateButton(ref) {
    return D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        window.dispatchEvent(new CustomEvent('clouseau:locate-evidence', { detail: { ref: ref } }));
      }
    }, D.icon('folder-open'), 'Locate file');
  }

  function evidenceTable(items, onSelect) {
    const wrap = D.el('div', { class: 'table-wrap' });
    const table = D.el('table', { class: 'data-table evidence-table' });
    const thead = D.el('thead');
    const headRow = D.el('tr');
    ['Page', 'Evidence reference', 'Status', 'Size', 'Expected SHA-256', ''].forEach(function (label) {
      headRow.appendChild(D.el('th', { text: label }));
    });
    thead.appendChild(headRow);
    const tbody = D.el('tbody');
    const rows = new Map();

    items.forEach(function (item) {
      const page = item.page || {};
      const tr = D.el('tr', {
        class: item.ref === selectedRef ? 'selected' : '',
        onClick: function () { onSelect(item.ref); },
        style: { cursor: 'pointer' }
      });
      const pageCell = D.el('td');
      pageCell.appendChild(D.el('div', { class: 'small strong', text: page.title || 'Untitled page' }));
      if (page.url) pageCell.appendChild(UI.urlValue(page.url, { open: false }));
      tr.appendChild(pageCell);

      const refCell = D.el('td');
      refCell.appendChild(D.el('span', { class: 'file-path' }, D.el('bdi', { text: item.ref })));
      const copy = UI.copyButton(item.ref, 'evidence reference');
      if (copy) refCell.appendChild(copy);
      tr.appendChild(refCell);

      tr.appendChild(D.el('td', {}, statusFor(item)));
      tr.appendChild(D.el('td', { class: 'nowrap tiny muted', text: item.record ? C.dom.formatBytes(item.record.size) : '—' }));
      tr.appendChild(D.el('td', {}, page.sha256 ? UI.hashValue(page.sha256, 'expected page hash') : D.el('span', { class: 'muted', text: '—' })));

      const action = D.el('td', { class: 'nowrap' });
      action.appendChild(D.el('button', {
        class: 'btn btn-ghost btn-sm',
        type: 'button',
        onClick: function (event) {
          event.stopPropagation();
          onSelect(item.ref);
        }
      }, D.icon('eye'), 'Preview'));
      tr.appendChild(action);

      rows.set(item.ref, tr);
      tbody.appendChild(tr);
    });

    table.appendChild(thead);
    table.appendChild(tbody);
    wrap.appendChild(table);
    return {
      node: wrap,
      select: function (ref) {
        rows.forEach(function (row, key) { row.classList.toggle('selected', key === ref); });
      }
    };
  }

  function hashStatus(page, record, container) {
    container.textContent = '';
    container.appendChild(D.el('span', { class: 'muted tiny', text: 'Computing SHA-256…' }));
    C.evidence.sha256(record).then(function (computed) {
      D.clear(container);
      if (!computed) {
        container.appendChild(D.el('span', { class: 'muted tiny', text: 'SHA-256 unavailable in this browser.' }));
        return;
      }
      container.appendChild(D.el('span', { class: 'tiny muted', text: 'SHA-256' }));
      container.appendChild(UI.hashValue(computed, 'computed hash'));
      if (page && page.sha256) {
        const match = String(page.sha256).toLowerCase() === computed.toLowerCase();
        container.appendChild(match
          ? UI.badge('Matches report', 'ok', 'check')
          : UI.badge('Mismatch', 'critical', 'alert-triangle'));
      }
    });
  }

  function readText(record) {
    if (!record._previewTextPromise) {
      record._previewTextPromise = C.files.readText(record).catch(function (error) {
        return Promise.reject(error);
      });
    }
    return record._previewTextPromise;
  }

  function imagePreview(record) {
    if (activeObjectUrl) URL.revokeObjectURL(activeObjectUrl);
    activeObjectUrl = URL.createObjectURL(record.file);
    const img = D.el('img', {
      src: activeObjectUrl,
      alt: record.name,
      style: { display: 'block', maxWidth: '100%', maxHeight: '64vh', margin: '0 auto', background: '#fff' }
    });
    return img;
  }

  function buildPreview(model, item, host) {
    const token = ++previewToken;
    D.clear(host);
    const record = item.record;
    const page = item.page || {};

    if (!record) {
      const empty = D.el('div', { class: 'evidence-empty' });
      empty.appendChild(D.icon('archive'));
      empty.appendChild(D.el('strong', { text: 'Evidence file not found' }));
      empty.appendChild(D.el('p', { text: 'Expected reference: ' + item.ref }));
      if (item.ambiguous && item.ambiguous.length) {
        empty.appendChild(D.el('p', { class: 'tiny', text: 'Multiple files share this basename: ' + item.ambiguous.map(function (entry) { return entry.path; }).join(', ') }));
      }
      empty.appendChild(locateButton(item.ref));
      host.appendChild(empty);
      return;
    }

    const isHtml = C.evidence.isHtml(record, page);
    const isImage = C.evidence.isImage(record, page);
    const isText = isHtml || /^(?:text\/|application\/(?:json|xml|javascript|x-httpd))/.test(String(record.file.type || '')) || /\.(?:txt|json|xml|har|log|md|css|js)$/i.test(record.name);

    const toolbar = D.el('div', { class: 'evidence-toolbar' });
    const fileInfo = D.el('div', { class: 'row-wrap' });
    fileInfo.appendChild(D.el('span', { class: 'mono small strong', text: record.name }));
    fileInfo.appendChild(UI.badge(item.method || 'resolved', 'info'));
    fileInfo.appendChild(D.el('span', { class: 'tiny muted', text: C.dom.formatBytes(record.size) }));
    toolbar.appendChild(fileInfo);

    if (isText) {
      const segmented = D.el('div', { class: 'segmented', role: 'group', 'aria-label': 'Preview mode' });
      [['rendered', 'Rendered'], ['source', 'Source']].forEach(function (mode) {
        segmented.appendChild(D.el('button', {
          type: 'button',
          class: previewMode === mode[0] ? 'active' : '',
          onClick: function () {
            previewMode = mode[0];
            buildPreview(model, item, host);
          }
        }, mode[1]));
      });
      toolbar.appendChild(segmented);
    }

    const spacer = D.el('div', { class: 'toolbar-spacer' });
    toolbar.appendChild(spacer);

    if (isHtml) {
      const remoteLabel = D.el('label', { class: 'switch-row', style: { padding: '0', gap: '6px' } });
      remoteLabel.appendChild(D.el('span', { class: 'tiny muted', text: 'Remote assets' }));
      const remoteSwitch = D.el('span', { class: 'switch' });
      remoteSwitch.appendChild(D.el('input', {
        type: 'checkbox',
        checked: allowRemote,
        onChange: function (event) {
          allowRemote = event.target.checked;
          buildPreview(model, item, host);
        }
      }));
      remoteSwitch.appendChild(D.el('span', { class: 'switch-track' }));
      remoteLabel.appendChild(remoteSwitch);
      toolbar.appendChild(remoteLabel);
    }

    toolbar.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        const target = D.el('div', { class: 'row-wrap' });
        hashStatus(page, record, target);
        D.modal({
          title: 'Verify evidence hash',
          icon: 'hash',
          body: D.el('div', { class: 'stack' }, target),
          actions: [{ label: 'Close', variant: 'btn-ghost' }]
        });
      }
    }, D.icon('hash'), 'Verify'));

    toolbar.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () { D.downloadFile(record.name, record.file, record.file.type); }
    }, D.icon('download'), 'Download'));

    const meta = D.el('div', { class: 'evidence-toolbar' });
    meta.appendChild(D.el('span', { class: 'file-path', text: record.path }));
    const methodBadge = UI.badge(item.method || 'resolved', 'muted');
    meta.appendChild(methodBadge);
    const hashHolder = D.el('div', { class: 'row' });
    meta.appendChild(hashHolder);
    hashStatus(page, record, hashHolder);

    const body = D.el('div');
    body.appendChild(toolbar);
    body.appendChild(meta);
    const frameWrap = D.el('div', { class: 'evidence-frame-wrap' });

    if (isImage) {
      frameWrap.appendChild(imagePreview(record));
      body.appendChild(frameWrap);
    } else if (isText) {
      readText(record).then(function (text) {
        if (token !== previewToken) return;
        D.clear(frameWrap);
        if (isHtml && previewMode === 'rendered') {
          const frame = D.el('iframe', {
            sandbox: '',
            referrerpolicy: 'no-referrer',
            title: 'Sandboxed evidence preview'
          });
          const baseUrl = allowRemote && page.url ? page.url : '';
          frame.srcdoc = C.evidence.buildPreviewHtml(text, { remote: allowRemote && Boolean(baseUrl), baseUrl: baseUrl });
          frameWrap.appendChild(frame);
          if (allowRemote) {
            frameWrap.appendChild(D.el('div', {
              class: 'tiny',
              style: { position: 'absolute', right: '10px', bottom: '10px', padding: '3px 7px', background: 'var(--warning-soft)', color: 'var(--warning)', border: '1px solid var(--border)', borderRadius: '5px' },
              text: 'Remote assets enabled'
            }));
          }
        } else if (isHtml) {
          const source = D.el('pre', { class: 'code-block evidence-source' });
          source.textContent = text.length > 1000000 ? text.slice(0, 1000000) + '\n\n[source truncated in preview]' : text;
          frameWrap.style.height = 'auto';
          frameWrap.style.background = 'transparent';
          frameWrap.appendChild(source);
        } else {
          const source = D.el('pre', { class: 'code-block evidence-source' });
          source.textContent = text.length > 1000000 ? text.slice(0, 1000000) + '\n\n[content truncated in preview]' : text;
          frameWrap.style.height = 'auto';
          frameWrap.style.background = 'transparent';
          frameWrap.appendChild(source);
        }
      }).catch(function (error) {
        if (token !== previewToken) return;
        D.clear(frameWrap);
        frameWrap.style.height = 'auto';
        frameWrap.style.background = 'transparent';
        frameWrap.appendChild(D.el('div', { class: 'evidence-empty' },
          D.icon('alert-triangle'),
          D.el('strong', { text: 'Could not read evidence' }),
          D.el('p', { text: error.message || String(error) })
        ));
      });
      body.appendChild(frameWrap);
    } else {
      D.clear(frameWrap);
      frameWrap.style.height = 'auto';
      frameWrap.style.background = 'transparent';
      frameWrap.appendChild(D.el('div', { class: 'evidence-empty' },
        D.icon('file-text'),
        D.el('strong', { text: 'Binary evidence file' }),
        D.el('p', { text: 'This file type cannot be previewed safely. Download it to inspect it locally.' })
      ));
      body.appendChild(frameWrap);
    }

    if (isHtml) {
      body.appendChild(D.el('div', { class: 'tiny muted', style: { padding: '8px 12px' }, text: 'Preview is sandboxed: scripts, forms, popups, and top navigation are blocked.' }));
    }

    const card = UI.card(previewMode === 'source' && isHtml ? 'Source preview' : 'Preview', body, {
      flush: true,
      icon: 'eye',
      subtitle: page.url || item.ref
    });
    host.appendChild(card);
  }

  C.views = C.views || {};
  C.views.evidence = function (model) {
    const view = D.el('div', { class: 'view' });
    let items = model.evidence && model.evidence.length ? model.evidence : C.evidence.resolveAll(model);
    if (!items.length) {
const empty = UI.card('Evidence', D.el('div', { class: 'evidence-empty' },
    D.icon('archive'),
    D.el('strong', { text: 'No saved evidence' })
  ), { flush: true, icon: 'archive' });
      view.appendChild(empty);
      return view;
    }

    if (C.state.evidenceFocus) {
      selectedRef = C.state.evidenceFocus;
      C.state.evidenceFocus = '';
    }
    if (!findItem(items, selectedRef)) {
      const firstFound = items.find(function (item) { return Boolean(item.record); });
      selectedRef = (firstFound || items[0]).ref;
    }

    view.appendChild(stats(items, model));

    const errors = evidenceErrorsCard(model);
    if (errors) view.appendChild(errors);

    let tableControl = null;
    const previewHost = D.el('div');
    const onSelect = function (ref) {
      selectedRef = ref;
      if (tableControl) tableControl.select(ref);
      const selected = findItem(items, ref);
      if (selected) buildPreview(model, selected, previewHost);
    };

    tableControl = evidenceTable(items, onSelect);
    view.appendChild(UI.section('Evidence files', 'evidence-files', [
      UI.card('References', tableControl.node, { flush: true, icon: 'archive' })
    ], { icon: 'archive', count: items.length }));

    const preview = D.el('div', { id: 'evidence-preview' });
    const selected = findItem(items, selectedRef);
    if (selected) buildPreview(model, selected, preview);
    else {
      const empty = D.el('div', { class: 'evidence-empty' },
        D.icon('archive'),
        D.el('strong', { text: 'Select a piece of evidence' }),
        D.el('p', { text: 'Choose a referenced page from the table above to preview it.' })
      );
      preview.appendChild(UI.card('Preview', empty, { flush: true, icon: 'eye' }));
    }
    view.appendChild(preview);
    return view;
  };
})();
