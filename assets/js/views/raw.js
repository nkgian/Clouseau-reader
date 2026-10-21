(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;
  const MAX_DISPLAY = 2 * 1024 * 1024;
  const MAX_MARKS = 1000;

  function appendHighlighted(pre, text, query) {
    if (!query) {
      pre.textContent = text;
      return 0;
    }
    const needle = query.toLowerCase();
    const haystack = text.toLowerCase();
    let index = 0;
    let count = 0;
    while (index < text.length) {
      const found = haystack.indexOf(needle, index);
      if (found === -1) {
        pre.appendChild(document.createTextNode(text.slice(index)));
        break;
      }
      if (found > index) pre.appendChild(document.createTextNode(text.slice(index, found)));
      const mark = document.createElement('mark');
      mark.textContent = text.slice(found, found + query.length);
      pre.appendChild(mark);
      count += 1;
      index = found + query.length;
      if (count >= MAX_MARKS) {
        pre.appendChild(document.createTextNode(text.slice(index)));
        break;
      }
    }
    return count;
  }

  C.views = C.views || {};
  C.views.raw = function (model) {
    const pretty = JSON.stringify(model.raw, null, 2);
    const displayText = pretty.length > MAX_DISPLAY ? pretty.slice(0, MAX_DISPLAY) : pretty;
    let query = '';
    let wrap = false;

    const view = D.el('div', { class: 'view' });
    view.appendChild(UI.statGrid([
      UI.stat('Report size', C.dom.formatBytes(pretty.length), 'Pretty-printed JSON', { icon: 'file-text' }),
      UI.stat('Result entries', model.results.length, model.taskCount + ' task' + (model.taskCount === 1 ? '' : 's'), { icon: 'layers' }),
      UI.stat('Unique tasks', model.byTask.size, 'Including unrecognised modules', { icon: 'list' }),
      UI.stat('Module errors', model.errorCount, model.errorCount ? 'Inspect below' : 'No errors reported', { icon: 'alert-triangle' })
    ]));

    if (model.errorCount) {
      view.appendChild(UI.card('Errors', UI.errorList(model.errors), { icon: 'alert-triangle' }));
    }
    if (model.unknownTasks.length) {
      const list = D.el('div', { class: 'stack' });
      model.unknownTasks.forEach(function (task) {
        const row = D.el('div', { class: 'check-row' });
        row.appendChild(D.el('div', { class: 'check-name', text: task }));
        row.appendChild(D.el('button', {
          class: 'btn btn-ghost btn-sm',
          type: 'button',
          onClick: function () { C.router.go(model.id, 'task:' + task); }
        }, 'Open generic view', D.icon('chevron-right')));
        list.appendChild(row);
      });
view.appendChild(UI.card('Unrecognised modules', list, {
    icon: 'file-text'
  }));
    }

    const toolbar = D.el('div', { class: 'toolbar' });
    const search = D.el('input', {
      class: 'input input-sm',
      type: 'search',
      placeholder: 'Search raw JSON…',
      'aria-label': 'Search raw JSON'
    });
    const matches = D.el('span', { class: 'tiny muted' });
    toolbar.appendChild(search);
    toolbar.appendChild(matches);
    toolbar.appendChild(D.el('div', { class: 'toolbar-spacer' }));
    const wrapLabel = D.el('label', { class: 'row tiny muted' });
    const wrapToggle = D.el('input', { type: 'checkbox' });
    wrapLabel.appendChild(wrapToggle);
    wrapLabel.appendChild(D.el('span', { text: 'Wrap lines' }));
    toolbar.appendChild(wrapLabel);
    toolbar.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () { D.copyText(pretty, 'raw JSON'); }
    }, D.icon('copy'), 'Copy JSON'));
    toolbar.appendChild(D.el('button', {
      class: 'btn btn-ghost btn-sm',
      type: 'button',
      onClick: function () {
        const host = (model.host || 'report').replace(/[^a-z0-9.-]+/gi, '_');
        D.downloadFile(host + '_report.json', pretty, 'application/json');
      }
    }, D.icon('download'), 'Download'));

    const pre = D.el('pre', { class: 'code-block raw-json' });
    const body = D.el('div', { class: 'stack' }, toolbar, pre);
    if (pretty.length > MAX_DISPLAY) {
      body.appendChild(UI.notice('warning', 'alert-triangle', 'Large report',
        'Only the first ' + C.dom.formatBytes(MAX_DISPLAY) + ' of ' + C.dom.formatBytes(pretty.length) + ' are displayed. Copy or download the full JSON.'));
    }

    function draw() {
      D.clear(pre);
      const count = appendHighlighted(pre, displayText, query);
      if (!query) {
        matches.textContent = '';
      } else {
        matches.textContent = count >= MAX_MARKS
          ? 'First ' + MAX_MARKS + ' matches highlighted'
          : count + ' ' + C.format.plural(count, 'match', 'matches');
      }
      pre.style.whiteSpace = wrap ? 'pre-wrap' : 'pre';
      pre.style.wordBreak = wrap ? 'break-word' : 'normal';
      if (query) {
        const mark = pre.querySelector('mark');
        if (mark) {
          const top = mark.getBoundingClientRect().top - pre.getBoundingClientRect().top + pre.scrollTop - pre.clientHeight / 3;
          pre.scrollTop = Math.max(0, top);
        }
      } else {
        pre.scrollTop = 0;
      }
    }

    search.addEventListener('input', function () {
      query = search.value;
      draw();
    });
    wrapToggle.addEventListener('change', function () {
      wrap = wrapToggle.checked;
      draw();
    });
    draw();

    view.appendChild(UI.section('Raw JSON', 'raw-json', UI.card('report.json', body, {
      icon: 'code',
      subtitle: model.path
    }), {
      icon: 'code',
      subtitle: 'Exact report document as loaded, including fields not surfaced in the views.'
    }));

    return view;
  };
})();
