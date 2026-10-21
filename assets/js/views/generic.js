(function () {
  'use strict';

  const C = window.C = window.C || {};
  const D = C.dom;
  const UI = C.ui;

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
  }

  function looksUrl(value) {
    return /^https?:\/\//i.test(String(value || ''));
  }

  function primitive(value, key, model) {
    if (value == null) return D.el('span', { class: 'muted', text: 'null' });
    if (typeof value === 'boolean') return UI.boolBadge(value, 'True', 'False', 'info', 'muted');
    if (typeof value === 'number') return D.el('span', { class: 'mono', text: String(value) });
    const text = String(value);
    if (!text) return D.el('span', { class: 'muted', text: '—' });
    if (looksUrl(text)) return UI.urlValue(text, { open: true, warn: true, source: key || 'value' });
    const type = C.format.detectType(text);
    if (type !== 'text') {
      return D.el('span', { class: 'row-wrap' },
        UI.copyable(text, key || type, type, { mono: true }),
        UI.pivotBtn(type, text, { model: model })
      );
    }
    return UI.copyable(text, key || 'value', 'text');
  }

  function valueNode(value, key, depth, model) {
    if (depth > 3) {
      return UI.collapsible('Nested value', UI.codeBlock(JSON.stringify(value, null, 2)), false);
    }
    if (Array.isArray(value)) {
      if (!value.length) return D.el('span', { class: 'muted', text: '[]' });
      const primitives = value.every(function (item) { return item == null || typeof item !== 'object'; });
      if (primitives) {
        const type = value.length ? C.format.detectType(String(value[0])) : 'text';
        return UI.chipList(value.map(function (item) { return item == null ? '' : String(item); }), {
          type: type,
          pivot: type !== 'text',
          ctx: { model: model },
          variant: '',
          empty: 'Empty list.'
        });
      }
      const list = D.el('div', { class: 'stack' });
      value.slice(0, 30).forEach(function (item, index) {
        list.appendChild(UI.collapsible('Item ' + (index + 1), valueNode(item, key, depth + 1, model), false));
      });
      if (value.length > 30) {
        list.appendChild(D.el('div', { class: 'tiny muted', text: (value.length - 30) + ' more items not shown' }));
      }
      return list;
    }
    if (isObject(value)) {
      const keys = Object.keys(value);
      if (!keys.length) return D.el('span', { class: 'muted', text: '{}' });
      const rows = keys.map(function (childKey) {
        return UI.kvRow(childKey, valueNode(value[childKey], childKey, depth + 1, model));
      });
      return UI.kvList(rows);
    }
    return primitive(value, key, model);
  }

  function resultCard(model, task, entry, index, total) {
    const hasError = Boolean(entry.error);
    const result = entry.result;
    const title = total > 1 ? 'Result ' + (index + 1) : 'Result';
    const actions = [hasError ? UI.badge('Error', 'critical', 'x-circle') : UI.badge('Result', 'ok', 'check')];
    const content = [];
    if (hasError) {
      content.push(UI.notice('warning', 'alert-triangle', 'Task error', String(entry.error)));
    }
    if (result !== undefined) {
      if (isObject(result)) {
        content.push(UI.kvList(Object.keys(result).map(function (key) {
          return UI.kvRow(key, valueNode(result[key], key, 1, model));
        })));
      } else if (Array.isArray(result)) {
        content.push(valueNode(result, task, 1, model));
      } else {
        content.push(D.el('div', { class: 'mono' }, primitive(result, task, model)));
      }
    } else if (!hasError) {
      content.push(UI.emptyInline('This entry has neither a result nor an error.'));
    }
    return UI.card(title, content, {
      icon: hasError ? 'alert-triangle' : 'file-text',
      subtitle: C.format.humanize(task),
      actions: actions
    });
  }

  C.views = C.views || {};
  C.views.generic = function (model) {
    const route = C.router.parse();
    let task = '';
    if (route.tab && route.tab.indexOf('task:') === 0) task = route.tab.slice(5);
    const view = D.el('div', { class: 'view' });

    if (!task || !model.hasTask(task)) {
      const tasks = model.unknownTasks.length ? model.unknownTasks : Array.from(model.byTask.keys());
      const list = D.el('div', { class: 'stack' });
      tasks.forEach(function (name) {
        const row = D.el('div', { class: 'check-row' });
        row.appendChild(D.el('div', { class: 'check-name', text: name }));
        row.appendChild(D.el('button', {
          class: 'btn btn-ghost btn-sm',
          type: 'button',
          onClick: function () { C.router.go(model.id, 'task:' + name); }
        }, 'Open', D.icon('chevron-right')));
        list.appendChild(row);
      });
      view.appendChild(UI.card('Generic result viewer', list, { icon: 'file-text' }));
      return view;
    }

    const entries = model.getEntries(task);
    view.appendChild(UI.card('Generic view', UI.notice('info', 'info', 'No dedicated renderer'), {
      icon: 'info',
      subtitle: 'Raw task output shown without a dedicated visualization.'
    }));

    const section = UI.section(C.format.humanize(task), 'generic-result', entries.map(function (entry, index) {
      return resultCard(model, task, entry, index, entries.length);
    }), {
      icon: 'file-text',
      count: entries.length,
      subtitle: 'Task key: ' + task + '. Shown without a dedicated renderer.'
    });
    view.appendChild(section);
    return view;
  };
})();
