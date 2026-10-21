(function () {
  'use strict';

  const C = window.C = window.C || {};
  const listeners = new Set();

  function decode(value) {
    try { return decodeURIComponent(value); } catch (error) { return value; }
  }

  function parse() {
    const raw = String(window.location.hash || '').replace(/^#\/?/, '');
    if (!raw) return { view: 'home' };
    const parts = raw.split('/').filter(Boolean);
    if ((parts[0] === 'r' || parts[0] === 'report') && parts[1]) {
      return {
        view: 'report',
        id: decode(parts[1]),
        tab: parts[2] ? decode(parts[2]) : 'overview'
      };
    }
    return { view: 'home' };
  }

  function hashFor(id, tab) {
    return '#/r/' + encodeURIComponent(id) + '/' + encodeURIComponent(tab || 'overview');
  }

  function go(id, tab) {
    const next = hashFor(id, tab);
    if (window.location.hash === next) {
      emit(parse());
      return;
    }
    window.location.hash = next;
  }

  function home() {
    if (window.location.hash) {
      history.pushState('', document.title, window.location.pathname + window.location.search);
    }
    emit({ view: 'home' });
  }

  function emit(route) {
    listeners.forEach(function (listener) {
      try { listener(route); } catch (error) { console.error(error); }
    });
  }

  function onChange(listener) {
    listeners.add(listener);
    return function () { listeners.delete(listener); };
  }

  window.addEventListener('hashchange', function () { emit(parse()); });

  C.router = {
    parse: parse,
    go: go,
    home: home,
    onChange: onChange,
    current: function () { return parse(); }
  };
})();
