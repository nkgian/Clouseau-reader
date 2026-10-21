(function () {
  'use strict';

  const C = window.C = window.C || {};
  const records = new Map();
  const basenameIndex = new Map();
  const roots = new Set();
  const MAX_REPORT_BYTES = 64 * 1024 * 1024;

  function normalisePath(value) {
    let path = String(value == null ? '' : value).replace(/\\/g, '/');
    path = path.replace(/\/+/g, '/');
    path = path.replace(/^\.\//, '');
    path = path.replace(/^\/+/, '');
    while (path.indexOf('../') === 0) path = path.slice(3);
    return path;
  }

  function pathKey(value) {
    return normalisePath(value).toLowerCase();
  }

  function basename(value) {
    const path = normalisePath(value).replace(/\/+$/, '');
    const index = path.lastIndexOf('/');
    return index === -1 ? path : path.slice(index + 1);
  }

  function dirname(value) {
    const path = normalisePath(value).replace(/\/+$/, '');
    const index = path.lastIndexOf('/');
    return index === -1 ? '' : path.slice(0, index);
  }

  function rootName(value) {
    const path = normalisePath(value);
    if (!path) return '';
    const index = path.indexOf('/');
    return index === -1 ? '' : path.slice(0, index);
  }

  function unindexBasename(record) {
    const key = record.name.toLowerCase();
    const set = basenameIndex.get(key);
    if (!set) return;
    set.delete(record.key);
    if (!set.size) basenameIndex.delete(key);
  }

  function indexBasename(record) {
    const key = record.name.toLowerCase();
    if (!basenameIndex.has(key)) basenameIndex.set(key, new Set());
    basenameIndex.get(key).add(record.key);
  }

  function addFile(path, file, source) {
    if (!file) return null;
    const resolvedPath = normalisePath(path || file.name || 'file');
    const key = resolvedPath.toLowerCase();
    const existing = records.get(key);
    if (existing) unindexBasename(existing);
    const record = {
      path: resolvedPath,
      key: key,
      name: basename(resolvedPath),
      file: file,
      size: file.size || 0,
      lastModified: file.lastModified || 0,
      source: source || 'file',
      ext: (basename(resolvedPath).split('.').pop() || '').toLowerCase()
    };
    records.set(key, record);
    indexBasename(record);
    const root = rootName(resolvedPath);
    if (root) roots.add(root);
    return record;
  }

  function addFileList(fileList, source) {
    const list = Array.from(fileList || []);
    const added = [];
    list.forEach(function (file) {
      const path = file.webkitRelativePath || file.name;
      const record = addFile(path, file, source || (file.webkitRelativePath ? 'folder' : 'file'));
      if (record) added.push(record);
    });
    return added;
  }

  function fileFromEntry(entry) {
    return new Promise(function (resolve, reject) {
      entry.file(resolve, reject);
    });
  }

  function readAllEntries(reader) {
    return new Promise(function (resolve, reject) {
      const all = [];
      const readBatch = function () {
        reader.readEntries(function (entries) {
          if (!entries.length) {
            resolve(all);
            return;
          }
          entries.forEach(function (entry) { all.push(entry); });
          readBatch();
        }, reject);
      };
      readBatch();
    });
  }

  async function walkEntry(entry, parentPath, added) {
    if (!entry) return;
    const path = parentPath ? parentPath + '/' + entry.name : entry.name;
    if (entry.isFile) {
      try {
        const file = await fileFromEntry(entry);
        const record = addFile(path, file, 'drop');
        if (record) added.push(record);
      } catch (error) {
        console.warn('Could not read dropped file', path, error);
      }
      return;
    }
    if (entry.isDirectory) {
      const root = rootName(path);
      if (root) roots.add(root);
      try {
        const reader = entry.createReader();
        const children = await readAllEntries(reader);
        for (const child of children) {
          await walkEntry(child, path, added);
        }
      } catch (error) {
        console.warn('Could not read dropped folder', path, error);
      }
    }
  }

  async function addDataTransfer(dataTransfer) {
    const added = [];
    if (!dataTransfer) return added;
    const files = Array.from(dataTransfer.files || []);
    const items = Array.from(dataTransfer.items || []);
    const entries = [];
    items.forEach(function (item) {
      if (item.kind !== 'file' || !item.webkitGetAsEntry) return;
      try {
        const entry = item.webkitGetAsEntry();
        if (entry) entries.push(entry);
      } catch (error) {}
    });
    for (const entry of entries) {
      await walkEntry(entry, '', added);
    }
    if (!added.length) {
      files.forEach(function (file) {
        const record = addFile(file.name, file, 'drop');
        if (record) added.push(record);
      });
    }
    return added;
  }

  function getFile(value) {
    return records.get(pathKey(value)) || null;
  }

  function findByBasename(value) {
    const name = basename(value).toLowerCase();
    const keys = basenameIndex.get(name);
    if (!keys) return [];
    return Array.from(keys).map(function (key) { return records.get(key); }).filter(Boolean);
  }

  function findBySuffix(reference) {
    const ref = pathKey(reference);
    if (!ref) return [];
    const found = [];
    records.forEach(function (record) {
      if (record.key === ref || record.key.endsWith('/' + ref)) found.push(record);
    });
    return found;
  }

  function resolveReference(reference, reportPath) {
    const ref = normalisePath(reference);
    if (!ref) return { record: null, method: null, candidates: [] };
    const reportDir = dirname(reportPath);
    const candidates = [];
    const seen = new Set();
    const push = function (path, method) {
      const normal = normalisePath(path);
      if (!normal) return;
      const key = normal.toLowerCase();
      if (seen.has(key)) return;
      seen.add(key);
      candidates.push({ path: normal, method: method });
    };

    push(reportDir ? reportDir + '/' + ref : ref, 'report-relative');
    Array.from(roots).forEach(function (root) {
      push(root + '/' + ref, 'root-relative');
      push(root + '/' + basename(ref), 'root-basename');
    });
    push(ref, 'as-given');
    push(reportDir ? reportDir + '/' + basename(ref) : basename(ref), 'report-basename');

    for (const candidate of candidates) {
      const record = records.get(candidate.path.toLowerCase());
      if (record) return { record: record, method: candidate.method, candidates: candidates };
    }

    const suffixMatches = findBySuffix(ref);
    if (suffixMatches.length === 1) {
      return { record: suffixMatches[0], method: 'unique-suffix', candidates: candidates };
    }

    const baseMatches = findByBasename(ref);
    if (baseMatches.length === 1) {
      return { record: baseMatches[0], method: 'unique-basename', candidates: candidates };
    }

    return {
      record: null,
      method: null,
      candidates: candidates,
      ambiguous: suffixMatches.length > 1 ? suffixMatches : baseMatches
    };
  }

  function reportCandidates() {
    const list = [];
    records.forEach(function (record) {
      if (record.ext === 'json' && record.size <= MAX_REPORT_BYTES) list.push(record);
    });
    list.sort(function (a, b) { return a.path.localeCompare(b.path); });
    return list;
  }

  async function readText(record) {
    if (!record || !record.file) throw new Error('File not available');
    if (record.file.text) return record.file.text();
    return new Promise(function (resolve, reject) {
      const reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result || '')); };
      reader.onerror = function () { reject(reader.error || new Error('Could not read file')); };
      reader.readAsText(record.file);
    });
  }

  function summary() {
    let jsonCount = 0;
    let evidenceCount = 0;
    let totalBytes = 0;
    records.forEach(function (record) {
      totalBytes += record.size;
      if (record.ext === 'json') jsonCount += 1;
      else evidenceCount += 1;
    });
    return {
      files: records.size,
      jsonCount: jsonCount,
      evidenceCount: evidenceCount,
      totalBytes: totalBytes,
      roots: Array.from(roots)
    };
  }

  function all() {
    return Array.from(records.values());
  }

  function clear() {
    records.clear();
    basenameIndex.clear();
    roots.clear();
  }

  C.files = {
    addFile: addFile,
    addFileList: addFileList,
    addDataTransfer: addDataTransfer,
    getFile: getFile,
    findByBasename: findByBasename,
    resolveReference: resolveReference,
    reportCandidates: reportCandidates,
    readText: readText,
    summary: summary,
    all: all,
    clear: clear,
    normalisePath: normalisePath,
    pathKey: pathKey,
    basename: basename,
    dirname: dirname,
    rootName: rootName,
    roots: function () { return Array.from(roots); },
    MAX_REPORT_BYTES: MAX_REPORT_BYTES
  };
})();
