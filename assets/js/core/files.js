(function () {
  'use strict';

  const C = window.C = window.C || {};
  const records = new Map();
  const MAX_REPORT_BYTES = 64 * 1024 * 1024;

  function addFile(file, source) {
    if (!file || !/\.json$/i.test(file.name || '')) return null;
    if ((file.size || 0) > MAX_REPORT_BYTES) return null;
    const name = file.name || 'report.json';
    const key = name.toLowerCase();
    const record = {
      path: name,
      key: key,
      name: name,
      file: file,
      size: file.size || 0,
      lastModified: file.lastModified || 0,
      source: source || 'file'
    };
    records.set(key, record);
    return record;
  }

  function addFileList(fileList, source) {
    const added = [];
    Array.from(fileList || []).forEach(function (file) {
      const record = addFile(file, source);
      if (record) added.push(record);
    });
    return added;
  }

  async function addDataTransfer(dataTransfer) {
    if (!dataTransfer) return [];
    return addFileList(dataTransfer.files, 'drop');
  }

  function reportCandidates() {
    return Array.from(records.values()).sort(function (a, b) {
      return a.path.localeCompare(b.path);
    });
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
    let totalBytes = 0;
    records.forEach(function (record) { totalBytes += record.size; });
    return { files: records.size, totalBytes: totalBytes };
  }

  function clear() {
    records.clear();
  }

  C.files = {
    addFile: addFile,
    addFileList: addFileList,
    addDataTransfer: addDataTransfer,
    reportCandidates: reportCandidates,
    readText: readText,
    summary: summary,
    clear: clear,
    MAX_REPORT_BYTES: MAX_REPORT_BYTES
  };
})();
