'use strict';

const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const DataType = {
  Boolean: 0x0001,
  SByte: 0x0002,
  Int16: 0x0003,
  Int32: 0x0004,
  Int64: 0x0005,
  Byte: 0x0006,
  UInt16: 0x0007,
  UInt32: 0x0008,
  UInt64: 0x0009,
  String: 0x000A,
  Single: 0x000B,
  Double: 0x000C,
  Locale: 0x000D,
  Guid: 0x000E,
  EnumChoice: 0x000F,
  Class: 0x0010,
  StrongPointer: 0x0110,
  WeakPointer: 0x0210,
  Reference: 0x0310
};
const EMPTY_GUID = '00000000-0000-0000-0000-000000000000';

class Reader {
  constructor(buffer) {
    this.buffer = buffer;
    this.offset = 0;
  }

  position() {
    return this.offset;
  }

  advance(count) {
    this.ensure(count);
    this.offset += count;
  }

  ensure(count) {
    if (this.offset + count > this.buffer.length) {
      throw new Error('Unexpected end of DCB data');
    }
  }

  readUInt32() {
    this.ensure(4);
    const value = this.buffer.readUInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  readUInt8() {
    this.ensure(1);
    const value = this.buffer.readUInt8(this.offset);
    this.offset += 1;
    return value;
  }

  readInt32() {
    this.ensure(4);
    const value = this.buffer.readInt32LE(this.offset);
    this.offset += 4;
    return value;
  }

  readUInt16() {
    this.ensure(2);
    const value = this.buffer.readUInt16LE(this.offset);
    this.offset += 2;
    return value;
  }

  readGuid() {
    this.ensure(16);
    const b = this.buffer;
    const o = this.offset;
    this.offset += 16;
    return [
      b[o + 7], b[o + 6], b[o + 5], b[o + 4],
      '-', b[o + 3], b[o + 2],
      '-', b[o + 1], b[o + 0],
      '-', b[o + 15], b[o + 14],
      '-', b[o + 13], b[o + 12], b[o + 11], b[o + 10], b[o + 9], b[o + 8]
    ].map((part) => (part === '-' ? '-' : Number(part).toString(16).padStart(2, '0'))).join('');
  }

  readSpan(count) {
    this.ensure(count);
    const start = this.offset;
    this.offset += count;
    return this.buffer.subarray(start, start + count);
  }
}

function lowerAscii(value) {
  return String(value || '').toLowerCase();
}

function escapeXml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function decodeXml(value) {
  return String(value || '')
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, '\'')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function encodeXmlName(value) {
  const input = String(value || '');
  let result = '';
  for (let i = 0; i < input.length; i += 1) {
    const c = input[i];
    const validFirst = /[A-Za-z_]/.test(c);
    const validRest = /[A-Za-z0-9_.-]/.test(c);
    if ((i === 0 && validFirst) || (i > 0 && validRest)) {
      result += c;
    } else {
      result += '_';
      if (i === 0 && /[A-Za-z0-9]/.test(c)) {
        result += c;
      }
    }
  }
  return result || 'Element';
}

function formatNumber(value, precision = 3) {
  const text = Number(value).toFixed(precision);
  return text.replace(/\.?0+$/, (match) => (match.startsWith('.') ? '' : match));
}

function dataTypeName(type) {
  for (const [key, value] of Object.entries(DataType)) {
    if (value === type) {
      return key;
    }
  }
  return 'Unknown';
}

function readNullTerminatedString(buffer, start, maxLength) {
  let end = start;
  const limit = Math.min(buffer.length, start + maxLength);
  while (end < limit && buffer[end] !== 0) {
    end += 1;
  }
  return buffer.toString('utf8', start, end);
}

function parseGuidText(value) {
  const text = String(value || '').trim();
  const match = /^([0-9a-fA-F]{8})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{4})-([0-9a-fA-F]{12})$/.exec(text);
  if (!match) {
    throw new Error(`Invalid GUID: ${value}`);
  }
  const compact = `${match[1]}${match[2]}${match[3]}${match[4]}${match[5]}`;
  const bytes = Buffer.alloc(16);
  bytes[7] = Number.parseInt(compact.slice(0, 2), 16);
  bytes[6] = Number.parseInt(compact.slice(2, 4), 16);
  bytes[5] = Number.parseInt(compact.slice(4, 6), 16);
  bytes[4] = Number.parseInt(compact.slice(6, 8), 16);
  bytes[3] = Number.parseInt(compact.slice(8, 10), 16);
  bytes[2] = Number.parseInt(compact.slice(10, 12), 16);
  bytes[1] = Number.parseInt(compact.slice(12, 14), 16);
  bytes[0] = Number.parseInt(compact.slice(14, 16), 16);
  bytes[15] = Number.parseInt(compact.slice(16, 18), 16);
  bytes[14] = Number.parseInt(compact.slice(18, 20), 16);
  bytes[13] = Number.parseInt(compact.slice(20, 22), 16);
  bytes[12] = Number.parseInt(compact.slice(22, 24), 16);
  bytes[11] = Number.parseInt(compact.slice(24, 26), 16);
  bytes[10] = Number.parseInt(compact.slice(26, 28), 16);
  bytes[9] = Number.parseInt(compact.slice(28, 30), 16);
  bytes[8] = Number.parseInt(compact.slice(30, 32), 16);
  return bytes;
}

function writeGuidAt(buffer, offset, value) {
  const guidBytes = typeof value === 'string' ? parseGuidText(value) : value;
  Buffer.from(guidBytes).copy(buffer, offset, 0, 16);
}

function parsePointerText(value) {
  const text = String(value || '').trim();
  const match = /^(.+)\[([0-9A-Fa-f]+)\]$/.exec(text);
  if (!match) {
    throw new Error(`Invalid pointer value: ${value}`);
  }
  return {
    structName: match[1],
    instanceIndex: Number.parseInt(match[2], 16)
  };
}

function parseXmlDocument(xmlText) {
  const source = String(xmlText || '');
  const tokens = source.match(/<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[[\s\S]*?\]\]>|<\/?[^>]+>|[^<]+/g) || [];
  const stack = [];
  let root = null;

  const parseTag = (token) => {
    const selfClosing = /\/>$/.test(token);
    const inner = token.slice(1, token.length - (selfClosing ? 2 : 1)).trim();
    const nameMatch = /^([A-Za-z0-9_.:-]+)/.exec(inner);
    if (!nameMatch) {
      throw new Error(`Invalid XML tag: ${token}`);
    }
    const name = nameMatch[1];
    const attrs = {};
    const attrRegex = /([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)"/g;
    let match;
    while ((match = attrRegex.exec(inner)) !== null) {
      attrs[match[1]] = decodeXml(match[2]);
    }
    return { name, attrs, selfClosing };
  };

  for (const token of tokens) {
    if (!token) {
      continue;
    }
    if (token.startsWith('<?') || token.startsWith('<!--') || token.startsWith('<![') || token.startsWith('<!')) {
      continue;
    }
    if (token.startsWith('</')) {
      const name = token.slice(2, -1).trim();
      const current = stack.pop();
      if (!current || current.name !== name) {
        throw new Error(`Unexpected closing tag: ${token}`);
      }
      continue;
    }
    if (token.startsWith('<')) {
      const tag = parseTag(token);
      const node = {
        name: tag.name,
        attrs: tag.attrs,
        children: [],
        text: ''
      };
      if (stack.length > 0) {
        stack[stack.length - 1].children.push(node);
      } else if (!root) {
        root = node;
      } else {
        throw new Error('XML contains multiple root elements');
      }
      if (!tag.selfClosing) {
        stack.push(node);
      }
      continue;
    }
    if (stack.length > 0) {
      const trimmed = decodeXml(token).trim();
      if (trimmed) {
        stack[stack.length - 1].text += trimmed;
      }
    }
  }

  if (stack.length > 0) {
    throw new Error(`Unclosed XML element: ${stack[stack.length - 1].name}`);
  }
  if (!root) {
    throw new Error('XML has no root element');
  }
  return root;
}

function diffXmlTrees(originalRoot, editedRoot, options = {}) {
  const changes = [];
  const problems = [];
  const ignoredProblemPaths = new Set(options.ignoredProblemPaths || []);
  const allowSparseChildren = Boolean(options.allowSparseChildren);

  const walk = (originalNode, editedNode, currentPath) => {
    if (!originalNode || !editedNode || originalNode.name !== editedNode.name) {
      problems.push(`${currentPath}: element name changed`);
      return;
    }

    const originalAttrKeys = Object.keys(originalNode.attrs).sort();
    const editedAttrKeys = Object.keys(editedNode.attrs).sort();
    const removedAttrKeys = originalAttrKeys.filter((key) => !Object.prototype.hasOwnProperty.call(editedNode.attrs, key));
    const unsupportedRemovedAttrs = removedAttrKeys.filter((key) => !isReferenceXmlAttrName(key));
    if (unsupportedRemovedAttrs.length > 0) {
      problems.push(`${currentPath}: attribute set changed`);
    }
    for (const key of removedAttrKeys) {
      if (!isReferenceXmlAttrName(key)) {
        continue;
      }
      changes.push({
        kind: 'attr',
        path: `${currentPath}@${key}`,
        oldValue: originalNode.attrs[key],
        newValue: ''
      });
    }
    const allAttrKeys = Array.from(new Set(originalAttrKeys.concat(editedAttrKeys))).sort();
    for (const key of allAttrKeys) {
      const oldValue = Object.prototype.hasOwnProperty.call(originalNode.attrs, key)
        ? originalNode.attrs[key]
        : undefined;
      const newValue = Object.prototype.hasOwnProperty.call(editedNode.attrs, key)
        ? editedNode.attrs[key]
        : undefined;
      if (oldValue !== newValue && newValue !== undefined) {
        changes.push({
          kind: 'attr',
          path: `${currentPath}@${key}`,
          oldValue,
          newValue
        });
      }
    }

    const originalText = String(originalNode.text || '').trim();
    const editedText = String(editedNode.text || '').trim();
    if (originalText !== editedText) {
      if (originalNode.children.length === 0 && editedNode.children.length === 0) {
        changes.push({
          kind: 'text',
          path: currentPath,
          oldValue: originalText,
          newValue: editedText
        });
      } else {
        problems.push(`${currentPath}: text content changed`);
      }
    }

    if (originalNode.children.length !== editedNode.children.length) {
      const sparseChildMatch = allowSparseChildren &&
        originalNode.children.length >= editedNode.children.length &&
        editedNode.children.every((editedChild, index) => originalNode.children[index] && originalNode.children[index].name === editedChild.name);
      if (!sparseChildMatch && !ignoredProblemPaths.has(`${currentPath}: child count changed`)) {
        problems.push(`${currentPath}: child count changed`);
      }
      if (!sparseChildMatch) {
        return;
      }
    }

    const childCounters = new Map();
    const childCount = Math.min(originalNode.children.length, editedNode.children.length);
    for (let index = 0; index < childCount; index += 1) {
      const originalChild = originalNode.children[index];
      const editedChild = editedNode.children[index];
      if (!editedChild || originalChild.name !== editedChild.name) {
        problems.push(`${currentPath}: child structure changed`);
        continue;
      }
      const occurrence = childCounters.get(originalChild.name) || 0;
      childCounters.set(originalChild.name, occurrence + 1);
      walk(originalChild, editedChild, `${currentPath}/${originalChild.name}[${occurrence}]`);
    }
  };

  walk(originalRoot, editedRoot, `/${originalRoot.name}[0]`);
  return { changes, problems };
}

function annotateXmlPaths(root) {
  const walk = (node, currentPath) => {
    node._path = currentPath;
    const nameCounts = new Map();
    for (const child of node.children) {
      const occurrence = nameCounts.get(child.name) || 0;
      nameCounts.set(child.name, occurrence + 1);
      walk(child, `${currentPath}/${child.name}[${occurrence}]`);
    }
  };
  walk(root, `/${root.name}[0]`);
  return root;
}

function cloneXmlNode(node) {
  return {
    name: node.name,
    attrs: { ...(node.attrs || {}) },
    children: (node.children || []).map((child) => cloneXmlNode(child)),
    text: node.text || ''
  };
}

function mergeXmlTrees(baseNode, patchNode) {
  if (!baseNode) {
    return cloneXmlNode(patchNode);
  }
  if (!patchNode) {
    return cloneXmlNode(baseNode);
  }
  if (baseNode.name !== patchNode.name) {
    throw new Error(`XML merge root mismatch: ${baseNode.name} vs ${patchNode.name}`);
  }

  const merged = {
    name: baseNode.name,
    attrs: { ...(baseNode.attrs || {}), ...(patchNode.attrs || {}) },
    children: [],
    text: (patchNode.children || []).length === 0 ? (patchNode.text || '') : (baseNode.text || '')
  };

  const patchChildrenByName = new Map();
  for (const child of patchNode.children || []) {
    const list = patchChildrenByName.get(child.name) || [];
    list.push(child);
    patchChildrenByName.set(child.name, list);
  }

  const seenByName = new Map();
  for (const child of baseNode.children || []) {
    const occurrence = seenByName.get(child.name) || 0;
    seenByName.set(child.name, occurrence + 1);
    const patchChildren = patchChildrenByName.get(child.name) || [];
    const matchingPatchChild = occurrence < patchChildren.length ? patchChildren[occurrence] : null;
    merged.children.push(matchingPatchChild ? mergeXmlTrees(child, matchingPatchChild) : cloneXmlNode(child));
  }

  for (const [childName, patchChildren] of patchChildrenByName.entries()) {
    const consumed = seenByName.get(childName) || 0;
    for (let index = consumed; index < patchChildren.length; index += 1) {
      merged.children.push(cloneXmlNode(patchChildren[index]));
    }
  }

  return merged;
}

function xmlNodeToString(node) {
  const attrs = Object.entries(node.attrs || {})
    .filter(([, value]) => value !== null && value !== undefined && value !== '')
    .map(([key, value]) => ` ${key}="${escapeXml(value)}"`)
    .join('');
  const text = String(node.text || '');
  const children = (node.children || []).map((child) => xmlNodeToString(child)).join('');
  if (!text && !children) {
    return `<${node.name}${attrs}/>`;
  }
  return `<${node.name}${attrs}>${escapeXml(text)}${children}</${node.name}>`;
}

function normalizeDcbFileName(value) {
  return String(value || '')
    .replace(/^file:\/\//i, '')
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/+/g, '/')
    .toLowerCase();
}

function hasMeaningfulXmlNode(node) {
  if (!node) {
    return false;
  }
  const attrKeys = Object.keys(node.attrs || {}).filter((key) => !['PointsTo', 'Pointer', 'Type'].includes(key));
  return attrKeys.length > 0 || (node.children || []).length > 0 || String(node.text || '').trim() !== '';
}

function resolveRecordReferenceFileName(referenceFile, currentFileName) {
  let reference = String(referenceFile || '').trim();
  if (!reference) {
    return '';
  }

  reference = reference.replace(/^file:\/\//i, '').replace(/\\/g, '/');
  const current = String(currentFileName || '').replace(/\\/g, '/').replace(/^\/+/, '');
  if (reference.startsWith('./') || reference.startsWith('../')) {
    const baseDir = current ? path.posix.dirname(current) : '';
    return path.posix.normalize(path.posix.join(baseDir, reference)).replace(/^\/+/, '');
  }
  return path.posix.normalize(reference).replace(/^\/+/, '');
}

function getXmlAttrNameFromPath(pathKey) {
  const text = String(pathKey || '');
  const at = text.lastIndexOf('@');
  return at >= 0 ? text.slice(at + 1) : '';
}

function isReferenceXmlAttrName(attrName) {
  return ['ReferencedFile', 'RecordReference', 'RecordId', 'RecordName'].includes(String(attrName || ''));
}

function isIgnorableXmlWritebackAttrPath(pathKey) {
  const attrName = getXmlAttrNameFromPath(pathKey);
  if (!attrName) {
    return false;
  }
  return ['Type', 'File', 'Count', 'Pointer', 'PointsTo', '__type', '__ref', '__path'].includes(attrName);
}

class NativeDcbSession {
  static async open(filePath) {
    const bytes = await fs.readFile(filePath);
    return new NativeDcbSession(filePath, bytes);
  }

  constructor(filePath, bytes) {
    this.filePath = filePath;
    this.bytes = bytes;
    this.version = 0;
    this.structCount = 0;
    this.propertyCount = 0;
    this.enumCount = 0;
    this.mappingCount = 0;
    this.recordCount = 0;
    this.stringTable1Offset = 0;
    this.stringTable1Length = 0;
    this.stringTable2Offset = 0;
    this.stringTable2Length = 0;
    this.structDefinitions = [];
    this.propertyDefinitions = [];
    this.enumDefinitions = [];
    this.dataMappings = [];
    this.structOffsets = [];
    this.structPropertyCache = [];
    this.structNameCache = [];
    this.encodedStructNameCache = [];
    this.propertyNameCache = [];
    this.encodedPropertyNameCache = [];
    this.records = [];
    this.recordSummaries = [];
    this.structTypeNamesCache = null;
    this.structTypeCompletionEntriesCache = null;
    this.structPropertyCompletionCache = new Map();
    this.propertyLookupCache = new Map();
    this.enumValueCache = new Map();
    this.stringTable1Lookup = null;
    this.structNameToIndex = null;
    this.recordGuidToIndex = null;
    this.fileNameToMainRecordIndex = null;
    this.mainRecordFileCounts = null;
    this._parse();
  }

  getMetadata() {
    return {
      sourcePath: this.filePath,
      recordCount: this.recordCount,
      structCount: this.structCount,
      propertyCount: this.propertyCount,
      version: this.version
    };
  }

  searchRecords(query, limit = 200) {
    const lowered = lowerAscii(query);
    const results = [];
    for (const summary of this.recordSummaries) {
      if (lowered && !summary.searchText.includes(lowered)) {
        continue;
      }
      results.push({
        index: summary.index,
        name: summary.name,
        typeName: summary.typeName,
        fileName: summary.fileName,
        guid: summary.guid
      });
      if (results.length >= limit) {
        break;
      }
    }
    return results;
  }

  getRecordSummary(index) {
    return this.recordSummaries[index] || null;
  }

  getMainRecordSummaries() {
    return this.recordSummaries.filter((summary) => summary.isMain);
  }

  getStructTypeNames() {
    if (this.structTypeNamesCache) {
      return this.structTypeNamesCache;
    }
    this._ensureStructTypeCaches();
    return this.structTypeNamesCache;
  }

  getStructTypeCompletionEntries() {
    if (this.structTypeCompletionEntriesCache) {
      return this.structTypeCompletionEntriesCache;
    }
    this._ensureStructTypeCaches();
    return this.structTypeCompletionEntriesCache;
  }

  hasStructType(typeName) {
    return this._getStructNameToIndexMap().has(String(typeName || '').trim());
  }

  getStructPropertyCompletionEntries(typeName) {
    const normalizedTypeName = String(typeName || '').trim();
    if (!normalizedTypeName) {
      return [];
    }
    if (this.structPropertyCompletionCache.has(normalizedTypeName)) {
      return this.structPropertyCompletionCache.get(normalizedTypeName);
    }

    const structIndex = this._getStructNameToIndexMap().get(normalizedTypeName);
    if (typeof structIndex !== 'number' || structIndex < 0 || structIndex >= this.structPropertyCache.length) {
      this.structPropertyCompletionCache.set(normalizedTypeName, []);
      return [];
    }

    const entries = this.structPropertyCache[structIndex].map((propertyIndex) => {
      const property = this.propertyDefinitions[propertyIndex];
      const name = this.propertyNameCache[propertyIndex] || '';
      const encodedName = this.encodedPropertyNameCache[propertyIndex] || encodeXmlName(name);
      const childTypeName = property.structIndex >= 0 && property.structIndex < this.structNameCache.length
        ? this.structNameCache[property.structIndex]
        : '';
      return {
        name,
        encodedName,
        dataType: property.dataType,
        dataTypeName: dataTypeName(property.dataType),
        childTypeName,
        isArray: property.conversionType !== 0,
        isBoolean: property.dataType === DataType.Boolean,
        isEnum: property.dataType === DataType.EnumChoice,
        isReference: property.dataType === DataType.Reference,
        isWeakPointer: property.dataType === DataType.WeakPointer,
        isStrongPointer: property.dataType === DataType.StrongPointer,
        isClassLike: property.dataType === DataType.Class || property.dataType === DataType.StrongPointer,
        enumValues: property.dataType === DataType.EnumChoice ? this.getEnumValues(property.structIndex) : []
      };
    }).sort((left, right) => left.encodedName.localeCompare(right.encodedName, undefined, { sensitivity: 'base' }));

    this.structPropertyCompletionCache.set(normalizedTypeName, entries);
    return entries;
  }

  getPropertyInfo(typeName, propertyName) {
    const normalizedTypeName = String(typeName || '').trim();
    const normalizedPropertyName = String(propertyName || '').trim();
    if (!normalizedTypeName || !normalizedPropertyName) {
      return null;
    }
    const key = `${normalizedTypeName}\n${normalizedPropertyName}`;
    if (this.propertyLookupCache.has(key)) {
      return this.propertyLookupCache.get(key);
    }
    const entries = this.getStructPropertyCompletionEntries(normalizedTypeName);
    const lowered = normalizedPropertyName.toLowerCase();
    const found = entries.find((entry) => entry.encodedName.toLowerCase() === lowered || entry.name.toLowerCase() === lowered) || null;
    this.propertyLookupCache.set(key, found);
    return found;
  }

  getEnumValues(enumIndex) {
    if (typeof enumIndex !== 'number' || enumIndex < 0 || enumIndex >= this.enumDefinitions.length) {
      return [];
    }
    if (this.enumValueCache.has(enumIndex)) {
      return this.enumValueCache.get(enumIndex);
    }

    const definition = this.enumDefinitions[enumIndex];
    const values = [];
    for (let i = 0; i < definition.valueCount; i += 1) {
      const optionIndex = definition.firstValueIndex + i;
      if (optionIndex < 0 || optionIndex >= this.enumOptionCount) {
        continue;
      }
      const offset = this.bytes.readInt32LE(this.enumOptionOffset + optionIndex * 4);
      const value = this._getString(offset, true);
      if (value) {
        values.push(value);
      }
    }
    this.enumValueCache.set(enumIndex, values);
    return values;
  }

  getRecordReferenceCompletionEntries(query = '', limit = 200, typeName = '') {
    const lowered = lowerAscii(query);
    const loweredTypeName = lowerAscii(typeName);
    const results = [];
    for (const summary of this.recordSummaries) {
      if (loweredTypeName && lowerAscii(summary.typeName) !== loweredTypeName) {
        continue;
      }
      if (lowered && !summary.searchText.includes(lowered)) {
        continue;
      }
      results.push({
        name: summary.name,
        typeName: summary.typeName,
        fileName: summary.fileName,
        guid: summary.guid
      });
      if (results.length >= limit) {
        break;
      }
    }
    return results;
  }

  isDirty() {
    return Boolean(this.dirty);
  }

  async saveToFile(targetPath = this.filePath) {
    await fs.writeFile(targetPath, this.bytes);
    this.filePath = targetPath;
    this.dirty = false;
  }

  deleteRecordsByFileName(fileName) {
    const normalizedFileName = String(fileName || '').trim().replace(/\\/g, '/');
    if (!normalizedFileName) {
      throw new Error('Cannot delete records without a file name.');
    }

    const indicesToDelete = [];
    for (let index = 0; index < this.recordSummaries.length; index += 1) {
      if (String(this.recordSummaries[index].fileName || '').replace(/\\/g, '/') === normalizedFileName) {
        indicesToDelete.push(index);
      }
    }
    if (indicesToDelete.length === 0) {
      throw new Error(`No records found for ${normalizedFileName}`);
    }

    const recordStorageSize = this.version >= 8 ? 36 : 32;
    const recordTableStart = this.recordsOffset;
    const recordTableEnd = this.recordsOffset + this.records.length * recordStorageSize;
    const keepSet = new Set(indicesToDelete);
    const keptChunks = [];
    for (let index = 0; index < this.records.length; index += 1) {
      if (keepSet.has(index)) {
        continue;
      }
      const start = recordTableStart + index * recordStorageSize;
      const end = start + recordStorageSize;
      keptChunks.push(this.bytes.subarray(start, end));
    }

    this.bytes = Buffer.concat([
      this.bytes.subarray(0, recordTableStart),
      ...keptChunks,
      this.bytes.subarray(recordTableEnd)
    ]);
    this.bytes.writeUInt32LE(this.records.length - indicesToDelete.length, this.recordCountHeaderOffset);

    this.dirty = true;
    this._parse();

    return {
      deletedRecordCount: indicesToDelete.length,
      fileName: normalizedFileName
    };
  }

  renameRecordsByFileName(oldFileName, newFileName) {
    const normalizedOldFileName = String(oldFileName || '').trim().replace(/\\/g, '/');
    const normalizedNewFileName = String(newFileName || '').trim().replace(/\\/g, '/');
    if (!normalizedOldFileName || !normalizedNewFileName) {
      throw new Error('Old and new file names are required for rename.');
    }
    if (normalizedOldFileName === normalizedNewFileName) {
      return {
        renamedRecordCount: 0,
        oldFileName: normalizedOldFileName,
        newFileName: normalizedNewFileName
      };
    }

    const indicesToRename = [];
    for (let index = 0; index < this.recordSummaries.length; index += 1) {
      if (String(this.recordSummaries[index].fileName || '').replace(/\\/g, '/') === normalizedOldFileName) {
        indicesToRename.push(index);
      }
    }
    if (indicesToRename.length === 0) {
      throw new Error(`No records found for ${normalizedOldFileName}`);
    }

    const newFileNameOffset = this._appendString1(normalizedNewFileName);
    this._parse();

    const recordStorageSize = this.version >= 8 ? 36 : 32;
    for (const index of indicesToRename) {
      this.bytes.writeInt32LE(newFileNameOffset, this.recordsOffset + index * recordStorageSize + 4);
    }

    this.dirty = true;
    this._parse();

    return {
      renamedRecordCount: indicesToRename.length,
      oldFileName: normalizedOldFileName,
      newFileName: normalizedNewFileName
    };
  }

  createRecordFromXmlScratch(editedXmlText, newFileName) {
    const parsedRoot = parseXmlDocument(editedXmlText);
    const normalizedType = String(parsedRoot.attrs?.Type || (String(parsedRoot.name || '').includes('.') ? String(parsedRoot.name).split('.')[0] : '')).trim();
    let normalizedName = String(parsedRoot.name || '').trim();
    const normalizedFileName = String(newFileName || '').trim().replace(/\\/g, '/').replace(/^\/+/, '');

    if (!normalizedType) {
      throw new Error('New record XML must include a Type attribute on the root element.');
    }
    if (!normalizedName) {
      throw new Error('New record XML must include a root element name.');
    }
    if (!normalizedFileName) {
      throw new Error('New record target path cannot be empty.');
    }
    if (!normalizedName.includes('.')) {
      normalizedName = `${normalizedType}.${normalizedName}`;
    }

    const structIndex = this._getStructNameToIndexMap().get(normalizedType);
    if (typeof structIndex !== 'number') {
      throw new Error(`Struct type '${normalizedType}' was not found in the DCB schema`);
    }

    const fileNameOffset = this._appendString1(normalizedFileName);
    const nameOffset = this._appendString2(normalizedName);

    this._parse();

    const requestedGuid = String(parsedRoot.attrs?.RecordId || '').trim();
    const newGuid = this._resolveRequestedOrGenerateGuid(requestedGuid);
    const mappingIndex = this.dataMappings.findIndex((mapping) => mapping.structIndex === structIndex);
    if (mappingIndex < 0) {
      throw new Error('Target record data mapping was not found');
    }

    const structSize = this.structDefinitions[structIndex]?.structSize || 0;
    const newInstanceIndex = this.dataMappings[mappingIndex].structCount;
    const recordStorageSize = this.version >= 8 ? 36 : 32;
    const recordInsertOffset = this.recordsOffset + this.records.length * recordStorageSize;
    const recordBytes = Buffer.alloc(recordStorageSize, 0);
    let cursor = 0;
    recordBytes.writeInt32LE(nameOffset, cursor); cursor += 4;
    recordBytes.writeInt32LE(fileNameOffset, cursor); cursor += 4;
    if (this.version >= 8) {
      recordBytes.writeInt32LE(-1, cursor); cursor += 4;
    }
    recordBytes.writeInt32LE(structIndex, cursor); cursor += 4;
    writeGuidAt(recordBytes, cursor, newGuid); cursor += 16;
    recordBytes.writeUInt16LE(newInstanceIndex, cursor); cursor += 2;
    recordBytes.writeUInt16LE(structSize, cursor);
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, recordInsertOffset),
      recordBytes,
      this.bytes.subarray(recordInsertOffset)
    ]);
    this.bytes.writeUInt32LE(this.recordCount + 1, this.recordCountHeaderOffset);

    this._parse();

    const mappingOffset = this.dataMappingsOffset + mappingIndex * 8;
    const instanceInsertOffset = this.structOffsets[structIndex] + structSize * newInstanceIndex;
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, instanceInsertOffset),
      Buffer.alloc(structSize, 0),
      this.bytes.subarray(instanceInsertOffset)
    ]);
    this.bytes.writeUInt32LE(newInstanceIndex + 1, mappingOffset);

    this._parse();

    const createdIndex = this._getRecordGuidToIndexMap().get(String(newGuid).toLowerCase());
    if (typeof createdIndex !== 'number') {
      throw new Error('Failed to locate the newly created record after insertion');
    }

    const createdRecord = this.records[createdIndex];
    this._initializeStructInstanceDefaults(createdRecord.structIndex, createdRecord.instanceIndex);

    const adjustedRoot = annotateXmlPaths(cloneXmlNode(parsedRoot));
    adjustedRoot.name = encodeXmlName(normalizedName);
    adjustedRoot.attrs = {
      ...(adjustedRoot.attrs || {}),
      RecordId: newGuid,
      Type: normalizedType
    };
    this._primeStringTableForXmlNode(createdRecord.structIndex, adjustedRoot);
    this._parse();
    const refreshedCreatedIndex = this._getRecordGuidToIndexMap().get(String(newGuid).toLowerCase());
    if (typeof refreshedCreatedIndex !== 'number') {
      throw new Error('Failed to relocate the newly created record after string table updates');
    }
    const refreshedCreatedRecord = this.records[refreshedCreatedIndex];
    const context = {
      currentFileName: normalizedFileName,
      pointerMap: new Map(),
      strongPointerTargets: new Map(),
      strongPointerArrays: new Map(),
      guidToRecordIndex: this._getRecordGuidToIndexMap(),
      fileNameToRecordIndex: this._getFileNameToMainRecordIndexMap()
    };
    const rootPointerId = String(adjustedRoot.attrs?.Pointer || '').trim();
    if (rootPointerId) {
      context.pointerMap.set(rootPointerId, {
        structIndex: refreshedCreatedRecord.structIndex,
        instanceIndex: refreshedCreatedRecord.instanceIndex
      });
    }
    this._prepareXmlGraphForStructInstance(refreshedCreatedRecord.structIndex, refreshedCreatedRecord.instanceIndex, adjustedRoot, context);
    this._parse();
    this._applyXmlNodeToStructInstance(refreshedCreatedRecord.structIndex, refreshedCreatedRecord.instanceIndex, adjustedRoot, context);
    this._parse();
    this.dirty = true;

    return {
      index: createdIndex,
      guid: newGuid,
      name: normalizedName,
      typeName: normalizedType,
      fileName: normalizedFileName,
      changedValues: 1
    };
  }

  applyRecordXml(index, editedXmlText, options = {}) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    if (!record || !summary) {
      throw new Error(`Record ${index} is out of range`);
    }

    let originalRoot = parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`);
    const editedRoot = parseXmlDocument(editedXmlText);
    if (originalRoot.name !== editedRoot.name) {
      const editedType = String(editedRoot.attrs?.Type || (String(editedRoot.name || '').includes('.') ? String(editedRoot.name).split('.')[0] : '')).trim();
      if (editedType && editedType === summary.typeName) {
        return this.replaceRecordXml(index, editedXmlText);
      }
      throw new Error('Edited XML root does not match the selected record');
    }

    const classArrayResult = this._applyClassArrayEdits(index, editedRoot);
    if (classArrayResult.changedValues > 0) {
      originalRoot = parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`);
    }
    const strongPointerArrayResult = this._applyStrongPointerArrayEdits(index, editedRoot);
    if (strongPointerArrayResult.changedValues > 0) {
      originalRoot = parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`);
    }
    const referenceArrayResult = this._applyReferenceArrayEdits(index, originalRoot, editedRoot);
    if (referenceArrayResult.changedValues > 0) {
      originalRoot = parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`);
    }

    const { changes, problems } = diffXmlTrees(originalRoot, editedRoot, options);
    if (problems.length > 0) {
      return this.replaceRecordXml(index, editedXmlText);
    }
    if (changes.length === 0) {
      const changedValues = classArrayResult.changedValues + strongPointerArrayResult.changedValues + referenceArrayResult.changedValues;
      this.dirty = this.dirty || changedValues > 0;
      return { changedValues };
    }

    let fieldIndex = this._buildRecordEditableFieldIndex(index, originalRoot);
    const unsupported = [];
    let changedValues = classArrayResult.changedValues + strongPointerArrayResult.changedValues + referenceArrayResult.changedValues;
    for (const change of changes) {
      const descriptor = fieldIndex.get(change.path);
      if (!descriptor) {
        if (change.kind === 'attr' && isIgnorableXmlWritebackAttrPath(change.path)) {
          continue;
        }
        unsupported.push(change.path);
        continue;
      }
      if (descriptor.read() === change.newValue) {
        continue;
      }
      descriptor.write(change.newValue);
      changedValues += 1;
      this._parse();
      fieldIndex = this._buildRecordEditableFieldIndex(index);
    }

    if (unsupported.length > 0) {
      return this.replaceRecordXml(index, editedXmlText);
    }

    this.dirty = this.dirty || changedValues > 0;
    return { changedValues };
  }

  replaceRecordXml(index, editedXmlText) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    if (!record || !summary) {
      throw new Error(`Record ${index} is out of range`);
    }

    const editedRoot = annotateXmlPaths(parseXmlDocument(editedXmlText));
    const editedType = String(editedRoot.attrs?.Type || (String(editedRoot.name || '').includes('.') ? String(editedRoot.name).split('.')[0] : '')).trim();
    if (editedType && editedType !== summary.typeName) {
      throw new Error(`Replacement XML type '${editedType}' does not match record type '${summary.typeName}'`);
    }

    editedRoot.name = encodeXmlName(summary.name);
    editedRoot.attrs = {
      ...(editedRoot.attrs || {}),
      RecordId: summary.guid,
      Type: summary.typeName
    };

    this._initializeStructInstanceDefaults(record.structIndex, record.instanceIndex);
    this._primeStringTableForXmlNode(record.structIndex, editedRoot);
    this._parse();

    const refreshedIndex = this._getRecordGuidToIndexMap().get(String(summary.guid).toLowerCase());
    if (typeof refreshedIndex !== 'number') {
      throw new Error('Failed to relocate the edited record after string table updates');
    }

    const refreshedRecord = this.records[refreshedIndex];
    const refreshedSummary = this.recordSummaries[refreshedIndex];
    const context = {
      currentFileName: refreshedSummary.fileName,
      pointerMap: new Map(),
      strongPointerTargets: new Map(),
      strongPointerArrays: new Map(),
      guidToRecordIndex: this._getRecordGuidToIndexMap(),
      fileNameToRecordIndex: this._getFileNameToMainRecordIndexMap()
    };
    const rootPointerId = String(editedRoot.attrs?.Pointer || '').trim();
    if (rootPointerId) {
      context.pointerMap.set(rootPointerId, {
        structIndex: refreshedRecord.structIndex,
        instanceIndex: refreshedRecord.instanceIndex
      });
    }

    this._prepareXmlGraphForStructInstance(refreshedRecord.structIndex, refreshedRecord.instanceIndex, editedRoot, context);
    this._parse();

    const finalIndex = this._getRecordGuidToIndexMap().get(String(summary.guid).toLowerCase());
    if (typeof finalIndex !== 'number') {
      throw new Error('Failed to relocate the edited record after graph allocation');
    }
    const finalRecord = this.records[finalIndex];
    this._applyXmlNodeToStructInstance(finalRecord.structIndex, finalRecord.instanceIndex, editedRoot, context);
    this._parse();
    this.dirty = true;

    return {
      changedValues: 1,
      replaced: true
    };
  }

  exportRecordXml(index) {
    return this.exportExpandedXml(index);
  }

  exportExpandedXml(index) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    if (!record || !summary) {
      throw new Error(`Record ${index} is out of range`);
    }

    const activeInstances = new Set();
    const activeRecordIds = new Set([summary.guid]);
    const pointerIds = this._buildPointerIdMap(record.structIndex, record.instanceIndex);
    const fileCounts = this._getMainRecordFileCounts();
    const guidToRecordIndex = this._getRecordGuidToIndexMap();
    const getStructName = (structIndex) => {
      if (structIndex < 0 || structIndex >= this.structNameCache.length) {
        return 'Unknown';
      }
      return this.structNameCache[structIndex];
    };
    const getEncodedStructName = (structIndex) => encodeXmlName(getStructName(structIndex));
    const instanceKey = (structIndex, instanceIndex) => `${structIndex}:${instanceIndex}`;
    const getInstanceSpan = (structIndex, instanceIndex) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return null;
      }
      const structSize = this.structDefinitions[structIndex].structSize;
      const offset = this.structOffsets[structIndex] + structSize * instanceIndex;
      if (offset + structSize > this.bytes.length) {
        return null;
      }
      return this.bytes.subarray(offset, offset + structSize);
    };
    const appendElement = (name, attrs, children) => {
      const attrText = Object.entries(attrs || {})
        .filter(([, value]) => value !== '' && value !== null && value !== undefined)
        .map(([key, value]) => ` ${key}="${escapeXml(value)}"`)
        .join('');
      if (!children) {
        return `<${name}${attrText}/>`;
      }
      return `<${name}${attrText}>${children}</${name}>`;
    };
    const relativeFileReference = (targetFile, currentFile) => {
      const slashCount = String(currentFile || '').split('/').length - 1;
      let result = 'file://./';
      for (let i = 0; i < slashCount; i += 1) {
        result += '../';
      }
      result += String(targetFile || '');
      return result;
    };
    const readPrimitiveInline = (dataType, reader) => {
      switch (dataType) {
        case DataType.Boolean: return reader.readUInt8() !== 0 ? 'true' : 'false';
        case DataType.SByte: return String(reader.buffer.readInt8((reader.offset += 1) - 1));
        case DataType.Int16: return String(reader.readUInt16() << 16 >> 16);
        case DataType.Int32: return String(reader.readInt32());
        case DataType.Int64: {
          const low = reader.readUInt32();
          const high = reader.readInt32();
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Byte: return String(reader.readUInt8());
        case DataType.UInt16: return String(reader.readUInt16());
        case DataType.UInt32: return String(reader.readUInt32());
        case DataType.UInt64: {
          const low = reader.readUInt32();
          const high = reader.readUInt32();
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Single: return formatNumber(reader.buffer.readFloatLE((reader.offset += 4) - 4));
        case DataType.Double: return formatNumber(reader.buffer.readDoubleLE((reader.offset += 8) - 8), 6);
        case DataType.Guid: return this._readGuidAtBuffer(reader.buffer, (reader.offset += 16) - 16);
        case DataType.String:
        case DataType.Locale:
        case DataType.EnumChoice:
          return this._getString(reader.readInt32(), false);
        default:
          return '';
      }
    };
    const readPrimitivePool = (dataType, poolIndex) => this._readPoolValueByIndex(dataType, poolIndex);
    const appendInstanceAttributes = (attrs, structIndex, instanceIndex) => {
      const out = { ...(attrs || {}) };
      const pointerId = pointerIds.get(instanceKey(structIndex, instanceIndex));
      if (pointerId !== undefined) {
        out.Pointer = `ptr:${pointerId}`;
      }
      if (structIndex >= 0) {
        out.Type = getStructName(structIndex);
      }
      return out;
    };
    const writeReferenceElement = (elementName, reference, filePath) => {
      if (!reference || reference.recordId === EMPTY_GUID || reference.instanceIndex < 0) {
        return appendElement(elementName, {}, '');
      }
      const targetIndex = guidToRecordIndex.get(String(reference.recordId).toLowerCase());
      if (typeof targetIndex !== 'number') {
        return appendElement(elementName, {}, '');
      }
      const targetSummary = this.recordSummaries[targetIndex];
      const targetRecord = this.records[targetIndex];
      const sameFile = targetSummary.fileName === filePath;
      const activeRecord = activeRecordIds.has(targetSummary.guid);
      const recordCountInFile = fileCounts.get(targetSummary.fileName) || 0;
      if (sameFile && !activeRecord) {
        activeRecordIds.add(targetSummary.guid);
        const result = writeInstanceElement(
          elementName,
          targetRecord.structIndex,
          targetRecord.instanceIndex,
          filePath,
          { RecordId: targetSummary.guid, RecordName: targetSummary.name }
        );
        activeRecordIds.delete(targetSummary.guid);
        return result;
      }
      if (!sameFile && recordCountInFile <= 1) {
        return appendElement(elementName, { ReferencedFile: relativeFileReference(targetSummary.fileName, filePath) }, '');
      }
      return appendElement(elementName, {
        RecordReference: relativeFileReference(targetSummary.fileName, filePath),
        RecordName: targetSummary.name,
        RecordId: targetSummary.guid
      }, '');
    };
    const writeAttributeValue = (propertyName, dataType, structIndex, reader, filePath) => {
      const encodedName = encodeXmlName(propertyName);
      switch (dataType) {
        case DataType.Reference:
          return writeReferenceElement(encodedName, this._readReferenceInline(reader), filePath);
        case DataType.WeakPointer: {
          const pointer = this._readPointerInline(reader);
          const attrs = {};
          const pointerId = pointerIds.get(instanceKey(pointer.structIndex, pointer.instanceIndex));
          if (pointerId !== undefined) {
            attrs.PointsTo = `ptr:${pointerId}`;
          }
          return appendElement(encodedName, attrs, '');
        }
        case DataType.StrongPointer: {
          const pointer = this._readPointerInline(reader);
          if (pointer.structIndex < 0 || pointer.instanceIndex < 0) {
            return appendElement(encodedName, {}, '');
          }
          return writeInstanceElement(encodedName, pointer.structIndex, pointer.instanceIndex, filePath, {});
        }
        case DataType.Class: {
          const children = writeStructContents(structIndex, reader, filePath);
          return appendElement(encodedName, { Type: getStructName(structIndex) }, children);
        }
        default:
          return appendElement(encodedName, {}, escapeXml(readPrimitiveInline(dataType, reader)));
      }
    };
    const writeArray = (propertyName, dataType, structIndex, reader, filePath) => {
      const count = reader.readInt32();
      const firstIndex = reader.readInt32();
      let children = '';
      if (count > 0 && firstIndex >= 0) {
        for (let i = 0; i < count; i += 1) {
          const poolIndex = firstIndex + i;
          switch (dataType) {
            case DataType.Reference: {
              if (poolIndex >= this.referenceCount) break;
              const reference = this._readReferenceAt(this.referenceOffset + poolIndex * 20);
              if (reference.recordId === EMPTY_GUID || reference.instanceIndex < 0) {
                children += appendElement(getEncodedStructName(structIndex), {}, '');
              } else {
                const targetIndex = guidToRecordIndex.get(String(reference.recordId).toLowerCase());
                if (typeof targetIndex === 'number') {
                  children += writeReferenceElement(getEncodedStructName(this.records[targetIndex].structIndex), reference, filePath);
                } else {
                  children += appendElement(getEncodedStructName(structIndex), {}, '');
                }
              }
              break;
            }
            case DataType.WeakPointer: {
              if (poolIndex >= this.weakCount) break;
              const pointer = this._readPointerAt(this.weakOffset + poolIndex * 8);
              const elementName = getEncodedStructName(pointer.structIndex >= 0 ? pointer.structIndex : structIndex);
              const attrs = {};
              const pointerId = pointerIds.get(instanceKey(pointer.structIndex, pointer.instanceIndex));
              if (pointerId !== undefined) {
                attrs.PointsTo = `ptr:${pointerId}`;
              }
              children += appendElement(elementName, attrs, '');
              break;
            }
            case DataType.StrongPointer: {
              if (poolIndex >= this.strongCount) break;
              const pointer = this._readPointerAt(this.strongOffset + poolIndex * 8);
              const elementName = getEncodedStructName(pointer.structIndex >= 0 ? pointer.structIndex : structIndex);
              children += pointer.structIndex < 0 || pointer.instanceIndex < 0
                ? appendElement(elementName, {}, '')
                : writeInstanceElement(elementName, pointer.structIndex, pointer.instanceIndex, filePath, {});
              break;
            }
            case DataType.Class:
              children += writeInstanceElement(getEncodedStructName(structIndex), structIndex, poolIndex, filePath, {});
              break;
            default:
              children += appendElement(encodeXmlName(dataTypeName(dataType)), {}, escapeXml(readPrimitivePool(dataType, poolIndex)));
              break;
          }
        }
      }
      const attrs = { Count: String(count) };
      if (structIndex >= 0 && structIndex < this.structDefinitions.length) {
        attrs.Type = getStructName(structIndex);
      }
      return appendElement(encodeXmlName(propertyName), attrs, children);
    };
    const writeStructContents = (structIndex, reader, filePath) => {
      if (structIndex < 0 || structIndex >= this.structPropertyCache.length) {
        return '';
      }
      let xml = '';
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        const propertyName = this.propertyNameCache[propertyIndex];
        if (property.conversionType === 0) {
          xml += writeAttributeValue(propertyName, property.dataType, property.structIndex, reader, filePath);
        } else {
          xml += writeArray(propertyName, property.dataType, property.structIndex, reader, filePath);
        }
      }
      return xml;
    };
    const writeInstanceElement = (elementName, structIndex, instanceIndex, filePath, extraAttrs) => {
      const key = instanceKey(structIndex, instanceIndex);
      if (activeInstances.has(key)) {
        return appendElement(elementName, appendInstanceAttributes(extraAttrs, structIndex, instanceIndex), '');
      }
      const span = getInstanceSpan(structIndex, instanceIndex);
      if (!span) {
        return appendElement(elementName, appendInstanceAttributes(extraAttrs, structIndex, instanceIndex), '');
      }
      activeInstances.add(key);
      const reader = new Reader(span);
      const children = writeStructContents(structIndex, reader, filePath);
      activeInstances.delete(key);
      return appendElement(elementName, appendInstanceAttributes(extraAttrs, structIndex, instanceIndex), children);
    };

    return writeInstanceElement(
      encodeXmlName(summary.name),
      record.structIndex,
      record.instanceIndex,
      summary.fileName,
      { RecordId: summary.guid }
    );
  }

  exportCompactXml(index) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    if (!record || !summary) {
      throw new Error(`Record ${index} is out of range`);
    }

    const activeInstances = new Set();
    const getStructName = (structIndex) => {
      if (structIndex < 0 || structIndex >= this.structNameCache.length) {
        return 'Unknown';
      }
      return this.structNameCache[structIndex];
    };
    const getEncodedStructName = (structIndex) => {
      if (structIndex < 0 || structIndex >= this.encodedStructNameCache.length) {
        return 'Unknown';
      }
      return this.encodedStructNameCache[structIndex];
    };
    const instanceKey = (structIndex, instanceIndex) => `${structIndex}:${instanceIndex}`;
    const getInstanceSpan = (structIndex, instanceIndex) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return null;
      }
      const structSize = this.structDefinitions[structIndex].structSize;
      const offset = this.structOffsets[structIndex] + structSize * instanceIndex;
      if (offset + structSize > this.bytes.length) {
        return null;
      }
      return this.bytes.subarray(offset, offset + structSize);
    };
    const formatPointerVariant = (instanceIndex) =>
      Number(instanceIndex).toString(16).toUpperCase().padStart(4, '0');
    const writeAttributes = (attrs) => attrs
      .filter((entry) => entry.value !== '')
      .map((entry) => ` ${entry.name}="${escapeXml(entry.value)}"`)
      .join('');
    const readPrimitiveInline = (dataType, reader) => {
      switch (dataType) {
        case DataType.Boolean: return reader.readUInt8() !== 0 ? 'true' : 'false';
        case DataType.SByte: return String(reader.buffer.readInt8((reader.offset += 1) - 1));
        case DataType.Int16: return String(reader.readUInt16() << 16 >> 16);
        case DataType.Int32: return String(reader.readInt32());
        case DataType.Int64: {
          const low = reader.readUInt32();
          const high = reader.readInt32();
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Byte: return String(reader.readUInt8());
        case DataType.UInt16: return String(reader.readUInt16());
        case DataType.UInt32: return String(reader.readUInt32());
        case DataType.UInt64: {
          const low = reader.readUInt32();
          const high = reader.readUInt32();
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Single: return formatNumber(reader.buffer.readFloatLE((reader.offset += 4) - 4));
        case DataType.Double: return formatNumber(reader.buffer.readDoubleLE((reader.offset += 8) - 8), 6);
        case DataType.Guid: return reader.readGuid();
        case DataType.String:
        case DataType.Locale:
        case DataType.EnumChoice:
          return this._getString(reader.readInt32(), false);
        default:
          return '';
      }
    };
    const readPrimitivePool = (dataType, indexInPool) => {
      switch (dataType) {
        case DataType.Boolean:
          return indexInPool < this.boolCount ? (this.bytes[this.boolOffset + indexInPool] !== 0 ? 'true' : 'false') : '';
        case DataType.SByte:
          return indexInPool < this.int8Count ? String(this.bytes.readInt8(this.int8Offset + indexInPool)) : '';
        case DataType.Int16:
          return indexInPool < this.int16Count ? String(this.bytes.readInt16LE(this.int16Offset + indexInPool * 2)) : '';
        case DataType.Int32:
          return indexInPool < this.int32Count ? String(this.bytes.readInt32LE(this.int32Offset + indexInPool * 4)) : '';
        case DataType.Int64: {
          if (indexInPool >= this.int64Count) return '';
          const o = this.int64Offset + indexInPool * 8;
          const low = this.bytes.readUInt32LE(o);
          const high = this.bytes.readInt32LE(o + 4);
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Byte:
          return indexInPool < this.uint8Count ? String(this.bytes[this.uint8Offset + indexInPool]) : '';
        case DataType.UInt16:
          return indexInPool < this.uint16Count ? String(this.bytes.readUInt16LE(this.uint16Offset + indexInPool * 2)) : '';
        case DataType.UInt32:
          return indexInPool < this.uint32Count ? String(this.bytes.readUInt32LE(this.uint32Offset + indexInPool * 4)) : '';
        case DataType.UInt64: {
          if (indexInPool >= this.uint64Count) return '';
          const o = this.uint64Offset + indexInPool * 8;
          const low = this.bytes.readUInt32LE(o);
          const high = this.bytes.readUInt32LE(o + 4);
          return String((BigInt(high) << 32n) | BigInt(low));
        }
        case DataType.Single:
          return indexInPool < this.floatCount ? formatNumber(this.bytes.readFloatLE(this.floatOffset + indexInPool * 4)) : '';
        case DataType.Double:
          return indexInPool < this.doubleCount ? formatNumber(this.bytes.readDoubleLE(this.doubleOffset + indexInPool * 8), 6) : '';
        case DataType.Guid:
          if (indexInPool >= this.guidCount) return '';
          return this._readGuidAt(this.guidOffset + indexInPool * 16);
        case DataType.String:
          return indexInPool < this.stringIdCount ? this._getString(this.bytes.readInt32LE(this.stringIdOffset + indexInPool * 4), false) : '';
        case DataType.Locale:
          return indexInPool < this.localeCount ? this._getString(this.bytes.readInt32LE(this.localeOffset + indexInPool * 4), false) : '';
        case DataType.EnumChoice:
          return indexInPool < this.enumValueCount ? this._getString(this.bytes.readInt32LE(this.enumValueOffset + indexInPool * 4), false) : '';
        default:
          return '';
      }
    };
    const scanStruct = (structIndex, reader, attrs) => {
      let hasChildren = false;
      if (structIndex < 0 || structIndex >= this.structPropertyCache.length) {
        return { attrs, hasChildren };
      }
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        const dataType = property.dataType;
        const propertyName = this.propertyNameCache[propertyIndex];
        if (property.conversionType !== 0) {
          const count = reader.readInt32();
          reader.readInt32();
          if (count > 0) {
            hasChildren = true;
          }
          continue;
        }
        switch (dataType) {
          case DataType.Reference: {
            const reference = this._readReferenceInline(reader);
            if (reference.recordId !== EMPTY_GUID) {
              attrs.push({ name: propertyName, value: reference.recordId });
            }
            break;
          }
          case DataType.WeakPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              hasChildren = true;
            }
            break;
          }
          case DataType.StrongPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              hasChildren = true;
            }
            break;
          }
          case DataType.Class:
            hasChildren = true;
            if (property.structIndex >= 0 && property.structIndex < this.structDefinitions.length) {
              reader.advance(this.structDefinitions[property.structIndex].structSize);
            }
            break;
          default: {
            const value = readPrimitiveInline(dataType, reader);
            if (value !== '') {
              attrs.push({ name: propertyName, value });
            }
            break;
          }
        }
      }
      return { attrs, hasChildren };
    };
    const writeArrayElement = (propertyIndex, dataType, structIndex, reader) => {
      const count = reader.readInt32();
      const firstIndex = reader.readInt32();
      if (count <= 0 || firstIndex < 0) {
        return '';
      }
      const attrs = [{ name: 'Count', value: String(count) }];
      if (structIndex >= 0 && structIndex < this.structDefinitions.length) {
        attrs.push({ name: 'Type', value: getStructName(structIndex) });
      }
      let xml = `<${this.encodedPropertyNameCache[propertyIndex]}${writeAttributes(attrs)}>`;
      for (let i = 0; i < count; i += 1) {
        const poolIndex = firstIndex + i;
        switch (dataType) {
          case DataType.Reference: {
            if (poolIndex >= this.referenceCount) break;
            const reference = this._readReferenceAt(this.referenceOffset + poolIndex * 20);
            if (reference.recordId === EMPTY_GUID) break;
            const itemName = encodeXmlName(structIndex >= 0 ? getStructName(structIndex) : 'Reference');
            xml += `<${itemName} value="${escapeXml(reference.recordId)}"/>`;
            break;
          }
          case DataType.WeakPointer: {
            if (poolIndex >= this.weakCount) break;
            const pointer = this._readPointerAt(this.weakOffset + poolIndex * 8);
            if (pointer.structIndex < 0 || pointer.instanceIndex < 0) break;
            const itemType = getStructName(pointer.structIndex);
            xml += `<${getEncodedStructName(pointer.structIndex)} value="${escapeXml(`${itemType}[${formatPointerVariant(pointer.instanceIndex)}]`)}"/>`;
            break;
          }
          case DataType.StrongPointer: {
            if (poolIndex >= this.strongCount) break;
            const pointer = this._readPointerAt(this.strongOffset + poolIndex * 8);
            if (pointer.structIndex < 0 || pointer.instanceIndex < 0) break;
            xml += writeStructInstance(getEncodedStructName(pointer.structIndex), pointer.structIndex, pointer.instanceIndex, []);
            break;
          }
          case DataType.Class:
            xml += writeStructInstance(getEncodedStructName(structIndex), structIndex, poolIndex, []);
            break;
          default: {
            const value = readPrimitivePool(dataType, poolIndex);
            if (value !== '') {
              xml += `<${encodeXmlName(dataTypeName(dataType))} value="${escapeXml(value)}"/>`;
            }
            break;
          }
        }
      }
      xml += `</${this.encodedPropertyNameCache[propertyIndex]}>`;
      return xml;
    };
    const writeInlineClassElement = (elementName, structIndex, reader) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return `<${elementName}/>`;
      }
      const structSize = this.structDefinitions[structIndex].structSize;
      const span = reader.readSpan(structSize);
      const scanReader = new Reader(span);
      const attrs = [];
      const { hasChildren } = scanStruct(structIndex, scanReader, attrs);
      if (!hasChildren) {
        return `<${elementName}${writeAttributes(attrs)}/>`;
      }
      const childReader = new Reader(span);
      return `<${elementName}${writeAttributes(attrs)}>${writeStructChildren(structIndex, childReader)}</${elementName}>`;
    };
    const writeStructChildren = (structIndex, reader) => {
      if (structIndex < 0 || structIndex >= this.structPropertyCache.length) {
        return '';
      }
      let xml = '';
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        const dataType = property.dataType;
        if (property.conversionType !== 0) {
          xml += writeArrayElement(propertyIndex, dataType, property.structIndex, reader);
          continue;
        }
        switch (dataType) {
          case DataType.Reference:
            this._readReferenceInline(reader);
            break;
          case DataType.WeakPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              const itemType = getStructName(pointer.structIndex);
              xml += `<${this.encodedPropertyNameCache[propertyIndex]} value="${escapeXml(`${itemType}[${formatPointerVariant(pointer.instanceIndex)}]`)}"/>`;
            }
            break;
          }
          case DataType.StrongPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              xml += writeStructInstance(this.encodedPropertyNameCache[propertyIndex], pointer.structIndex, pointer.instanceIndex, []);
            }
            break;
          }
          case DataType.Class:
            xml += writeInlineClassElement(this.encodedPropertyNameCache[propertyIndex], property.structIndex, reader);
            break;
          default:
            readPrimitiveInline(dataType, reader);
            break;
        }
      }
      return xml;
    };
    const writeStructInstance = (elementName, structIndex, instanceIndex, extraAttrs) => {
      const key = instanceKey(structIndex, instanceIndex);
      if (activeInstances.has(key)) {
        return `<${elementName}${writeAttributes(extraAttrs)}/>`;
      }
      activeInstances.add(key);
      const span = getInstanceSpan(structIndex, instanceIndex);
      if (!span) {
        activeInstances.delete(key);
        return `<${elementName}${writeAttributes(extraAttrs)}/>`;
      }
      const scanReader = new Reader(span);
      const attrs = [...extraAttrs];
      const { hasChildren } = scanStruct(structIndex, scanReader, attrs);
      if (!hasChildren) {
        activeInstances.delete(key);
        return `<${elementName}${writeAttributes(attrs)}/>`;
      }
      const childReader = new Reader(span);
      const children = writeStructChildren(structIndex, childReader);
      activeInstances.delete(key);
      return `<${elementName}${writeAttributes(attrs)}>${children}</${elementName}>`;
    };

    return writeStructInstance(
      encodeXmlName(summary.name),
      record.structIndex,
      record.instanceIndex,
      [
        { name: '__type', value: getStructName(record.structIndex) },
        { name: '__ref', value: record.guid },
        { name: '__path', value: summary.fileName }
      ]
    );
  }

  _buildRecordEditableFieldIndex(index, rootNode = null) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    const parsedRoot = annotateXmlPaths(rootNode || parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
    const fieldIndex = new Map();
    const activeInstances = new Set();
    const structNameToIndex = this._getStructNameToIndexMap();
    const guidToRecordIndex = this._getRecordGuidToIndexMap();
    const fileNameToRecordIndex = this._getFileNameToMainRecordIndexMap();
    const getStructOffset = (structIndex, instanceIndex) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return -1;
      }
      return this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * instanceIndex;
    };
    const findChild = (node, name) => node.children.find((child) => child.name === name) || null;
    const instanceKey = (structIndex, instanceIndex) => `${structIndex}:${instanceIndex}`;
    const addDescriptor = (pathKey, descriptor) => fieldIndex.set(pathKey, descriptor);
    const addPrimitiveDescriptor = (pathKey, dataType, absoluteOffset) => {
      addDescriptor(pathKey, {
        read: () => this._readInlineValueString(dataType, absoluteOffset),
        write: (value) => this._writeInlineValueString(dataType, absoluteOffset, value)
      });
    };
    const addPoolDescriptor = (pathKey, dataType, poolIndex) => {
      addDescriptor(pathKey, {
        read: () => this._readPoolValueString(dataType, poolIndex),
        write: (value) => this._writePoolValueString(dataType, poolIndex, value)
      });
    };
    const addReferenceDescriptor = (pathKey, absoluteOffset) => {
      addDescriptor(pathKey, {
        read: () => this._readReferenceAt(absoluteOffset).recordId,
        write: (value) => this._writeReferenceValue(absoluteOffset, value, guidToRecordIndex)
      });
    };
    const addReferenceElementDescriptor = (pathKey, absoluteOffset, xmlAttrs, attributeName) => {
      addDescriptor(pathKey, {
        read: () => String(xmlAttrs?.[attributeName] || ''),
        write: (value) => {
          const mergedAttrs = { ...(xmlAttrs || {}), [attributeName]: value };
          const hasAnyReferenceTarget = ['ReferencedFile', 'RecordReference', 'RecordId', 'RecordName']
            .some((key) => String(mergedAttrs[key] || '').trim() !== '');
          if (!hasAnyReferenceTarget) {
            this.bytes.writeInt32LE(-1, absoluteOffset);
            writeGuidAt(this.bytes, absoluteOffset + 4, EMPTY_GUID);
            return;
          }
          const reference = this._resolveReferenceAttrsOrThrow(
            mergedAttrs,
            summary.fileName,
            guidToRecordIndex,
            fileNameToRecordIndex,
            pathKey
          );
          this.bytes.writeInt32LE(reference.instanceIndex, absoluteOffset);
          writeGuidAt(this.bytes, absoluteOffset + 4, reference.recordId);
        }
      });
    };
    const addReferenceElementDescriptors = (xmlNode, absoluteOffset) => {
      if (!xmlNode) {
        return;
      }
      for (const attributeName of ['ReferencedFile', 'RecordReference', 'RecordId', 'RecordName']) {
        addReferenceElementDescriptor(`${xmlNode._path}@${attributeName}`, absoluteOffset, xmlNode.attrs, attributeName);
      }
    };
    const addWeakPointerDescriptor = (pathKey, absoluteOffset) => {
      addDescriptor(pathKey, {
        read: () => this._pointerToText(this._readPointerAt(absoluteOffset)),
        write: (value) => this._writePointerValue(absoluteOffset, value, structNameToIndex)
      });
    };

    const indexStructAtOffset = (structIndex, absoluteOffset, xmlNode) => {
      if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return;
      }
      const structSize = this.structDefinitions[structIndex].structSize;
      const span = this.bytes.subarray(absoluteOffset, absoluteOffset + structSize);
      const reader = new Reader(span);
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        const propertyName = this.encodedPropertyNameCache[propertyIndex];
        const propertyChild = findChild(xmlNode, propertyName);
        if (property.conversionType !== 0) {
          const count = reader.readInt32();
          const firstIndex = reader.readInt32();
          if (!propertyChild || count <= 0 || firstIndex < 0) {
            continue;
          }
          for (let childIndex = 0; childIndex < propertyChild.children.length; childIndex += 1) {
            const childXml = propertyChild.children[childIndex];
            const poolIndex = firstIndex + childIndex;
            switch (property.dataType) {
              case DataType.Boolean:
              case DataType.SByte:
              case DataType.Int16:
              case DataType.Int32:
              case DataType.Int64:
              case DataType.Byte:
              case DataType.UInt16:
              case DataType.UInt32:
              case DataType.UInt64:
              case DataType.String:
              case DataType.Single:
              case DataType.Double:
              case DataType.Locale:
              case DataType.Guid:
              case DataType.EnumChoice:
                addPoolDescriptor(
                  Object.prototype.hasOwnProperty.call(childXml.attrs, 'value') ? `${childXml._path}@value` : childXml._path,
                  property.dataType,
                  poolIndex
                );
                break;
              case DataType.Class:
                indexStructInstance(property.structIndex, poolIndex, childXml);
                break;
              case DataType.StrongPointer: {
                const pointer = this._readPointerAt(this.strongOffset + poolIndex * 8);
                if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
                  indexStructInstance(pointer.structIndex, pointer.instanceIndex, childXml);
                }
                break;
              }
              case DataType.WeakPointer:
                addWeakPointerDescriptor(`${childXml._path}@value`, this.weakOffset + poolIndex * 8);
                break;
              case DataType.Reference:
                if (childXml?.attrs && Object.keys(childXml.attrs).length > 0) {
                  addReferenceElementDescriptors(childXml, this.referenceOffset + poolIndex * 20);
                } else {
                  addReferenceDescriptor(`${childXml._path}@value`, this.referenceOffset + poolIndex * 20);
                }
                break;
              default:
                break;
            }
          }
          continue;
        }

        const valueOffset = reader.position();
        const absoluteValueOffset = absoluteOffset + valueOffset;
        switch (property.dataType) {
          case DataType.Boolean:
          case DataType.SByte:
          case DataType.Int16:
          case DataType.Int32:
          case DataType.Int64:
          case DataType.Byte:
          case DataType.UInt16:
          case DataType.UInt32:
          case DataType.UInt64:
          case DataType.String:
          case DataType.Single:
          case DataType.Double:
          case DataType.Locale:
          case DataType.Guid:
          case DataType.EnumChoice:
            addPrimitiveDescriptor(`${xmlNode._path}@${propertyName}`, property.dataType, absoluteValueOffset);
            if (propertyChild && propertyChild.children.length === 0) {
              addPrimitiveDescriptor(propertyChild._path, property.dataType, absoluteValueOffset);
            }
            reader.advance(this._inlineValueSize(property.dataType));
            break;
          case DataType.Class:
            indexStructAtOffset(property.structIndex, absoluteValueOffset, propertyChild);
            reader.advance(this.structDefinitions[property.structIndex]?.structSize || 0);
            break;
          case DataType.StrongPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              indexStructInstance(pointer.structIndex, pointer.instanceIndex, propertyChild);
            }
            break;
          }
          case DataType.WeakPointer:
            if (propertyChild) {
              addWeakPointerDescriptor(`${propertyChild._path}@value`, absoluteValueOffset);
            }
            reader.advance(8);
            break;
          case DataType.Reference:
            if (Object.prototype.hasOwnProperty.call(xmlNode.attrs, propertyName)) {
              addReferenceDescriptor(`${xmlNode._path}@${propertyName}`, absoluteValueOffset);
            } else if (propertyChild && propertyChild.children.length === 0) {
              addReferenceElementDescriptors(propertyChild, absoluteValueOffset);
            }
            reader.advance(20);
            break;
          default:
            break;
        }
      }
    };

    const indexStructInstance = (structIndex, instanceIndex, xmlNode) => {
      if (!xmlNode) {
        return;
      }
      const key = instanceKey(structIndex, instanceIndex);
      if (activeInstances.has(key)) {
        return;
      }
      activeInstances.add(key);
      try {
        const absoluteOffset = getStructOffset(structIndex, instanceIndex);
        if (absoluteOffset >= 0) {
          indexStructAtOffset(structIndex, absoluteOffset, xmlNode);
        }
      } finally {
        activeInstances.delete(key);
      }
    };

    if (parsedRoot.name !== encodeXmlName(summary.name)) {
      throw new Error(`Record XML root mismatch while indexing editable fields: expected ${encodeXmlName(summary.name)}, got ${parsedRoot.name}`);
    }
    indexStructInstance(record.structIndex, record.instanceIndex, parsedRoot);
    return fieldIndex;
  }

  _buildRecordArrayFieldIndex(index, rootNode = null) {
    const record = this.records[index];
    const summary = this.recordSummaries[index];
    const parsedRoot = annotateXmlPaths(rootNode || parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
    const arrayIndex = new Map();
    const activeInstances = new Set();
    const getStructOffset = (structIndex, instanceIndex) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return -1;
      }
      return this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * instanceIndex;
    };
    const findChild = (node, name) => node.children.find((child) => child.name === name) || null;
    const instanceKey = (structIndex, instanceIndex) => `${structIndex}:${instanceIndex}`;

    const indexStructAtOffset = (structIndex, absoluteOffset, xmlNode) => {
      if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return;
      }
      const structSize = this.structDefinitions[structIndex].structSize;
      const span = this.bytes.subarray(absoluteOffset, absoluteOffset + structSize);
      const reader = new Reader(span);
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        const propertyName = this.encodedPropertyNameCache[propertyIndex];
        const propertyChild = findChild(xmlNode, propertyName);
        if (property.conversionType !== 0) {
          const arrayAbsoluteOffset = absoluteOffset + reader.position();
          const count = reader.readInt32();
          const firstIndex = reader.readInt32();
          if (propertyChild) {
            arrayIndex.set(propertyChild._path, {
              property,
              propertyName,
              itemTypeName: property.structIndex >= 0 && property.structIndex < this.structNameCache.length ? this.structNameCache[property.structIndex] : '',
              arrayAbsoluteOffset,
              count,
              firstIndex
            });
          }
          if (propertyChild && count > 0 && firstIndex >= 0) {
            for (let childIndex = 0; childIndex < propertyChild.children.length; childIndex += 1) {
              const childXml = propertyChild.children[childIndex];
              const poolIndex = firstIndex + childIndex;
              switch (property.dataType) {
                case DataType.Class:
                  indexStructInstance(property.structIndex, poolIndex, childXml);
                  break;
                case DataType.StrongPointer: {
                  const pointer = this._readPointerAt(this.strongOffset + poolIndex * 8);
                  if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
                    indexStructInstance(pointer.structIndex, pointer.instanceIndex, childXml);
                  }
                  break;
                }
                default:
                  break;
              }
            }
          }
          continue;
        }

        const valueOffset = reader.position();
        const absoluteValueOffset = absoluteOffset + valueOffset;
        switch (property.dataType) {
          case DataType.Class:
            indexStructAtOffset(property.structIndex, absoluteValueOffset, propertyChild);
            reader.advance(this.structDefinitions[property.structIndex]?.structSize || 0);
            break;
          case DataType.StrongPointer: {
            const pointer = this._readPointerInline(reader);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              indexStructInstance(pointer.structIndex, pointer.instanceIndex, propertyChild);
            }
            break;
          }
          default:
            reader.advance(this._inlineValueSize(property.dataType));
            break;
        }
      }
    };

    const indexStructInstance = (structIndex, instanceIndex, xmlNode) => {
      if (!xmlNode) {
        return;
      }
      const key = instanceKey(structIndex, instanceIndex);
      if (activeInstances.has(key)) {
        return;
      }
      activeInstances.add(key);
      try {
        const absoluteOffset = getStructOffset(structIndex, instanceIndex);
        if (absoluteOffset >= 0) {
          indexStructAtOffset(structIndex, absoluteOffset, xmlNode);
        }
      } finally {
        activeInstances.delete(key);
      }
    };

    if (parsedRoot.name !== encodeXmlName(summary.name)) {
      throw new Error(`Record XML root mismatch while indexing arrays: expected ${encodeXmlName(summary.name)}, got ${parsedRoot.name}`);
    }
    indexStructInstance(record.structIndex, record.instanceIndex, parsedRoot);
    return arrayIndex;
  }

  _applyReferenceArrayEdits(index, originalRoot, editedRoot) {
    const originalArrays = this._buildRecordArrayFieldIndex(index, originalRoot);
    const guidToRecordIndex = this._getRecordGuidToIndexMap();
    const fileNameToRecordIndex = this._getFileNameToMainRecordIndexMap();
    const currentFileName = this.recordSummaries[index]?.fileName || '';
    let changedValues = 0;
    let insertedByteShift = 0;

    const walk = (originalNode, editedNode) => {
      if (!originalNode || !editedNode || originalNode.name !== editedNode.name) {
        return;
      }

      const descriptor = originalArrays.get(originalNode._path);
      if (descriptor && descriptor.property.dataType === DataType.Reference) {
        const originalChildren = originalNode.children || [];
        const editedChildren = editedNode.children || [];
        const expectedName = encodeXmlName(descriptor.itemTypeName || '');
        const sameExistingPrefix = editedChildren.length >= originalChildren.length &&
          originalChildren.every((child, childIndex) => {
            const editedChild = editedChildren[childIndex];
            return editedChild && child.name === editedChild.name && JSON.stringify(child.attrs || {}) === JSON.stringify(editedChild.attrs || {});
          });
        const appendOnly = editedChildren.length >= originalChildren.length &&
          editedChildren.every((child) => !expectedName || child.name === expectedName) &&
          sameExistingPrefix;
        if (appendOnly && editedChildren.length !== originalChildren.length) {
          const appended = editedChildren.slice(originalChildren.length);
          const references = appended.map((child) => this._resolveReferenceXmlNode(child, currentFileName, guidToRecordIndex, fileNameToRecordIndex));
          insertedByteShift += this._appendReferenceArrayEntries(descriptor, references, insertedByteShift);
          changedValues += references.length;
          return;
        }
      }

      const count = Math.min((originalNode.children || []).length, (editedNode.children || []).length);
      for (let i = 0; i < count; i += 1) {
        walk(originalNode.children[i], editedNode.children[i]);
      }
    };

    walk(annotateXmlPaths(originalRoot), editedRoot);
    if (changedValues > 0) {
      this.dirty = true;
      this._parse();
    }
    return { changedValues };
  }

  _copyStructInstance(structIndex, sourceInstanceIndex, targetInstanceIndex) {
    if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }
    const structSize = this.structDefinitions[structIndex]?.structSize || 0;
    const baseOffset = this.structOffsets[structIndex];
    const sourceOffset = baseOffset + structSize * sourceInstanceIndex;
    const targetOffset = baseOffset + structSize * targetInstanceIndex;
    const snapshot = Buffer.from(this.bytes.subarray(sourceOffset, sourceOffset + structSize));
    snapshot.copy(this.bytes, targetOffset);
  }

  _appendClassArrayEntries(descriptor, totalCount) {
    const structIndex = descriptor?.property?.structIndex;
    if (typeof structIndex !== 'number' || structIndex < 0) {
      throw new Error(`Cannot append class-array entries for '${descriptor?.propertyName || 'unknown'}' without a valid struct type`);
    }

    const oldCount = Math.max(descriptor.count || 0, 0);
    const oldFirstIndex = descriptor.firstIndex ?? -1;
    let firstNewIndex = -1;
    for (let index = 0; index < totalCount; index += 1) {
      const newInstanceIndex = this._appendStructInstance(structIndex);
      if (firstNewIndex < 0) {
        firstNewIndex = newInstanceIndex;
      }
    }

    if (oldCount > 0 && oldFirstIndex >= 0) {
      for (let index = 0; index < oldCount; index += 1) {
        this._copyStructInstance(structIndex, oldFirstIndex + index, firstNewIndex + index);
      }
    }

    return {
      count: totalCount,
      firstIndex: firstNewIndex
    };
  }

  _applyClassArrayEdits(index, editedRoot) {
    let changedValues = 0;

    while (true) {
      const originalRoot = annotateXmlPaths(parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
      const originalArrays = this._buildRecordArrayFieldIndex(index, originalRoot);
      let handled = false;

      const walk = (originalNode, editedNode) => {
        if (handled || !originalNode || !editedNode || originalNode.name !== editedNode.name) {
          return;
        }

        const descriptor = originalArrays.get(originalNode._path);
        if (descriptor && descriptor.property.dataType === DataType.Class) {
          const originalChildren = originalNode.children || [];
          const editedChildren = editedNode.children || [];
          const sameExistingPrefix = editedChildren.length >= originalChildren.length &&
            originalChildren.every((child, childIndex) => {
              const editedChild = editedChildren[childIndex];
              return editedChild && child.name === editedChild.name && JSON.stringify(child.attrs || {}) === JSON.stringify(editedChild.attrs || {});
            });
          if (sameExistingPrefix && editedChildren.length > originalChildren.length) {
            const allocation = this._appendClassArrayEntries(descriptor, editedChildren.length);
            const refreshedRoot = annotateXmlPaths(parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
            const refreshedArrays = this._buildRecordArrayFieldIndex(index, refreshedRoot);
            const refreshedDescriptor = refreshedArrays.get(originalNode._path);
            if (!refreshedDescriptor) {
              throw new Error(`Failed to relocate class-array '${originalNode._path}' after allocating child instances`);
            }
            this.bytes.writeInt32LE(allocation.count, refreshedDescriptor.arrayAbsoluteOffset);
            this.bytes.writeInt32LE(allocation.count > 0 ? allocation.firstIndex : -1, refreshedDescriptor.arrayAbsoluteOffset + 4);
            this._parse();
            changedValues += editedChildren.length - originalChildren.length;
            handled = true;
            return;
          }
        }

        const count = Math.min((originalNode.children || []).length, (editedNode.children || []).length);
        for (let childIndex = 0; childIndex < count; childIndex += 1) {
          walk(originalNode.children[childIndex], editedNode.children[childIndex]);
          if (handled) {
            return;
          }
        }
      };

      walk(originalRoot, editedRoot);
      if (!handled) {
        break;
      }
    }

    if (changedValues > 0) {
      this.dirty = true;
    }
    return { changedValues };
  }

  _applyStrongPointerArrayEdits(index, editedRoot) {
    const currentFileName = this.recordSummaries[index]?.fileName || '';
    const context = {
      currentFileName,
      pointerMap: new Map(),
      guidToRecordIndex: this._getRecordGuidToIndexMap(),
      fileNameToRecordIndex: this._getFileNameToMainRecordIndexMap()
    };
    let changedValues = 0;

    while (true) {
      const originalRoot = annotateXmlPaths(parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
      const originalArrays = this._buildRecordArrayFieldIndex(index, originalRoot);
      let handled = false;

      const walk = (originalNode, editedNode) => {
        if (handled || !originalNode || !editedNode || originalNode.name !== editedNode.name) {
          return;
        }

        const descriptor = originalArrays.get(originalNode._path);
        if (descriptor && descriptor.property.dataType === DataType.StrongPointer) {
          const originalChildren = originalNode.children || [];
          const editedChildren = editedNode.children || [];
          const sameExistingPrefix = editedChildren.length >= originalChildren.length &&
            originalChildren.every((child, childIndex) => {
              const editedChild = editedChildren[childIndex];
              return editedChild && child.name === editedChild.name && JSON.stringify(child.attrs || {}) === JSON.stringify(editedChild.attrs || {});
            });
          const sameEditedPrefix = editedChildren.length <= originalChildren.length &&
            editedChildren.every((child, childIndex) => {
              const originalChild = originalChildren[childIndex];
              return originalChild && child.name === originalChild.name && JSON.stringify(child.attrs || {}) === JSON.stringify(originalChild.attrs || {});
            });
          if (sameExistingPrefix && editedChildren.length > originalChildren.length) {
            const appended = editedChildren.slice(originalChildren.length);
            const allocations = this._allocateStructTargetsForXmlNodes(appended, context, descriptor.itemTypeName || '');
            const refreshedRoot = annotateXmlPaths(parseXmlDocument(`<?xml version="1.0" encoding="utf-8"?>\n${this.exportRecordXml(index)}\n`));
            const refreshedArrays = this._buildRecordArrayFieldIndex(index, refreshedRoot);
            const refreshedDescriptor = refreshedArrays.get(originalNode._path);
            if (!refreshedDescriptor) {
              throw new Error(`Failed to relocate strong-pointer array '${originalNode._path}' after allocating child instances`);
            }
            this._appendStrongPointerArrayEntries(refreshedDescriptor, allocations);
            this._parse();
            allocations.forEach((entry) => this._applyXmlNodeToStructInstance(entry.structIndex, entry.instanceIndex, entry.xmlNode, context));
            changedValues += allocations.length;
            handled = true;
            return;
          }
          if (sameEditedPrefix && editedChildren.length < originalChildren.length) {
            const nextCount = editedChildren.length;
            this.bytes.writeInt32LE(nextCount, descriptor.arrayAbsoluteOffset);
            this.bytes.writeInt32LE(nextCount > 0 ? descriptor.firstIndex : -1, descriptor.arrayAbsoluteOffset + 4);
            this._parse();
            changedValues += originalChildren.length - editedChildren.length;
            handled = true;
            return;
          }
        }

        const count = Math.min((originalNode.children || []).length, (editedNode.children || []).length);
        for (let i = 0; i < count; i += 1) {
          walk(originalNode.children[i], editedNode.children[i]);
          if (handled) {
            return;
          }
        }
      };

      walk(originalRoot, editedRoot);
      if (!handled) {
        break;
      }
    }

    if (changedValues > 0) {
      this.dirty = true;
    }
    return { changedValues };
  }

  _ensureString1Value(value) {
    const text = String(value ?? '');
    const existingOffset = this._getString1Lookup().get(text);
    if (typeof existingOffset === 'number') {
      return existingOffset;
    }
    return this._appendString1(text);
  }

  _primeStringTableForXmlNode(structIndex, xmlNode) {
    if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }
    const findChild = (node, name) => (node?.children || []).find((child) => child.name === name) || null;
    const hasMeaningfulInlineNode = (node) => {
      if (!node) {
        return false;
      }
      const attrKeys = Object.keys(node.attrs || {}).filter((key) => !['PointsTo', 'Pointer', 'Type'].includes(key));
      return attrKeys.length > 0 || (node.children || []).length > 0 || String(node.text || '').trim() !== '';
    };

    for (const propertyIndex of this.structPropertyCache[structIndex]) {
      const property = this.propertyDefinitions[propertyIndex];
      const propertyName = this.encodedPropertyNameCache[propertyIndex];
      const propertyChild = findChild(xmlNode, propertyName);

      if (property.conversionType !== 0) {
        if (!propertyChild) {
          continue;
        }
        if ([DataType.String, DataType.Locale, DataType.EnumChoice].includes(property.dataType)) {
          for (const itemNode of propertyChild.children || []) {
            const itemValue = Object.prototype.hasOwnProperty.call(itemNode.attrs || {}, 'value')
              ? itemNode.attrs.value
              : itemNode.text;
            if (itemValue !== undefined && String(itemValue).trim() !== '') {
              this._ensureString1Value(itemValue);
            }
          }
        } else if (property.dataType === DataType.Class) {
          for (const itemNode of propertyChild.children || []) {
            this._primeStringTableForXmlNode(property.structIndex, itemNode);
          }
        } else if (property.dataType === DataType.StrongPointer) {
          const fallbackTypeName = property.structIndex >= 0 ? this.structNameCache[property.structIndex] : '';
          for (const itemNode of propertyChild.children || []) {
            const childStructIndex = this._resolveStructIndexForXmlNode(itemNode, fallbackTypeName);
            this._primeStringTableForXmlNode(childStructIndex, itemNode);
          }
        }
        continue;
      }

      if ([DataType.String, DataType.Locale, DataType.EnumChoice].includes(property.dataType)) {
        const attrValue = Object.prototype.hasOwnProperty.call(xmlNode.attrs || {}, propertyName)
          ? xmlNode.attrs[propertyName]
          : undefined;
        const nodeValue = propertyChild && propertyChild.children.length === 0 ? propertyChild.text : undefined;
        const value = attrValue !== undefined ? attrValue : nodeValue;
        if (value !== undefined && String(value).trim() !== '') {
          this._ensureString1Value(value);
        }
        continue;
      }

      if (property.dataType === DataType.Class && propertyChild) {
        this._primeStringTableForXmlNode(property.structIndex, propertyChild);
        continue;
      }

      if (property.dataType === DataType.StrongPointer && propertyChild && hasMeaningfulInlineNode(propertyChild)) {
        const childStructIndex = this._resolveStructIndexForXmlNode(
          propertyChild,
          property.structIndex >= 0 ? this.structNameCache[property.structIndex] : ''
        );
        this._primeStringTableForXmlNode(childStructIndex, propertyChild);
      }
    }
  }

  _resolveReferenceAttrsToTarget(attrs, currentFileName, guidToRecordIndex, fileNameToRecordIndex) {
    const byGuid = String(attrs.RecordId || '').trim().toLowerCase();
    if (byGuid && guidToRecordIndex.has(byGuid)) {
      const recordIndex = guidToRecordIndex.get(byGuid);
      return {
        instanceIndex: this.records[recordIndex].instanceIndex,
        recordId: this.records[recordIndex].guid
      };
    }

    const referenceFile = attrs.ReferencedFile || attrs.RecordReference || '';
    const resolvedFileName = resolveRecordReferenceFileName(referenceFile, currentFileName);
    if (resolvedFileName) {
      const recordIndex = fileNameToRecordIndex.get(normalizeDcbFileName(resolvedFileName));
      if (typeof recordIndex === 'number') {
        return {
          instanceIndex: this.records[recordIndex].instanceIndex,
          recordId: this.records[recordIndex].guid
        };
      }
    }

    const recordName = String(attrs.RecordName || '').trim();
    if (recordName) {
      const recordIndex = this.recordSummaries.findIndex((summary) => summary.name === recordName);
      if (recordIndex >= 0) {
        return {
          instanceIndex: this.records[recordIndex].instanceIndex,
          recordId: this.records[recordIndex].guid
        };
      }
    }

    return null;
  }

  _resolveReferenceXmlNode(node, currentFileName, guidToRecordIndex, fileNameToRecordIndex) {
    const attrs = node?.attrs || {};
    return this._resolveReferenceAttrsOrThrow(
      attrs,
      currentFileName,
      guidToRecordIndex,
      fileNameToRecordIndex,
      node?.name || 'Reference'
    );
  }

  _resolveReferenceAttrsOrThrow(attrs, currentFileName, guidToRecordIndex, fileNameToRecordIndex, contextLabel = 'Reference') {
    const resolved = this._resolveReferenceAttrsToTarget(attrs, currentFileName, guidToRecordIndex, fileNameToRecordIndex);
    if (resolved) {
      return resolved;
    }

    const referenceFile = String(attrs?.ReferencedFile || attrs?.RecordReference || '').trim();
    const resolvedFileName = resolveRecordReferenceFileName(referenceFile, currentFileName);
    const recordId = String(attrs?.RecordId || '').trim();
    const recordName = String(attrs?.RecordName || '').trim();
    const details = [];
    if (resolvedFileName) {
      details.push(`file '${resolvedFileName}'`);
    }
    if (recordName) {
      details.push(`record '${recordName}'`);
    }
    if (recordId) {
      details.push(`GUID '${recordId}'`);
    }
    const suffix = details.length > 0 ? ` (${details.join(', ')})` : '';
    throw new Error(`Reference target for ${contextLabel} was not found in the loaded DCB${suffix}. Create/import the target record first, then save the referencing XML again.`);
  }

  _resolveStructIndexForXmlNode(xmlNode, fallbackTypeName = '') {
    const typeName = String(xmlNode?.attrs?.Type || fallbackTypeName || xmlNode?.name || '').trim();
    if (!typeName) {
      throw new Error(`Could not resolve struct type for XML node '${xmlNode?.name || 'Unknown'}'`);
    }
    const structIndex = this._getStructNameToIndexMap().get(typeName);
    if (typeof structIndex !== 'number') {
      throw new Error(`Struct type '${typeName}' was not found in the DCB schema`);
    }
    return structIndex;
  }

  _appendStructInstance(structIndex) {
    const mappingIndex = this.dataMappings.findIndex((mapping) => mapping.structIndex === structIndex);
    if (mappingIndex < 0) {
      throw new Error(`Target data mapping for struct '${this.structNameCache[structIndex] || structIndex}' was not found`);
    }

    const structSize = this.structDefinitions[structIndex]?.structSize || 0;
    const newInstanceIndex = this.dataMappings[mappingIndex].structCount;
    const instanceInsertOffset = this.structOffsets[structIndex] + structSize * newInstanceIndex;
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, instanceInsertOffset),
      Buffer.alloc(structSize, 0),
      this.bytes.subarray(instanceInsertOffset)
    ]);
    this.bytes.writeUInt32LE(newInstanceIndex + 1, this.dataMappingsOffset + mappingIndex * 8);
    this._parse();
    this._initializeStructInstanceDefaults(structIndex, newInstanceIndex);
    return newInstanceIndex;
  }

  _writePointerTarget(absoluteOffset, target) {
    if (!target || target.structIndex < 0 || target.instanceIndex < 0) {
      this.bytes.writeInt32LE(-1, absoluteOffset);
      this.bytes.writeInt32LE(-1, absoluteOffset + 4);
      return;
    }
    this.bytes.writeInt32LE(target.structIndex, absoluteOffset);
    this.bytes.writeInt32LE(target.instanceIndex, absoluteOffset + 4);
  }

  _allocateStructTargetsForXmlNodes(xmlNodes, context, fallbackTypeName = '') {
    return (xmlNodes || []).map((xmlNode) => {
      const structIndex = this._resolveStructIndexForXmlNode(xmlNode, fallbackTypeName);
      const instanceIndex = this._appendStructInstance(structIndex);
      const pointerId = String(xmlNode?.attrs?.Pointer || '').trim();
      if (pointerId) {
        context.pointerMap.set(pointerId, { structIndex, instanceIndex });
      }
      return { xmlNode, structIndex, instanceIndex };
    });
  }

  _appendStrongPointerArrayEntries(descriptor, pointers) {
    if (!pointers.length) {
      return 0;
    }

    const arrayAbsoluteOffset = descriptor.arrayAbsoluteOffset;
    const oldCount = this.bytes.readInt32LE(arrayAbsoluteOffset);
    const oldFirstIndex = this.bytes.readInt32LE(arrayAbsoluteOffset + 4);
    const insertIndex = oldCount > 0 && oldFirstIndex >= 0
      ? oldFirstIndex + oldCount
      : this.strongCount;
    const insertOffset = this.strongOffset + insertIndex * 8;
    const payload = Buffer.alloc(pointers.length * 8, 0);
    pointers.forEach((pointer, index) => {
      const offset = index * 8;
      payload.writeInt32LE(pointer.structIndex, offset);
      payload.writeInt32LE(pointer.instanceIndex, offset + 4);
    });

    this._shiftStrongArrayFirstIndices(insertIndex, pointers.length, arrayAbsoluteOffset);
    this.bytes.writeUInt32LE(this.strongCount + pointers.length, this.strongCountHeaderOffset);
    this.bytes.writeInt32LE(oldCount + pointers.length, arrayAbsoluteOffset);
    if (oldCount <= 0 || oldFirstIndex < 0) {
      this.bytes.writeInt32LE(insertIndex, arrayAbsoluteOffset + 4);
    }
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, insertOffset),
      payload,
      this.bytes.subarray(insertOffset)
    ]);
    this.strongCount += pointers.length;
    return payload.length;
  }

  _shiftStrongArrayFirstIndices(insertIndex, insertedCount, skipArrayAbsoluteOffset = -1) {
    const shiftStruct = (structIndex, absoluteOffset) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return;
      }
      const span = this.bytes.subarray(absoluteOffset, absoluteOffset + this.structDefinitions[structIndex].structSize);
      const reader = new Reader(span);
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        if (property.conversionType !== 0) {
          const arrayOffset = absoluteOffset + reader.position();
          const count = reader.readInt32();
          const firstIndex = reader.readInt32();
          if (property.dataType === DataType.StrongPointer && arrayOffset !== skipArrayAbsoluteOffset && count > 0 && firstIndex >= insertIndex) {
            this.bytes.writeInt32LE(firstIndex + insertedCount, arrayOffset + 4);
          }
          continue;
        }
        switch (property.dataType) {
          case DataType.Class:
            shiftStruct(property.structIndex, absoluteOffset + reader.position());
            reader.advance(this.structDefinitions[property.structIndex]?.structSize || 0);
            break;
          default:
            reader.advance(this._inlineValueSize(property.dataType));
            break;
        }
      }
    };

    for (const mapping of this.dataMappings) {
      if (mapping.structIndex < 0 || mapping.structIndex >= this.structDefinitions.length) {
        continue;
      }
      const structSize = this.structDefinitions[mapping.structIndex].structSize;
      const baseOffset = this.structOffsets[mapping.structIndex];
      for (let instanceIndex = 0; instanceIndex < mapping.structCount; instanceIndex += 1) {
        shiftStruct(mapping.structIndex, baseOffset + structSize * instanceIndex);
      }
    }
  }

  _prepareXmlGraphForStructInstance(structIndex, instanceIndex, xmlNode, context) {
    if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }
    this._prepareXmlGraphForStructTarget(
      structIndex,
      () => this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * instanceIndex,
      xmlNode,
      context
    );
  }

  _prepareXmlGraphForStructTarget(structIndex, offsetResolver, xmlNode, context) {
    if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }

    const findChild = (node, name) => (node?.children || []).find((child) => child.name === name) || null;

    for (let propertyOrder = 0; propertyOrder < this.structPropertyCache[structIndex].length; propertyOrder += 1) {
      const descriptor = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
      if (!descriptor) {
        continue;
      }

      const { property, propertyName } = descriptor;
      const propertyChild = findChild(xmlNode, propertyName);
      if (!propertyChild) {
        continue;
      }

      if (property.conversionType !== 0) {
        if (property.dataType === DataType.StrongPointer && propertyChild.children.length > 0) {
          const fallbackTypeName = property.structIndex >= 0 ? this.structNameCache[property.structIndex] : '';
          const existingCount = Math.max(descriptor.count || 0, 0);
          const appendedChildren = propertyChild.children.slice(existingCount);
          if (appendedChildren.length > 0) {
            const allocations = this._allocateStructTargetsForXmlNodes(appendedChildren, context, fallbackTypeName);
            const refreshedDescriptorForAppend = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
            this._appendStrongPointerArrayEntries(refreshedDescriptorForAppend, allocations);
            this._parse();
          }

          const refreshedDescriptor = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
          const targets = [];
          const count = Math.min(propertyChild.children.length, Math.max(refreshedDescriptor?.count || 0, 0));
          const firstIndex = refreshedDescriptor?.firstIndex ?? -1;
          for (let childIndex = 0; childIndex < count; childIndex += 1) {
            const pointer = this._readPointerAt(this.strongOffset + (firstIndex + childIndex) * 8);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              targets.push(pointer);
              this._prepareXmlGraphForStructInstance(pointer.structIndex, pointer.instanceIndex, propertyChild.children[childIndex], context);
            }
          }
          context.strongPointerArrays?.set(propertyChild._path || `${xmlNode._path || xmlNode.name}/${propertyName}`, {
            count,
            firstIndex,
            targets
          });
        }
        continue;
      }

      switch (property.dataType) {
        case DataType.Class:
          this._prepareXmlGraphForStructTarget(
            property.structIndex,
            () => offsetResolver() + descriptor.relativeOffset,
            propertyChild,
            context
          );
          break;
        case DataType.StrongPointer: {
          const pointsTo = String(propertyChild.attrs?.PointsTo || '').trim();
          let target = pointsTo && context.pointerMap.has(pointsTo)
            ? context.pointerMap.get(pointsTo)
            : this._readPointerAt(descriptor.absoluteValueOffset);
          if ((target.structIndex < 0 || target.instanceIndex < 0) && hasMeaningfulXmlNode(propertyChild)) {
            const [allocation] = this._allocateStructTargetsForXmlNodes(
              [propertyChild],
              context,
              property.structIndex >= 0 ? this.structNameCache[property.structIndex] : ''
            );
            const refreshedDescriptorForWrite = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
            this._writePointerTarget(refreshedDescriptorForWrite.absoluteValueOffset, allocation);
            this._parse();
            target = allocation;
          }
          if (target.structIndex >= 0 && target.instanceIndex >= 0) {
            context.strongPointerTargets?.set(propertyChild._path || `${xmlNode._path || xmlNode.name}/${propertyName}`, target);
            this._prepareXmlGraphForStructInstance(target.structIndex, target.instanceIndex, propertyChild, context);
          }
          break;
        }
        default:
          break;
      }
    }
  }

  _applyXmlNodeToStructInstance(structIndex, instanceIndex, xmlNode, context) {
    if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }
    this._applyXmlNodeToStructTarget(
      structIndex,
      () => this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * instanceIndex,
      xmlNode,
      context
    );
  }

  _describeStructPropertyAtOffset(structIndex, absoluteOffset, propertyOrder) {
    if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return null;
    }

    const propertyIndex = this.structPropertyCache[structIndex]?.[propertyOrder];
    if (typeof propertyIndex !== 'number') {
      return null;
    }

    const structSize = this.structDefinitions[structIndex]?.structSize || 0;
    const span = this.bytes.subarray(absoluteOffset, absoluteOffset + structSize);
    const reader = new Reader(span);

    for (let currentOrder = 0; currentOrder <= propertyOrder; currentOrder += 1) {
      const currentPropertyIndex = this.structPropertyCache[structIndex][currentOrder];
      const property = this.propertyDefinitions[currentPropertyIndex];
      const propertyName = this.encodedPropertyNameCache[currentPropertyIndex];

      if (property.conversionType !== 0) {
        const arrayAbsoluteOffset = absoluteOffset + reader.position();
        const count = reader.readInt32();
        const firstIndex = reader.readInt32();
        if (currentOrder === propertyOrder) {
          return {
            propertyIndex: currentPropertyIndex,
            property,
            propertyName,
            isArray: true,
            relativeOffset: arrayAbsoluteOffset - absoluteOffset,
            absoluteValueOffset: arrayAbsoluteOffset,
            arrayAbsoluteOffset,
            count,
            firstIndex
          };
        }
        continue;
      }

      const valueOffset = reader.position();
      const absoluteValueOffset = absoluteOffset + valueOffset;
      if (currentOrder === propertyOrder) {
        return {
          propertyIndex: currentPropertyIndex,
          property,
          propertyName,
          isArray: false,
          relativeOffset: valueOffset,
          absoluteValueOffset
        };
      }

      switch (property.dataType) {
        case DataType.Class:
          reader.advance(this.structDefinitions[property.structIndex]?.structSize || 0);
          break;
        default:
          reader.advance(this._inlineValueSize(property.dataType));
          break;
      }
    }

    return null;
  }

  _applyXmlNodeToStructTarget(structIndex, offsetResolver, xmlNode, context) {
    if (!xmlNode || structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }

    const findChild = (node, name) => (node?.children || []).find((child) => child.name === name) || null;

    for (let propertyOrder = 0; propertyOrder < this.structPropertyCache[structIndex].length; propertyOrder += 1) {
      const descriptor = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
      if (!descriptor) {
        continue;
      }
      const { property, propertyName } = descriptor;
      const propertyChild = findChild(xmlNode, propertyName);

      if (property.conversionType !== 0) {
        if (propertyChild) {
          if (property.dataType === DataType.StrongPointer && propertyChild.children.length > 0) {
            const arrayKey = propertyChild._path || `${xmlNode._path || xmlNode.name}/${propertyName}`;
            const preparedArray = context.strongPointerArrays?.get(arrayKey) || null;
            const count = preparedArray ? preparedArray.count : Math.min(propertyChild.children.length, Math.max(descriptor.count || 0, 0));
            const firstIndex = preparedArray ? preparedArray.firstIndex : (descriptor.firstIndex ?? -1);
            this.bytes.writeInt32LE(count, descriptor.arrayAbsoluteOffset);
            this.bytes.writeInt32LE(count > 0 ? firstIndex : -1, descriptor.arrayAbsoluteOffset + 4);

            for (let childIndex = 0; childIndex < count; childIndex += 1) {
              const pointer = preparedArray?.targets?.[childIndex]
                || this._readPointerAt(this.strongOffset + (firstIndex + childIndex) * 8);
              if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
                this._applyXmlNodeToStructInstance(pointer.structIndex, pointer.instanceIndex, propertyChild.children[childIndex], context);
              }
            }
          } else if (propertyChild.children.length === 0) {
            this.bytes.writeInt32LE(0, descriptor.arrayAbsoluteOffset);
            this.bytes.writeInt32LE(-1, descriptor.arrayAbsoluteOffset + 4);
          }
        }
        continue;
      }

      switch (property.dataType) {
        case DataType.Boolean:
        case DataType.SByte:
        case DataType.Int16:
        case DataType.Int32:
        case DataType.Int64:
        case DataType.Byte:
        case DataType.UInt16:
        case DataType.UInt32:
        case DataType.UInt64:
        case DataType.String:
        case DataType.Single:
        case DataType.Double:
        case DataType.Locale:
        case DataType.Guid:
        case DataType.EnumChoice: {
          const attrValue = Object.prototype.hasOwnProperty.call(xmlNode.attrs || {}, propertyName)
            ? xmlNode.attrs[propertyName]
            : undefined;
          const nodeValue = propertyChild && propertyChild.children.length === 0 ? propertyChild.text : undefined;
          if (attrValue !== undefined) {
            this._writeInlineValueString(property.dataType, descriptor.absoluteValueOffset, attrValue);
          } else if (nodeValue !== undefined && String(nodeValue).trim() !== '') {
            this._writeInlineValueString(property.dataType, descriptor.absoluteValueOffset, nodeValue);
          }
          break;
        }
        case DataType.Class:
          if (propertyChild) {
            this._applyXmlNodeToStructTarget(
              property.structIndex,
              () => offsetResolver() + descriptor.relativeOffset,
              propertyChild,
              context
            );
          }
          break;
        case DataType.StrongPointer: {
          if (propertyChild) {
            const pointsTo = String(propertyChild.attrs?.PointsTo || '').trim();
            const pointerKey = propertyChild._path || `${xmlNode._path || xmlNode.name}/${propertyName}`;
            if (pointsTo && context.pointerMap.has(pointsTo)) {
              this._writePointerTarget(descriptor.absoluteValueOffset, context.pointerMap.get(pointsTo));
              this._applyXmlNodeToStructInstance(
                context.pointerMap.get(pointsTo).structIndex,
                context.pointerMap.get(pointsTo).instanceIndex,
                propertyChild,
                context
              );
            } else if (context.strongPointerTargets?.has(pointerKey)) {
              const target = context.strongPointerTargets.get(pointerKey);
              this._writePointerTarget(descriptor.absoluteValueOffset, target);
              this._applyXmlNodeToStructInstance(target.structIndex, target.instanceIndex, propertyChild, context);
            } else if (hasMeaningfulXmlNode(propertyChild)) {
              let target = this._readPointerAt(descriptor.absoluteValueOffset);
              if (target.structIndex < 0 || target.instanceIndex < 0) {
                const [allocation] = this._allocateStructTargetsForXmlNodes(
                  [propertyChild],
                  context,
                  property.structIndex >= 0 ? this.structNameCache[property.structIndex] : ''
                );
                const refreshedDescriptorForWrite = this._describeStructPropertyAtOffset(structIndex, offsetResolver(), propertyOrder);
                this._writePointerTarget(refreshedDescriptorForWrite.absoluteValueOffset, allocation);
                this._parse();
                target = allocation;
              }
              this._applyXmlNodeToStructInstance(target.structIndex, target.instanceIndex, propertyChild, context);
            } else {
              this._writePointerTarget(descriptor.absoluteValueOffset, null);
            }
          }
          break;
        }
        case DataType.WeakPointer: {
          const pointsTo = String(propertyChild?.attrs?.PointsTo || '').trim();
          if (pointsTo && context.pointerMap.has(pointsTo)) {
            this._writePointerTarget(descriptor.absoluteValueOffset, context.pointerMap.get(pointsTo));
          } else if (propertyChild) {
            this._writePointerTarget(descriptor.absoluteValueOffset, null);
          }
          break;
        }
        case DataType.Reference:
          if (Object.prototype.hasOwnProperty.call(xmlNode.attrs || {}, propertyName)) {
            this._writeReferenceValue(descriptor.absoluteValueOffset, xmlNode.attrs[propertyName], context.guidToRecordIndex);
          } else if (propertyChild?.attrs && Object.keys(propertyChild.attrs).length > 0) {
            const reference = this._resolveReferenceAttrsOrThrow(
              propertyChild.attrs,
              context.currentFileName,
              context.guidToRecordIndex,
              context.fileNameToRecordIndex,
              propertyChild._path || propertyName
            );
            this.bytes.writeInt32LE(reference.instanceIndex, descriptor.absoluteValueOffset);
            writeGuidAt(this.bytes, descriptor.absoluteValueOffset + 4, reference.recordId);
          } else if (propertyChild) {
            this.bytes.writeInt32LE(-1, descriptor.absoluteValueOffset);
            writeGuidAt(this.bytes, descriptor.absoluteValueOffset + 4, EMPTY_GUID);
          }
          break;
        default:
          break;
      }
    }
  }

  _applyXmlNodeToStructAtOffset(structIndex, absoluteOffset, xmlNode, context) {
    this._applyXmlNodeToStructTarget(structIndex, () => absoluteOffset, xmlNode, context);
  }

  _appendReferenceArrayEntries(descriptor, references, dataOffsetShift = 0) {
    if (!references.length) {
      return 0;
    }

    const arrayAbsoluteOffset = descriptor.arrayAbsoluteOffset + dataOffsetShift;
    const oldCount = this.bytes.readInt32LE(arrayAbsoluteOffset);
    const oldFirstIndex = this.bytes.readInt32LE(arrayAbsoluteOffset + 4);
    const insertIndex = oldCount > 0 && oldFirstIndex >= 0
      ? oldFirstIndex + oldCount
      : this.referenceCount;
    const insertOffset = this.referenceOffset + insertIndex * 20;
    const payload = Buffer.alloc(references.length * 20, 0);
    references.forEach((reference, index) => {
      const offset = index * 20;
      payload.writeInt32LE(reference.instanceIndex, offset);
      writeGuidAt(payload, offset + 4, reference.recordId);
    });

    this._shiftReferenceArrayFirstIndices(insertIndex, references.length, arrayAbsoluteOffset, dataOffsetShift);
    this.bytes.writeUInt32LE(this.referenceCount + references.length, this.referenceCountHeaderOffset);
    this.bytes.writeInt32LE(oldCount + references.length, arrayAbsoluteOffset);
    if (oldCount <= 0 || oldFirstIndex < 0) {
      this.bytes.writeInt32LE(insertIndex, arrayAbsoluteOffset + 4);
    }
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, insertOffset),
      payload,
      this.bytes.subarray(insertOffset)
    ]);
    this.referenceCount += references.length;
    return payload.length;
  }

  _shiftReferenceArrayFirstIndices(insertIndex, insertedCount, skipArrayAbsoluteOffset = -1, dataOffsetShift = 0) {
    const shiftStruct = (structIndex, absoluteOffset) => {
      if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
        return;
      }
      const span = this.bytes.subarray(absoluteOffset, absoluteOffset + this.structDefinitions[structIndex].structSize);
      const reader = new Reader(span);
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        if (property.conversionType !== 0) {
          const arrayOffset = absoluteOffset + reader.position();
          const count = reader.readInt32();
          const firstIndex = reader.readInt32();
          if (property.dataType === DataType.Reference && arrayOffset !== skipArrayAbsoluteOffset && count > 0 && firstIndex >= insertIndex) {
            this.bytes.writeInt32LE(firstIndex + insertedCount, arrayOffset + 4);
          }
          continue;
        }
        switch (property.dataType) {
          case DataType.Class:
            shiftStruct(property.structIndex, absoluteOffset + reader.position());
            reader.advance(this.structDefinitions[property.structIndex]?.structSize || 0);
            break;
          default:
            reader.advance(this._inlineValueSize(property.dataType));
            break;
        }
      }
    };

    for (const mapping of this.dataMappings) {
      if (mapping.structIndex < 0 || mapping.structIndex >= this.structDefinitions.length) {
        continue;
      }
      const structSize = this.structDefinitions[mapping.structIndex].structSize;
      const baseOffset = this.structOffsets[mapping.structIndex] + dataOffsetShift;
      for (let instanceIndex = 0; instanceIndex < mapping.structCount; instanceIndex += 1) {
        shiftStruct(mapping.structIndex, baseOffset + structSize * instanceIndex);
      }
    }
  }

  _parse() {
    this.dirty = false;
    this.structDefinitions = [];
    this.propertyDefinitions = [];
    this.enumDefinitions = [];
    this.dataMappings = [];
    this.structOffsets = [];
    this.structPropertyCache = [];
    this.structNameCache = [];
    this.encodedStructNameCache = [];
    this.propertyNameCache = [];
    this.encodedPropertyNameCache = [];
    this.records = [];
    this.recordSummaries = [];
    this.structTypeNamesCache = null;
    this.structTypeCompletionEntriesCache = null;
    this.structPropertyCompletionCache = new Map();
    this.propertyLookupCache = new Map();
    this.enumValueCache = new Map();
    this.stringTable1Lookup = null;
    this.structNameToIndex = null;
    this.recordGuidToIndex = null;
    this.fileNameToMainRecordIndex = null;
    this.mainRecordFileCounts = null;
    const reader = new Reader(this.bytes);

    reader.readUInt32();
    this.version = reader.readUInt32();
    if (this.version < 5) {
      throw new Error(`Unsupported DCB version ${this.version}`);
    }

    reader.readUInt32();
    reader.readUInt32();

    this.structCount = reader.readInt32();
    this.propertyCount = reader.readInt32();
    this.enumCount = reader.readInt32();
    this.mappingCount = reader.readInt32();
    this.recordCountHeaderOffset = reader.position();
    this.recordCount = reader.readInt32();

    if (this.version >= 8) {
      this.boolCount = reader.readInt32();
      this.int8Count = reader.readInt32();
      this.int16Count = reader.readInt32();
      this.int32Count = reader.readInt32();
      this.int64Count = reader.readInt32();
      this.uint8Count = reader.readInt32();
      this.uint16Count = reader.readInt32();
      this.uint32Count = reader.readInt32();
      this.uint64Count = reader.readInt32();
      this.stringIdCount = reader.readInt32();
      this.doubleCount = reader.readInt32();
      this.guidCount = reader.readInt32();
      this.floatCount = reader.readInt32();
      this.localeCount = reader.readInt32();
      this.enumValueCount = reader.readInt32();
      this.strongCountHeaderOffset = reader.position();
      this.strongCount = reader.readInt32();
      this.weakCount = reader.readInt32();
      this.referenceCountHeaderOffset = reader.position();
      this.referenceCount = reader.readInt32();
      this.enumOptionCount = reader.readInt32();
    } else {
      this.boolCount = reader.readInt32();
      this.int8Count = reader.readInt32();
      this.int16Count = reader.readInt32();
      this.int32Count = reader.readInt32();
      this.int64Count = reader.readInt32();
      this.uint8Count = reader.readInt32();
      this.uint16Count = reader.readInt32();
      this.uint32Count = reader.readInt32();
      this.uint64Count = reader.readInt32();
      this.floatCount = reader.readInt32();
      this.doubleCount = reader.readInt32();
      this.guidCount = reader.readInt32();
      this.stringIdCount = reader.readInt32();
      this.localeCount = reader.readInt32();
      this.enumValueCount = reader.readInt32();
      this.strongCountHeaderOffset = reader.position();
      this.strongCount = reader.readInt32();
      this.weakCount = reader.readInt32();
      this.referenceCountHeaderOffset = reader.position();
      this.referenceCount = reader.readInt32();
      this.enumOptionCount = reader.readInt32();
    }

    this.textLength1HeaderOffset = reader.position();
    this.stringTable1Length = reader.readUInt32();
    this.textLength2HeaderOffset = reader.position();
    const textLength2 = reader.readUInt32();

    for (let i = 0; i < this.structCount; i += 1) {
      this.structDefinitions.push({
        nameOffset: reader.readInt32(),
        parentTypeIndex: reader.readInt32(),
        attributeCount: reader.readUInt16(),
        firstAttributeIndex: reader.readUInt16(),
        structSize: reader.readUInt32()
      });
    }

    for (let i = 0; i < this.propertyCount; i += 1) {
      this.propertyDefinitions.push({
        nameOffset: reader.readInt32(),
        structIndex: reader.readUInt16(),
        dataType: reader.readUInt16(),
        conversionType: reader.readUInt16(),
        padding: reader.readUInt16()
      });
    }
    for (let i = 0; i < this.enumCount; i += 1) {
      this.enumDefinitions.push({
        nameOffset: reader.readInt32(),
        valueCount: reader.readUInt16(),
        firstValueIndex: reader.readUInt16()
      });
    }
    this.dataMappingsOffset = reader.position();
    for (let i = 0; i < this.mappingCount; i += 1) {
      this.dataMappings.push({
        structCount: reader.readUInt32(),
        structIndex: reader.readInt32()
      });
    }

    if (this.version >= 8) {
      this.recordsOffset = reader.position();
      for (let i = 0; i < this.recordCount; i += 1) {
        this.records.push({
          nameOffset: reader.readInt32(),
          fileNameOffset: reader.readInt32(),
          extraOffset: reader.readInt32(),
          structIndex: reader.readInt32(),
          guid: reader.readGuid(),
          instanceIndex: reader.readUInt16(),
          structSize: reader.readUInt16()
        });
      }

      this.boolOffset = reader.position();
      reader.advance(this.boolCount);
      this.int8Offset = reader.position();
      reader.advance(this.int8Count);
      this.int16Offset = reader.position();
      reader.advance(this.int16Count * 2);
      this.int32Offset = reader.position();
      reader.advance(this.int32Count * 4);
      this.int64Offset = reader.position();
      reader.advance(this.int64Count * 8);
      this.uint8Offset = reader.position();
      reader.advance(this.uint8Count);
      this.uint16Offset = reader.position();
      reader.advance(this.uint16Count * 2);
      this.uint32Offset = reader.position();
      reader.advance(this.uint32Count * 4);
      this.uint64Offset = reader.position();
      reader.advance(this.uint64Count * 8);
      this.stringIdOffset = reader.position();
      reader.advance(this.stringIdCount * 4);
      this.doubleOffset = reader.position();
      reader.advance(this.doubleCount * 8);
      this.guidOffset = reader.position();
      reader.advance(this.guidCount * 16);
      this.floatOffset = reader.position();
      reader.advance(this.floatCount * 4);
      this.localeOffset = reader.position();
      reader.advance(this.localeCount * 4);
      this.enumValueOffset = reader.position();
      reader.advance(this.enumValueCount * 4);
      this.strongOffset = reader.position();
      reader.advance(this.strongCount * 8);
      this.weakOffset = reader.position();
      reader.advance(this.weakCount * 8);
      this.referenceOffset = reader.position();
      reader.advance(this.referenceCount * 20);
      this.enumOptionOffset = reader.position();
      reader.advance(this.enumOptionCount * 4);

      this.stringTable1Offset = reader.position();
      reader.advance(this.stringTable1Length);
      this.stringTable2Offset = reader.position();
      this.stringTable2Length = textLength2;
      reader.advance(this.stringTable2Length);
    } else {
      this.recordsOffset = reader.position();
      for (let i = 0; i < this.recordCount; i += 1) {
        this.records.push({
          nameOffset: reader.readInt32(),
          fileNameOffset: reader.readInt32(),
          extraOffset: -1,
          structIndex: reader.readInt32(),
          guid: reader.readGuid(),
          instanceIndex: reader.readUInt16(),
          structSize: reader.readUInt16()
        });
      }

      this.int8Offset = reader.position();
      reader.advance(this.int8Count);
      this.int16Offset = reader.position();
      reader.advance(this.int16Count * 2);
      this.int32Offset = reader.position();
      reader.advance(this.int32Count * 4);
      this.int64Offset = reader.position();
      reader.advance(this.int64Count * 8);
      this.uint8Offset = reader.position();
      reader.advance(this.uint8Count);
      this.uint16Offset = reader.position();
      reader.advance(this.uint16Count * 2);
      this.uint32Offset = reader.position();
      reader.advance(this.uint32Count * 4);
      this.uint64Offset = reader.position();
      reader.advance(this.uint64Count * 8);
      this.boolOffset = reader.position();
      reader.advance(this.boolCount);
      this.floatOffset = reader.position();
      reader.advance(this.floatCount * 4);
      this.doubleOffset = reader.position();
      reader.advance(this.doubleCount * 8);
      this.guidOffset = reader.position();
      reader.advance(this.guidCount * 16);
      this.stringIdOffset = reader.position();
      reader.advance(this.stringIdCount * 4);
      this.localeOffset = reader.position();
      reader.advance(this.localeCount * 4);
      this.enumValueOffset = reader.position();
      reader.advance(this.enumValueCount * 4);
      this.strongOffset = reader.position();
      reader.advance(this.strongCount * 8);
      this.weakOffset = reader.position();
      reader.advance(this.weakCount * 8);
      this.referenceOffset = reader.position();
      reader.advance(this.referenceCount * 20);
      this.enumOptionOffset = reader.position();
      reader.advance(this.enumOptionCount * 4);

      this.stringTable1Offset = reader.position();
      reader.advance(this.stringTable1Length);
      this.stringTable2Offset = reader.position();
      this.stringTable2Length = this.version >= 6 ? textLength2 : this.stringTable1Length;
      if (this.version >= 6) {
        reader.advance(this.stringTable2Length);
      }
    }

    this.dataSectionOffset = reader.position();
    this._buildStructOffsets();
    this._buildXmlCaches();
    this._buildStructPropertyCache();
    this._buildRecordSummaries();
  }

  _getString(offset, secondTable) {
    if (offset < 0) {
      return '';
    }
    const tableOffset = secondTable ? this.stringTable2Offset : this.stringTable1Offset;
    const tableLength = secondTable ? this.stringTable2Length : this.stringTable1Length;
    if (offset >= tableLength) {
      return '';
    }
    return readNullTerminatedString(this.bytes, tableOffset + offset, tableLength - offset);
  }

  _readGuidAt(offset) {
    return this._readGuidAtBuffer(this.bytes, offset);
  }

  _readGuidAtBuffer(buffer, offset) {
    return [
      buffer[offset + 7], buffer[offset + 6], buffer[offset + 5], buffer[offset + 4],
      '-', buffer[offset + 3], buffer[offset + 2],
      '-', buffer[offset + 1], buffer[offset + 0],
      '-', buffer[offset + 15], buffer[offset + 14],
      '-', buffer[offset + 13], buffer[offset + 12], buffer[offset + 11], buffer[offset + 10], buffer[offset + 9], buffer[offset + 8]
    ].map((part) => (part === '-' ? '-' : Number(part).toString(16).padStart(2, '0'))).join('');
  }

  _readPointerInline(reader) {
    return {
      structIndex: reader.readInt32(),
      instanceIndex: reader.readInt32()
    };
  }

  _readPointerAt(offset) {
    return {
      structIndex: this.bytes.readInt32LE(offset),
      instanceIndex: this.bytes.readInt32LE(offset + 4)
    };
  }

  _readReferenceInline(reader) {
    return {
      instanceIndex: reader.readInt32(),
      recordId: reader.readGuid()
    };
  }

  _readReferenceAt(offset) {
    return {
      instanceIndex: this.bytes.readInt32LE(offset),
      recordId: this._readGuidAt(offset + 4)
    };
  }

  _buildStructOffsets() {
    this.structOffsets = new Array(this.structDefinitions.length).fill(0);
    let currentOffset = this.dataSectionOffset;
    for (const mapping of this.dataMappings) {
      if (mapping.structIndex < 0 || mapping.structIndex >= this.structDefinitions.length) {
        continue;
      }
      this.structOffsets[mapping.structIndex] = currentOffset;
      currentOffset += this.structDefinitions[mapping.structIndex].structSize * mapping.structCount;
    }
  }

  _buildXmlCaches() {
    this.structNameCache = this.structDefinitions.map((def) => this._getString(def.nameOffset, true));
    this.encodedStructNameCache = this.structNameCache.map((name) => encodeXmlName(name));
    this.propertyNameCache = this.propertyDefinitions.map((def) => this._getString(def.nameOffset, true));
    this.encodedPropertyNameCache = this.propertyNameCache.map((name) => encodeXmlName(name));
    this._ensureStructTypeCaches();
  }

  _ensureStructTypeCaches() {
    if (this.structTypeNamesCache && this.structTypeCompletionEntriesCache) {
      return;
    }
    const names = Array.from(new Set(this.structNameCache.filter((name) => String(name || '').trim())))
      .sort((left, right) => left.localeCompare(right, undefined, { sensitivity: 'base' }));
    this.structTypeNamesCache = names;
    this.structTypeCompletionEntriesCache = names.map((name) => ({
      name,
      lowered: name.toLowerCase()
    }));
  }

  _buildStructPropertyCache() {
    this.structPropertyCache = new Array(this.structDefinitions.length).fill(null).map(() => []);
    const build = (structIndex) => {
      const cached = this.structPropertyCache[structIndex];
      if (cached.length > 0 || this.structDefinitions[structIndex].attributeCount === 0) {
        if (cached.length > 0) {
          return;
        }
      }
      const parentIndex = this.structDefinitions[structIndex].parentTypeIndex;
      if (parentIndex >= 0 && parentIndex < this.structDefinitions.length) {
        build(parentIndex);
        this.structPropertyCache[structIndex] = [...this.structPropertyCache[parentIndex]];
      }
      const start = this.structDefinitions[structIndex].firstAttributeIndex;
      const end = start + this.structDefinitions[structIndex].attributeCount;
      for (let propertyIndex = start; propertyIndex < end && propertyIndex < this.propertyDefinitions.length; propertyIndex += 1) {
        this.structPropertyCache[structIndex].push(propertyIndex);
      }
    };
    for (let i = 0; i < this.structDefinitions.length; i += 1) {
      build(i);
    }
  }

  _buildRecordSummaries() {
    const firstRecordByFile = new Map();

    this.recordSummaries = this.records.map((record, index) => {
      const typeName = record.structIndex >= 0 && record.structIndex < this.structDefinitions.length
        ? this._getString(this.structDefinitions[record.structIndex].nameOffset, true)
        : 'Unknown';
      const fileName = this._getString(record.fileNameOffset, false);
      if (!firstRecordByFile.has(record.fileNameOffset)) {
        firstRecordByFile.set(record.fileNameOffset, record.guid);
      }
      const summary = {
        index,
        name: this._getString(record.nameOffset, true),
        typeName,
        fileName,
        guid: record.guid
      };
      summary.searchText = lowerAscii(`${summary.name}\n${summary.typeName}\n${summary.fileName}\n${summary.guid}`);
      return summary;
    });

    for (let i = 0; i < this.recordSummaries.length; i += 1) {
      const record = this.records[i];
      const firstGuid = firstRecordByFile.get(record.fileNameOffset);
      this.recordSummaries[i].isMain = firstGuid === record.guid;
    }
  }

  _getMainRecordFileCounts() {
    if (this.mainRecordFileCounts) {
      return this.mainRecordFileCounts;
    }
    this.mainRecordFileCounts = new Map();
    for (const summary of this.recordSummaries) {
      if (!summary.isMain) {
        continue;
      }
      this.mainRecordFileCounts.set(summary.fileName, (this.mainRecordFileCounts.get(summary.fileName) || 0) + 1);
    }
    return this.mainRecordFileCounts;
  }

  _getFileNameToMainRecordIndexMap() {
    if (this.fileNameToMainRecordIndex) {
      return this.fileNameToMainRecordIndex;
    }
    this.fileNameToMainRecordIndex = new Map();
    for (let index = 0; index < this.recordSummaries.length; index += 1) {
      const summary = this.recordSummaries[index];
      if (!summary?.fileName || !summary.isMain) {
        continue;
      }
      const key = normalizeDcbFileName(summary.fileName);
      if (!this.fileNameToMainRecordIndex.has(key)) {
        this.fileNameToMainRecordIndex.set(key, index);
      }
    }
    return this.fileNameToMainRecordIndex;
  }

  _buildPointerIdMap(rootStructIndex, rootInstanceIndex) {
    const pointerIds = new Map();
    const visited = new Set();
    const instanceKey = (structIndex, instanceIndex) => `${structIndex}:${instanceIndex}`;
    const walkStruct = (structIndex, reader) => {
      if (structIndex < 0 || structIndex >= this.structPropertyCache.length) {
        return;
      }
      for (const propertyIndex of this.structPropertyCache[structIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        if (property.conversionType === 0) {
          walkAttribute(property.dataType, property.structIndex, reader);
        } else {
          walkArray(property.dataType, property.structIndex, reader);
        }
      }
    };
    const walkInstance = (structIndex, instanceIndex) => {
      const key = instanceKey(structIndex, instanceIndex);
      if (visited.has(key)) {
        return;
      }
      visited.add(key);
      const span = (structIndex >= 0 && structIndex < this.structDefinitions.length)
        ? this.bytes.subarray(this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * instanceIndex, this.structOffsets[structIndex] + this.structDefinitions[structIndex].structSize * (instanceIndex + 1))
        : null;
      if (!span || span.length === 0) {
        return;
      }
      walkStruct(structIndex, new Reader(span));
    };
    const rememberPointer = (pointer) => {
      if (!pointer || pointer.structIndex < 0 || pointer.instanceIndex < 0) {
        return;
      }
      const key = instanceKey(pointer.structIndex, pointer.instanceIndex);
      if (!pointerIds.has(key)) {
        pointerIds.set(key, pointerIds.size);
      }
    };
    const walkAttribute = (dataType, structIndex, reader) => {
      switch (dataType) {
        case DataType.Reference:
          reader.advance(20);
          break;
        case DataType.WeakPointer: {
          const pointer = this._readPointerInline(reader);
          rememberPointer(pointer);
          break;
        }
        case DataType.StrongPointer: {
          const pointer = this._readPointerInline(reader);
          if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
            walkInstance(pointer.structIndex, pointer.instanceIndex);
          }
          break;
        }
        case DataType.Class:
          walkStruct(structIndex, new Reader(reader.readSpan(this.structDefinitions[structIndex]?.structSize || 0)));
          break;
        default:
          reader.advance(this._inlineValueSize(dataType));
          break;
      }
    };
    const walkArray = (dataType, structIndex, reader) => {
      const count = reader.readInt32();
      const firstIndex = reader.readInt32();
      if (count <= 0 || firstIndex < 0) {
        return;
      }
      for (let i = 0; i < count; i += 1) {
        const poolIndex = firstIndex + i;
        switch (dataType) {
          case DataType.WeakPointer:
            rememberPointer(this._readPointerAt(this.weakOffset + poolIndex * 8));
            break;
          case DataType.StrongPointer: {
            const pointer = this._readPointerAt(this.strongOffset + poolIndex * 8);
            if (pointer.structIndex >= 0 && pointer.instanceIndex >= 0) {
              walkInstance(pointer.structIndex, pointer.instanceIndex);
            }
            break;
          }
          case DataType.Class:
            walkInstance(structIndex, poolIndex);
            break;
          default:
            break;
        }
      }
    };
    walkInstance(rootStructIndex, rootInstanceIndex);
    return pointerIds;
  }

  _getStructNameToIndexMap() {
    if (this.structNameToIndex) {
      return this.structNameToIndex;
    }
    this.structNameToIndex = new Map();
    for (let i = 0; i < this.structNameCache.length; i += 1) {
      this.structNameToIndex.set(this.structNameCache[i], i);
    }
    return this.structNameToIndex;
  }

  _getRecordGuidToIndexMap() {
    if (this.recordGuidToIndex) {
      return this.recordGuidToIndex;
    }
    this.recordGuidToIndex = new Map();
    for (let index = 0; index < this.records.length; index += 1) {
      this.recordGuidToIndex.set(String(this.records[index].guid).toLowerCase(), index);
    }
    return this.recordGuidToIndex;
  }

  _getString1Lookup() {
    if (this.stringTable1Lookup) {
      return this.stringTable1Lookup;
    }
    const lookup = new Map();
    let relativeOffset = 0;
    while (relativeOffset < this.stringTable1Length) {
      const value = readNullTerminatedString(this.bytes, this.stringTable1Offset + relativeOffset, this.stringTable1Length - relativeOffset);
      if (!lookup.has(value)) {
        lookup.set(value, relativeOffset);
      }
      relativeOffset += Buffer.byteLength(value, 'utf8') + 1;
      if (value.length === 0) {
        relativeOffset += 0;
      }
    }
    this.stringTable1Lookup = lookup;
    return lookup;
  }

  _appendString1(value) {
    const key = String(value || '');
    const existing = this._getString1Lookup().get(key);
    if (typeof existing === 'number') {
      return existing;
    }

    const bytesToInsert = Buffer.from(`${key}\0`, 'utf8');
    const insertOffset = this.stringTable2Offset;
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, insertOffset),
      bytesToInsert,
      this.bytes.subarray(insertOffset)
    ]);

    const newOffset = this.stringTable1Length;
    const delta = bytesToInsert.length;
    this.stringTable1Length += delta;
    this.stringTable2Offset += delta;
    this.dataSectionOffset += delta;
    this.bytes.writeUInt32LE(this.stringTable1Length, this.textLength1HeaderOffset);
    this.stringTable1Lookup.set(key, newOffset);
    return newOffset;
  }

  _ensureString1OffsetDetails(value) {
    const key = String(value || '');
    const existing = this._getString1Lookup().get(key);
    if (typeof existing === 'number') {
      return {
        offset: existing,
        delta: 0,
        insertOffset: -1
      };
    }

    const insertOffset = this.stringTable2Offset;
    const bytesToInsert = Buffer.from(`${key}\0`, 'utf8');
    const delta = bytesToInsert.length;
    const offset = this._appendString1(key);
    return {
      offset,
      delta,
      insertOffset
    };
  }

  _appendString2(value) {
    const key = String(value || '');
    const existing = [];
    let relativeOffset = 0;
    while (relativeOffset < this.stringTable2Length) {
      const text = readNullTerminatedString(this.bytes, this.stringTable2Offset + relativeOffset, this.stringTable2Length - relativeOffset);
      if (text === key) {
        return relativeOffset;
      }
      relativeOffset += Buffer.byteLength(text, 'utf8') + 1;
    }

    const bytesToInsert = Buffer.from(`${key}\0`, 'utf8');
    const insertOffset = this.dataSectionOffset;
    this.bytes = Buffer.concat([
      this.bytes.subarray(0, insertOffset),
      bytesToInsert,
      this.bytes.subarray(insertOffset)
    ]);

    const newOffset = this.stringTable2Length;
    this.stringTable2Length += bytesToInsert.length;
    this.dataSectionOffset += bytesToInsert.length;
    this.bytes.writeUInt32LE(this.stringTable2Length, this.textLength2HeaderOffset);
    return newOffset;
  }

  _generateUniqueGuid() {
    const existing = new Set(this.records.map((record) => String(record.guid).toLowerCase()));
    while (true) {
      const candidate = crypto.randomUUID().toLowerCase();
      if (candidate !== EMPTY_GUID && !existing.has(candidate)) {
        return candidate;
      }
    }
  }

  _resolveRequestedOrGenerateGuid(requestedGuid) {
    const normalized = String(requestedGuid || '').trim().toLowerCase();
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(normalized) && normalized !== EMPTY_GUID) {
      const existing = this._getRecordGuidToIndexMap().get(normalized);
      if (typeof existing !== 'number') {
        return normalized;
      }
    }
    return this._generateUniqueGuid();
  }

  _initializeStructInstanceDefaults(structIndex, instanceIndex) {
    if (structIndex < 0 || structIndex >= this.structDefinitions.length) {
      return;
    }

    const structSize = this.structDefinitions[structIndex].structSize;
    const offset = this.structOffsets[structIndex] + structSize * instanceIndex;
    if (offset + structSize > this.bytes.length) {
      return;
    }

    const initializeStructSpan = (currentStructIndex, span, baseOffset = 0) => {
      if (currentStructIndex < 0 || currentStructIndex >= this.structPropertyCache.length) {
        return;
      }

      let cursor = 0;
      for (const propertyIndex of this.structPropertyCache[currentStructIndex]) {
        const property = this.propertyDefinitions[propertyIndex];
        if (!property) {
          continue;
        }

        if (property.conversionType !== 0) {
          cursor += 8;
          continue;
        }

        switch (property.dataType) {
          case DataType.Boolean:
          case DataType.SByte:
          case DataType.Byte:
            cursor += 1;
            break;
          case DataType.Int16:
          case DataType.UInt16:
            cursor += 2;
            break;
          case DataType.Int32:
          case DataType.UInt32:
          case DataType.Single:
          case DataType.String:
          case DataType.Locale:
          case DataType.EnumChoice:
            cursor += 4;
            break;
          case DataType.Int64:
          case DataType.UInt64:
          case DataType.Double:
            cursor += 8;
            break;
          case DataType.Guid:
            cursor += 16;
            break;
          case DataType.Reference:
            span.writeInt32LE(-1, baseOffset + cursor);
            writeGuidAt(span, baseOffset + cursor + 4, EMPTY_GUID);
            cursor += 20;
            break;
          case DataType.StrongPointer:
          case DataType.WeakPointer:
            span.writeInt32LE(-1, baseOffset + cursor);
            span.writeInt32LE(-1, baseOffset + cursor + 4);
            cursor += 8;
            break;
          case DataType.Class: {
            const nestedSize = (property.structIndex >= 0 && property.structIndex < this.structDefinitions.length)
              ? this.structDefinitions[property.structIndex].structSize
              : 0;
            initializeStructSpan(property.structIndex, span, baseOffset + cursor);
            cursor += nestedSize;
            break;
          }
          default:
            cursor += this._inlineValueSize(property.dataType);
            break;
        }
      }
    };

    initializeStructSpan(structIndex, this.bytes, offset);
  }

  _inlineValueSize(dataType) {
    switch (dataType) {
      case DataType.Boolean:
      case DataType.SByte:
      case DataType.Byte:
        return 1;
      case DataType.Int16:
      case DataType.UInt16:
        return 2;
      case DataType.Int32:
      case DataType.UInt32:
      case DataType.Single:
      case DataType.String:
      case DataType.Locale:
      case DataType.EnumChoice:
        return 4;
      case DataType.Int64:
      case DataType.UInt64:
      case DataType.Double:
      case DataType.StrongPointer:
      case DataType.WeakPointer:
        return 8;
      case DataType.Guid:
        return 16;
      case DataType.Reference:
        return 20;
      default:
        return 0;
    }
  }

  _readInlineValueString(dataType, absoluteOffset) {
    switch (dataType) {
      case DataType.Boolean:
        return this.bytes.readUInt8(absoluteOffset) !== 0 ? 'true' : 'false';
      case DataType.SByte:
        return String(this.bytes.readInt8(absoluteOffset));
      case DataType.Int16:
        return String(this.bytes.readInt16LE(absoluteOffset));
      case DataType.Int32:
        return String(this.bytes.readInt32LE(absoluteOffset));
      case DataType.Int64: {
        const low = this.bytes.readUInt32LE(absoluteOffset);
        const high = this.bytes.readInt32LE(absoluteOffset + 4);
        return String((BigInt(high) << 32n) | BigInt(low));
      }
      case DataType.Byte:
        return String(this.bytes.readUInt8(absoluteOffset));
      case DataType.UInt16:
        return String(this.bytes.readUInt16LE(absoluteOffset));
      case DataType.UInt32:
        return String(this.bytes.readUInt32LE(absoluteOffset));
      case DataType.UInt64: {
        const low = this.bytes.readUInt32LE(absoluteOffset);
        const high = this.bytes.readUInt32LE(absoluteOffset + 4);
        return String((BigInt(high) << 32n) | BigInt(low));
      }
      case DataType.Single:
        return formatNumber(this.bytes.readFloatLE(absoluteOffset));
      case DataType.Double:
        return formatNumber(this.bytes.readDoubleLE(absoluteOffset), 6);
      case DataType.Guid:
        return this._readGuidAt(absoluteOffset);
      case DataType.String:
      case DataType.Locale:
      case DataType.EnumChoice:
        return this._getString(this.bytes.readInt32LE(absoluteOffset), false);
      default:
        return '';
    }
  }

  _readPoolValueString(dataType, poolIndex) {
    return this._readPoolValueByIndex(dataType, poolIndex);
  }

  _readPoolValueByIndex(dataType, indexInPool) {
    switch (dataType) {
      case DataType.Boolean:
      case DataType.SByte:
      case DataType.Int16:
      case DataType.Int32:
      case DataType.Int64:
      case DataType.Byte:
      case DataType.UInt16:
      case DataType.UInt32:
      case DataType.UInt64:
      case DataType.String:
      case DataType.Single:
      case DataType.Double:
      case DataType.Locale:
      case DataType.Guid:
      case DataType.EnumChoice:
        return this.exportRecordXml ? (() => {
          switch (dataType) {
            case DataType.Boolean:
              return indexInPool < this.boolCount ? (this.bytes[this.boolOffset + indexInPool] !== 0 ? 'true' : 'false') : '';
            case DataType.SByte:
              return indexInPool < this.int8Count ? String(this.bytes.readInt8(this.int8Offset + indexInPool)) : '';
            case DataType.Int16:
              return indexInPool < this.int16Count ? String(this.bytes.readInt16LE(this.int16Offset + indexInPool * 2)) : '';
            case DataType.Int32:
              return indexInPool < this.int32Count ? String(this.bytes.readInt32LE(this.int32Offset + indexInPool * 4)) : '';
            case DataType.Int64: {
              if (indexInPool >= this.int64Count) return '';
              const o = this.int64Offset + indexInPool * 8;
              const low = this.bytes.readUInt32LE(o);
              const high = this.bytes.readInt32LE(o + 4);
              return String((BigInt(high) << 32n) | BigInt(low));
            }
            case DataType.Byte:
              return indexInPool < this.uint8Count ? String(this.bytes[this.uint8Offset + indexInPool]) : '';
            case DataType.UInt16:
              return indexInPool < this.uint16Count ? String(this.bytes.readUInt16LE(this.uint16Offset + indexInPool * 2)) : '';
            case DataType.UInt32:
              return indexInPool < this.uint32Count ? String(this.bytes.readUInt32LE(this.uint32Offset + indexInPool * 4)) : '';
            case DataType.UInt64: {
              if (indexInPool >= this.uint64Count) return '';
              const o = this.uint64Offset + indexInPool * 8;
              const low = this.bytes.readUInt32LE(o);
              const high = this.bytes.readUInt32LE(o + 4);
              return String((BigInt(high) << 32n) | BigInt(low));
            }
            case DataType.Single:
              return indexInPool < this.floatCount ? formatNumber(this.bytes.readFloatLE(this.floatOffset + indexInPool * 4)) : '';
            case DataType.Double:
              return indexInPool < this.doubleCount ? formatNumber(this.bytes.readDoubleLE(this.doubleOffset + indexInPool * 8), 6) : '';
            case DataType.Guid:
              return indexInPool < this.guidCount ? this._readGuidAt(this.guidOffset + indexInPool * 16) : '';
            case DataType.String:
              return indexInPool < this.stringIdCount ? this._getString(this.bytes.readInt32LE(this.stringIdOffset + indexInPool * 4), false) : '';
            case DataType.Locale:
              return indexInPool < this.localeCount ? this._getString(this.bytes.readInt32LE(this.localeOffset + indexInPool * 4), false) : '';
            case DataType.EnumChoice:
              return indexInPool < this.enumValueCount ? this._getString(this.bytes.readInt32LE(this.enumValueOffset + indexInPool * 4), false) : '';
            default:
              return '';
          }
        })() : '';
      default:
        return '';
    }
  }

  _writeInlineValueString(dataType, absoluteOffset, value) {
    switch (dataType) {
      case DataType.Boolean:
        this.bytes.writeUInt8(/^(1|true)$/i.test(String(value || '').trim()) ? 1 : 0, absoluteOffset);
        break;
      case DataType.SByte:
        this.bytes.writeInt8(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.Int16:
        this.bytes.writeInt16LE(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.Int32:
        this.bytes.writeInt32LE(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.Int64:
        this.bytes.writeBigInt64LE(BigInt(String(value).trim()), absoluteOffset);
        break;
      case DataType.Byte:
        this.bytes.writeUInt8(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.UInt16:
        this.bytes.writeUInt16LE(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.UInt32:
        this.bytes.writeUInt32LE(Number.parseInt(String(value), 10), absoluteOffset);
        break;
      case DataType.UInt64:
        this.bytes.writeBigUInt64LE(BigInt(String(value).trim()), absoluteOffset);
        break;
      case DataType.Single:
        this.bytes.writeFloatLE(Number.parseFloat(String(value)), absoluteOffset);
        break;
      case DataType.Double:
        this.bytes.writeDoubleLE(Number.parseFloat(String(value)), absoluteOffset);
        break;
      case DataType.Guid:
        writeGuidAt(this.bytes, absoluteOffset, String(value).trim());
        break;
      case DataType.String:
      case DataType.Locale:
      case DataType.EnumChoice: {
        const text = String(value ?? '');
        const stringRef = this._ensureString1OffsetDetails(text);
        const writeOffset = stringRef.delta > 0 && absoluteOffset >= stringRef.insertOffset
          ? absoluteOffset + stringRef.delta
          : absoluteOffset;
        this.bytes.writeInt32LE(stringRef.offset, writeOffset);
        break;
      }
      default:
        throw new Error(`Unsupported inline data type for XML save: ${dataTypeName(dataType)}`);
    }
  }

  _writePoolValueString(dataType, poolIndex, value) {
    switch (dataType) {
      case DataType.Boolean:
        this.bytes.writeUInt8(/^(1|true)$/i.test(String(value || '').trim()) ? 1 : 0, this.boolOffset + poolIndex);
        break;
      case DataType.SByte:
        this.bytes.writeInt8(Number.parseInt(String(value), 10), this.int8Offset + poolIndex);
        break;
      case DataType.Int16:
        this.bytes.writeInt16LE(Number.parseInt(String(value), 10), this.int16Offset + poolIndex * 2);
        break;
      case DataType.Int32:
        this.bytes.writeInt32LE(Number.parseInt(String(value), 10), this.int32Offset + poolIndex * 4);
        break;
      case DataType.Int64:
        this.bytes.writeBigInt64LE(BigInt(String(value).trim()), this.int64Offset + poolIndex * 8);
        break;
      case DataType.Byte:
        this.bytes.writeUInt8(Number.parseInt(String(value), 10), this.uint8Offset + poolIndex);
        break;
      case DataType.UInt16:
        this.bytes.writeUInt16LE(Number.parseInt(String(value), 10), this.uint16Offset + poolIndex * 2);
        break;
      case DataType.UInt32:
        this.bytes.writeUInt32LE(Number.parseInt(String(value), 10), this.uint32Offset + poolIndex * 4);
        break;
      case DataType.UInt64:
        this.bytes.writeBigUInt64LE(BigInt(String(value).trim()), this.uint64Offset + poolIndex * 8);
        break;
      case DataType.Single:
        this.bytes.writeFloatLE(Number.parseFloat(String(value)), this.floatOffset + poolIndex * 4);
        break;
      case DataType.Double:
        this.bytes.writeDoubleLE(Number.parseFloat(String(value)), this.doubleOffset + poolIndex * 8);
        break;
      case DataType.Guid:
        writeGuidAt(this.bytes, this.guidOffset + poolIndex * 16, String(value).trim());
        break;
      case DataType.String: {
        const text = String(value ?? '');
        const stringRef = this._ensureString1OffsetDetails(text);
        const baseOffset = this.stringIdOffset + poolIndex * 4;
        const writeOffset = stringRef.delta > 0 && baseOffset >= stringRef.insertOffset
          ? baseOffset + stringRef.delta
          : baseOffset;
        this.bytes.writeInt32LE(stringRef.offset, writeOffset);
        break;
      }
      case DataType.Locale: {
        const text = String(value ?? '');
        const stringRef = this._ensureString1OffsetDetails(text);
        const baseOffset = this.localeOffset + poolIndex * 4;
        const writeOffset = stringRef.delta > 0 && baseOffset >= stringRef.insertOffset
          ? baseOffset + stringRef.delta
          : baseOffset;
        this.bytes.writeInt32LE(stringRef.offset, writeOffset);
        break;
      }
      case DataType.EnumChoice: {
        const text = String(value ?? '');
        const stringRef = this._ensureString1OffsetDetails(text);
        const baseOffset = this.enumValueOffset + poolIndex * 4;
        const writeOffset = stringRef.delta > 0 && baseOffset >= stringRef.insertOffset
          ? baseOffset + stringRef.delta
          : baseOffset;
        this.bytes.writeInt32LE(stringRef.offset, writeOffset);
        break;
      }
      default:
        throw new Error(`Unsupported pooled data type for XML save: ${dataTypeName(dataType)}`);
    }
  }

  _pointerToText(pointer) {
    if (!pointer || pointer.structIndex < 0 || pointer.instanceIndex < 0 || pointer.structIndex >= this.structNameCache.length) {
      return '';
    }
    return `${this.structNameCache[pointer.structIndex]}[${pointer.instanceIndex.toString(16).toUpperCase().padStart(4, '0')}]`;
  }

  _writePointerValue(absoluteOffset, value, structNameToIndex) {
    const parsed = parsePointerText(value);
    const structIndex = structNameToIndex.get(parsed.structName);
    if (typeof structIndex !== 'number') {
      throw new Error(`Unknown pointer struct type: ${parsed.structName}`);
    }
    this.bytes.writeInt32LE(structIndex, absoluteOffset);
    this.bytes.writeInt32LE(parsed.instanceIndex, absoluteOffset + 4);
  }

  _writeReferenceValue(absoluteOffset, value, guidToRecordIndex) {
    const normalizedGuid = String(value).trim().toLowerCase();
    const targetIndex = guidToRecordIndex.get(normalizedGuid);
    if (typeof targetIndex !== 'number') {
      throw new Error(`Reference target GUID was not found in the loaded DCB: ${value}`);
    }
    this.bytes.writeInt32LE(this.records[targetIndex].instanceIndex, absoluteOffset);
    writeGuidAt(this.bytes, absoluteOffset + 4, this.records[targetIndex].guid);
  }
}

module.exports = {
  NativeDcbSession
};
