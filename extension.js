'use strict';

const vscode = require('vscode');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { NativeDcbSession } = require('./dcb-native');

class RecordTreeItem extends vscode.TreeItem {
  constructor(label, options = {}) {
    super(label, options.collapsibleState ?? vscode.TreeItemCollapsibleState.None);
    this.id = options.id;
    this.contextValue = options.contextValue;
    this.description = options.description;
    this.tooltip = options.tooltip;
    this.command = options.command;
    this.iconPath = options.iconPath;
    this.children = options.children || [];
  }
}

class DcbFileSystemProvider {
  constructor(state) {
    this.state = state;
    this._onDidChangeFile = new vscode.EventEmitter();
    this.onDidChangeFile = this._onDidChangeFile.event;
  }

  watch() {
    return new vscode.Disposable(() => {});
  }

  async stat(uri) {
    await this.state.ensureMountedSession(uri.authority);
    this.state.output.appendLine(`[dcb fs] stat ${uri.toString()}`);
    if (uri.scheme === 'dcb' && (!uri.path || uri.path === '/' || uri.path === '')) {
      return {
        type: vscode.FileType.Directory,
        ctime: 0,
        mtime: 0,
        size: 0
      };
    }
    const node = this.state.getVirtualNode(uri);
    if (!node) {
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    return {
      type: node.type === 'dir' ? vscode.FileType.Directory : vscode.FileType.File,
      ctime: 0,
      mtime: 0,
      size: node.type === 'file' ? this.state.getVirtualFileContent(node).length : 0
    };
  }

  async readDirectory(uri) {
    await this.state.ensureMountedSession(uri.authority);
    this.state.output.appendLine(`[dcb fs] readDirectory ${uri.toString()}`);
    const entries = this.state.listVirtualDirectory(uri);
    if (!entries) {
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    this.state.output.appendLine(`[dcb fs] -> ${entries.length} entries`);
    return entries;
  }

  async readFile(uri) {
    await this.state.ensureMountedSession(uri.authority);
    this.state.output.appendLine(`[dcb fs] readFile ${uri.toString()}`);
    const node = this.state.getVirtualNode(uri);
    if (!node || node.type !== 'file') {
      throw vscode.FileSystemError.FileNotFound(uri);
    }
    return this.state.getVirtualFileContent(node);
  }

  async createDirectory(uri) {
    await this.state.ensureMountedSession(uri.authority);
    await this.state.createVirtualDirectory(uri);
  }

  async writeFile(uri, content, options = {}) {
    await this.state.ensureMountedSession(uri.authority);
    const node = this.state.getVirtualNode(uri);
    if (node && node.type === 'file' && node.record) {
      await this.state.applyXmlToRecord(node.record.index, Buffer.from(content).toString('utf8'), uri);
      return;
    }
    await this.state.writeVirtualFile(uri, content, options);
  }

  async delete(uri) {
    if (this.state.deletePendingVirtualFile(uri)) {
      return;
    }
    if (this.state.deletePendingVirtualDirectory(uri)) {
      return;
    }
    await this.state.deleteVirtualRecord(uri);
  }

  async rename(oldUri, newUri, options = {}) {
    await this.state.ensureMountedSession(oldUri.authority);
    await this.state.renameVirtualPath(oldUri, newUri, options);
  }

  refresh(uri) {
    this._onDidChangeFile.fire([
      {
        type: vscode.FileChangeType.Changed,
        uri
      }
    ]);
  }

  fire(events) {
    this._onDidChangeFile.fire(events);
  }
}

class DcbTreeProvider {
  constructor(state) {
    this.state = state;
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
  }

  refresh() {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) {
    return element;
  }

  async getChildren(element) {
    if (element) {
      return element.children || [];
    }

    const nodes = [];
    if (!this.state.session) {
      nodes.push(new RecordTreeItem('Open a DCB to start', {
        description: 'No active session',
        command: {
          command: 'dcbEditor.openDcb',
          title: 'Open DCB'
        },
        iconPath: new vscode.ThemeIcon('folder-opened')
      }));
      return nodes;
    }

    nodes.push(new RecordTreeItem(path.basename(this.state.session.sourcePath), {
      id: `session:${this.state.session.sourcePath}`,
      description: `${this.state.session.recordCount} records`,
      tooltip: this.state.session.sourcePath,
      iconPath: new vscode.ThemeIcon('database')
    }));

    nodes.push(new RecordTreeItem(`Search: ${this.state.lastQuery || '(none)'}`, {
      id: 'search-root',
      description: `${this.state.searchResults.length} results`,
      command: {
        command: 'dcbEditor.searchRecords',
        title: 'Search Records'
      },
      iconPath: new vscode.ThemeIcon('search')
    }));

    nodes.push(new RecordTreeItem('Import XML File...', {
      id: 'import-action',
      command: {
        command: 'dcbEditor.importXmlFile',
        title: 'Import XML File'
      },
      iconPath: new vscode.ThemeIcon('cloud-upload')
    }));

    nodes.push(new RecordTreeItem('Save DCB To Source', {
      id: 'save-action',
      command: {
        command: 'dcbEditor.saveDcb',
        title: 'Save DCB'
      },
      iconPath: new vscode.ThemeIcon('save')
    }));

    const resultChildren = this.state.searchResults.map((record) => {
      const label = `${record.name}`;
      return new RecordTreeItem(label, {
        id: `search-record:${record.index}`,
        description: `${record.typeName} | ${record.fileName}`,
        tooltip: `${record.guid}\n${record.fileName}`,
        command: {
          command: 'dcbEditor.openRecord',
          title: 'Open Record',
          arguments: [record]
        },
        iconPath: new vscode.ThemeIcon('file-code'),
        contextValue: 'dcbRecord'
      });
    });

    nodes.push(new RecordTreeItem('Search Results', {
      id: 'search-results',
      description: `${this.state.searchResults.length}`,
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      children: resultChildren,
      iconPath: new vscode.ThemeIcon('list-unordered')
    }));

    nodes.push(new RecordTreeItem('Files', {
      id: 'files-root',
      description: `${this.state.fileTreeRoots.length}`,
      collapsibleState: vscode.TreeItemCollapsibleState.Expanded,
      children: this.state.fileTreeRoots,
      iconPath: new vscode.ThemeIcon('files')
    }));

    return nodes;
  }
}

class DcbExtensionState {
  constructor(context) {
    this.context = context;
    this.output = vscode.window.createOutputChannel('DCB Editor');
    this.treeProvider = new DcbTreeProvider(this);
    this.fileSystemProvider = new DcbFileSystemProvider(this);
    this.nativeSession = null;
    this.session = null;
    this.searchResults = [];
    this.lastQuery = '';
    this.fileTreeRoots = [];
    this.virtualRoot = null;
    this.virtualAuthority = '';
    this.virtualNodeByPath = new Map();
    this.virtualRecordByPath = new Map();
    this.virtualDirectoryEntries = new Map();
    this.virtualFileCache = new Map();
    this.pendingVirtualFiles = new Map();
    this.pendingVirtualDirectories = new Set();
    this.mountedWorkspaceUri = null;
    this.mountedMirrorWorkspaceUri = null;
    this.mirrorRootPath = '';
    this.mirrorFilePathByRecordIndex = new Map();
    this.mountSourceByAuthority = new Map(Object.entries(this.context.globalState.get('dcbEditor.mountSourceByAuthority', {})));
    this.restorePromise = null;
    this.docBindings = new Map();
    this.isApplyingSave = new Set();
    this.hydratingMirrorFiles = new Set();
  }

  isDcbXmlDocument(document) {
    if (!document) {
      return false;
    }
    if (document.languageId !== 'xml') {
      return false;
    }
    if (document.uri?.scheme === 'dcb') {
      return true;
    }
    return this.docBindings.has(path.resolve(document.uri?.fsPath || ''));
  }

  async dispose() {
    try {
      this.nativeSession = null;
      this.session = null;
    } catch (error) {
      this.output.appendLine(`Dispose error: ${error.message}`);
    }
    this.output.dispose();
  }

  async restoreMountedDcbWorkspaceFolders() {
    const folders = vscode.workspace.workspaceFolders;
    if (!folders || folders.length === 0) {
      return;
    }
    const dcbFolders = folders.filter((folder) => folder.uri.scheme === 'dcb');
    if (dcbFolders.length === 0) {
      return;
    }
    for (const folder of dcbFolders) {
      const authority = String(folder.uri.authority || '').toLowerCase();
      if (!authority) {
        continue;
      }
      const sourcePath = this.mountSourceByAuthority.get(authority);
      if (!sourcePath) {
        this.output.appendLine(`[dcb fs] no persisted source for existing folder ${folder.uri.toString()}; leaving as-is`);
        continue;
      }
      try {
        await this.ensureMountedSession(authority);
        this.mountedWorkspaceUri = folder.uri;
        this.virtualAuthority = authority;
        this.fileSystemProvider.refresh(folder.uri);
        this.output.appendLine(`[dcb fs] restored mount for ${folder.uri.toString()}`);
      } catch (error) {
        this.output.appendLine(`[dcb fs] failed to restore ${folder.uri.toString()}: ${error.message}`);
      }
    }
  }

  async openDcb() {
    const picked = await vscode.window.showOpenDialog({
      canSelectMany: false,
      filters: { DCB: ['dcb'] },
      openLabel: 'Open DCB'
    });
    if (!picked || !picked.length) {
      return;
    }

    const sourcePath = picked[0].fsPath;
    const targetAuthority = sanitizeAuthority(path.basename(sourcePath));
    const willTriggerHostRestart = !vscode.workspace.workspaceFolders || vscode.workspace.workspaceFolders.length === 0;

    if (willTriggerHostRestart) {
      this.mountSourceByAuthority.set(targetAuthority, sourcePath);
      await this.context.globalState.update(
        'dcbEditor.mountSourceByAuthority',
        Object.fromEntries(this.mountSourceByAuthority.entries())
      );
      this.output.appendLine(`[dcb fs] empty window detected; persisting ${targetAuthority} -> ${sourcePath} before mount`);
      const uri = vscode.Uri.parse(`dcb://${targetAuthority}/`);
      const folderName = `${path.basename(sourcePath)} [DCB]`;
      const success = vscode.workspace.updateWorkspaceFolders(0, null, { uri, name: folderName });
      if (!success) {
        throw new Error('VS Code could not mount the DCB virtual filesystem.');
      }
      vscode.window.showInformationMessage(
        `Mounting ${path.basename(sourcePath)}... VS Code will reload the window to attach the DCB filesystem.`
      );
      return;
    }

    await this.closeSession();
    await this.unmountAllDcbWorkspaceFolders();

    this.output.appendLine(`Opening DCB: ${sourcePath}`);
    const nativeSession = await NativeDcbSession.open(picked[0].fsPath);
    const payload = nativeSession.getMetadata();
    this.nativeSession = nativeSession;
    this.session = {
      id: 'dcb',
      sourcePath: payload.sourcePath,
      sessionPath: payload.sourcePath,
      recordCount: payload.recordCount,
      structCount: payload.structCount,
      propertyCount: payload.propertyCount,
      version: payload.version,
      backend: 'dcb'
    };
    this.searchResults = [];
    this.lastQuery = '';
    const mainRecords = this.nativeSession.getMainRecordSummaries();
    this.fileTreeRoots = this.buildFileTreeItems(mainRecords);
    this.buildVirtualFileSystem(mainRecords);
    await this.unmountMirrorWorkspace();
    await this.mountInNativeExplorer();
    this.treeProvider.refresh();
    vscode.window.showInformationMessage(
      `Opened ${path.basename(this.session.sourcePath)} (${this.session.recordCount} records, v${this.session.version}).`
    );
  }

  async closeSession() {
    await this.unmountAllDcbWorkspaceFolders();
    await this.unmountMirrorWorkspace();
    this.nativeSession = null;
    this.virtualRoot = null;
    this.virtualAuthority = '';
    this.mirrorRootPath = '';
    this.virtualNodeByPath.clear();
    this.virtualRecordByPath.clear();
    this.virtualDirectoryEntries.clear();
    this.virtualFileCache.clear();
    this.pendingVirtualFiles.clear();
    this.pendingVirtualDirectories.clear();
    this.mirrorFilePathByRecordIndex.clear();
    this.restorePromise = null;
    this.docBindings.clear();
    this.isApplyingSave.clear();
    this.hydratingMirrorFiles.clear();

    this.session = null;
    this.searchResults = [];
    this.lastQuery = '';
    this.fileTreeRoots = [];
    this.docBindings.clear();
    this.pendingVirtualFiles.clear();
    this.pendingVirtualDirectories.clear();
    this.treeProvider.refresh();
  }

  async refresh() {
    if (!this.session || !this.lastQuery) {
      if (this.mountedWorkspaceUri) {
        this.fileSystemProvider.refresh(this.mountedWorkspaceUri);
      }
      this.treeProvider.refresh();
      return;
    }
    await this.searchRecords(this.lastQuery);
  }

  async searchRecords(initialQuery) {
    if (!this.session) {
      await this.openDcb();
      if (!this.session) {
        return;
      }
    }

    let query = initialQuery;
    if (typeof query !== 'string') {
      query = await vscode.window.showInputBox({
        prompt: 'Search records by name, type, file path, or GUID',
        value: this.lastQuery || ''
      });
      if (typeof query !== 'string') {
        return;
      }
    }

    const limit = vscode.workspace.getConfiguration('dcbEditor').get('searchLimit', 200);
    if (!this.nativeSession) {
      throw new Error('No DCB session is loaded.');
    }
    const results = this.nativeSession.searchRecords(query, limit);
    this.lastQuery = query;
    this.searchResults = results;
    this.treeProvider.refresh();
    vscode.window.showInformationMessage(`Found ${results.length} record(s) for "${query}".`);
  }

  async openRecord(record) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    const summary = this.nativeSession.getRecordSummary(record.index);
    if (!summary) {
      throw new Error(`Record ${record.index} was not found in the DCB session.`);
    }

    const mirrorFilePath = this.mirrorFilePathByRecordIndex.get(record.index);
    if (mirrorFilePath && fs.existsSync(mirrorFilePath)) {
      const document = await vscode.workspace.openTextDocument(mirrorFilePath);
      this.docBindings.set(path.resolve(document.uri.fsPath), {
        recordIndex: record.index,
        sourcePath: summary.fileName,
        isMirror: true
      });
      await vscode.languages.setTextDocumentLanguage(document, 'xml');
      await vscode.window.showTextDocument(document, { preview: false });
      return;
    }

    const storageRoot = this.context.globalStorageUri.fsPath;
    const sessionFolder = path.join(storageRoot, this.session.id);
    await fsp.mkdir(sessionFolder, { recursive: true });

    const safeName = sanitizeFileName(`${summary.index}-${summary.name}.xml`);
    const filePath = path.join(sessionFolder, safeName);
    const xml = formatXmlDocument(
      `<?xml version="1.0" encoding="utf-8"?>\n${this.nativeSession.exportRecordXml(record.index)}\n`
    );
    await fsp.writeFile(filePath, xml, 'utf8');

    const document = await vscode.workspace.openTextDocument(filePath);
    this.docBindings.set(path.resolve(document.uri.fsPath), {
      recordIndex: record.index,
      sourcePath: summary.fileName
    });
    await vscode.languages.setTextDocumentLanguage(document, 'xml');
    await vscode.window.showTextDocument(document, { preview: false });
    vscode.window.showInformationMessage('Record XML was opened from the DCB. Saving this document writes the changes back to the DCB session.');
  }

  async importXmlFromFile(fileUri) {
    throw new Error('XML file import is not available from this command yet. Open the DCB in the Explorer and create or edit XML there.');
  }

  async importActiveXml() {
    throw new Error('Active XML import is not available from this command yet. Open the DCB in the Explorer and create or edit XML there.');
  }

  async importXmlText(xmlText, sourcePathHint) {
    throw new Error('XML text import is not available from this command yet. Open the DCB in the Explorer and create or edit XML there.');
  }

  async saveSessionToSource() {
    if (!this.session) {
      throw new Error('No active DCB session');
    }
    if (!this.nativeSession) {
      throw new Error('No DCB session is loaded.');
    }
    if (!this.nativeSession.isDirty()) {
      vscode.window.showInformationMessage('No pending DCB changes to save.');
      return;
    }
    await this.nativeSession.saveToFile(this.session.sourcePath);
    vscode.window.showInformationMessage(`Saved ${path.basename(this.session.sourcePath)}.`);
  }

  async handleDocumentSave(document) {
    const documentPath = document.uri?.scheme === 'file' ? path.resolve(document.uri.fsPath) : '';
    if (documentPath && this.hydratingMirrorFiles.has(documentPath)) {
      return;
    }
    const binding = this.docBindings.get(documentPath);
    if (!binding) {
      if (documentPath && this.isPathInsideMirror(documentPath) && path.extname(documentPath).toLowerCase() === '.xml') {
        await this.createMirrorRecordFromFile(documentPath, document.getText(), { showWarnings: false });
      }
      return;
    }
    if (this.isApplyingSave.has(document.uri.toString())) {
      return;
    }
    await this.applyXmlToRecord(binding.recordIndex, document.getText(), document.uri);
  }

  async handleDocumentOpen(document) {
    if (!document || document.uri?.scheme !== 'file') {
      return;
    }
    const documentPath = path.resolve(document.uri.fsPath);
    const binding = this.docBindings.get(documentPath);
    if (!binding || !binding.isMirror || binding.hydrated) {
      return;
    }
    if (!isMirrorPlaceholderText(document.getText())) {
      binding.hydrated = true;
      return;
    }
    await this.hydrateMirrorDocument(document, binding);
  }

  async hydrateMirrorDocument(document, binding) {
    if (!this.nativeSession || !binding || typeof binding.recordIndex !== 'number') {
      return;
    }

    const documentPath = path.resolve(document.uri.fsPath);
    if (this.hydratingMirrorFiles.has(documentPath)) {
      return;
    }

    this.hydratingMirrorFiles.add(documentPath);
    try {
      const xmlText = this.buildRecordXmlDocument(binding.recordIndex);
      await fsp.writeFile(documentPath, xmlText, 'utf8');

      const fullRange = new vscode.Range(
        new vscode.Position(0, 0),
        document.lineAt(Math.max(0, document.lineCount - 1)).range.end
      );
      const edit = new vscode.WorkspaceEdit();
      edit.replace(document.uri, fullRange, xmlText);
      await vscode.workspace.applyEdit(edit);
      binding.hydrated = true;
      await document.save();
    } finally {
      this.hydratingMirrorFiles.delete(documentPath);
    }
  }

  async applyXmlToRecord(recordIndex, xmlText, sourceUri) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    xmlText = syncXmlCountAttributes(xmlText);
    const saveKey = sourceUri.toString();
    if (this.isApplyingSave.has(saveKey)) {
      return;
    }
    this.isApplyingSave.add(saveKey);
    try {
      const result = this.nativeSession.applyRecordXml(recordIndex, xmlText);
      this.invalidateRecordCaches(recordIndex);
      await this.syncMirrorRecord(recordIndex, sourceUri);
      if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
        await this.nativeSession.saveToFile(this.session.sourcePath);
      }
      this.treeProvider.refresh();
      if (this.mountedWorkspaceUri) {
        this.fileSystemProvider.refresh(this.mountedWorkspaceUri);
      }
      this.output.appendLine(`[dcb write] record ${recordIndex} -> ${result.changedValues} changed value(s)`);
    } finally {
      this.isApplyingSave.delete(saveKey);
    }
  }

  async createMirrorRecordFromFile(filePath, xmlText, options = {}) {
    if (!this.session || !this.nativeSession || !this.isPathInsideMirror(filePath)) {
      return false;
    }

    const resolvedFilePath = path.resolve(filePath);
    if (this.docBindings.has(resolvedFilePath)) {
      return false;
    }

    const virtualPath = this.mirrorFilePathToVirtualPath(resolvedFilePath);
    if (!virtualPath || path.extname(virtualPath).toLowerCase() !== '.xml') {
      return false;
    }

    const text = syncXmlCountAttributes(String(xmlText || ''));
    if (!text.trim()) {
      return false;
    }

    const parsed = parseRecordXml(text);
    if (!parsed.rootName || !parsed.typeName || parsed.typeName === 'StructType' || !this.nativeSession.hasStructType(parsed.typeName)) {
      const message = `Mirror XML is not ready to create a DCB record yet: ${virtualPath}`;
      this.output.appendLine(`[dcb mirror create] ${message}`);
      if (options.showWarnings) {
        void vscode.window.showWarningMessage(message);
      }
      return false;
    }

    const shouldExpandToDefaultTemplate = isBareRecordRootXml(text);
    const result = this.nativeSession.createRecordFromXmlScratch(text, virtualPath.replace(/^\/+/, ''));
    this.rebuildVirtualExplorer();
    this.refreshMirrorBindingsFromSummaries();
    if (shouldExpandToDefaultTemplate) {
      await this.syncMirrorRecord(result.index);
    }
    if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
      await this.nativeSession.saveToFile(this.session.sourcePath);
    }
    this.output.appendLine(`[dcb mirror create] ${result.name} -> ${result.fileName}`);
    return true;
  }

  async writeVirtualFile(uri, content, options = {}) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    const virtualPath = normalizeVirtualPath(uri.path || '/');
    if (virtualPath === '/') {
      throw vscode.FileSystemError.NoPermissions('Cannot write to the DCB root.');
    }

    const existingNode = this.getVirtualNode(uri);
    if (existingNode && existingNode.record) {
      throw vscode.FileSystemError.FileExists(uri);
    }

    let xmlText = Buffer.from(content).toString('utf8');
    const hadPendingFile = this.pendingVirtualFiles.has(virtualPath);
    if (!xmlText.trim() && !hadPendingFile && options.create) {
      xmlText = buildNewRecordStub(virtualPath);
    }

    xmlText = syncXmlCountAttributes(xmlText);
    const parsed = parseRecordXml(xmlText);
    if (!parsed.rootName || !parsed.typeName) {
      this.pendingVirtualFiles.set(virtualPath, Buffer.from(xmlText, 'utf8'));
      this.rebuildVirtualExplorer();
      this.fileSystemProvider.fire([
        { type: hadPendingFile ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created, uri },
        { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
      ]);
      if (xmlText.trim()) {
        this.output.appendLine(`[dcb create] pending ${virtualPath} (waiting for root Type + valid XML)`);
      }
      return;
    }

    if (parsed.typeName === 'StructType' || !this.nativeSession.hasStructType(parsed.typeName)) {
      this.pendingVirtualFiles.set(virtualPath, Buffer.from(xmlText, 'utf8'));
      this.rebuildVirtualExplorer();
      this.fileSystemProvider.fire([
        { type: hadPendingFile ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created, uri },
        { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
      ]);
      this.output.appendLine(`[dcb create] pending ${virtualPath} (waiting for valid schema type)`);
      return;
    }

    try {
      const result = this.nativeSession.createRecordFromXmlScratch(xmlText, virtualPath.replace(/^\/+/, ''));
      this.pendingVirtualFiles.delete(virtualPath);
      this.rebuildVirtualExplorer();
      this.invalidateRecordCaches(result.index);
      await this.ensureMirrorRecord(result.index, virtualPath);
      if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
        await this.nativeSession.saveToFile(this.session.sourcePath);
      }
      this.treeProvider.refresh();
      this.fileSystemProvider.fire([
        { type: hadPendingFile ? vscode.FileChangeType.Changed : vscode.FileChangeType.Created, uri },
        { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
      ]);
      this.output.appendLine(`[dcb create] ${result.name} -> ${result.fileName}`);
    } catch (error) {
      this.pendingVirtualFiles.set(virtualPath, Buffer.from(xmlText, 'utf8'));
      this.rebuildVirtualExplorer();
      this.output.appendLine(`[dcb create] pending ${virtualPath}: ${error.message}`);
      vscode.window.showWarningMessage(`DCB file kept as pending XML: ${error.message}`);
    }
  }

  async createVirtualDirectory(uri) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    const virtualPath = normalizeVirtualPath(uri.path || '/');
    if (virtualPath === '/') {
      return;
    }

    const existingNode = this.getVirtualNode(uri);
    if (existingNode) {
      if (existingNode.type === 'dir') {
        return;
      }
      throw vscode.FileSystemError.FileExists(uri);
    }

    const parts = virtualPath.split('/').filter(Boolean);
    let current = '';
    for (const part of parts) {
      current = `${current}/${part}`;
      this.pendingVirtualDirectories.add(current);
    }

    this.rebuildVirtualExplorer();
    this.fileSystemProvider.fire([
      { type: vscode.FileChangeType.Created, uri },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
    ]);
    this.output.appendLine(`[dcb mkdir] ${virtualPath}`);
  }

  invalidateRecordCaches(recordIndex) {
    const virtualPath = this.findVirtualPathForRecordIndex(recordIndex);
    if (virtualPath) {
      this.virtualFileCache.delete(virtualPath);
      this.fileSystemProvider.refresh(vscode.Uri.parse(`dcb://${this.virtualAuthority}${virtualPath}`));
    }
  }

  deletePendingVirtualFile(uri) {
    const virtualPath = normalizeVirtualPath(uri.path || '/');
    if (!this.pendingVirtualFiles.has(virtualPath)) {
      return false;
    }
    this.pendingVirtualFiles.delete(virtualPath);
    this.rebuildVirtualExplorer();
    this.fileSystemProvider.fire([
      { type: vscode.FileChangeType.Deleted, uri },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
    ]);
    return true;
  }

  deletePendingVirtualDirectory(uri) {
    const virtualPath = normalizeVirtualPath(uri.path || '/');
    if (!this.pendingVirtualDirectories.has(virtualPath)) {
      return false;
    }

    const prefix = `${virtualPath}/`;
    for (const [nodePath] of this.virtualNodeByPath.entries()) {
      if (nodePath && nodePath !== virtualPath && nodePath.startsWith(prefix)) {
        return false;
      }
    }
    for (const filePath of this.pendingVirtualFiles.keys()) {
      if (filePath === virtualPath || filePath.startsWith(prefix)) {
        return false;
      }
    }
    for (const dirPath of this.pendingVirtualDirectories) {
      if (dirPath !== virtualPath && dirPath.startsWith(prefix)) {
        return false;
      }
    }

    this.pendingVirtualDirectories.delete(virtualPath);
    this.rebuildVirtualExplorer();
    this.fileSystemProvider.fire([
      { type: vscode.FileChangeType.Deleted, uri },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath)}`) }
    ]);
    return true;
  }

  async deleteVirtualRecord(uri) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    const node = this.getVirtualNode(uri);
    if (!node || node.type !== 'file' || !node.record) {
      throw vscode.FileSystemError.NoPermissions('DCB explorer directories are currently read-only.');
    }

    const fileName = String(node.record.fileName || '').replace(/\\/g, '/');
    const confirmation = await vscode.window.showWarningMessage(
      `Delete ${path.posix.basename(fileName)} from the DCB?`,
      { modal: true, detail: 'This first version removes the record entries for this file from the DCB record table.' },
      'Delete'
    );
    if (confirmation !== 'Delete') {
      return;
    }

    const result = this.nativeSession.deleteRecordsByFileName(fileName);
    this.virtualFileCache.delete(normalizeVirtualPath(uri.path || '/'));
    await this.deleteMirrorVirtualPath(normalizeVirtualPath(uri.path || '/'));
    this.rebuildVirtualExplorer();
    if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
      await this.nativeSession.saveToFile(this.session.sourcePath);
    }
    this.fileSystemProvider.fire([
      { type: vscode.FileChangeType.Deleted, uri },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(normalizeVirtualPath(uri.path || '/')) === '.' ? '/' : path.posix.dirname(normalizeVirtualPath(uri.path || '/'))}`) }
    ]);
    this.output.appendLine(`[dcb delete] ${result.fileName} -> ${result.deletedRecordCount} record(s) removed`);
  }

  async handleMirrorFilesCreated(event) {
    if (!this.session || !this.nativeSession || !this.mirrorRootPath) {
      return;
    }

    for (const uri of event.files || []) {
      if (uri.scheme !== 'file' || !this.isPathInsideMirror(uri.fsPath) || path.extname(uri.fsPath).toLowerCase() !== '.xml') {
        continue;
      }
      try {
        const xmlText = await fsp.readFile(uri.fsPath, 'utf8');
        await this.createMirrorRecordFromFile(uri.fsPath, xmlText, { showWarnings: false });
      } catch (error) {
        this.output.appendLine(`[dcb mirror create] warning: ${error.message}`);
      }
    }
  }

  async handleMirrorFilesDeleted(event) {
    if (!this.session || !this.nativeSession || !this.mirrorRootPath) {
      return;
    }

    let changed = false;
    for (const uri of event.files || []) {
      if (uri.scheme !== 'file' || !this.isPathInsideMirror(uri.fsPath) || path.extname(uri.fsPath).toLowerCase() !== '.xml') {
        continue;
      }

      const resolvedFilePath = path.resolve(uri.fsPath);
      const binding = this.docBindings.get(resolvedFilePath);
      const fileName = binding?.sourcePath || this.mirrorFilePathToVirtualPath(resolvedFilePath).replace(/^\/+/, '');
      this.docBindings.delete(resolvedFilePath);
      try {
        const result = this.nativeSession.deleteRecordsByFileName(fileName);
        this.output.appendLine(`[dcb mirror delete] ${result.fileName} -> ${result.deletedRecordCount} record(s) removed`);
        changed = true;
      } catch (error) {
        this.output.appendLine(`[dcb mirror delete] warning: ${fileName}: ${error.message}`);
      }
    }

    if (!changed) {
      return;
    }

    this.rebuildVirtualExplorer();
    this.refreshMirrorBindingsFromSummaries();
    if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
      await this.nativeSession.saveToFile(this.session.sourcePath);
    }
  }

  async handleMirrorFilesRenamed(event) {
    if (!this.session || !this.nativeSession || !this.mirrorRootPath) {
      return;
    }

    let changed = false;
    for (const file of event.files || []) {
      const oldUri = file.oldUri;
      const newUri = file.newUri;
      const oldInside = oldUri?.scheme === 'file' && this.isPathInsideMirror(oldUri.fsPath);
      const newInside = newUri?.scheme === 'file' && this.isPathInsideMirror(newUri.fsPath);

      if (!oldInside && newInside) {
        try {
          const xmlText = await fsp.readFile(newUri.fsPath, 'utf8');
          changed = await this.createMirrorRecordFromFile(newUri.fsPath, xmlText, { showWarnings: false }) || changed;
        } catch (error) {
          this.output.appendLine(`[dcb mirror rename/create] warning: ${error.message}`);
        }
        continue;
      }

      if (oldInside && !newInside) {
        await this.handleMirrorFilesDeleted({ files: [oldUri] });
        changed = true;
        continue;
      }

      if (!oldInside || !newInside || path.extname(newUri.fsPath).toLowerCase() !== '.xml') {
        continue;
      }

      const oldPath = path.resolve(oldUri.fsPath);
      const newPath = path.resolve(newUri.fsPath);
      const binding = this.docBindings.get(oldPath);
      const oldFileName = binding?.sourcePath || this.mirrorFilePathToVirtualPath(oldPath).replace(/^\/+/, '');
      const newFileName = this.mirrorFilePathToVirtualPath(newPath).replace(/^\/+/, '');

      try {
        const result = this.nativeSession.renameRecordsByFileName(oldFileName, newFileName);
        this.output.appendLine(`[dcb mirror rename] ${result.oldFileName} -> ${result.newFileName} (${result.renamedRecordCount} record(s))`);
        changed = true;
      } catch (error) {
        this.output.appendLine(`[dcb mirror rename] warning: ${oldFileName} -> ${newFileName}: ${error.message}`);
      }
    }

    if (!changed) {
      return;
    }

    this.rebuildVirtualExplorer();
    this.refreshMirrorBindingsFromSummaries();
    if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
      await this.nativeSession.saveToFile(this.session.sourcePath);
    }
  }

  async renameVirtualPath(oldUri, newUri, options = {}) {
    if (!this.session || !this.nativeSession) {
      throw new Error('No active DCB session');
    }

    const oldPath = normalizeVirtualPath(oldUri.path || '/');
    const newPath = normalizeVirtualPath(newUri.path || '/');
    if (oldPath === '/' || newPath === '/') {
      throw vscode.FileSystemError.NoPermissions('Cannot rename the DCB root.');
    }
    if (oldPath === newPath) {
      return;
    }

    const oldNode = this.getVirtualNode(oldUri);
    if (!oldNode) {
      throw vscode.FileSystemError.FileNotFound(oldUri);
    }
    if (oldNode.type !== 'file') {
      throw vscode.FileSystemError.NoPermissions('Directory rename is not supported yet.');
    }

    const targetNode = this.getVirtualNode(newUri);
    if (targetNode) {
      if (!options.overwrite) {
        throw vscode.FileSystemError.FileExists(newUri);
      }
      if (targetNode.record) {
        throw vscode.FileSystemError.NoPermissions('Overwriting an existing DCB record file is not supported.');
      }
      this.deletePendingVirtualFile(newUri);
    }

    if (this.pendingVirtualFiles.has(oldPath)) {
      const pending = this.pendingVirtualFiles.get(oldPath);
      this.pendingVirtualFiles.delete(oldPath);
      this.pendingVirtualFiles.set(newPath, pending);
      this.rebuildVirtualExplorer();
      this.fileSystemProvider.fire([
        { type: vscode.FileChangeType.Deleted, uri: oldUri },
        { type: vscode.FileChangeType.Created, uri: newUri },
        { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(oldPath) === '.' ? '/' : path.posix.dirname(oldPath)}`) },
        { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(newPath) === '.' ? '/' : path.posix.dirname(newPath)}`) }
      ]);
      this.output.appendLine(`[dcb rename] pending ${oldPath} -> ${newPath}`);
      return;
    }

    if (!oldNode.record) {
      throw vscode.FileSystemError.NoPermissions('Only DCB files can be renamed right now.');
    }

    const oldFileName = String(oldNode.record.fileName || '').replace(/\\/g, '/');
    const newFileName = newPath.replace(/^\/+/, '');
    const result = this.nativeSession.renameRecordsByFileName(oldFileName, newFileName);
    this.virtualFileCache.delete(oldPath);
    this.virtualFileCache.delete(newPath);
    await this.renameMirrorVirtualPath(oldPath, newPath, oldNode.record?.index);
    this.rebuildVirtualExplorer();
    if (vscode.workspace.getConfiguration('dcbEditor').get('autoSaveDcbOnXmlSave', true)) {
      await this.nativeSession.saveToFile(this.session.sourcePath);
    }
    this.fileSystemProvider.fire([
      { type: vscode.FileChangeType.Deleted, uri: oldUri },
      { type: vscode.FileChangeType.Created, uri: newUri },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(oldPath) === '.' ? '/' : path.posix.dirname(oldPath)}`) },
      { type: vscode.FileChangeType.Changed, uri: vscode.Uri.parse(`dcb://${this.virtualAuthority}${path.posix.dirname(newPath) === '.' ? '/' : path.posix.dirname(newPath)}`) }
    ]);
    this.output.appendLine(`[dcb rename] ${result.oldFileName} -> ${result.newFileName} (${result.renamedRecordCount} record(s))`);
  }

  findVirtualPathForRecordIndex(recordIndex) {
    for (const [virtualPath, record] of this.virtualRecordByPath.entries()) {
      if (record && record.index === recordIndex) {
        return virtualPath;
      }
    }
    return '';
  }

  async findExistingRecord(parsed, fileName) {
    const exactMatches = [];
    const seen = new Set();

    const searchAndCollect = async (query) => {
      if (!query) {
        return;
      }
      const results = this.nativeSession ? this.nativeSession.searchRecords(query, 200) : [];
      for (const result of results || []) {
        if (seen.has(result.index)) {
          continue;
        }
        seen.add(result.index);
        exactMatches.push(result);
      }
    };

    await searchAndCollect(parsed.guid);
    await searchAndCollect(fileName);
    await searchAndCollect(parsed.rootName);

    const lowerFileName = (fileName || '').toLowerCase();
    const lowerRootName = (parsed.rootName || '').toLowerCase();
    const lowerTypeName = (parsed.typeName || '').toLowerCase();
    const lowerGuid = (parsed.guid || '').toLowerCase();

    let best = null;
    let bestScore = -1;
    for (const result of exactMatches) {
      let score = 0;
      if (lowerGuid && (result.guid || '').toLowerCase() === lowerGuid) {
        score += 100;
      }
      if (lowerFileName && (result.fileName || '').toLowerCase() === lowerFileName) {
        score += 50;
      }
      if (lowerRootName && (result.name || '').toLowerCase() === lowerRootName) {
        score += 25;
      }
      if (lowerTypeName && (result.typeName || '').toLowerCase() === lowerTypeName) {
        score += 10;
      }
      if (score > bestScore) {
        best = result;
        bestScore = score;
      }
    }

    return bestScore > 0 ? best : null;
  }

  buildFileTreeItems(records) {
    const makeDirNode = (name, fullPath) => ({
      type: 'dir',
      name,
      fullPath,
      children: new Map(),
      record: null
    });

    const root = makeDirNode('', '');
    for (const record of records) {
      const normalizedPath = String(record.fileName || '').replace(/\\/g, '/');
      const parts = normalizedPath.split('/').filter(Boolean);
      let current = root;
      let accumulated = '';
      for (let i = 0; i < parts.length; i += 1) {
        const part = parts[i];
        accumulated = accumulated ? `${accumulated}/${part}` : part;
        const isLeaf = i === parts.length - 1;
        if (isLeaf) {
          current.children.set(part, {
            type: 'file',
            name: part,
            fullPath: accumulated,
            children: new Map(),
            record
          });
        } else {
          if (!current.children.has(part)) {
            current.children.set(part, makeDirNode(part, accumulated));
          }
          current = current.children.get(part);
        }
      }
    }

    const toItems = (node) => {
      const entries = Array.from(node.children.values()).sort((left, right) => {
        if (left.type !== right.type) {
          return left.type === 'dir' ? -1 : 1;
        }
        return left.name.localeCompare(right.name, undefined, { sensitivity: 'base' });
      });

      return entries.map((entry) => {
        if (entry.type === 'dir') {
          return new RecordTreeItem(entry.name, {
            id: `dir:${entry.fullPath}`,
            description: `${entry.children.size}`,
            tooltip: entry.fullPath,
            collapsibleState: vscode.TreeItemCollapsibleState.Collapsed,
            children: toItems(entry),
            iconPath: new vscode.ThemeIcon('folder')
          });
        }

        return new RecordTreeItem(entry.name, {
          id: `file:${entry.record.index}`,
          description: entry.record.typeName,
          tooltip: `${entry.record.fileName}\n${entry.record.guid}`,
          command: {
            command: 'dcbEditor.openRecord',
            title: 'Open Record',
            arguments: [entry.record]
          },
          iconPath: new vscode.ThemeIcon('file-code'),
          contextValue: 'dcbRecord'
        });
      });
    };

    return toItems(root);
  }

  buildVirtualFileSystem(records) {
    const makeDirNode = (name, fullPath) => ({
      type: 'dir',
      name,
      fullPath,
      children: new Map(),
      record: null
    });

    const root = makeDirNode('', '/');
    this.virtualNodeByPath = new Map();
    this.virtualRecordByPath = new Map();
    this.virtualDirectoryEntries = new Map();
    this.virtualFileCache = new Map();
    this.virtualNodeByPath.set('/', root);
    this.virtualNodeByPath.set('', root);

    const addFileNode = (normalizedPath, record = null, pending = false) => {
      const parts = normalizedPath.split('/').filter(Boolean);
      let current = root;
      let accumulated = '';
      for (let i = 0; i < parts.length; i += 1) {
        const part = parts[i];
        accumulated = `${accumulated}/${part}`;
        const isLeaf = i === parts.length - 1;
        if (isLeaf) {
          const fileNode = {
            type: 'file',
            name: part,
            fullPath: accumulated,
            children: new Map(),
            record,
            pending
          };
          current.children.set(part, fileNode);
          this.virtualNodeByPath.set(accumulated, fileNode);
          if (record) {
            this.virtualRecordByPath.set(accumulated, record);
          }
        } else {
          if (!current.children.has(part)) {
            const dirNode = makeDirNode(part, accumulated);
            current.children.set(part, dirNode);
            this.virtualNodeByPath.set(accumulated, dirNode);
          }
          current = current.children.get(part);
        }
      }
    };

    const addDirectoryNode = (normalizedPath) => {
      const parts = normalizedPath.split('/').filter(Boolean);
      let current = root;
      let accumulated = '';
      for (const part of parts) {
        accumulated = `${accumulated}/${part}`;
        if (!current.children.has(part)) {
          const dirNode = makeDirNode(part, accumulated);
          current.children.set(part, dirNode);
          this.virtualNodeByPath.set(accumulated, dirNode);
        }
        current = current.children.get(part);
      }
    };

    for (const pendingDirPath of this.pendingVirtualDirectories) {
      addDirectoryNode(normalizeVirtualPath(pendingDirPath));
    }

    for (const record of records) {
      const normalizedPath = `/${String(record.fileName || '').replace(/\\/g, '/').replace(/^\/+/, '')}`;
      addFileNode(normalizedPath, record, false);
    }

    for (const pendingPath of this.pendingVirtualFiles.keys()) {
      addFileNode(normalizeVirtualPath(pendingPath), null, true);
    }

    this.virtualRoot = root;
    this.buildVirtualDirectoryCache();
    this.output.appendLine(`[dcb fs] built virtual tree with ${records.length} main records and ${root.children.size} root entries`);
  }

  async ensureMountedSession(authority) {
    const normalizedAuthority = String(authority || '').toLowerCase();
    if (!normalizedAuthority) {
      return;
    }
    if (this.nativeSession && this.virtualAuthority === normalizedAuthority && this.virtualRecordByPath.size > 0) {
      return;
    }

    if (this.restorePromise) {
      await this.restorePromise;
      if (this.nativeSession && this.virtualAuthority === normalizedAuthority && this.virtualRecordByPath.size > 0) {
        return;
      }
    }

    let sourcePath = this.mountSourceByAuthority.get(normalizedAuthority);
    if (!sourcePath && this.session && sanitizeAuthority(path.basename(this.session.sourcePath)) === normalizedAuthority) {
      sourcePath = this.session.sourcePath;
    }
    if (!sourcePath) {
      this.output.appendLine(`[dcb fs] no persisted source for authority ${normalizedAuthority}`);
      return;
    }

    this.restorePromise = (async () => {
      this.output.appendLine(`[dcb fs] restoring session for ${normalizedAuthority} from ${sourcePath}`);
      const nativeSession = await NativeDcbSession.open(sourcePath);
      const payload = nativeSession.getMetadata();
      this.nativeSession = nativeSession;
      this.session = {
        id: 'dcb',
        sourcePath: payload.sourcePath,
        sessionPath: payload.sourcePath,
        recordCount: payload.recordCount,
        structCount: payload.structCount,
        propertyCount: payload.propertyCount,
        version: payload.version,
        backend: 'dcb'
      };
      this.virtualAuthority = normalizedAuthority;
      this.fileTreeRoots = this.buildFileTreeItems(this.nativeSession.getMainRecordSummaries());
      this.buildVirtualFileSystem(this.nativeSession.getMainRecordSummaries());
      this.treeProvider.refresh();
    })();

    try {
      await this.restorePromise;
    } finally {
      this.restorePromise = null;
    }
  }

  getVirtualNode(uri) {
    if (!this.session || !this.virtualRoot) {
      return null;
    }
    if (uri.scheme === 'dcb' && (!uri.path || uri.path === '/' || uri.path === '') &&
        (!this.virtualAuthority || !uri.authority || uri.authority === this.virtualAuthority)) {
      this.output.appendLine(`[dcb fs] resolve root ${uri.toString()} -> /`);
      return this.virtualRoot;
    }
    const normalized = normalizeVirtualPath(uri.path || '/');
    this.output.appendLine(`[dcb fs] resolve ${uri.toString()} -> ${normalized}`);
    const mapped = this.virtualNodeByPath.get(normalized);
    if (mapped) {
      return mapped;
    }
    if (this.virtualRecordByPath.has(normalized)) {
      return {
        type: 'file',
        name: path.posix.basename(normalized),
        fullPath: normalized,
        children: new Map(),
        record: this.virtualRecordByPath.get(normalized)
      };
    }
    if (this.hasVirtualDirectory(normalized)) {
      return {
        type: 'dir',
        name: path.posix.basename(normalized),
        fullPath: normalized,
        children: new Map(),
        record: null
      };
    }
    return null;
  }

  getVirtualFileContent(node) {
    if (!node || node.type !== 'file') {
      return Buffer.alloc(0);
    }
    const key = node.fullPath;
    const cached = this.virtualFileCache.get(key);
    if (cached) {
      return cached;
    }
    if (node.pending) {
      const pending = this.pendingVirtualFiles.get(key) || Buffer.alloc(0);
      this.virtualFileCache.set(key, pending);
      return pending;
    }
    const xml = formatXmlDocument(
      `<?xml version="1.0" encoding="utf-8"?>\n${this.nativeSession.exportRecordXml(node.record.index)}\n`
    );
    const bytes = Buffer.from(xml, 'utf8');
    this.virtualFileCache.set(key, bytes);
    return bytes;
  }

  hasVirtualDirectory(normalizedPath) {
    return this.virtualDirectoryEntries.has(normalizedPath);
  }

  listVirtualDirectory(uri) {
    if (!this.session || !this.virtualDirectoryEntries) {
      return null;
    }
    const normalized = normalizeVirtualPath(uri.path || '/');
    return this.virtualDirectoryEntries.get(normalized) || null;
  }

  buildVirtualDirectoryCache() {
    this.virtualDirectoryEntries = new Map();
    this.virtualDirectoryEntries.set('/', []);

    const directoryMaps = new Map();
    directoryMaps.set('/', new Map());

    const ensureDirectory = (dirPath) => {
      if (!directoryMaps.has(dirPath)) {
        directoryMaps.set(dirPath, new Map());
      }
      if (!this.virtualDirectoryEntries.has(dirPath)) {
        this.virtualDirectoryEntries.set(dirPath, []);
      }
    };

    for (const [virtualPath, node] of this.virtualNodeByPath.entries()) {
      if (!node || !virtualPath || virtualPath === '/') {
        continue;
      }
      const parentPath = path.posix.dirname(virtualPath) === '.' ? '/' : path.posix.dirname(virtualPath);
      ensureDirectory(parentPath);
      if (node.type === 'dir') {
        ensureDirectory(virtualPath);
        directoryMaps.get(parentPath).set(node.name, vscode.FileType.Directory);
      } else if (node.type === 'file') {
        directoryMaps.get(parentPath).set(node.name, vscode.FileType.File);
      }
    }

    for (const [dirPath, children] of directoryMaps.entries()) {
      const entries = Array.from(children.entries()).sort((left, right) => {
        if (left[1] !== right[1]) {
          return left[1] === vscode.FileType.Directory ? -1 : 1;
        }
        return left[0].localeCompare(right[0], undefined, { sensitivity: 'base' });
      });
      this.virtualDirectoryEntries.set(dirPath, entries);
    }
  }

  async mountInNativeExplorer() {
    if (!this.session) {
      return;
    }

    await this.unmountNativeExplorer();

    const authority = sanitizeAuthority(path.basename(this.session.sourcePath));
    this.virtualAuthority = authority;
    this.mountSourceByAuthority.set(authority, this.session.sourcePath);
    await this.context.globalState.update(
      'dcbEditor.mountSourceByAuthority',
      Object.fromEntries(this.mountSourceByAuthority.entries())
    );
    const uri = vscode.Uri.parse(`dcb://${authority}/`);
    const folderName = `${path.basename(this.session.sourcePath)} [DCB]`;
    this.output.appendLine(`[dcb fs] mounting ${uri.toString()} as ${folderName}`);

    const success = vscode.workspace.updateWorkspaceFolders(
      vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders.length : 0,
      null,
      { uri, name: folderName }
    );
    if (!success) {
      throw new Error('VS Code could not mount the DCB virtual filesystem.');
    }

    this.mountedWorkspaceUri = uri;
    this.fileSystemProvider.refresh(uri);
  }

  async unmountAllDcbWorkspaceFolders() {
    if (!vscode.workspace.workspaceFolders) {
      this.mountedWorkspaceUri = null;
      return;
    }

    let removed = 0;
    for (let index = vscode.workspace.workspaceFolders.length - 1; index >= 0; index -= 1) {
      const folder = vscode.workspace.workspaceFolders[index];
      if (folder.uri.scheme === 'dcb') {
        if (vscode.workspace.updateWorkspaceFolders(index, 1)) {
          removed += 1;
        }
      }
    }
    if (removed > 0) {
      this.output.appendLine(`[dcb fs] unmounted ${removed} stale DCB workspace folder(s)`);
    }
    this.mountedWorkspaceUri = null;
  }

  getMirrorRootPath() {
    if (!this.session) {
      return '';
    }
    const sourceKey = crypto.createHash('sha1').update(String(this.session.sourcePath || '')).digest('hex').slice(0, 12);
    const folderName = `${sanitizeAuthority(path.basename(this.session.sourcePath))}-${sourceKey}`;
    return path.join(os.tmpdir(), 'dcb-editor-vscode-mirror', folderName);
  }

  async materializeMirrorWorkspace() {
    if (!this.session || !this.nativeSession) {
      return;
    }

    const mirrorRootPath = this.getMirrorRootPath();
    const records = this.nativeSession.getMainRecordSummaries();
    this.output.appendLine(`[dcb mirror] materializing ${records.length} file(s) to ${mirrorRootPath}`);

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: `Materializing ${path.basename(this.session.sourcePath)} mirror workspace`,
      cancellable: false
    }, async (progress) => {
      await fsp.mkdir(mirrorRootPath, { recursive: true });

      for (const [filePath, binding] of Array.from(this.docBindings.entries())) {
        if (binding && binding.isMirror) {
          this.docBindings.delete(filePath);
        }
      }
      this.mirrorFilePathByRecordIndex.clear();

      const total = Math.max(1, records.length);
      let lastProgress = 0;
      const pendingWrites = [];
      const flushWrites = async () => {
        if (pendingWrites.length === 0) {
          return;
        }
        const batch = pendingWrites.splice(0, pendingWrites.length);
        await Promise.all(batch);
      };

      for (let index = 0; index < records.length; index += 1) {
        const record = records[index];
        const mirrorFilePath = path.join(mirrorRootPath, ...String(record.fileName || '').replace(/\\/g, '/').split('/'));
        const resolvedMirrorPath = path.resolve(mirrorFilePath);
        const placeholderText = buildMirrorPlaceholderXml(record);
        pendingWrites.push((async () => {
          await fsp.mkdir(path.dirname(mirrorFilePath), { recursive: true });
          await fsp.writeFile(mirrorFilePath, placeholderText, 'utf8');
        })());
        this.docBindings.set(resolvedMirrorPath, {
          recordIndex: record.index,
          sourcePath: record.fileName,
          isMirror: true,
          hydrated: false
        });
        this.mirrorFilePathByRecordIndex.set(record.index, resolvedMirrorPath);

        if (pendingWrites.length >= 128) {
          await flushWrites();
        }

        if (index === 0 || (index + 1) % 1000 === 0 || index === records.length - 1) {
          await flushWrites();
          const nextProgress = ((index + 1) / total) * 100;
          progress.report({
            increment: nextProgress - lastProgress,
            message: `${index + 1}/${records.length}`
          });
          lastProgress = nextProgress;
          await new Promise((resolve) => setImmediate(resolve));
        }
      }
    });

    this.mirrorRootPath = mirrorRootPath;
    await this.mountMirrorWorkspace();
  }

  async mountMirrorWorkspace() {
    await this.unmountMirrorWorkspace();
    if (!this.mirrorRootPath) {
      return;
    }

    const uri = vscode.Uri.file(this.mirrorRootPath);
    const folderName = `${path.basename(this.session.sourcePath)} [Mirror]`;
    const success = vscode.workspace.updateWorkspaceFolders(
      vscode.workspace.workspaceFolders ? vscode.workspace.workspaceFolders.length : 0,
      null,
      { uri, name: folderName }
    );
    if (!success) {
      throw new Error('VS Code could not mount the DCB mirror workspace.');
    }

    this.mountedMirrorWorkspaceUri = uri;
  }

  async unmountMirrorWorkspace() {
    if (!this.mountedMirrorWorkspaceUri || !vscode.workspace.workspaceFolders) {
      this.mountedMirrorWorkspaceUri = null;
      return;
    }

    const index = vscode.workspace.workspaceFolders.findIndex((folder) => folder.uri.toString() === this.mountedMirrorWorkspaceUri.toString());
    if (index >= 0) {
      vscode.workspace.updateWorkspaceFolders(index, 1);
    }
    this.mountedMirrorWorkspaceUri = null;
  }

  buildRecordXmlDocument(recordIndex) {
    return formatXmlDocument(
      `<?xml version="1.0" encoding="utf-8"?>\n${this.nativeSession.exportRecordXml(recordIndex)}\n`
    );
  }

  async syncMirrorRecord(recordIndex, sourceUri) {
    const mirrorFilePath = this.mirrorFilePathByRecordIndex.get(recordIndex);
    if (!mirrorFilePath || !this.nativeSession) {
      return;
    }
    if (sourceUri?.scheme === 'file' && path.resolve(sourceUri.fsPath) === path.resolve(mirrorFilePath)) {
      return;
    }

    await fsp.mkdir(path.dirname(mirrorFilePath), { recursive: true });
    await fsp.writeFile(mirrorFilePath, this.buildRecordXmlDocument(recordIndex), 'utf8');
  }

  refreshMirrorBindingsFromSummaries() {
    if (!this.mirrorRootPath || !this.nativeSession) {
      return;
    }

    for (const [filePath, binding] of Array.from(this.docBindings.entries())) {
      if (binding && binding.isMirror) {
        this.docBindings.delete(filePath);
      }
    }
    this.mirrorFilePathByRecordIndex.clear();

    for (const record of this.nativeSession.getMainRecordSummaries()) {
      const mirrorFilePath = path.resolve(path.join(this.mirrorRootPath, ...String(record.fileName || '').replace(/\\/g, '/').split('/')));
      if (!fs.existsSync(mirrorFilePath)) {
        continue;
      }
      this.docBindings.set(mirrorFilePath, {
        recordIndex: record.index,
        sourcePath: record.fileName,
        isMirror: true,
        hydrated: true
      });
      this.mirrorFilePathByRecordIndex.set(record.index, mirrorFilePath);
    }
  }

  isPathInsideMirror(filePath) {
    if (!this.mirrorRootPath || !filePath) {
      return false;
    }
    const relative = path.relative(path.resolve(this.mirrorRootPath), path.resolve(filePath));
    return Boolean(relative) && !relative.startsWith('..') && !path.isAbsolute(relative);
  }

  mirrorFilePathToVirtualPath(filePath) {
    const relative = path.relative(path.resolve(this.mirrorRootPath), path.resolve(filePath));
    return normalizeVirtualPath(relative.replace(/\\/g, '/'));
  }

  async ensureMirrorRecord(recordIndex, virtualPath) {
    if (!this.mirrorRootPath || !this.nativeSession) {
      return;
    }
    const mirrorFilePath = path.resolve(path.join(this.mirrorRootPath, ...String(virtualPath || '').replace(/^\/+/, '').split('/')));
    await fsp.mkdir(path.dirname(mirrorFilePath), { recursive: true });
    await fsp.writeFile(mirrorFilePath, this.buildRecordXmlDocument(recordIndex), 'utf8');
    const summary = this.nativeSession.getRecordSummary(recordIndex);
    this.docBindings.set(mirrorFilePath, {
      recordIndex,
      sourcePath: summary?.fileName || virtualPath.replace(/^\/+/, ''),
      isMirror: true,
      hydrated: true
    });
    this.mirrorFilePathByRecordIndex.set(recordIndex, mirrorFilePath);
  }

  async deleteMirrorVirtualPath(virtualPath) {
    if (!this.mirrorRootPath) {
      return;
    }
    const mirrorFilePath = path.resolve(path.join(this.mirrorRootPath, ...String(virtualPath || '').replace(/^\/+/, '').split('/')));
    await fsp.rm(mirrorFilePath, { force: true });
    this.docBindings.delete(mirrorFilePath);
    for (const [recordIndex, filePath] of Array.from(this.mirrorFilePathByRecordIndex.entries())) {
      if (filePath === mirrorFilePath) {
        this.mirrorFilePathByRecordIndex.delete(recordIndex);
      }
    }
  }

  async renameMirrorVirtualPath(oldVirtualPath, newVirtualPath, recordIndex) {
    if (!this.mirrorRootPath) {
      return;
    }
    const oldMirrorFilePath = path.resolve(path.join(this.mirrorRootPath, ...String(oldVirtualPath || '').replace(/^\/+/, '').split('/')));
    const newMirrorFilePath = path.resolve(path.join(this.mirrorRootPath, ...String(newVirtualPath || '').replace(/^\/+/, '').split('/')));
    if (oldMirrorFilePath === newMirrorFilePath) {
      return;
    }

    if (fs.existsSync(oldMirrorFilePath)) {
      await fsp.mkdir(path.dirname(newMirrorFilePath), { recursive: true });
      await fsp.rename(oldMirrorFilePath, newMirrorFilePath);
    }

    const binding = this.docBindings.get(oldMirrorFilePath);
    if (binding) {
      this.docBindings.delete(oldMirrorFilePath);
      this.docBindings.set(newMirrorFilePath, { ...binding, isMirror: true });
    }
    if (typeof recordIndex === 'number') {
      this.mirrorFilePathByRecordIndex.set(recordIndex, newMirrorFilePath);
    }
  }

  rebuildVirtualExplorer() {
    if (!this.nativeSession) {
      return;
    }
    this.fileTreeRoots = this.buildFileTreeItems(this.nativeSession.getMainRecordSummaries());
    this.buildVirtualFileSystem(this.nativeSession.getMainRecordSummaries());
    this.treeProvider.refresh();
    if (this.mountedWorkspaceUri) {
      this.fileSystemProvider.refresh(this.mountedWorkspaceUri);
    }
  }

  async unmountNativeExplorer() {
    if (!this.mountedWorkspaceUri || !vscode.workspace.workspaceFolders) {
      this.mountedWorkspaceUri = null;
      return;
    }

    const index = vscode.workspace.workspaceFolders.findIndex((folder) => folder.uri.toString() === this.mountedWorkspaceUri.toString());
    if (index >= 0) {
      vscode.workspace.updateWorkspaceFolders(index, 1);
    }
    this.mountedWorkspaceUri = null;
  }
}

class DcbXmlCompletionProvider {
  constructor(state) {
    this.state = state;
  }

  provideCompletionItems(document, position) {
    if (!this.state.nativeSession || !this.state.isDcbXmlDocument(document)) {
      return undefined;
    }

    const lineText = document.lineAt(position.line).text;
    const attributeValueContext = getAttributeValueContext(lineText, position.character);
    if (attributeValueContext) {
      attributeValueContext.line = position.line;
      if (attributeValueContext.attributeName === 'Type') {
        return this.provideTypeAttributeItems(attributeValueContext, position);
      }
      if (isReferenceAttributeName(attributeValueContext.attributeName)) {
        const referenceContext = getReferenceAttributeContext(document, position, this.state);
        if (referenceContext) {
          Object.assign(attributeValueContext, referenceContext);
        }
        return this.provideReferenceAttributeItems(attributeValueContext, position);
      }
    }

    const attributeNameContext = getAttributeNameContext(lineText, position.character);
    if (attributeNameContext) {
      attributeNameContext.line = position.line;
      return this.provideAttributeNameItems(attributeNameContext, position);
    }

    const childContext = getChildElementContext(document, position, this.state.nativeSession);
    if (childContext) {
      return this.provideChildElementItems(childContext, position);
    }

    const valueContext = getElementValueContext(document, position, this.state.nativeSession);
    if (valueContext?.propertyInfo?.isBoolean) {
      return this.provideBooleanValueItems(valueContext, position);
    }
    if (valueContext?.propertyInfo?.isEnum) {
      return this.provideEnumValueItems(valueContext, position);
    }

    return undefined;
  }

  provideTypeAttributeItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );

    const typedPrefix = String(context.currentValue || '').toLowerCase();
    const allTypes = this.state.nativeSession.getStructTypeCompletionEntries();
    const matched = [];
    const fallback = [];
    const limit = 200;

    for (const entry of allTypes) {
      const typeName = entry.name;
      const lowered = entry.lowered;
      if (!typedPrefix || lowered.startsWith(typedPrefix)) {
        matched.push(typeName);
        if (matched.length >= limit) {
          break;
        }
        continue;
      }
      if (typedPrefix && lowered.includes(typedPrefix)) {
        fallback.push(typeName);
      }
    }

    const finalNames = matched.length < limit
      ? matched.concat(fallback.slice(0, limit - matched.length))
      : matched;

    const items = finalNames.map((typeName, index) => {
      const item = new vscode.CompletionItem(typeName, vscode.CompletionItemKind.Class);
      item.insertText = typeName;
      item.range = replaceRange;
      item.detail = 'DCB struct type';
      item.sortText = `${index.toString().padStart(4, '0')}_${typeName}`;
      return item;
    });

    return new vscode.CompletionList(items, false);
  }

  provideAttributeNameItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );
    const existing = new Set((context.existingAttributes || []).map((name) => name.toLowerCase()));
    const names = [
      'RecordId',
      'Type',
      'Count',
      'Pointer',
      'PointsTo',
      'RecordName',
      'RecordReference',
      'ReferencedFile',
      'File'
    ].filter((name) => !existing.has(name.toLowerCase()) && name.toLowerCase().startsWith(context.currentValue.toLowerCase()));

    const items = names.map((name, index) => {
      const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Property);
      item.insertText = new vscode.SnippetString(`${name}="$0"`);
      item.range = replaceRange;
      item.detail = 'DCB XML attribute';
      item.sortText = `${index.toString().padStart(4, '0')}_${name}`;
      return item;
    });
    return new vscode.CompletionList(items, false);
  }

  provideChildElementItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );
    if (context.parentIsArrayContainer && context.parentItemTypeName) {
      const itemName = encodeXmlNameLocal(context.parentItemTypeName);
      if (!context.currentValue || itemName.toLowerCase().startsWith(context.currentValue.toLowerCase())) {
        const item = new vscode.CompletionItem(itemName, vscode.CompletionItemKind.Struct);
        item.detail = `${context.parentItemTypeName} array item`;
        item.range = replaceRange;
        item.insertText = new vscode.SnippetString(buildArrayItemSnippet(context.parentItemTypeName, context.parentItemDataTypeName));
        item.sortText = `0000_${itemName}`;
        return new vscode.CompletionList([item], false);
      }
      return undefined;
    }

    const properties = this.state.nativeSession.getStructPropertyCompletionEntries(context.parentTypeName);
    const typedPrefix = String(context.currentValue || '').toLowerCase();
    const items = [];
    for (const property of properties) {
      const name = property.encodedName || property.name;
      if (typedPrefix && !name.toLowerCase().startsWith(typedPrefix)) {
        continue;
      }
      const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Field);
      item.detail = `${context.parentTypeName}.${name} (${property.dataTypeName}${property.isArray ? '[]' : ''})`;
      item.range = replaceRange;
      item.insertText = new vscode.SnippetString(buildChildElementSnippet(property));
      item.sortText = `${items.length.toString().padStart(4, '0')}_${name}`;
      items.push(item);
      if (items.length >= 200) {
        break;
      }
    }
    return new vscode.CompletionList(items, false);
  }

  provideBooleanValueItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );
    return new vscode.CompletionList(['true', 'false'].map((value, index) => {
      const item = new vscode.CompletionItem(value, vscode.CompletionItemKind.Value);
      item.insertText = value;
      item.range = replaceRange;
      item.detail = 'Boolean value';
      item.sortText = `${index}_${value}`;
      return item;
    }), false);
  }

  provideEnumValueItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );
    const typedPrefix = String(context.currentValue || '').toLowerCase();
    const values = (context.propertyInfo.enumValues || []).filter((value) => !typedPrefix || value.toLowerCase().startsWith(typedPrefix));
    const items = values.slice(0, 200).map((value, index) => {
      const item = new vscode.CompletionItem(value, vscode.CompletionItemKind.EnumMember);
      item.insertText = value;
      item.range = replaceRange;
      item.detail = `${context.propertyInfo.name || context.elementName} enum value`;
      item.sortText = `${index.toString().padStart(4, '0')}_${value}`;
      return item;
    });
    return new vscode.CompletionList(items, false);
  }

  provideReferenceAttributeItems(context) {
    const replaceRange = new vscode.Range(
      new vscode.Position(context.line, context.valueStart),
      new vscode.Position(context.line, context.valueEnd)
    );
    const query = normalizeReferenceCompletionQuery(context.currentValue);
    const nativeEntries = this.state.nativeSession.getRecordReferenceCompletionEntries(query, 200, context.expectedTypeName || '');
    const pendingEntries = getPendingReferenceCompletionEntries(this.state, query, 200, context.expectedTypeName || '');
    const seen = new Set();
    const entries = [];
    for (const entry of pendingEntries.concat(nativeEntries)) {
      const key = `${String(entry.fileName || '').toLowerCase()}\n${String(entry.guid || '').toLowerCase()}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      entries.push(entry);
      if (entries.length >= 200) {
        break;
      }
    }
    const items = entries.map((entry, index) => {
      const value = getReferenceCompletionValue(context.attributeName, entry, context);
      const label = getReferenceCompletionLabel(context.attributeName, entry, value);
      const item = new vscode.CompletionItem(label, vscode.CompletionItemKind.Reference);
      item.insertText = value;
      item.range = replaceRange;
      item.filterText = `${entry.name || ''} ${entry.typeName || ''} ${entry.fileName || ''} ${entry.guid || ''}`;
      item.detail = `${entry.pending ? 'Pending XML' : entry.typeName} | ${entry.fileName}`;
      item.documentation = value;
      item.sortText = `${index.toString().padStart(4, '0')}_${label}`;
      return item;
    });
    return new vscode.CompletionList(items, false);
  }
}

function getTypeAttributeContext(lineText, cursorCharacter) {
  const context = getAttributeValueContext(lineText, cursorCharacter);
  return context && context.attributeName === 'Type' ? context : null;
}

function getAttributeValueContext(lineText, cursorCharacter) {
  const text = String(lineText || '');
  const regex = /\b([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const attributeName = match[1] || '';
    const fullMatch = match[0];
    const value = match[2] || '';
    const attributeStart = match.index;
    const openingQuote = attributeStart + fullMatch.indexOf('"');
    const valueStart = openingQuote + 1;
    const valueEnd = valueStart + value.length;
    if (cursorCharacter >= valueStart && cursorCharacter <= valueEnd) {
      return {
        attributeName,
        currentValue: value,
        line: 0,
        valueStart,
        valueEnd
      };
    }
  }

  const partialPrefix = text.slice(0, cursorCharacter);
  const partialMatch = /\b([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)$/i.exec(partialPrefix);
  if (!partialMatch) {
    return null;
  }

  const openingQuote = partialPrefix.lastIndexOf('"');
  return {
    attributeName: partialMatch[1] || '',
    currentValue: partialMatch[2] || '',
    line: 0,
    valueStart: openingQuote + 1,
    valueEnd: cursorCharacter
  };
}

function getAttributeNameContext(lineText, cursorCharacter) {
  const text = String(lineText || '');
  const beforeCursor = text.slice(0, cursorCharacter);
  const tagStart = beforeCursor.lastIndexOf('<');
  if (tagStart < 0 || beforeCursor.lastIndexOf('>') > tagStart || beforeCursor[tagStart + 1] === '/') {
    return null;
  }
  const afterTagStart = beforeCursor.slice(tagStart + 1);
  if (/^\s*[!?]/.test(afterTagStart)) {
    return null;
  }
  const match = /(?:^|\s)([A-Za-z0-9_.:-]*)$/.exec(afterTagStart);
  if (!match) {
    return null;
  }
  const currentValue = match[1] || '';
  const valueStart = cursorCharacter - currentValue.length;
  const between = beforeCursor.slice(valueStart, cursorCharacter);
  if (between.includes('=') || /<\/?$/.test(beforeCursor)) {
    return null;
  }
  const tagEnd = text.indexOf('>', tagStart);
  const tagText = text.slice(tagStart, tagEnd >= 0 ? tagEnd : text.length);
  const existingAttributes = [];
  const attrRegex = /\b([A-Za-z0-9_.:-]+)\s*=/g;
  let attrMatch;
  while ((attrMatch = attrRegex.exec(tagText)) !== null) {
    existingAttributes.push(attrMatch[1]);
  }
  return {
    currentValue,
    existingAttributes,
    line: 0,
    valueStart,
    valueEnd: cursorCharacter
  };
}

function getChildElementContext(document, position, nativeSession) {
  const lineText = document.lineAt(position.line).text;
  const beforeCursor = lineText.slice(0, position.character);
  const match = /<([A-Za-z0-9_.:-]*)$/.exec(beforeCursor);
  if (!match || beforeCursor.endsWith('</')) {
    return null;
  }
  const currentValue = match[1] || '';
  const offset = document.offsetAt(position) - currentValue.length - 1;
  const text = document.getText();
  const stack = getXmlContextStack(text, Math.max(0, offset), nativeSession);
  const parent = stack[stack.length - 1];
  const parentTypeName = parent?.isArrayContainer ? parent.itemTypeName : (parent?.typeName || '');
  if (!parentTypeName) {
    return null;
  }
  return {
    parentTypeName,
    parentItemTypeName: parent?.isArrayContainer ? parent.itemTypeName : '',
    parentItemDataTypeName: parent?.isArrayContainer ? parent.itemDataTypeName : '',
    parentIsArrayContainer: Boolean(parent?.isArrayContainer),
    currentValue,
    line: position.line,
    valueStart: position.character - currentValue.length,
    valueEnd: position.character
  };
}

function getElementValueContext(document, position, nativeSession) {
  const offset = document.offsetAt(position);
  const text = document.getText();
  const stack = getXmlContextStack(text, offset, nativeSession);
  const element = stack[stack.length - 1];
  const parent = stack[stack.length - 2];
  const parentTypeName = parent?.isArrayContainer ? parent.itemTypeName : (parent?.typeName || '');
  if (!element || !parentTypeName) {
    return null;
  }
  const propertyInfo = nativeSession.getPropertyInfo(parentTypeName, element.name);
  if (!propertyInfo) {
    return null;
  }
  const lineText = document.lineAt(position.line).text;
  const left = lineText.lastIndexOf('>', position.character - 1);
  const right = lineText.indexOf('<', position.character);
  const valueStart = left >= 0 ? left + 1 : 0;
  const valueEnd = right >= 0 ? right : lineText.length;
  return {
    elementName: element.name,
    propertyInfo,
    currentValue: lineText.slice(valueStart, valueEnd).trim(),
    line: position.line,
    valueStart,
    valueEnd
  };
}

function getReferenceAttributeContext(document, position, state) {
  const nativeSession = state?.nativeSession;
  if (!nativeSession) {
    return null;
  }
  const offset = document.offsetAt(position);
  const stack = getXmlContextStack(document.getText(), offset, nativeSession);
  const currentTagName = getCurrentTagNameAtPosition(document, position);
  const parent = stack[stack.length - 1];
  const parentTypeName = parent?.isArrayContainer ? parent.itemTypeName : parent?.typeName;
  let expectedTypeName = '';

  if (currentTagName && parentTypeName) {
    const propertyInfo = nativeSession.getPropertyInfo(parentTypeName, currentTagName);
    if (propertyInfo?.childTypeName) {
      expectedTypeName = propertyInfo.childTypeName;
    } else if (parent?.isArrayContainer && currentTagName === encodeXmlNameLocal(parent.itemTypeName)) {
      expectedTypeName = parent.itemTypeName;
    }
  }

  if (!expectedTypeName) {
    const element = stack[stack.length - 1];
    expectedTypeName = element?.isArrayContainer ? element.itemTypeName : (element?.typeName || element?.itemTypeName || '');
  }

  const currentFileName = getCurrentDcbFileNameFromDocument(document, state);
  return {
    expectedTypeName,
    currentFileName
  };
}

function getCurrentTagNameAtPosition(document, position) {
  const lineText = document.lineAt(position.line).text;
  const beforeCursor = lineText.slice(0, position.character);
  const tagStart = beforeCursor.lastIndexOf('<');
  if (tagStart < 0 || beforeCursor.lastIndexOf('>') > tagStart) {
    return '';
  }
  const afterTagStart = beforeCursor.slice(tagStart + 1).trimStart();
  if (!afterTagStart || afterTagStart.startsWith('/') || afterTagStart.startsWith('!') || afterTagStart.startsWith('?')) {
    return '';
  }
  return afterTagStart.split(/\s+/)[0] || '';
}

function getXmlContextStack(text, offset, nativeSession) {
  const stack = [];
  const source = String(text || '').slice(0, Math.max(0, offset));
  const tagRegex = /<([^>]+)>/g;
  let match;
  while ((match = tagRegex.exec(source)) !== null) {
    const raw = match[1] || '';
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('?') || trimmed.startsWith('!')) {
      continue;
    }
    if (trimmed.startsWith('/')) {
      const name = trimmed.slice(1).trim().split(/\s+/)[0];
      const index = stack.map((entry) => entry.name).lastIndexOf(name);
      if (index >= 0) {
        stack.splice(index);
      }
      continue;
    }

    const selfClosing = /\/\s*$/.test(trimmed);
    const name = trimmed.replace(/\/\s*$/, '').split(/\s+/)[0];
    const attrs = parseTagAttributes(trimmed);
    const parent = stack[stack.length - 1];
    const parentTypeName = parent?.isArrayContainer ? parent.itemTypeName : parent?.typeName;
    const parentPropertyInfo = parentTypeName && nativeSession ? nativeSession.getPropertyInfo(parentTypeName, name) : null;
    const isArrayContainer = Boolean(attrs.Count !== undefined && attrs.Type);
    const isArrayItem = Boolean(parent?.isArrayContainer && name === encodeXmlNameLocal(parent.itemTypeName));
    let typeName = attrs.Type || '';
    if (!typeName && !parent && name.includes('.')) {
      typeName = name.split('.')[0];
    }
    if (!typeName && parentPropertyInfo?.childTypeName && (parentPropertyInfo.isClassLike || parentPropertyInfo.isArray)) {
      typeName = parentPropertyInfo.childTypeName;
    }
    if (!typeName && isArrayItem) {
      typeName = parent.itemTypeName;
    }
    let itemTypeName = '';
    let itemDataTypeName = '';
    if (isArrayContainer && attrs.Type && nativeSession?.hasStructType(attrs.Type)) {
      itemTypeName = attrs.Type;
      itemDataTypeName = parentPropertyInfo?.dataTypeName || '';
    } else if (parentPropertyInfo?.isArray && parentPropertyInfo.childTypeName) {
      itemTypeName = parentPropertyInfo.childTypeName;
      itemDataTypeName = parentPropertyInfo.dataTypeName || '';
    }
    if (!itemTypeName && typeName && parentPropertyInfo?.isArray) {
      itemTypeName = typeName;
    }
    if (isArrayItem) {
      typeName = parent.itemTypeName;
    }
    if (!selfClosing) {
      stack.push({ name, attrs, typeName, itemTypeName, itemDataTypeName, isArrayContainer, start: match.index, openEnd: tagRegex.lastIndex });
    } else if (isArrayItem) {
      // Self-closing array references still need to influence attribute completion while typing inside the tag.
      const tagEnd = match.index + match[0].length;
      if (offset <= tagEnd) {
        stack.push({ name, attrs, typeName: parent.itemTypeName, itemTypeName: '', itemDataTypeName: '', isArrayContainer: false, start: match.index, openEnd: tagRegex.lastIndex });
      }
    }
  }
  return stack;
}

function parseTagAttributes(tagText) {
  const attrs = {};
  const attrRegex = /\b([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)"/g;
  let match;
  while ((match = attrRegex.exec(tagText || '')) !== null) {
    attrs[match[1]] = match[2];
  }
  return attrs;
}

function collectDirectChildNames(text, startOffset, endOffset) {
  const names = new Set();
  if (typeof startOffset !== 'number' || startOffset < 0 || endOffset <= startOffset) {
    return names;
  }
  const source = String(text || '').slice(startOffset, endOffset);
  const tagRegex = /<([^>]+)>/g;
  let depth = 0;
  let match;
  while ((match = tagRegex.exec(source)) !== null) {
    const raw = String(match[1] || '').trim();
    if (!raw || raw.startsWith('?') || raw.startsWith('!')) {
      continue;
    }
    if (raw.startsWith('/')) {
      depth = Math.max(0, depth - 1);
      continue;
    }
    const selfClosing = /\/\s*$/.test(raw);
    const name = raw.replace(/\/\s*$/, '').split(/\s+/)[0];
    if (depth === 0 && name) {
      names.add(name);
    }
    if (!selfClosing) {
      depth += 1;
    }
  }
  return names;
}

function isReferenceAttributeName(name) {
  return ['RecordId', 'RecordName', 'RecordReference', 'ReferencedFile'].includes(String(name || ''));
}

function getReferenceCompletionValue(attributeName, entry, context = {}) {
  switch (attributeName) {
    case 'RecordId':
      return entry.guid || '';
    case 'RecordName':
      return entry.name || '';
    case 'RecordReference':
    case 'ReferencedFile':
      return entry.fileName ? relativeRecordReference(entry.fileName, context.currentFileName || '') : '';
    default:
      return entry.name || '';
  }
}

function getReferenceCompletionLabel(attributeName, entry, value) {
  if (attributeName === 'RecordId') {
    return entry.name ? `${entry.name} (${entry.guid})` : value;
  }
  if (attributeName === 'ReferencedFile' || attributeName === 'RecordReference') {
    return entry.name || path.posix.basename(String(entry.fileName || value), '.xml') || value;
  }
  return entry.name || value;
}

function relativeRecordReference(targetFileName, currentFileName) {
  const target = String(targetFileName || '').replace(/\\/g, '/');
  const current = String(currentFileName || '').replace(/\\/g, '/');
  if (!target) {
    return '';
  }
  if (!current) {
    return `file://./${target}`;
  }
  const upCount = Math.max(0, current.split('/').length - 1);
  return `file://./${'../'.repeat(upCount)}${target}`;
}

function normalizeReferenceCompletionQuery(value) {
  let text = String(value || '').trim();
  text = text.replace(/^file:\/\/\.?\//i, '');
  text = text.replace(/^(\.\.\/)+/, '');
  text = text.replace(/^\.\/+/, '');
  if (text.includes('/')) {
    const parts = text.split('/').filter(Boolean);
    return parts[parts.length - 1] || '';
  }
  return text;
}

function getCurrentDcbFileNameFromDocument(document, state = null) {
  if (!document?.uri) {
    return '';
  }
  if (document.uri.scheme === 'dcb') {
    return String(document.uri.path || '').replace(/^\/+/, '').replace(/\\/g, '/');
  }
  if (document.uri.scheme === 'file' && state?.docBindings) {
    const binding = state.docBindings.get(path.resolve(document.uri.fsPath || ''));
    if (binding?.sourcePath) {
      return String(binding.sourcePath || '').replace(/^\/+/, '').replace(/\\/g, '/');
    }
  }
  return '';
}

function getPendingReferenceCompletionEntries(state, query = '', limit = 200, typeName = '') {
  if (!state?.pendingVirtualFiles || state.pendingVirtualFiles.size === 0) {
    return [];
  }

  const lowered = String(query || '').toLowerCase();
  const loweredTypeName = String(typeName || '').toLowerCase();
  const entries = [];

  for (const [virtualPath, bytes] of state.pendingVirtualFiles.entries()) {
    const fileName = normalizeVirtualPath(virtualPath).replace(/^\/+/, '');
    if (!fileName.toLowerCase().endsWith('.xml')) {
      continue;
    }

    const text = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes || '');
    const rootMatch = text.match(/<([A-Za-z_][A-Za-z0-9_.:-]*)(?:\s|>|\/)/);
    const typeMatch = text.match(/\bType\s*=\s*"([^"]*)"/);
    const guidMatch = text.match(/\bRecordId\s*=\s*"([^"]*)"/);
    const rootName = rootMatch?.[1] || path.posix.basename(fileName, '.xml');
    const type = String(typeMatch?.[1] || (rootName.includes('.') ? rootName.split('.')[0] : '')).trim();
    const name = rootName.includes('.') ? rootName.split('.').slice(1).join('.') : rootName;

    if (loweredTypeName && type.toLowerCase() !== loweredTypeName) {
      continue;
    }

    const searchText = `${name}\n${type}\n${fileName}\n${guidMatch?.[1] || ''}`.toLowerCase();
    if (lowered && !searchText.includes(lowered)) {
      continue;
    }

    entries.push({
      name,
      typeName: type || 'Pending XML',
      fileName,
      guid: guidMatch?.[1] || '',
      pending: true
    });

    if (entries.length >= limit) {
      break;
    }
  }

  return entries;
}

function encodeXmlNameLocal(value) {
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

function buildChildElementSnippet(property) {
  const name = property.encodedName || property.name || 'element';
  if (property.isArray) {
    const typeAttr = property.childTypeName ? ` Type="${property.childTypeName}"` : '';
    if (property.childTypeName) {
      const itemName = encodeXmlNameLocal(property.childTypeName);
      if (property.isReference) {
        return `${name} Count="1"${typeAttr}>\n  <${itemName} ReferencedFile="\${1:file://./path/to/${itemName}.xml}"/>\n</${name}>`;
      }
      if (property.isWeakPointer) {
        return `${name} Count="1"${typeAttr}>\n  <${itemName} PointsTo="\${1:ptr:0}"/>\n</${name}>`;
      }
      return `${name} Count="1"${typeAttr}>\n  <${itemName} Type="${property.childTypeName}">\n    $0\n  </${itemName}>\n</${name}>`;
    }
    return `${name} Count="0"${typeAttr}>$0</${name}>`;
  }
  if (property.isReference) {
    return `${name} ReferencedFile="\${1:file://./path/to/${name}.xml}"/>`;
  }
  if (property.isWeakPointer) {
    return `${name} PointsTo="\${1:ptr:0}"/>`;
  }
  if (property.isClassLike && property.childTypeName) {
    return `${name} Type="${property.childTypeName}">\n  $0\n</${name}>`;
  }
  if (property.isBoolean) {
    return `${name}>\${1|true,false|}</${name}>`;
  }
  if (property.isEnum && property.enumValues && property.enumValues.length > 0) {
    return `${name}>${property.enumValues[0]}</${name}>`;
  }
  return `${name}>$0</${name}>`;
}

function buildArrayItemSnippet(typeName, dataTypeName = '') {
  const itemName = encodeXmlNameLocal(typeName);
  if (dataTypeName === 'Reference') {
    return `${itemName} ReferencedFile="\${1:file://./path/to/${itemName}.xml}"/>`;
  }
  if (dataTypeName === 'WeakPointer') {
    return `${itemName} PointsTo="\${1:ptr:0}"/>`;
  }
  return `${itemName} Type="${typeName}">\n  $0\n</${itemName}>`;
}

function escapeXmlAttr(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function sanitizeFileName(value) {
  return String(value).replace(/[<>:"/\\|?*\x00-\x1F]/g, '_');
}

function sanitizeAuthority(value) {
  const cleaned = String(value || '')
    .replace(/[^A-Za-z0-9._-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase();
  return cleaned || 'dcb';
}

function normalizeVirtualPath(value) {
  const source = String(value || '/').replace(/\\/g, '/');
  if (!source || source === '/') {
    return '/';
  }
  const normalized = `/${source.replace(/^\/+/, '')}`.replace(/\/+/g, '/');
  return normalized || '/';
}

function formatXmlDocument(xml) {
  const source = String(xml || '').trim();
  if (!source) {
    return '';
  }

  const tokens = source
    .replace(/>\s*</g, '>\n<')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean);

  const lines = [];
  let indent = 0;

  for (const token of tokens) {
    if (token.startsWith('<?') || token.startsWith('<!')) {
      lines.push(`${'  '.repeat(indent)}${token}`);
      continue;
    }

    if (token.startsWith('</')) {
      indent = Math.max(0, indent - 1);
      lines.push(`${'  '.repeat(indent)}${token}`);
      continue;
    }

    const selfClosing = token.endsWith('/>');
    const inlineNode = /^<[^/!?][^>]*>[^<]+<\/[^>]+>$/.test(token);
    lines.push(`${'  '.repeat(indent)}${token}`);
    if (!selfClosing && !inlineNode) {
      indent += 1;
    }
  }

  return `${lines.join('\n')}\n`;
}

function parseRecordXml(xmlText) {
  const tagRegex = /<([A-Za-z0-9_.:-]+)\b([^>]*)>/g;
  let match;
  while ((match = tagRegex.exec(xmlText)) !== null) {
    const tagName = match[1];
    if (tagName.startsWith('?') || tagName.startsWith('!')) {
      continue;
    }
    const attrs = {};
    const attrRegex = /([A-Za-z0-9_.:-]+)\s*=\s*"([^"]*)"/g;
    let attrMatch;
    while ((attrMatch = attrRegex.exec(match[2])) !== null) {
      attrs[attrMatch[1]] = attrMatch[2];
    }
    return {
      rootName: tagName,
      typeName: attrs.Type || (tagName.includes('.') ? tagName.split('.')[0] : ''),
      guid: attrs.RecordId || '',
      fileName: attrs.File || ''
    };
  }
  return {
    rootName: '',
    typeName: '',
    guid: '',
    fileName: ''
  };
}

function isBareRecordRootXml(xmlText) {
  const source = String(xmlText || '').trim();
  if (!source) {
    return false;
  }
  const withoutDeclaration = source.replace(/^\s*<\?xml[\s\S]*?\?>\s*/i, '').trim();
  const rootMatch = withoutDeclaration.match(/^<([A-Za-z0-9_.:-]+)\b[^>]*>([\s\S]*)<\/\1>\s*$/);
  if (!rootMatch) {
    return false;
  }
  return !/<[A-Za-z0-9_.:-]+\b/.test(rootMatch[2] || '');
}

function deriveRecordFileName(sourcePathHint, xmlDeclaredFileName) {
  if (xmlDeclaredFileName && String(xmlDeclaredFileName).trim()) {
    return String(xmlDeclaredFileName).trim().replace(/\\/g, '/');
  }

  if (!sourcePathHint) {
    return '';
  }

  const normalized = sourcePathHint.replace(/\\/g, '/');
  const marker = '/libs/foundry/records/';
  const lower = normalized.toLowerCase();
  const markerIndex = lower.indexOf(marker);
  if (markerIndex !== -1) {
    return normalized.slice(markerIndex + 1);
  }
  return path.basename(sourcePathHint).replace(/\\/g, '/');
}

function syncXmlCountAttributes(xmlText) {
  const source = String(xmlText || '');
  if (!source.includes('Count=')) {
    return source;
  }

  const replacements = [];
  const stack = [];
  const tagRegex = /<[^>]+>/g;
  let match;
  while ((match = tagRegex.exec(source)) !== null) {
    const tag = match[0];
    if (tag.startsWith('<?') || tag.startsWith('<!')) {
      continue;
    }
    const isClosing = /^<\s*\//.test(tag);
    if (isClosing) {
      const closingName = tag.replace(/^<\s*\//, '').replace(/\s*>$/, '').trim();
      let index = stack.length - 1;
      while (index >= 0 && stack[index].name !== closingName) {
        index -= 1;
      }
      if (index < 0) {
        continue;
      }
      const closed = stack.splice(index, 1)[0];
      if (closed.countValueStart >= 0 && String(closed.childCount) !== closed.countValue) {
        replacements.push({
          start: closed.countValueStart,
          end: closed.countValueEnd,
          value: String(closed.childCount)
        });
      }
      continue;
    }

    const selfClosing = /\/\s*>$/.test(tag);
    const nameMatch = /^<\s*([A-Za-z0-9_.:-]+)/.exec(tag);
    if (!nameMatch) {
      continue;
    }
    if (stack.length > 0) {
      stack[stack.length - 1].childCount += 1;
    }
    if (selfClosing) {
      const countMatch = /\bCount\s*=\s*"(\d*)"/.exec(tag);
      if (countMatch && countMatch[1] !== '0') {
        const countValueStart = match.index + countMatch.index + countMatch[0].indexOf('"') + 1;
        replacements.push({
          start: countValueStart,
          end: countValueStart + countMatch[1].length,
          value: '0'
        });
      }
      continue;
    }

    const countMatch = /\bCount\s*=\s*"(\d*)"/.exec(tag);
    const countValueStart = countMatch ? match.index + countMatch.index + countMatch[0].indexOf('"') + 1 : -1;
    const countValueEnd = countMatch ? countValueStart + countMatch[1].length : -1;
    stack.push({
      name: nameMatch[1],
      childCount: 0,
      countValue: countMatch ? countMatch[1] : '',
      countValueStart,
      countValueEnd
    });
  }

  if (replacements.length === 0) {
    return source;
  }

  let result = source;
  for (const replacement of replacements.sort((left, right) => right.start - left.start)) {
    result = `${result.slice(0, replacement.start)}${replacement.value}${result.slice(replacement.end)}`;
  }
  return result;
}

function buildNewRecordStub(virtualPath) {
  const baseName = path.posix.basename(String(virtualPath || ''), '.xml') || 'NewRecord';
  const rootName = baseName.replace(/[^A-Za-z0-9_.-]/g, '_') || 'NewRecord';
  const guid = crypto.randomUUID().toLowerCase();
  const fileName = String(virtualPath || '').replace(/^\/+/, '').replace(/\\/g, '/');
  return formatXmlDocument(`<?xml version="1.0" encoding="utf-8"?>
<${rootName} RecordId="${guid}" Type="StructType" File="${escapeXmlAttr(fileName)}">
</${rootName}>`);
}

function buildMirrorPlaceholderXml(record) {
  const safeName = escapeXmlAttr(record?.name || 'Record');
  const safeType = escapeXmlAttr(record?.typeName || '');
  const safeGuid = escapeXmlAttr(record?.guid || '');
  const safePath = escapeXmlAttr(record?.fileName || '');
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- DCB_EDITOR_LAZY_MIRROR
     This file is a lightweight placeholder so VS Code/Cursor can browse the full DCB quickly.
     Open the file in the editor and the extension will replace it with the real exported XML.
     Record="${safeName}" Type="${safeType}" RecordId="${safeGuid}" Path="${safePath}"
-->
`;
}

function isMirrorPlaceholderText(text) {
  return String(text || '').includes('DCB_EDITOR_LAZY_MIRROR');
}

async function activate(context) {
  const state = new DcbExtensionState(context);
  const xmlCompletionProvider = new DcbXmlCompletionProvider(state);
  void state.restoreMountedDcbWorkspaceFolders();

  context.subscriptions.push(
    state.output,
    vscode.workspace.registerFileSystemProvider('dcb', state.fileSystemProvider),
    vscode.window.registerTreeDataProvider('dcbEditorExplorer', state.treeProvider),
    vscode.languages.registerCompletionItemProvider(
      [
        { language: 'xml', scheme: 'dcb' },
        { language: 'xml', scheme: 'file' }
      ],
      xmlCompletionProvider,
      '"',
      '=',
      '<',
      ' '
    ),
    vscode.commands.registerCommand('dcbEditor.openDcb', async () => withErrorHandling(() => state.openDcb())),
    vscode.commands.registerCommand('dcbEditor.closeDcb', async () => withErrorHandling(async () => {
      await state.closeSession();
      await state.unmountAllDcbWorkspaceFolders();
    })),
    vscode.commands.registerCommand('dcbEditor.searchRecords', async (query) => withErrorHandling(() => state.searchRecords(query))),
    vscode.commands.registerCommand('dcbEditor.openRecord', async (record) => withErrorHandling(() => state.openRecord(record))),
    vscode.commands.registerCommand('dcbEditor.saveDcb', async () => withErrorHandling(() => state.saveSessionToSource())),
    vscode.commands.registerCommand('dcbEditor.importXmlFile', async (uri) => withErrorHandling(() => state.importXmlFromFile(uri))),
    vscode.commands.registerCommand('dcbEditor.importActiveXml', async () => withErrorHandling(() => state.importActiveXml())),
    vscode.commands.registerCommand('dcbEditor.refresh', async () => withErrorHandling(() => state.refresh())),
    vscode.workspace.onDidOpenTextDocument(async (document) => {
      await withErrorHandling(() => state.handleDocumentOpen(document), false);
    }),
    vscode.workspace.onDidSaveTextDocument(async (document) => {
      await withErrorHandling(() => state.handleDocumentSave(document), false);
    }),
    vscode.workspace.onDidCreateFiles(async (event) => {
      await withErrorHandling(() => state.handleMirrorFilesCreated(event), false);
    }),
    vscode.workspace.onDidDeleteFiles(async (event) => {
      await withErrorHandling(() => state.handleMirrorFilesDeleted(event), false);
    }),
    vscode.workspace.onDidRenameFiles(async (event) => {
      await withErrorHandling(() => state.handleMirrorFilesRenamed(event), false);
    }),
    vscode.workspace.onDidChangeTextDocument((event) => {
      const editor = vscode.window.activeTextEditor;
      if (!editor || editor.document !== event.document || !state.isDcbXmlDocument(event.document)) {
        return;
      }
      if (!event.contentChanges || event.contentChanges.length !== 1) {
        return;
      }

      const change = event.contentChanges[0];
      const cursor = editor.selection.active;
      if (!cursor || cursor.line !== change.range.start.line) {
        return;
      }

      const triggerText = String(change.text || '');
      const isDelete = triggerText.length === 0;
      const isTypingRelevant = /^[A-Za-z0-9_.:-]+$/.test(triggerText) || triggerText === '<' || triggerText === ' ';
      if (!isDelete && !isTypingRelevant) {
        return;
      }

      const lineText = event.document.lineAt(cursor.line).text;
      const shouldSuggest = Boolean(
        getTypeAttributeContext(lineText, cursor.character) ||
        getAttributeValueContext(lineText, cursor.character) ||
        getAttributeNameContext(lineText, cursor.character) ||
        getChildElementContext(event.document, cursor, state.nativeSession) ||
        getElementValueContext(event.document, cursor, state.nativeSession)
      );
      if (!shouldSuggest) {
        return;
      }

      void vscode.commands.executeCommand('editor.action.triggerSuggest');
    }),
    {
      dispose: () => {
        void state.dispose();
      }
    }
  );
}

async function withErrorHandling(action, showPopup = true) {
  try {
    return await action();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (showPopup) {
      void vscode.window.showErrorMessage(message);
    }
    return undefined;
  }
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};
