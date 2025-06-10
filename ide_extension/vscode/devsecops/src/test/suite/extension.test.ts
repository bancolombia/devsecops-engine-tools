import * as assert from 'assert';

import * as vscode from 'vscode';
import * as sinon from 'sinon';
import { DiagnosticService } from '../../tree/DiagnosticService';
import { Finding } from '../../domain/model/Finding';
import { SecurityCodeActionProvider } from '../../actions/SecurityCodeActionProvider';

suite('Extension Test Suite', () => {
    // Clean up after tests
    suiteTeardown(() => {
      void vscode.window.showInformationMessage('All tests done!');
    });
  
    // Clean up after each test
    teardown(() => {
      sinon.restore();
    });
    
    test('Sample test', () => {
      assert.strictEqual(-1, [1, 2, 3].indexOf(5));
      assert.strictEqual(-1, [1, 2, 3].indexOf(0));
    });

  test('Extension should activate correctly', async () => {
    // Arrange
    const context: any = { subscriptions: [] };
    const initializeSpy = sinon.spy(DiagnosticService, 'initialize');
    const registerTreeSpy = sinon.spy(vscode.window, 'registerTreeDataProvider');
    const createTreeSpy = sinon.spy(vscode.window, 'createTreeView');
    const registerCommandStub = sinon.stub(vscode.commands, 'registerCommand').returns({
      dispose: () => {}
    });
    const registerProviderStub = sinon.stub(vscode.languages, 'registerCodeActionsProvider').returns({
      dispose: () => {}
    });
    
    // Mock dependent functions
    const iacScanDisposable = { dispose: () => {} };
    const imageScanDisposable = { dispose: () => {} };
    const registerIacScanStub = sinon.stub(require('../../commands/IacScanCommand'), 'registerIacScanCommand').returns(iacScanDisposable);
    const registerImageScanStub = sinon.stub(require('../../commands/ImageScanCommand'), 'registerImageScanCommand').returns(imageScanDisposable);
    const registerCopilotStub = sinon.stub(require('../../commands/copilotCommands'), 'registerCopilotCommands');
    
    // Act
    await require('../../extension').activate(context);
    
    // Assert
    assert.strictEqual(initializeSpy.calledOnce, true, 'DiagnosticService should be initialized');
    assert.strictEqual(registerTreeSpy.calledWith('devsecops'), true, 'Tree data provider should be registered');
    assert.strictEqual(createTreeSpy.calledOnce, true, 'Tree view should be created');
    assert.strictEqual(registerIacScanStub.calledOnce, true, 'IAC scan command should be registered');
    assert.strictEqual(registerImageScanStub.calledOnce, true, 'Image scan command should be registered');
    assert.strictEqual(registerCopilotStub.calledOnce, true, 'Copilot commands should be registered');
    assert.strictEqual(registerCommandStub.calledWith('devsecops.openWithDiagnostic'), true, 'Open with diagnostic command should be registered');
    assert.strictEqual(registerProviderStub.calledOnce, true, 'Code action provider should be registered');
    
    // Check subscriptions
    assert.strictEqual(context.subscriptions.length, 6, 'All disposables should be added to subscriptions');
  });

  test('Extension should deactivate correctly', () => {
    // Arrange
    const disposeSpy = sinon.spy(DiagnosticService, 'dispose');
    
    // Act
    require('../../extension').deactivate();
    
    // Assert
    assert.strictEqual(disposeSpy.calledOnce, true, 'DiagnosticService should be disposed on deactivation');
  });

test('openWithDiagnostic command should call DiagnosticService.showFindingInFile', async () => {
  // Arrange
  sinon.restore(); // Make sure we start clean
  
  // Instead of manually initializing DiagnosticService, let's mock its methods
  // to prevent the "object disposed" error
  const showFindingInFileSpy = sinon.stub(DiagnosticService, 'showFindingInFile').returns();
  
  // Create a mock Finding with the required methods
  const mockFinding = { 
    id: 'test-finding', 
    severity: 'high',
    getDescription: () => 'Test description',
    getId: () => 'Test ID',
    getTitle: () => 'Test title',
    getSeverityText: () => 'High'
  } as unknown as Finding;
  
  const filePath = '/path/to/file.js';
  const lineNumberStart = 10;
  const lineNumberEnd = 15;
  
  // Prepare context and command registration
  const context: any = { subscriptions: [] };
  let registeredCommands: Record<string, Function> = {};
  
  sinon.stub(vscode.commands, 'registerCommand').callsFake((commandId, handler) => {
    registeredCommands[commandId] = handler;
    return { dispose: () => {} };
  });
  
  // Mock other dependencies
  sinon.stub(DiagnosticService, 'initialize');
  sinon.stub(require('../../commands/IacScanCommand'), 'registerIacScanCommand').returns({ dispose: () => {} });
  sinon.stub(require('../../commands/ImageScanCommand'), 'registerImageScanCommand').returns({ dispose: () => {} });
  sinon.stub(require('../../commands/copilotCommands'), 'registerCopilotCommands');
  
  // Act - activate the extension
  await require('../../extension').activate(context);
  
  // Assert command handler was registered
  const handler = registeredCommands['devsecops.openWithDiagnostic'];
  assert.notStrictEqual(handler, undefined, 'Command handler should be registered');
  
  // Act - call the handler directly
  handler(mockFinding, filePath, lineNumberStart, lineNumberEnd);
  
  // Assert
  assert.strictEqual(
    showFindingInFileSpy.calledWith(mockFinding, filePath, lineNumberStart), 
    true, 
    'showFindingInFile should be called with correct parameters'
  );
});

  test('Extension registers SecurityCodeActionProvider correctly', async () => {
    // Arrange
    sinon.restore(); // Make sure we start clean
    const context: any = { subscriptions: [] };
    
    // Track provider registration
    let registeredProvider: any = null;
    let registeredSelector = null;
    let registeredMetadata = null;
    
    sinon.stub(vscode.languages, 'registerCodeActionsProvider').callsFake((selector, provider, metadata) => {
      registeredSelector = selector;
      registeredProvider = provider;
      registeredMetadata = metadata;
      return { dispose: () => {} };
    });
    
    // Mock other dependencies
    sinon.stub(vscode.commands, 'registerCommand').returns({ dispose: () => {} });
    sinon.stub(require('../../commands/IacScanCommand'), 'registerIacScanCommand').returns({ dispose: () => {} });
    sinon.stub(require('../../commands/ImageScanCommand'), 'registerImageScanCommand').returns({ dispose: () => {} });
    sinon.stub(require('../../commands/copilotCommands'), 'registerCopilotCommands');
    
    // Act
    await require('../../extension').activate(context);
    
    // Assert
    assert.notStrictEqual(registeredProvider, null, 'Code action provider should be registered');
    assert.deepStrictEqual(registeredSelector, { scheme: 'file' }, 'Should register for file scheme');
    assert.strictEqual(
      registeredProvider && typeof registeredProvider === 'object' && registeredProvider.constructor === SecurityCodeActionProvider,
      true,
      'Should register SecurityCodeActionProvider instance'
    );
    assert.deepStrictEqual(
      registeredMetadata,
      { providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds },
      'Should register with correct code action kinds'
    );
  });
});