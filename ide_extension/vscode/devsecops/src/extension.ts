import * as vscode from 'vscode';
import { iacScanRequest, secretScanRequest } from './application/InitEngineCore';

class DevSecOpsTreeDataProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
    private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
    readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

    getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
        return element;
    }

    getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
        return Promise.resolve(this.getItems());
    }

	private getItems(): vscode.TreeItem[] {
		const items: vscode.TreeItem[] = [];

		const helloWorldItem = new vscode.TreeItem('Hello world', vscode.TreeItemCollapsibleState.None);
		helloWorldItem.command = {
			command: 'devsecops.helloWorld',
			title: 'Hello World',
			arguments: [helloWorldItem]
		};
		items.push(helloWorldItem);

		const iacScanItem = new vscode.TreeItem('Iac Scan', vscode.TreeItemCollapsibleState.None);
		iacScanItem.command = {
			command: 'devsecops.iacScan',
			title: 'Iac Scan',
			arguments: [iacScanItem]
		};
		items.push(iacScanItem);

		const secretScanItem = new vscode.TreeItem('Secret Scan', vscode.TreeItemCollapsibleState.None);
		iacScanItem.command = {
			command: 'devsecops.secretScan',
			title: 'Secret Scan',
			arguments: [secretScanItem]
		};
		items.push(secretScanItem);

		return items;
	}
}

function removeAnsiEscapeCodes(text: string): string {
    return text.replace(/\x1b\[[0-9;]*m/g, '');
}

export function activate(context: vscode.ExtensionContext) {

	const treeDataProvider = new DevSecOpsTreeDataProvider();
	vscode.window.registerTreeDataProvider('devsecops', treeDataProvider);

	console.log('DevSecOpse IDE Extension active');

	const disposable = vscode.commands.registerCommand('devsecops.helloWorld', () => {
		vscode.window.showInformationMessage('Hello World');
	});

	const iacScanDisposable = vscode.commands.registerCommand('devsecops.iacScan', async () => {
		const selectedFolder = await vscode.window.showOpenDialog({
			canSelectFolders: true,
			canSelectFiles: false,
			canSelectMany: false,
			openLabel: 'Select Folder'
		});

		const organizationName: string = vscode.workspace.getConfiguration('devsecops').get('organizationName') || '';
		const projectName: string = vscode.workspace.getConfiguration('devsecops').get('projectName') || '';
		const definitionId: string = vscode.workspace.getConfiguration('devsecops').get('releaseId') || '';
		const environment: string = vscode.workspace.getConfiguration('devsecops').get('environment') || '';
		const adUserName: string = vscode.workspace.getConfiguration('devsecops').get('username') || '';
		const adPersonalAccessToken: string = vscode.workspace.getConfiguration('devsecops').get('personalAccessToken') || '';

		if (selectedFolder && selectedFolder.length > 0) {
			let folderPath = selectedFolder[0].fsPath;

			folderPath = folderPath.replace(/^file:\/\//, '');

			vscode.window.showInformationMessage(`DevSecOps Iac Scanning: ${folderPath}`);

			const scanner = iacScanRequest();
			const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');
			scanner.makeScan(folderPath,
				organizationName,
				projectName,
				definitionId,
				adUserName,
				adPersonalAccessToken,
				environment,
				outputChannel
			);
		}
	});

	const secretScanDisposable = vscode.commands.registerCommand('devsecops.secretScan', async () => {
		const selectedFolder = await vscode.window.showOpenDialog({
			canSelectFolders: true,
			canSelectFiles: false,
			canSelectMany: false,
			openLabel: 'Select Folder'
		});

		const organizationName: string = vscode.workspace.getConfiguration('devsecops').get('organizationName') || '';
		const projectName: string = vscode.workspace.getConfiguration('devsecops').get('projectName') || '';
		const groupName: string = vscode.workspace.getConfiguration('devsecops').get('groupName') || '';
		const adUserName: string = vscode.workspace.getConfiguration('devsecops').get('username') || '';
		const adPersonalAccessToken: string = vscode.workspace.getConfiguration('devsecops').get('personalAccessToken') || '';

		vscode.window.showInformationMessage(`Devsecops Secret Scanning`);

		if (selectedFolder && selectedFolder.length > 0) {
			let folderPath = selectedFolder[0].fsPath;

			folderPath = folderPath.replace(/^file:\/\//, '');

			vscode.window.showInformationMessage(`Devsecops Secret Scanning: ${folderPath}`);

			const scanner = secretScanRequest();
			const outputChannel = vscode.window.createOutputChannel('Secret Scan Results');
			scanner.makeScan(folderPath,
				organizationName,
				projectName,
				groupName,
				adUserName,
				adPersonalAccessToken,
				outputChannel
			);
		}
	});

	context.subscriptions.push(disposable);
	context.subscriptions.push(iacScanDisposable);
	context.subscriptions.push(secretScanDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
