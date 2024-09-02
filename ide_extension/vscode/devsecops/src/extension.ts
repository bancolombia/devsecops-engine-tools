import * as vscode from 'vscode';
import { iacScanRequest } from './application/InitEngineCore';

function removeAnsiEscapeCodes(text: string): string {
    return text.replace(/\x1b\[[0-9;]*m/g, '');
}

export function activate(context: vscode.ExtensionContext) {

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
		const groupName: string = vscode.workspace.getConfiguration('devsecops').get('groupName') || '';
		const adUserName: string = vscode.workspace.getConfiguration('devsecops').get('username') || '';
		const adPersonalAccessToken: string = vscode.workspace.getConfiguration('devsecops').get('personalAccessToken') || '';

		if (selectedFolder && selectedFolder.length > 0) {
			let folderPath = selectedFolder[0].fsPath;

			folderPath = folderPath.replace(/^file:\/\//, '');

			vscode.window.showInformationMessage(`Devsecops Scanning: ${folderPath}`);

			const scanner = iacScanRequest();
			const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');
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
}

// This method is called when your extension is deactivated
export function deactivate() {}
