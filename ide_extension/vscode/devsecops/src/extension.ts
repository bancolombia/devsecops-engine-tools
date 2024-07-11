// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {exec} from 'child_process';
import { Scanner } from './infraestructure/drivenAdapter/Scanner';

function removeAnsiEscapeCodes(text: string): string {
    return text.replace(/\x1b\[[0-9;]*m/g, '');
}

export function activate(context: vscode.ExtensionContext) {

	console.log('DevSecOpse IDE Extension active');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	const disposable = vscode.commands.registerCommand('devsecops.helloWorld', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World');
		
	});

	const iacScanDisposable = vscode.commands.registerCommand('devsecops.iacScan', async () => {
		const selectedFolder = await vscode.window.showOpenDialog({
			canSelectFolders: true,
			canSelectFiles: false,
			canSelectMany: false,
			openLabel: 'Select Folder'
		});
		if (selectedFolder && selectedFolder.length > 0) {
			let folderPath = selectedFolder[0].fsPath;
			
			folderPath = folderPath.replace(/^file:\/\//, '');
		
			vscode.window.showInformationMessage(`Devsecops Scanning: ${folderPath}`);

			const scanner = new Scanner();
			const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');
			scanner.iacScan(folderPath, outputChannel);
		}
	});

	context.subscriptions.push(disposable);
	context.subscriptions.push(iacScanDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
