// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';
import {exec} from 'child_process';

function removeAnsiEscapeCodes(text: string): string {
    return text.replace(/\x1b\[[0-9;]*m/g, '');
}

// This method is called when your extension is activated
// Your extension is activated the very first time the command is executed
export function activate(context: vscode.ExtensionContext) {

	// Use the console to output diagnostic information (console.log) and errors (console.error)
	// This line of code will only be executed once when your extension is activated
	console.log('DevSecOpse IDE Extension active');

	// The command has been defined in the package.json file
	// Now provide the implementation of the command with registerCommand
	// The commandId parameter must match the command field in package.json
	const disposable = vscode.commands.registerCommand('devsecops.helloWorld', () => {
		// The code you place here will be executed every time your command is executed
		// Display a message box to the user
		vscode.window.showInformationMessage('Hello World');
		
	});

	const iacScanDisposable = vscode.commands.registerCommand('devsecops.iacScan', () => {

		vscode.window.showInformationMessage('Iac Scan init');
		
		// Crea un canal de salida
        const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');

        // Ejecuta el comando 'ls' en el directorio '~/'
		
		exec('pwd', (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return;
            }
            // Muestra el resultado en el canal de salida
            outputChannel.appendLine('IaC Scan Output:');
            outputChannel.appendLine(stdout);
            outputChannel.show();
        });

        exec('docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v ./ms_artifact/ms_artifact:/ms_artifact devsecops_docker_36  devsecops-engine-tools --platform_devops local --remote_config_repo example_remote_config_local --tool engine_iac --folder_path /ms_artifact', (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return;
            }
            // Muestra el resultado en el canal de salida
			const cleanedOutput = removeAnsiEscapeCodes(stdout);
            outputChannel.appendLine('IaC Scan Output:');
            outputChannel.appendLine(cleanedOutput);
            outputChannel.show();
        });
	
	});

	context.subscriptions.push(disposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
