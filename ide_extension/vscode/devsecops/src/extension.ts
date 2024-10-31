import * as vscode from 'vscode';
import { iacScanRequest, imageScanRequest } from './application/InitEngineCore';
import { Docker, IOptions } from 'docker-cli-js';

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
			title: 'IAC SCAN',
			arguments: [iacScanItem]
		};
		items.push(iacScanItem);

		return items;
	}
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

	const getDockerImages = async () => {
		const options: IOptions = {
			env: {
				...process.env,
				PATH: process.env.PATH + ':/usr/local/bin'
			}
		};
		const dockerCli = new Docker(options);
	
		return dockerCli.command('images').then(function (data) {
			const output = data.raw.split('\n');
			const images = [];
	
			for (let i = 1; i < output.length; i++) {
				const imageInfo = output[i].split(/\s+/);
				const imageName = imageInfo[0];
				const imageTag = imageInfo[1];
				const imageSize = imageInfo[6];
	
				if (imageName && imageTag && imageSize) {
					const imageLabel = `${imageName}:${imageTag} (${imageSize})`;
					const imageItem = new vscode.TreeItem(imageLabel, vscode.TreeItemCollapsibleState.None);
					imageItem.command = {
						command: 'devsecops.imageScan',
						title: 'Image Scan',
						arguments: [imageItem]
					};
					images.push(imageItem);
				}
			}
	
			return images;
		}).catch(function (err) {
			console.error(err);
			return [];
		});
	};

	const imageScanDisposable = vscode.commands.registerCommand('devsecops.imageScan', async () => {
		const images = await getDockerImages();
		images.map((image) => console.log(image));
		const imageName = "defectdojo/defectdojo-django";
		const imageOptions = images.map(image => image.label);
		const quickPickItems: vscode.QuickPickItem[] = images.map(i => {
			return {
				label: i.label?.toString() ?? '',
			};
		});

		await vscode.window.showQuickPick(quickPickItems,{
			placeHolder: 'Select an image to scan'
		});		

		vscode.window.showInformationMessage(`DevSecOps Image Scanning: ${imageName}`);

		const scanner = imageScanRequest();
		const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');
		scanner.makeScan(
			imageName,
			outputChannel
		);
	});

	context.subscriptions.push(disposable);
	context.subscriptions.push(iacScanDisposable);
	context.subscriptions.push(imageScanDisposable);
}

// This method is called when your extension is deactivated
export function deactivate() {}
