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


		const iacScanItem = new vscode.TreeItem('Scan IaC', vscode.TreeItemCollapsibleState.None);
		iacScanItem.command = {
			command: 'devsecops.iacScan',
			title: 'Scan IaC',
			arguments: [iacScanItem]
		};
		items.push(iacScanItem);

		const imageScanItem = new vscode.TreeItem('Scan Image', vscode.TreeItemCollapsibleState.None);
		imageScanItem.command = {
			command: 'devsecops.imageScan',
			title: 'Scan Image',
			arguments: [imageScanItem]
		};
		items.push(imageScanItem);

		return items;
	}
}

export function activate(context: vscode.ExtensionContext) {

	const treeDataProvider = new DevSecOpsTreeDataProvider();
	vscode.window.registerTreeDataProvider('devsecops', treeDataProvider);

	console.log('DevSecOpse IDE Extension active');

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
					const imageLabel = `${imageName}:${imageTag}`;
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
		const quickPickItems: vscode.QuickPickItem[] = images.map(i => {
			return {
				label: i.label?.toString() ?? '',
			};
		});

		const selectedImage = await vscode.window.showQuickPick(quickPickItems, {
			placeHolder: 'Select an image to scan',
		});		

		if (!selectedImage) {
			return;
		} else {
			vscode.window.showInformationMessage(`DevSecOps Image Scanning: ${selectedImage.label}`);
			const scanner = imageScanRequest();
			const outputChannel = vscode.window.createOutputChannel('IaC Scan Results');
			scanner.makeScan(
				selectedImage.label,
				outputChannel
			);
		}
	});

	context.subscriptions.push(iacScanDisposable, imageScanDisposable);
}

export function deactivate() {}
