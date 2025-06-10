import * as vscode from "vscode";
import * as path from "path";
import * as os from "os";
import { iacScanRequest } from "../application/InitEngineCore";
import { DevSecOpsTreeDataProvider } from "../tree/DevSecOpsTreeDataProvider";
import { ScanConfiguration } from "../domain/model/ScanConfiguration";

export function registerIacScanCommand(
  context: vscode.ExtensionContext,
  treeDataProvider: DevSecOpsTreeDataProvider
): vscode.Disposable {
  const iacScanDisposable = vscode.commands.registerCommand("devsecops.iacScan", async () => {
    const selectedFolder = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectFiles: false,
      canSelectMany: false,
      defaultUri:
        vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
          ? vscode.Uri.file(path.join(vscode.workspace.workspaceFolders[0].uri.fsPath, ""))
          : vscode.Uri.file(os.homedir()),
      openLabel: "Select Folder",
    });

    if (selectedFolder && selectedFolder.length > 0) {
      let folderPath = selectedFolder[0].fsPath;
      folderPath = folderPath.replace(/^file:\/\//, "");

      void vscode.window.showInformationMessage(`DevSecOps Iac Scanning: ${folderPath}`);

      const scanner = await iacScanRequest();
      const outputChannel = vscode.window.createOutputChannel("IaC Scan Results");

      outputChannel.appendLine(`Starting Infrastructure as Code scan for: ${folderPath}`);
      outputChannel.show();

      const scanResult = await scanner.makeScan(folderPath, outputChannel, new ScanConfiguration());

      if (scanResult) {
        void vscode.window.showInformationMessage("Iac Scan completed successfully");
        treeDataProvider.addScanResult(
          "IAC SCAN RESULT",
          scanResult.getFindings(),
          "iac",
          folderPath
        );
      } else {
        void vscode.window.showErrorMessage("Iac Scan failed");
      }
    }
  });

  return iacScanDisposable;
}
