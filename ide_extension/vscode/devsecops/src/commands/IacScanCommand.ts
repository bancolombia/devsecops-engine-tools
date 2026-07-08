import * as vscode from "vscode";
import * as path from "path";
import * as os from "os";
import { iacScanRequest } from "../application/InitEngineCore";
import { ResultsTreeDataProvider } from "../tree/ResultsTreeDataProvider";
import { ScanConfiguration } from "../domain/model/ScanConfiguration";
import { ScanOutputLoader } from "../infrastructure/helper/LoadingAnimator";
import { ErrorHandlingService } from "../infrastructure/services/ErrorHandlingService";

export function registerIacScanCommand(
  context: vscode.ExtensionContext,
  treeDataProvider: ResultsTreeDataProvider
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

      let useCase;
      try {
        useCase = await iacScanRequest();
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        void vscode.window.showErrorMessage(`IaC Scan configuration error: ${errorMessage}`);
        return;
      }

      const outputChannel = vscode.window.createOutputChannel("IaC Scan Results");
      outputChannel.clear();

      const scanLoader = new ScanOutputLoader(outputChannel);

      // Add loading placeholder
      const scanId = treeDataProvider.addLoadingScanResult(
        `IaC: ${folderPath.split('/').pop() || 'folder'}`,
        "iac",
        outputChannel
      );

      try {
        const scanResult = await useCase.scan(folderPath, outputChannel, new ScanConfiguration(), scanLoader);

        if (scanResult) {
          scanLoader.stop(scanResult.getFindings().length, "Infrastructure as Code");

          void vscode.window.showInformationMessage("Iac Scan completed successfully");
          
          // Update the loading placeholder with actual results
          treeDataProvider.updateScanResult(
            scanId,
            scanResult.getFindings(),
            "iac",
            folderPath
          );
        } else {
          scanLoader.showError("Iac Scan failed - No results returned");
          void vscode.window.showErrorMessage("Iac Scan failed - Check Output for details");
          // Mark the scan as failed but keep it visible
          treeDataProvider.updateScanResultWithError(scanId, "No results returned");
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        scanLoader.showError(`Iac Scan failed: ${errorMessage}`);
        const userMessage = ErrorHandlingService.isVpnError(errorMessage)
          ? "Cannot reach the microservice. Please check your VPN or internal Wi-Fi connection and try again."
          : ErrorHandlingService.isSelfSignedCertificateError(errorMessage)
          ? "SSL certificate error: self-signed certificate detected. Please update your certificates and try again."
          : ErrorHandlingService.isMicroserviceError(errorMessage)
          ? "The microservice is experiencing high transaction load and the scan was retried automatically, but it still could not complete. Please try again later."
          : "Iac Scan failed - Check Output for details";
        void vscode.window.showErrorMessage(userMessage);
        // Mark the scan as failed but keep it visible
        treeDataProvider.updateScanResultWithError(scanId, errorMessage);
      }
    }
  });

  return iacScanDisposable;
}
