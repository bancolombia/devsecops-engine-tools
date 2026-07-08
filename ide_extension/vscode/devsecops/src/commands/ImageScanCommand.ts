import * as vscode from "vscode";
import { ResultsTreeDataProvider } from "../tree/ResultsTreeDataProvider";
import { imageScanRequest } from "../application/InitEngineCore";
import { ScanConfiguration } from "../domain/model/ScanConfiguration";
import { ScanOutputLoader } from "../infrastructure/helper/LoadingAnimator";
import ContainerEngineManager from "../infrastructure/helper/ContainerEngineManager";
import { ErrorHandlingService } from "../infrastructure/services/ErrorHandlingService";

export function registerImageScanCommand(
  context: vscode.ExtensionContext,
  treeDataProvider: ResultsTreeDataProvider
): vscode.Disposable {
  const imageScanDisposable = vscode.commands.registerCommand(
    "devsecops.imageScan",
    async () => {
      const images = await getContainerImages();
      let imageName = "";
      const quickPickItems: vscode.QuickPickItem[] = images.map((image) => {
        return {
          label: image.fullName
        };
      });

      if (quickPickItems.length === 0) {
        void vscode.window.showErrorMessage("No container images found. Please ensure you have images available in your container engine.");
        return;
      }

      const pickedImage = await vscode.window.showQuickPick(quickPickItems, {
        placeHolder: "Select an image to scan",
      });

      if (!pickedImage) {
        void vscode.window.showErrorMessage("No image selected");
        return;
      } else {
        imageName = pickedImage.label;
      }

      void vscode.window.showInformationMessage(
        `DevSecOps Image Scanning: ${imageName}`
      );

      let useCase;
      try {
        useCase = await imageScanRequest();
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        void vscode.window.showErrorMessage(`Image Scan configuration error: ${errorMessage}`);
        return;
      }

      const outputChannel = vscode.window.createOutputChannel("Image Scan Results");
      outputChannel.clear(); 

      const scanLoader = new ScanOutputLoader(outputChannel);

      // Add loading placeholder
      const scanId = treeDataProvider.addLoadingScanResult(
        `Image: ${imageName}`,
        "image",
        outputChannel
      );

      try {
        const scanResult = await useCase.scan(
          imageName,
          outputChannel,
          new ScanConfiguration(),
          scanLoader
        );

        if (scanResult) {
          scanLoader.stop(scanResult.getFindings().length, "image vulnerability");

          void vscode.window.showInformationMessage(
            "Image Scan completed successfully"
          );
          
          // Update the loading placeholder with actual results
          treeDataProvider.updateScanResult(
            scanId,
            scanResult.getFindings(),
            "image"
          );
        } else {
          scanLoader.showError("Image Scan failed - No results returned");
          void vscode.window.showErrorMessage("Image Scan failed - Check Output for details");
          // Mark the scan as failed but keep it visible
          treeDataProvider.updateScanResultWithError(scanId, "No results returned");
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : "Unknown error occurred";
        scanLoader.showError(`Image Scan failed: ${errorMessage}`);
        const userMessage = ErrorHandlingService.isVpnError(errorMessage)
          ? "Cannot reach the microservice. Please check your VPN or internal Wi-Fi connection and try again."
          : ErrorHandlingService.isSelfSignedCertificateError(errorMessage)
          ? "SSL certificate error: self-signed certificate detected. Please update your certificates and try again."
          : ErrorHandlingService.isMicroserviceError(errorMessage)
          ? "The microservice is experiencing high transaction load and the scan was retried automatically, but it still could not complete. Please try again later."
          : "Image Scan failed - Check Output for details";
        void vscode.window.showErrorMessage(userMessage);
        // Mark the scan as failed but keep it visible
        treeDataProvider.updateScanResultWithError(scanId, errorMessage);
      }
    }
  );
  return imageScanDisposable;
}

const getContainerImages = async (): Promise<Array<{name: string, tag: string, fullName: string}>> => {
  const engineStatus = await ContainerEngineManager.isContainerEngineAvailable();

  if (!engineStatus.available) {
    const engineType = ContainerEngineManager.getEngineType();
    void vscode.window.showErrorMessage(
      `${engineType.charAt(0).toUpperCase() + engineType.slice(1)} is not installed or not found in the PATH.`
    );
    return [];
  }

  try {
    const images = await ContainerEngineManager.getContainerImages();
    return images;
  } catch (error) {
    console.error("Error getting container images:", error);
    void vscode.window.showErrorMessage(
      `Error retrieving container images: ${error instanceof Error ? error.message : String(error)}`
    );
    return [];
  }
};
