import { OutputChannel } from "vscode";
import { ScannerRes } from "../../model/ScannerRes";
import { ScanConfiguration } from "../../model/ScanConfiguration";

export interface IImageScanUseCase {
  scan(
    imageToScan: string,
    outputChannel: OutputChannel,
    scanConfiguration: ScanConfiguration
  ): Promise<ScannerRes>;
}
