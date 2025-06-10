import { OutputChannel } from "vscode";
import { ScannerRes } from "../../model/ScannerRes";
import { ScanConfiguration } from "../../model/ScanConfiguration";

export interface ISecretScanUseCase {
    scan(folderToScan: string,
        outputChannel: OutputChannel,
        scannerConfiguration: ScanConfiguration
    ): Promise<ScannerRes>;
}