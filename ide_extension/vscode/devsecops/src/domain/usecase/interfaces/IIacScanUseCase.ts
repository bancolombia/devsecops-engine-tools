import { OutputChannel } from "vscode";
import { ScannerRes } from "../../model/ScannerRes";
import { ScanConfiguration } from "../../model/ScanConfiguration";

export interface IIacScanUseCase {
    scan(folderToScan: string,
        outputChannel: OutputChannel,
        scanConfiguration: ScanConfiguration,
    ): Promise<ScannerRes>;
}