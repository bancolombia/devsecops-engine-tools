import { OutputChannel } from "vscode";
import { ISecretScanUseCase } from "../../domain/usecase/interfaces/ISecretScanUseCase";
import { ScannerRes } from "../../domain/model/ScannerRes";
import { ScanConfiguration } from "../../domain/model/ScanConfiguration";

export class SecretScanRequest {

    constructor(private secretScannerUseCase: ISecretScanUseCase){}

    makeScan(
        folderToScan: string,
        outputChannel: OutputChannel,
        scannerConfiguration: ScanConfiguration
        ): Promise<ScannerRes> {
        return this.secretScannerUseCase.scan(folderToScan,
            outputChannel,
            scannerConfiguration
        );
    }

}