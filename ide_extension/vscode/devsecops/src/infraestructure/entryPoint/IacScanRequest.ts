import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "../../domain/usecase/interfaces/IIacScanUseCase";

export class IacScanRequest {

    constructor(private iacScannerUseCase: IIacScanUseCase){}

    makeScan(folderToScan: string, outputChannel: OutputChannel): any {
        this.iacScannerUseCase.scan(folderToScan, outputChannel);
    }

}