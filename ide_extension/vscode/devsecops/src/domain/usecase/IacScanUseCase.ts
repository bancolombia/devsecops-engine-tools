import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "./interfaces/IIacScanUseCase";
import { IacScanner } from "../../infraestructure/drivenAdapter/IacScanner";

export class IacScanUseCase implements IIacScanUseCase {

    constructor(private iacScanner: IacScanner){}

    scan(folderToScan: string, outputChannel: OutputChannel): void {
        this.iacScanner.iacScan(folderToScan, outputChannel);
    }

}