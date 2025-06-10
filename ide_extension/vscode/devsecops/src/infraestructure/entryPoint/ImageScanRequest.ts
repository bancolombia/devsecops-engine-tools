import { OutputChannel } from "vscode";
import { IImageScanUseCase } from "../../domain/usecase/interfaces/IImageScanUseCase";
import { ScannerRes } from "../../domain/model/ScannerRes";
import { ScanConfiguration } from "../../domain/model/ScanConfiguration";

export class ImageScanRequest {

    constructor(private imageScanUseCase: IImageScanUseCase){}

    makeScan(elementToScan: string, outputChannel: OutputChannel, scanConfiguration: ScanConfiguration): Promise<ScannerRes> {
        return this.imageScanUseCase.scan(
            elementToScan,
            outputChannel,
            scanConfiguration
        );
    }

}