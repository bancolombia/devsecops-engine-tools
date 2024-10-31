import { OutputChannel } from "vscode";
import { IImageScanUseCase } from "../../domain/usecase/interfaces/IImageScanUseCase";

export class ImageScanRequest {

    constructor(private imageScanUseCase: IImageScanUseCase){}

    makeScan(elementToScan: string, outputChannel: OutputChannel): any {
        this.imageScanUseCase.scan(
            elementToScan,
            outputChannel
        );
    }

}