import { OutputChannel } from "vscode";
import { IImageScanUseCase } from "./interfaces/IImageScanUseCase";
import IScannerGateway from "../model/gateways/IScannerGateway";

export class ImageScanUseCase implements IImageScanUseCase {

    constructor(
        private imageScanner: IScannerGateway
    ){}
    
    scan(imageToScan: string, outputChannel: OutputChannel): void {
        this.imageScanner.scan(imageToScan, outputChannel);
    }
    
}