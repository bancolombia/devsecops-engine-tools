import { OutputChannel } from "vscode";

export interface IImageScanUseCase {
    scan(imageToScan: string, outputChannel: OutputChannel): void;
}