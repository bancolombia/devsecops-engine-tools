import { OutputChannel } from "vscode";

export interface IIacScanUseCase {
    scan(folderToScan: string, outputChannel: OutputChannel): void;
}