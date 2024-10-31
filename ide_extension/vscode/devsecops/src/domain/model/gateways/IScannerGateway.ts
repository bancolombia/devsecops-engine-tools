import { OutputChannel } from "vscode";

export default interface IScannerGateway{

    scan(elementToScan: string, outputChannel: OutputChannel): void

};