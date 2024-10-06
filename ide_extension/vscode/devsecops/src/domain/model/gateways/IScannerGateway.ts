import { OutputChannel } from "vscode";

export default interface IScannerGateway{

    iacScan(folderToScan: string, outputChannel: OutputChannel): void
    secretScan(folderToScan: string, outputChannel: OutputChannel): void

};