import { OutputChannel } from "vscode";
import { ScannerRes } from "../ScannerRes";

export default interface IScannerGateway {
  scan(
    elementToScan: string,
    outputChannel: OutputChannel,
    dockerImageName: string,
    toolVersion?: string,
    dockerPath?: string
  ): Promise<ScannerRes>;
}
