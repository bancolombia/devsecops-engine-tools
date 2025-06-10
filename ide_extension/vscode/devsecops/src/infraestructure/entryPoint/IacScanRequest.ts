import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "../../domain/usecase/interfaces/IIacScanUseCase";
import { ScannerRes } from "../../domain/model/ScannerRes";
import { ScanConfiguration } from "../../domain/model/ScanConfiguration";

export class IacScanRequest {
  constructor(private iacScannerUseCase: IIacScanUseCase) {}

  async makeScan(
    folderToScan: string,
    outputChannel: OutputChannel,
    scanConfiguration: ScanConfiguration
  ): Promise<ScannerRes> {
    return await this.iacScannerUseCase.scan(
      folderToScan,
      outputChannel,
      scanConfiguration
    );
  }
}
