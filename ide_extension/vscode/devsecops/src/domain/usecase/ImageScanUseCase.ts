import { OutputChannel } from "vscode";
import { IImageScanUseCase } from "./interfaces/IImageScanUseCase";
import IScannerGateway from "../model/gateways/IScannerGateway";
import { ScannerRes } from "../model/ScannerRes";
import { ScanConfiguration } from "../model/ScanConfiguration";

export class ImageScanUseCase implements IImageScanUseCase {
  constructor(
    private imageScanner: IScannerGateway,
    private dockerImageVersion: string,
    private dockerPath: string
  ) {}

  async scan(
    imageToScan: string,
    outputChannel: OutputChannel,
    scanConfiguration: ScanConfiguration
  ): Promise<ScannerRes> {
    return await this.imageScanner.scan(
      imageToScan,
      outputChannel,
      scanConfiguration.getDockerImageName(),
      this.dockerImageVersion,
      this.dockerPath
    );
  }
}
