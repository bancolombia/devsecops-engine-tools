import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "../../domain/usecase/interfaces/IIacScanUseCase";

export class IacScanRequest {

    constructor(private iacScannerUseCase: IIacScanUseCase){}

    makeScan(
folderToScan: string, organizationName: string, projectName: string, groupName: string, adUserName: string, adPersonalAccessToken: string, environment: string, outputChannel: OutputChannel): any {
        this.iacScannerUseCase.scan(folderToScan,
            organizationName,
            projectName,
            groupName,
            adUserName,
            adPersonalAccessToken,
            environment,
            outputChannel
        );
    }

}