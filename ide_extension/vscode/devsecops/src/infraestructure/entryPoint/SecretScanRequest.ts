import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "../../domain/usecase/interfaces/IIacScanUseCase";
import { ISecretScanUseCase } from "../../domain/usecase/interfaces/ISecretScanUseCase";

export class SecretScanRequest {

    constructor(private secretScannerUseCase: ISecretScanUseCase){}

    makeScan(
        folderToScan: string,
        organizationName: string,
        projectName: string,
        groupName: string,
        adUserName: string,
        adPersonalAccessToken: string,
        outputChannel: OutputChannel
        ): any {
        this.secretScannerUseCase.scan(folderToScan,
            organizationName,
            projectName,
            groupName,
            adUserName,
            adPersonalAccessToken,
            outputChannel
        );
    }

}