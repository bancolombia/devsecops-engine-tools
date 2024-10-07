import { OutputChannel } from "vscode";

export interface IIacScanUseCase {
    scan(folderToScan: string,
        organizationName: string,
        projectName: string,
        definitionId: string,
        adUserName: string,
        adPersonalAccessToken: string,
        environment: string,
        outputChannel: OutputChannel
    ): void;
}