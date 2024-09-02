import { OutputChannel } from "vscode";

export interface IIacScanUseCase {
    scan(folderToScan: string,
        organizationName: string,
        projectName: string,
        groupName: string,
        adUserName: string,
        adPersonalAccessToken: string,
        outputChannel: OutputChannel
    ): void;
}