import { OutputChannel } from "vscode";

export interface ISecretScanUseCase {
    scan(folderToScan: string,
        organizationName: string,
        projectName: string,
        groupName: string,
        adUserName: string,
        adPersonalAccessToken: string,
        outputChannel: OutputChannel
    ): void;
}