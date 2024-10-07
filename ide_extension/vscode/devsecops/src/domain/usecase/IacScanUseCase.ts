import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "./interfaces/IIacScanUseCase";
import { IacScanner } from "../../infraestructure/drivenAdapter/IacScanner";
import { IRestClientGateway } from "../model/gateways/IRestClientGateway";
import { VARIABLE_GROUPS_AD_BY_RELEASE_DEFINITION_ID, VARIABLE_GROUPS_AD_BY_ID } from "../../application/appService/Constants";
import { AuthEncoder } from "../../infraestructure/helper/AuthEncoder";
import {promises as fs} from 'fs';
import * as path from 'path';

interface VariableData {
    value: string;
}

export class IacScanUseCase implements IIacScanUseCase {

    private files: string[] = [];

    constructor(
        private iacScanner: IacScanner,
        private restClient: IRestClientGateway
    ){}

    public async scan(folderToScan: string,
        organizationName: string,
        projectName: string,
        definitionId: string,
        adUserName: string,
        adPersonalAccessToken: string,
        environment: string,
        outputChannel: OutputChannel
    ): Promise<void> {

        const releaseIdData = await this.restClient.get(VARIABLE_GROUPS_AD_BY_RELEASE_DEFINITION_ID
            .replace("{organization}", organizationName)
            .replace("{project}", projectName)
            .replace("{definitionId}", definitionId),
            AuthEncoder.encode(adUserName, adPersonalAccessToken)
        );

        const variablesFromLibrary = releaseIdData.variables;

        const releaseEnvironments = releaseIdData.environments.map( (environment: { variableGroups: number[]; }) => {
            return environment.variableGroups;
        });

        releaseEnvironments.push(releaseIdData.variableGroups);

        const variableGroupsIds = [...new Set(releaseEnvironments.flat())];

        const variableGroupsData = await this.restClient.get(VARIABLE_GROUPS_AD_BY_ID
            .replace("{organization}", organizationName)
            .replace("{project}", projectName)
            .replace("{groupIds}", variableGroupsIds.join(",")),
            AuthEncoder.encode(adUserName, adPersonalAccessToken)
        );

        variableGroupsData.value.forEach((variableGroup: { variables: { [x: string]: VariableData; }; }) => {
            Object.keys(variableGroup.variables).forEach((variableName: string) => {
                variablesFromLibrary[variableName] = variableGroup.variables[variableName];
            });
        });

        this.files = await fs.readdir(folderToScan);
        const regex = /#{|}#/g;
        let replacedFile: string = "";

        let i = 0;
        while (this.files.length > 0) {
            const file = this.files[0];
            replacedFile = "";

            const filePath = path.join(folderToScan, file);
            const fileStats = await fs.stat(filePath);
            if (fileStats.isDirectory()) {
                this.files = this.files.filter((value) => value !== file);
                await this.scanSubFolder(filePath, folderToScan);
                continue;
            }
            const fileContent = await fs.readFile(filePath, 'utf-8');
            const lines = fileContent.split('\n');
            lines.forEach((line, _) => {
                if(regex.test(line)){
                    const variableName = line.split("#{")[1].split("}#")[0];
                    if(variablesFromLibrary[variableName]){
                        replacedFile = replacedFile + "\n" + line.replace(`#{${variableName}}#`, variablesFromLibrary[variableName].value);
                    }
                }else{
                    replacedFile = replacedFile + "\n" + line;
                }
            });
            console.log(replacedFile);
            const newFilePath = path.join(folderToScan, `modified_${file}`);
            await fs.writeFile(newFilePath, replacedFile, 'utf-8');
            this.files = this.files.filter((value) => value !== file);
            i++;
        }
        this.iacScanner.iacScan(folderToScan, outputChannel);
        await this.cleanFolder(folderToScan);

    }

    private async cleanFolder(folderToScan: string): Promise<void> {
        const files = await fs.readdir(folderToScan);
        for (const file of files) {
            if(file.startsWith("modified_")){
                const filePath = path.join(folderToScan, file);
                const fileStats = await fs.stat(filePath);
                if(fileStats.isFile()){
                    await fs.unlink(filePath);
                }
            }
        }
    }

    private async scanSubFolder(folderPath: string, folderToScan: string): Promise<void> {
        const subFolderFiles = await fs.readdir(folderPath);
        for (const subFile of subFolderFiles) {
            const subFilePath = path.join(folderPath, subFile);
            const subFileStats = await fs.stat(subFilePath);
            if (subFileStats.isFile()) {
                const newFilePath = path.join(folderToScan, subFile);
                await fs.copyFile(subFilePath, newFilePath);
                this.files.push(subFile);
            } else if (subFileStats.isDirectory()) {
                await this.scanSubFolder(subFilePath, folderToScan);
            }
        }
    };

}