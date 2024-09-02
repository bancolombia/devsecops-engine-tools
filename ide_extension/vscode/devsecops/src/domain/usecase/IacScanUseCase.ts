import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "./interfaces/IIacScanUseCase";
import { IacScanner } from "../../infraestructure/drivenAdapter/IacScanner";
import { IRestClientGateway } from "../model/gateways/IRestClientGateway";
import { VARIABLE_GROUPS_AD_BY_NAME } from "../../application/appService/Constants";
import { AuthEncoder } from "../../infraestructure/helper/AuthEncoder";
import {promises as fs} from 'fs';
import * as path from 'path';

interface VariableData {
    value: string;
}

export class IacScanUseCase implements IIacScanUseCase {

    constructor(
        private iacScanner: IacScanner,
        private restClient: IRestClientGateway
    ){}

    async scan(folderToScan: string,
        organizationName: string,
        projectName: string,
        groupName: string,
        adUserName: string,
        adPersonalAccessToken: string,
        outputChannel: OutputChannel
    ): Promise<void> {
        const variablesData = await this.restClient.get(VARIABLE_GROUPS_AD_BY_NAME
            .replace("{organization}", organizationName)
            .replace("{project}", projectName)
            .replace("{groupName}", groupName),
            AuthEncoder.encode(adUserName, adPersonalAccessToken)
        );
        console.log(variablesData);

        const variablesFromLibrary = variablesData.value[0].variables;

        const files = await fs.readdir(folderToScan);
        const regex = /#{|}#/g;
        let replacedFile: string = "";

        for (const file of files) {
            replacedFile = "";

            const filePath = path.join(folderToScan, file);
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
        }
        this.iacScanner.iacScan(folderToScan, outputChannel);
    }

}