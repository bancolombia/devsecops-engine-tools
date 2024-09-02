import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "./interfaces/IIacScanUseCase";
import { IacScanner } from "../../infraestructure/drivenAdapter/IacScanner";
import { IRestClientGateway } from "../model/gateways/IRestClientGateway";
import { VARIABLE_GROUPS_AD_BY_NAME } from "../../application/appService/Constants";
import { AuthEncoder } from "../../infraestructure/helper/AuthEncoder";

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
        this.iacScanner.iacScan(folderToScan, outputChannel);
    }

}