import { OutputChannel } from "vscode";
import { IIacScanUseCase } from "./interfaces/IIacScanUseCase";
import { IacScanner } from "../../infraestructure/drivenAdapter/IacScanner";
import { IRestClientGateway } from "../model/gateways/IRestClientGateway";
import {
  VARIABLE_GROUPS_AD_BY_RELEASE_DEFINITION_ID,
  VARIABLE_GROUPS_AD_BY_ID,
} from "../../application/appService/Constants";
import { AuthEncoder } from "../../infraestructure/helper/AuthEncoder";
import { promises as fs } from "fs";
import * as path from "path";
import { ScannerRes } from "../model/ScannerRes";
import { ScanConfiguration } from "../model/ScanConfiguration";

interface IVariableData {
  value: string;
}

interface IReleaseIdData {
  variables: { [key: string]: IVariableData };
  environments: { variableGroups: number[] }[];
}

interface IVariableGroupData {
  value: { variables: { [key: string]: IVariableData } }[];
}

export class IacScanUseCase implements IIacScanUseCase {
  private files: string[] = [];

  constructor(
    private iacScanner: IacScanner,
    private restClient: IRestClientGateway,
    private toolVersion: string,
    private dockerPath: string
  ) { }

  public async scan(
    folderToScan: string,
    outputChannel: OutputChannel,
    scanConfiguration: ScanConfiguration
  ): Promise<ScannerRes> {
    let releaseIdData: IReleaseIdData;
    let variablesFromLibrary: { [key: string]: IVariableData } = {};
    let releaseEnvironments: number[] = [];
    let variableGroupsIds: number[] = [];
    let variableGroupsData: IVariableGroupData;
    let variableReplace: boolean = false;

    if (
      !scanConfiguration.isValidAdReplace()
    ) {
      outputChannel.append("Configuration values are missing≤ avoiding variable replace");
    } else {
      variableReplace = true;
      releaseIdData = await this.restClient.get(
        VARIABLE_GROUPS_AD_BY_RELEASE_DEFINITION_ID.replace(
          "{organization}",
          scanConfiguration.getOrganizationName()
        )
          .replace("{project}", scanConfiguration.getProjectName())
          .replace("{definitionId}", scanConfiguration.getDefinitionId()),
        AuthEncoder.encode(scanConfiguration.getAdUserName(), scanConfiguration.getAdPersonalAccessToken())
      ) as IReleaseIdData;
      variablesFromLibrary = releaseIdData.variables;
      releaseEnvironments = releaseIdData.environments
        .map((environment: { variableGroups: number[] }) => environment.variableGroups)
        .flat();
      variableGroupsIds = [...new Set(releaseEnvironments)];
      variableGroupsData = await this.restClient.get(
        VARIABLE_GROUPS_AD_BY_ID.replace("{organization}", scanConfiguration.getOrganizationName())
          .replace("{project}", scanConfiguration.getProjectName())
          .replace("{groupIds}", variableGroupsIds.join(",")),
        AuthEncoder.encode(scanConfiguration.getAdUserName(), scanConfiguration.getAdPersonalAccessToken())
      ) as IVariableGroupData;
      variableGroupsData.value.forEach(
        (variableGroup: { variables: { [x: string]: IVariableData } }) => {
          Object.keys(variableGroup.variables).forEach(
            (variableName: string) => {
              variablesFromLibrary[variableName] =
                variableGroup.variables[variableName];
            }
          );
        }
      );
    }

    this.files = await fs.readdir(folderToScan);
    const regex = /#{|}#/g;
    let replacedFile: string = "";

    while (this.files.length > 0) {
      const file = this.files[0];
      replacedFile = "";

      const filePath = path.join(folderToScan, file);
      const fileStats = await fs.stat(filePath);
      if (fileStats.isDirectory()) {
        continue;
      }
      const fileContent = await fs.readFile(filePath, "utf-8");
      const lines = fileContent.split("\n");
      lines.forEach((line, _) => {
        if (regex.test(line)) {
          const variableName = line.split("#{")[1].split("}#")[0];
          if (variablesFromLibrary[variableName] && variableReplace) {
            replacedFile =
              replacedFile +
              "\n" +
              line.replace(
                `#{${variableName}}#`,
                variablesFromLibrary[variableName].value
              );
          }
        } else {
          replacedFile = replacedFile + "\n" + line;
        }
      });
      const newFilePath = path.join(folderToScan, `modified_${file}`);
      await fs.writeFile(newFilePath, replacedFile, "utf-8");
      this.files = this.files.filter((value) => value !== file);
    }

    await this.cleanFolder(folderToScan);
    return await this.iacScanner.scan(
      folderToScan,
      outputChannel,
      scanConfiguration.getDockerImageName(),
      this.toolVersion,
      this.dockerPath
    );

  }

  private async cleanFolder(folderToScan: string): Promise<void> {
    const files = await fs.readdir(folderToScan);
    for (const file of files) {
      if (file.startsWith("modified_")) {
        const filePath = path.join(folderToScan, file);
        const fileStats = await fs.stat(filePath);
        if (fileStats.isFile()) {
          await fs.unlink(filePath);
        }
      }
    }
  }

}
