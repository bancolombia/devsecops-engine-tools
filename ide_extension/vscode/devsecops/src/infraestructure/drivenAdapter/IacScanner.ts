import { OutputChannel } from "vscode";
import IScannerGateway from "../../domain/model/gateways/IScannerGateway";
import {exec} from 'child_process';
import OutputManager from "../helper/OutputManager";

export class IacScanner implements IScannerGateway{

    scan(elementToScan: string, outputChannel: OutputChannel): void {
        exec(`/usr/local/bin/docker run --rm -v ${elementToScan}:/ms_artifact felipe/devsecops-engine-tools:2  devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_iac --folder_path /ms_artifact`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                console.error(`stderr: ${stderr}`);
                return;
            }

            const cleanedOutput = OutputManager.removeAnsiEscapeCodes(stdout);
            outputChannel.appendLine('IAC SCAN OUTPUT:');
            outputChannel.appendLine(cleanedOutput);
            outputChannel.show();
        });
    }

}