import { OutputChannel } from "vscode";
import IScannerGateway from "../../domain/model/gateways/IScannerGateway";
import {exec} from 'child_process';
import OutputManager from "../helper/OutputManager";

export class Scanner implements IScannerGateway{

    iacScan(folderToScan: string, outputChannel: OutputChannel): void {
        exec(`docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v ${folderToScan}:/ms_artifact devsecops_docker_36  devsecops-engine-tools --platform_devops local --remote_config_repo example_remote_config_local --tool engine_iac --folder_path /ms_artifact`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                return;
            }
            // Muestra el resultado en el canal de salida
			const cleanedOutput = OutputManager.removeAnsiEscapeCodes(stdout);
            outputChannel.appendLine('IaC Scan Output:');
            outputChannel.appendLine(cleanedOutput);
            outputChannel.show();
        });
    }
    
}