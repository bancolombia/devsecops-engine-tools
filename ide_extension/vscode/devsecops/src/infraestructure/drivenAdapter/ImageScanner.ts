import { OutputChannel } from "vscode";
import OutputManager from "../helper/OutputManager";
import {exec} from 'child_process';

import IScannerGateway from "../../domain/model/gateways/IScannerGateway";

export class ImageScanner implements IScannerGateway{

    scan(elementToScan: string, outputChannel: OutputChannel): void {
        exec(`/usr/local/bin/docker run --rm -v /var/run/docker.sock:/var/run/docker.sock devsecops-engine-tools:10 devsecops-engine-tools --platform_devops local --remote_config_source local --remote_config_repo docker_default_remote_config --module engine_container --tool trivy --image_to_scan ${elementToScan}`, (error, stdout, stderr) => {
            if (error) {
                console.error(`exec error: ${error}`);
                console.error(`stderr: ${stderr}`);
                return;
            }

            const cleanedOutput = OutputManager.removeAnsiEscapeCodes(stdout);
            outputChannel.appendLine('IMAGE SCAN OUTPUT:');
            outputChannel.appendLine(cleanedOutput);
            outputChannel.show();
        });
    }

}