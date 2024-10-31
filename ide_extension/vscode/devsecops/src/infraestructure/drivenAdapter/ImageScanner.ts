import { OutputChannel } from "vscode";
import OutputManager from "../helper/OutputManager";
import {exec} from 'child_process';

import IScannerGateway from "../../domain/model/gateways/IScannerGateway";

export class ImageScanner implements IScannerGateway{

    scan(elementToScan: string, outputChannel: OutputChannel): void {
        exec(`/usr/local/bin/docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v ~/dev/bancolombia/NU0429001_DevSecOps_Remote_Config:/app/custom_remote_config felipe/devsecops-engine-tools:10 devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_container --token_engine_container 3F9F5v15/Vsf7JOwg1Y9Vz3OeWg= --image_to_scan ${elementToScan}`, (error, stdout, stderr) => {
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