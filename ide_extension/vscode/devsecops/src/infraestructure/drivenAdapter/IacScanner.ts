import { OutputChannel } from "vscode";
import IScannerGateway from "../../domain/model/gateways/IScannerGateway";
import {exec} from 'child_process';
import OutputManager from "../helper/OutputManager";

export class IacScanner implements IScannerGateway{

    scan(elementToScan: string, outputChannel: OutputChannel): void {
        // exec(`/usr/local/bin/docker run --rm -v ${elementToScan}:/ms_artifact devsecops-engine-tools:10  devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --module engine_iac --tool checkov --folder_path /ms_artifact`, (error, stdout, stderr) => {
           exec(`/usr/local/bin/docker run --rm \
                -v ${elementToScan}:/ms_artifact \
                -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
                -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
                -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
                -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
                bancolombia/devsecops-engine-tools:1.51.1 \
                devsecops-engine-tools --platform_devops local \
                --remote_config_repo docker_default_remote_config \
                -m engine_iac --tool checkov \
                --use_secrets_manager false --use_vulnerability_management false --send_metrics false \
                --folder_path /ms_artifact`,
            (error, stdout, stderr) => {
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