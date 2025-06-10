import { OutputChannel } from "vscode";
import IScannerGateway from "../../domain/model/gateways/IScannerGateway";
import OutputManager from "../helper/OutputManager";
import { ScannerRes } from "../../domain/model/ScannerRes";
import { Finding } from "../../domain/model/Finding";

import { exec } from "child_process";
import { IIacContextCheckov, Mappers } from "../../domain/model/mappers/Mappers";

export class IacScanner implements IScannerGateway {
  async scan(
    elementToScan: string,
    outputChannel: OutputChannel,
    dockerImageName: string,
    toolVersion: string,
    dockerPath: string
  ): Promise<ScannerRes> {
    outputChannel.clear();
    outputChannel.show();
    return new Promise((resolve, _reject) => {
      let scanResult: boolean = false;
      let findings: Finding[] = [];

      const timeout = setTimeout(() => {
        outputChannel.appendLine("Scan timed out after 2 minutes");
        outputChannel.appendLine(
          "Docker command may be hanging. Check Docker configuration."
        );
        resolve(new ScannerRes(false, []));
      }, 120000);

      const dockerCommand = `${dockerPath} run --rm -v ${elementToScan}:/ms_artifact ${dockerImageName}:1.59.0 devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --module engine_iac --tool checkov --folder_path /ms_artifact --context true`;

      const childProcess = exec(dockerCommand, (error, stdout, stderr) => {
        clearTimeout(timeout);
        if (error) {
          outputChannel.appendLine(
            `Error executing Docker command: ${error.message}`
          );
          if (stderr.includes("Unable to find image")) {
            outputChannel.appendLine(
              "Docker image not found. Attempting to download..."
            );
          } else {
            outputChannel.appendLine(`Standard Error: ${stderr}`);
            outputChannel.appendLine(
              "Attempting to process partial results..."
            );
          }
        }

        if (stdout) {
          let contextJson: { iac_context: IIacContextCheckov[] } | null = null;
          let normalOutput = stdout;

          const contextRegex =
            /===== BEGIN CONTEXT OUTPUT =====\s*([\s\S]*?)\s*===== END CONTEXT OUTPUT =====/;
          const match = stdout.match(contextRegex);

          if (match && match[1]) {
            try {
              contextJson = JSON.parse(match[1].trim()) as { iac_context: IIacContextCheckov[] };

              normalOutput = stdout.replace(contextRegex, "");

              findings = contextJson.iac_context.map(
                (finding: IIacContextCheckov) =>
                  Mappers.mapIacContextCheckovToFinding(finding)
              );

              scanResult = true;
              outputChannel.appendLine(
                `Successfully extracted context data with ${findings.length} findings`
              );
            } catch (jsonError: unknown) {
              let errorMsg = "Unknown error";
              if (jsonError instanceof Error) {
                errorMsg = jsonError.message;
              } else if (typeof jsonError === "string") {
                errorMsg = jsonError;
              }
              outputChannel.appendLine(
                `Error parsing context JSON: ${errorMsg}`
              );
              outputChannel.appendLine("Raw context data:");
              outputChannel.appendLine(match[1]);
            }
          } else {
            outputChannel.appendLine(
              "No context data found in scanner output. Using default context."
            );
            scanResult = false;
          }

          const cleanedOutput =
            OutputManager.removeAnsiEscapeCodes(normalOutput);
          outputChannel.appendLine("SCAN OUTPUT:");
          outputChannel.appendLine(cleanedOutput);
          outputChannel.appendLine(`Found ${findings.length} issues in scan`);
        } else {
          outputChannel.appendLine("Docker command completed with no output");
        }

        resolve(new ScannerRes(scanResult, findings));
      });

      childProcess.on("exit", (code) => {
        if (code !== 0 && code !== null) {
          outputChannel.appendLine(`Docker process exited with code ${code}`);
        }
      });
    });
  }
}
