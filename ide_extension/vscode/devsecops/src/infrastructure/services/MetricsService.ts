import * as https from 'https';
import { OutputChannel } from "vscode";
import { Finding } from "../../domain/model/Finding";
import { ISeverityCounts } from "../../domain/model/mappers/Mappers";
import { IMetricsData, IMetricsInput } from "../../domain/model/metrics/IMetricsData";
import { METRICS_DATA_UPLOAD_URL } from '../../application/appService/Constants';
import { ErrorHandlingService } from './ErrorHandlingService';
import { ScanConfigurationService } from '../config/ScanConfigurationService';

/**
 * MetricsService - Consolidated service for metrics collection, storage, and management
 * Combines functionality from MetricsCollectorService, MetricsStorageService, ScannerMetricsHelper,
 * ScanStatusService, and ToolIdentificationService
 */
export class MetricsService {
    private static readonly REQUEST_TIMEOUT = 30000;
    private outputLogs: string[] = [];

    private static readonly previousFindingsCounts = new Map<string, number>();

    // ===== Log Management Methods (from ScannerMetricsHelper) =====

    clearLogs(): void {
        this.outputLogs = [];
    }

    getLogs(): string[] {
        return [...this.outputLogs];
    }

    captureLog(outputChannel: OutputChannel, message: string): void {
        outputChannel.appendLine(message);
        this.outputLogs.push(message);
    }

    captureOnly(message: string): void {
        this.outputLogs.push(message);
    }

    captureError(outputChannel: OutputChannel, error: unknown, context: string): void {
        const errorMessage = `Error ${context}: ${error instanceof Error ? error.message : String(error)}`;
        this.captureLog(outputChannel, errorMessage);
    }

    captureExitCode(outputChannel: OutputChannel, exitCode: number): void {
        if (exitCode !== 0) {
            const exitMessage = `Container process exited with code ${exitCode}`;
            this.captureLog(outputChannel, exitMessage);
        }
    }

    // ===== Metrics Collection Methods (from MetricsCollectorService) =====

    public static collectMetrics(input: IMetricsInput): IMetricsData {
        const severityCounts = this.parseSeverityCounts(input.severityCounts);
        const hasLogErrors = ErrorHandlingService.hasErrors(input.output_logs);
        const scanStatus = this.determineScanStatus(
            input.scan_success,
            input.findings.length,
            hasLogErrors,
            input.output_logs
        );
        const exceptionLog = ErrorHandlingService.extractExceptionMessage(
            input.output_logs,
            input.findings.length,
            input.exception_message
        );
        const tool = this.determineToolName(
            input.findings,
            input.tool
        );

        const findingsDelta = this.calculateRemediationDelta(
            input.scan_component,
            tool,
            input.findings.length,
            input.scan_success
        );

        const metricsData: IMetricsData = {
            tool: tool,
            scan_component: input.scan_component,
            scan_date: new Date().toLocaleString(),
            findings_severity_very_critical: severityCounts.very_critical,
            findings_severity_critical: severityCounts.critical,
            findings_severity_high: severityCounts.high,
            findings_severity_medium_low: severityCounts.medium_low,
            findings_severity_unknown: severityCounts.unknown,
            total_findings: input.findings.length.toString(),
            exception_log: exceptionLog,
            scan_status: scanStatus,
            execution_mode: input.execution_mode,
            scan_duration_s: (input.scan_duration_ms / 1000).toFixed(2),
            ...(findingsDelta !== undefined && { findings_delta: findingsDelta })
        };

        return metricsData;
    }

    private static getComponentKey(scanComponent: string, tool: string): string {
        return `${scanComponent}|${tool}`;
    }

    private static getPreviousFindingsCount(key: string): number | undefined {
        return this.previousFindingsCounts.get(key);
    }

    private static setPreviousFindingsCount(key: string, value: number): void {
        this.previousFindingsCounts.set(key, value);
    }

    private static calculateRemediationDelta(
        scanComponent: string,
        tool: string,
        currentFindingsCount: number,
        scanSuccess: boolean
    ): string | undefined {
        const key = this.getComponentKey(scanComponent, tool);

        if (!scanSuccess) {
            return undefined;
        }

        const previousCount = this.getPreviousFindingsCount(key);
        this.setPreviousFindingsCount(key, currentFindingsCount);

        if (previousCount === undefined) {
            return undefined;
        }

        return (currentFindingsCount - previousCount).toString();
    }

    private static parseSeverityCounts(severityCounts: IMetricsInput['severityCounts']) {
        if (!severityCounts) {
            return { very_critical: "0", critical: "0", high: "0", medium_low: "0", unknown: "0" };
        }

        return {
            very_critical: severityCounts.very_critical || "0",
            critical: severityCounts.critical || "0",
            high: severityCounts.high || "0",
            medium_low: severityCounts.medium_low || "0",
            unknown: severityCounts.unknown || "0"
        };
    }

    /**
     * Determines scan status based on success, findings, and log errors
     * (consolidated from ScanStatusService)
     */
    private static determineScanStatus(
        scanSuccess: boolean,
        findingsCount: number,
        hasLogErrors: boolean,
        logs?: string[]
    ): IMetricsData['scan_status'] {
        if (hasLogErrors || !scanSuccess) {
            if (logs && logs.length > 0) {
                if (ErrorHandlingService.hasCriticalDockerErrors(logs)) {
                    return 'Error: Docker inactive';
                }
                if (ErrorHandlingService.hasNetworkErrors(logs)) {
                    return 'Error: VPN inactive';
                }
                if (ErrorHandlingService.hasDockerErrors(logs)) {
                    return 'Error: Docker inactive';
                }
                if (ErrorHandlingService.hasConfigurationErrors(logs)) {
                    return 'Error: Configuration issues';
                }
                if (ErrorHandlingService.hasMicroserviceErrors(logs)) {
                    return 'Error: Microservice unavailable';
                }
                if (ErrorHandlingService.hasCertificateErrors(logs)) {
                    return 'Error: SSL certificate';
                }
            }
            return 'Error: Unknown';
        }

        return findingsCount > 0
            ? 'Success with findings'
            : 'Success with no findings';
    }

    /**
     * Determines tool name from findings
     * (consolidated from ToolIdentificationService)
     */
    private static determineToolName(findings: any[], fallbackTool?: string): string {
        if (findings && findings.length > 0) {
            const firstFinding = findings[0];
            if (firstFinding && firstFinding.module) {
                return firstFinding.module;
            }
        }

        return fallbackTool || 'unknown';
    }

    // ===== Metrics Storage Methods (from MetricsStorageService) =====

    public static async storeMetricsData(metricsData: IMetricsData): Promise<void> {
        try {
            await this.uploadMetricsDataToServer(metricsData);
        } catch (error) {
            throw new Error(`Failed to upload metrics: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    private static async uploadMetricsDataToServer(metricsData: IMetricsData): Promise<void> {
        return new Promise((resolve, reject) => {
            const url = new URL(METRICS_DATA_UPLOAD_URL);
            const jsonPayload = JSON.stringify(metricsData);
            const debugMode = ScanConfigurationService.getDebugMode();

            if (debugMode) {
                console.log('[DevSecOps Metrics] POST', METRICS_DATA_UPLOAD_URL);
                console.log('[DevSecOps Metrics] Payload:', JSON.stringify(metricsData, null, 2));
            }

            const options = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname + url.search,
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(jsonPayload),
                    'User-Agent': 'DevSecOps-VSCode-Extension'
                },
                timeout: this.REQUEST_TIMEOUT
            };

            const request = https.request(options, (response) => {
                let responseData = '';

                response.on('data', (chunk) => {
                    responseData += chunk;
                });

                response.on('end', () => {
                    if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
                        if (debugMode) {
                            console.log(`[DevSecOps Metrics] Response: ${response.statusCode} OK`);
                        }
                        resolve();
                    } else {
                        if (debugMode) {
                            console.log(`[DevSecOps Metrics] Response: ${response.statusCode} ERROR - ${responseData}`);
                        }
                        const error = new Error(`Remote upload failed with status ${response.statusCode}: ${responseData}`);
                        reject(error);
                    }
                });
            });

            request.on('error', (error) => {
                reject(new Error(`Network error during remote upload: ${error.message}`));
            });

            request.on('timeout', () => {
                request.destroy();
                reject(new Error(`Remote upload timed out after ${this.REQUEST_TIMEOUT}ms`));
            });

            request.write(jsonPayload);
            request.end();
        });
    }

    // ===== Combined Collection and Storage Method =====

    async collectAndstoreMetricsData(
        elementToScan: string,
        findings: Finding[],
        severityCounts: ISeverityCounts | null,
        scanResult: boolean,
        scanType: "engine_iac" | "engine_container" | "engine_dependencies",
        executionMode: 'local-docker' | 'remote-microservice' = 'local-docker',
        scanDurationMs: number = 0
    ): Promise<void> {
        try {
            const metricsInput: IMetricsInput = {
                scan_component: elementToScan,
                findings: findings,
                severityCounts: severityCounts,
                scan_success: scanResult,
                output_logs: this.outputLogs,
                exception_message: `Found ${findings.length} issues in scan`,
                tool: scanType,
                execution_mode: executionMode,
                scan_duration_ms: scanDurationMs
            };

            const metricsData = MetricsService.collectMetrics(metricsInput);

            await MetricsService.storeMetricsData(metricsData);

        } catch (error) {
            const errorMessage = `Failed to collect metrics: ${error instanceof Error ? error.message : String(error)}`;
            this.outputLogs.push(errorMessage);
        }
    }

    // ===== Scanner Helper Methods =====

    /**
     * Handles errors from scanner execution
     */
    handleScanError(
        error: Error,
        stderr: string,
        containerImageName: string,
        toolVersion: string,
        outputChannel: OutputChannel,
        dockerErrorHandler: any,
        networkErrorHandler: any
    ): void {
        const errorContext = {
            imageTag: containerImageName,
            containerImageName,
            toolVersion
        };

        const logCapture = (message: string) => {
            this.captureOnly(message);
        };

        dockerErrorHandler.handle(error.message, outputChannel, errorContext, logCapture);

        if (stderr) {
            dockerErrorHandler.handle(stderr, outputChannel, errorContext, logCapture);
            networkErrorHandler.handle(stderr, outputChannel, errorContext, logCapture);
        }
    }

    /**
     * Collects metrics for a failed scan
     */
    async collectFailedScanMetrics(
        elementToScan: string,
        scanType: "engine_iac" | "engine_container" | "engine_dependencies",
        executionMode: 'local-docker' | 'remote-microservice' = 'local-docker',
        scanDurationMs: number = 0
    ): Promise<void> {
        await this.collectAndstoreMetricsData(
            elementToScan,
            [],
            null,
            false,
            scanType,
            executionMode,
            scanDurationMs
        );
    }

    /**
     * Calculates severity counts from scan context
     */
    static calculateRawSeverityCounts<T extends { severity?: string; priority?: string }>(contexts: T[]): ISeverityCounts {
        const counts = {
            very_critical: 0,
            critical: 0,
            high: 0,
            medium_low: 0,
            unknown: 0
        };

        contexts.forEach((context) => {
            const effective = (context.priority || context.severity)?.toLowerCase();

            if (effective === 'very critical') {
                counts.very_critical++;
            } else if (effective === 'critical') {
                counts.critical++;
            } else if (effective === 'high') {
                counts.high++;
            } else if (effective === 'medium low') {
                counts.medium_low++;
            } else {
                counts.unknown++;
            }
        });

        return {
            very_critical: counts.very_critical.toString(),
            critical: counts.critical.toString(),
            high: counts.high.toString(),
            medium_low: counts.medium_low.toString(),
            unknown: counts.unknown.toString()
        };
    }
}
