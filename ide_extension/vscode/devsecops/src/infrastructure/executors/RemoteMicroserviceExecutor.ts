import * as vscode from "vscode";
import { OutputChannel } from "vscode";
import * as https from 'https';
import * as http from 'http';
import { URL } from 'url';
import { IScanExecutor, IScanExecutionConfig, IScanExecutionResult } from "./IScanExecutor";
import { ScanConfigurationService } from "../config/ScanConfigurationService";
import { ErrorHandlingService } from "../services/ErrorHandlingService";
import { ScanContextMapper } from "../mappers/ScanContextMapper";
import FileCompressionHelper from "../helper/FileCompressionHelper";
import ContainerEngineManager from "../helper/ContainerEngineManager";
import { UploadProgressTracker } from "../helper/UploadProgressTracker";
import * as fs from "fs";
import * as path from "path";

/**
 * RemoteMicroserviceExecutor - Remote scan execution via microservice
 * 
 * This executor sends scan requests to a remote microservice and receives
 * the scan context JSON in response. It compresses the target files/folders
 * and sends them as multipart/form-data.
 */
export class RemoteMicroserviceExecutor implements IScanExecutor {
    private microserviceUrl: string;
    private readonly MAX_RETRIES = 5;
    private readonly INITIAL_DELAY_MS = 3000;

    constructor(microserviceUrl?: string) {
        this.microserviceUrl = microserviceUrl || ScanConfigurationService.getMicroserviceUrl() || '';
    }

    getExecutionMode(): 'local-docker' | 'remote-microservice' {
        return 'remote-microservice';
    }

    canExecute(): Promise<boolean> {
        // Validate configuration
        const validation = ScanConfigurationService.validateMicroserviceConfig();
        if (!validation.valid) {
            console.error(`Microservice validation failed: ${validation.error}`);
            return Promise.resolve(false);
        }

        return Promise.resolve(true);
    }

    async execute(
        scanConfig: IScanExecutionConfig,
        outputChannel: OutputChannel,
        logCapture?: (message: string) => void
    ): Promise<IScanExecutionResult> {
        const startTime = Date.now();
        let compressedFilePath: string | undefined;

        try {
            outputChannel.appendLine(`🌐 Starting remote scan via microservice...`);
            outputChannel.appendLine(`Target: ${scanConfig.target}`);
            outputChannel.appendLine(`Scan type: ${scanConfig.scanType}`);
            outputChannel.appendLine('');

            if (logCapture) {
                logCapture('Starting remote microservice scan');
            }

            // Step 1: Prepare the file to send
            outputChannel.appendLine('📦 Preparing file for upload...');
            const fileResult = await this.prepareFileForUpload(scanConfig, outputChannel);
            
            if (!fileResult.success || !fileResult.filePath) {
                throw new Error(fileResult.error || 'Failed to prepare file for upload');
            }

            compressedFilePath = fileResult.filePath;
            const fileSize = FileCompressionHelper.getFileSize(compressedFilePath);
            outputChannel.appendLine(`✓ File prepared: ${FileCompressionHelper.formatFileSize(fileSize)}`);
            outputChannel.appendLine('');

            if (logCapture) {
                logCapture(`File prepared for upload: ${FileCompressionHelper.formatFileSize(fileSize)}`);
            }

            // Start measuring from here: excludes file preparation (compression/export)
            const scanStartTime = Date.now();

            // Step 2: Build configuration JSON
            const configJson = this.buildConfigJson(scanConfig);
            outputChannel.appendLine('⚙️ Configuration prepared');
            outputChannel.appendLine('');

            if (logCapture) {
                logCapture('Configuration prepared for remote scan');
            }

            // Step 3: Send request to microservice
            outputChannel.appendLine('🚀 Uploading to microservice...');
            const practice = this.getPracticeFromScanType(scanConfig.scanType);

            if (logCapture) {
                logCapture(`Uploading to microservice (practice: ${practice})`);
            }
            
            // Show native VS Code progress for large files (≥1MB)
            const showProgress = UploadProgressTracker.shouldShowProgress(fileSize);
            
            let response: any;
            
            if (showProgress) {
                // Use VS Code native progress API for large files
                response = await vscode.window.withProgress(
                    {
                        location: vscode.ProgressLocation.Notification,
                        title: "Uploading to DevSecOps Microservice",
                        cancellable: false
                    },
                    async (progress) => {
                        return await this.executeWithRetry(
                            practice,
                            configJson,
                            compressedFilePath!, // Safe because we checked earlier
                            outputChannel,
                            progress
                        );
                    }
                );
            } else {
                // No progress indicator for small files
                response = await this.executeWithRetry(
                    practice,
                    configJson,
                    compressedFilePath!, // Safe because we checked earlier
                    outputChannel
                );
            }

            outputChannel.appendLine('✓ Upload completed');
            outputChannel.appendLine('');

            if (logCapture) {
                logCapture('Upload completed successfully');
            }

            // Step 4: Parse response
            outputChannel.appendLine('📥 Processing response...');

            if (logCapture) {
                logCapture('Processing response from microservice');
            }
            const contextJson = await this.parseResponse(response, outputChannel);
            
            if (logCapture) {
                logCapture('Response parsed successfully');
            }
            
            const executionTime = Date.now() - scanStartTime;

            if (logCapture) {
                logCapture(`Remote scan completed in ${executionTime}ms`);
            }

            outputChannel.appendLine(`✓ Remote scan completed in ${(executionTime / 1000).toFixed(2)}s`);
            outputChannel.appendLine('');

            return {
                success: true,
                contextJson,
                executionMode: 'remote-microservice',
                executionTime
            };

        } catch (error) {
            const executionTime = Date.now() - startTime;
            const errorMessage = error instanceof Error ? error.message : String(error);
            
            outputChannel.appendLine(`❌ Remote scan failed: ${errorMessage}`);
            outputChannel.appendLine('');
            
            if (logCapture) {
                logCapture(`Remote scan error: ${errorMessage}`);
            }

            return {
                success: false,
                contextJson: '',
                executionMode: 'remote-microservice',
                executionTime,
                error: errorMessage
            };
        } finally {
            // Cleanup compressed file
            if (compressedFilePath) {
                FileCompressionHelper.cleanup(compressedFilePath);
            }
        }
    }

    /**
     * Prepare file for upload (compress if needed, or export image to tar)
     */
    private async prepareFileForUpload(
        scanConfig: IScanExecutionConfig,
        outputChannel: OutputChannel
    ): Promise<{ success: boolean; filePath?: string; error?: string }> {
        try {
            // For image scans, always export the image to tar
            // (target is always an image name from the local images list)
            if (scanConfig.scanType === 'image') {
                outputChannel.appendLine('Exporting container image to tar...');
                const tarPath = ContainerEngineManager.createTemporaryImagePath(scanConfig.target);
                const exported = await ContainerEngineManager.exportImageToTar(scanConfig.target, tarPath);
                
                if (!exported) {
                    return {
                        success: false,
                        error: `Failed to export image ${scanConfig.target}`
                    };
                }
                
                return {
                    success: true,
                    filePath: tarPath
                };
            }

            // For IaC and Dependencies scans, compress the folder/file to zip
            outputChannel.appendLine('Compressing files...');
            const compressionResult = await FileCompressionHelper.compressToZip(scanConfig.target);
            
            return compressionResult;
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            return {
                success: false,
                error: `File preparation failed: ${errorMessage}`
            };
        }
    }

    /**
     * Build configuration JSON string from scan config
     */
    private buildConfigJson(scanConfig: IScanExecutionConfig): string {
        const config: Record<string, string> = {
            '--platform_devops': 'azure',
            '--remote_config_source': 'azure',
            '--remote_config_repo': 'NU0429001_DevSecOps_Remote_Config'
        };

        // Add type-specific configurations
        switch (scanConfig.scanType) {
            case 'iac':
                if (scanConfig.iacTool) {
                    config['--tool'] = scanConfig.iacTool;
                    if (scanConfig.iacTool === 'kics') {
                        config['--platform'] = 'openapi';
                    }
                }
                config['--use_secrets_manager'] = 'true';
                break;

            case 'dependencies':
                if (scanConfig.dependenciesTool) {
                    config['--tool'] = scanConfig.dependenciesTool;
                }
                break;

            case 'image':
                config['--tool'] = 'trivy';
                break;
        }

        return JSON.stringify(config);
    }

    /**
     * Get practice name from scan type
     */
    private getPracticeFromScanType(scanType: string): string {
        const practiceMap: Record<string, string> = {
            'iac': 'engine_iac',
            'dependencies': 'engine_dependencies',
            'image': 'engine_container'
        };

        return practiceMap[scanType] || scanType;
    }

    /**
     * Clean invalid Unicode characters from string (e.g., � - U+FFFD)
     */
    private cleanInvalidCharacters(text: string): string {
        if (!text) return text;
        
        // Remove U+FFFD (replacement character �) and other common invalid characters
        return text
            .replace(/\uFFFD/g, '') // Remove replacement character
            .replace(/[\x00-\x08\x0B-\x0C\x0E-\x1F]/g, ''); // Remove control characters except \n, \r, \t
    }

    /**
     * Clean invalid characters from response object recursively
     */
    private cleanResponseObject(obj: any): any {
        if (typeof obj === 'string') {
            return this.cleanInvalidCharacters(obj);
        }
        
        if (Array.isArray(obj)) {
            return obj.map(item => this.cleanResponseObject(item));
        }
        
        if (obj && typeof obj === 'object') {
            const cleaned: any = {};
            for (const key in obj) {
                if (obj.hasOwnProperty(key)) {
                    cleaned[key] = this.cleanResponseObject(obj[key]);
                }
            }
            return cleaned;
        }
        
        return obj;
    }

    /**
     * Wraps sendScanRequest with exponential-backoff retry logic.
     * Retries only on transient microservice errors (5xx / upstream errors).
     * Does NOT retry on VPN/DNS or certificate errors.
     */
    private async executeWithRetry(
        practice: string,
        configJson: string,
        filePath: string,
        outputChannel: OutputChannel,
        progressReporter?: vscode.Progress<{ message?: string; increment?: number }>
    ): Promise<any> {
        let lastError: Error | undefined;

        for (let attempt = 1; attempt <= this.MAX_RETRIES; attempt++) {
            try {
                return await this.sendScanRequest(practice, configJson, filePath, outputChannel, progressReporter);
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                const isTransient =
                    ErrorHandlingService.isMicroserviceError(errorMessage) &&
                    !ErrorHandlingService.isVpnError(errorMessage) &&
                    !ErrorHandlingService.isSelfSignedCertificateError(errorMessage);

                if (!isTransient || attempt === this.MAX_RETRIES) {
                    throw error;
                }

                lastError = error instanceof Error ? error : new Error(errorMessage);
                const delay = this.INITIAL_DELAY_MS * Math.pow(2, attempt - 1) + Math.random() * 500;
                const retryReason = '⚠️ Microservice is experiencing high transaction load. Retrying the scan automatically';
                outputChannel.appendLine(
                    `${retryReason} (attempt ${attempt}/${this.MAX_RETRIES}) in ${(delay / 1000).toFixed(1)}s...`
                );
                outputChannel.appendLine('');

                if (progressReporter) {
                    progressReporter.report({ message: 'Microservice busy, retrying scan...' });
                }

                // Notify the user only once so we don't spam them on every retry attempt
                if (attempt === 1) {
                    void vscode.window.showWarningMessage(
                        '⚠️ The microservice is experiencing high transaction load. The scan is being retried automatically.'
                    );
                }

                await new Promise(res => setTimeout(res, delay));
            }
        }

        throw lastError!;
    }

    /**
     * Send multipart form-data request to microservice
     */
    private async sendScanRequest(
        practice: string,
        configJson: string,
        filePath: string,
        outputChannel: OutputChannel,
        progressReporter?: vscode.Progress<{ message?: string; increment?: number }>
    ): Promise<any> {
        const endpoint = this.microserviceUrl;
        const debugMode = ScanConfigurationService.getDebugMode();
        
        if (debugMode) {
            outputChannel.appendLine(`📤 REQUEST DETAILS:`);
            outputChannel.appendLine(`URL: ${endpoint}`);
            outputChannel.appendLine(`Method: POST`);
            outputChannel.appendLine('');
        }

        // Use form-data library
        const FormData = (await import('form-data')).default;
        const formData = new FormData();

        // Add form fields
        formData.append('practice', practice);
        formData.append('config', configJson);
        
        // Add file
        // Explicitly specify binary mode for cross-platform consistency (Windows/Linux)
        const fileStream = fs.createReadStream(filePath, {
            flags: 'r',           // Read-only mode
            autoClose: true,      // Auto-close on end or error
            highWaterMark: 64 * 1024  // 64KB buffer for consistent chunking
        });
        const fileName = path.basename(filePath);
        const fileStats = fs.statSync(filePath);
        const contentType = fileName.endsWith('.tar') ? 'application/x-tar' : 'application/zip';
        
        formData.append('file', fileStream, {
            filename: fileName,
            contentType: contentType
        });

        // Log request details
        const headers = formData.getHeaders();
        
        if (debugMode) {
            outputChannel.appendLine(`Headers:`);
            Object.keys(headers).forEach(key => {
                outputChannel.appendLine(`  ${key}: ${headers[key]}`);
            });
            outputChannel.appendLine('');
            
            outputChannel.appendLine(`Form Fields:`);
            outputChannel.appendLine(`  practice: ${practice}`);
            outputChannel.appendLine(`  config: ${configJson}`);
            outputChannel.appendLine(`  file:`);
            outputChannel.appendLine(`    - name: ${fileName}`);
            outputChannel.appendLine(`    - size: ${FileCompressionHelper.formatFileSize(fileStats.size)}`);
            outputChannel.appendLine(`    - type: ${contentType}`);
            outputChannel.appendLine('');
        }

        try {
            // Get configured timeout before sending request
            const scanTimeout = ScanConfigurationService.getScanTimeout();
            const timeoutSeconds = Math.floor(scanTimeout / 1000);
            
            // Get total size for progress tracking
            let totalSize = 0;
            try {
                // Try to get size synchronously from form-data
                if (typeof formData.getLengthSync === 'function') {
                    totalSize = formData.getLengthSync();
                } else {
                    // Fallback: use file size as approximation
                    totalSize = fileStats.size;
                }
            } catch {
                // If getLengthSync fails, use file size
                totalSize = fileStats.size;
            }
            
            // Show progress for large files (≥1MB)
            const showProgress = UploadProgressTracker.shouldShowProgress(totalSize);
            let progressTracker: UploadProgressTracker | undefined;
            
            if (showProgress) {
                progressTracker = new UploadProgressTracker(totalSize, outputChannel, progressReporter);
                progressTracker.start();
            }
            
            outputChannel.appendLine('🚀 Sending request...');
            outputChannel.appendLine(`⏱️ Request timeout: ${timeoutSeconds} seconds`);
            outputChannel.appendLine('');
            
            // Parse URL
            const parsedUrl = new URL(endpoint);
            const isHttps = parsedUrl.protocol === 'https:';
            const httpModule = isHttps ? https : http;

            // Send request using https/http with form-data
            const response: any = await new Promise((resolve, reject) => {
                const request = httpModule.request({
                    hostname: parsedUrl.hostname,
                    port: parsedUrl.port,
                    path: parsedUrl.pathname + parsedUrl.search,
                    method: 'POST',
                    headers: headers
                }, (response) => {
                    let data = '';
                    
                    response.on('data', (chunk) => {
                        data += chunk;
                    });
                    
                    response.on('end', () => {
                        // Clean invalid characters from response body
                        const cleanedData = this.cleanInvalidCharacters(data);
                        
                        if (progressTracker) {
                            progressTracker.complete();
                        }
                        
                        resolve({
                            ok: response.statusCode && response.statusCode >= 200 && response.statusCode < 300,
                            status: response.statusCode,
                            statusText: response.statusMessage,
                            headers: response.headers,
                            bodyText: cleanedData,
                            json: async () => JSON.parse(cleanedData),
                            text: async () => cleanedData
                        });
                    });
                });

                // Set timeout for the request
                request.setTimeout(scanTimeout, () => {
                    request.destroy();
                    reject(new Error(`Request timed out after ${timeoutSeconds} seconds`));
                });

                request.on('error', (error) => {
                    reject(error);
                });

                // Track upload progress if enabled
                if (progressTracker) {
                    let uploadedBytes = 0;
                    
                    // Intercept data being written to track progress
                    const originalWrite = request.write.bind(request);
                    request.write = function(chunk: any, encoding?: any, callback?: any): boolean {
                        const chunkSize = Buffer.isBuffer(chunk) ? chunk.length : Buffer.byteLength(chunk, encoding);
                        uploadedBytes += chunkSize;
                        progressTracker?.update(uploadedBytes);
                        
                        return originalWrite(chunk, encoding, callback);
                    };
                }

                // Pipe form data to request
                formData.pipe(request);
            });

            // Log response details
            const responseText = response.bodyText;
            
            if (debugMode) {
                outputChannel.appendLine('📥 RESPONSE DETAILS:');
                outputChannel.appendLine(`Status: ${response.status} ${response.statusText || ''}`);
                outputChannel.appendLine(`Success: ${response.ok ? '✓' : '✗'}`);
                
                if (response.headers) {
                    outputChannel.appendLine(`Headers:`);
                    Object.keys(response.headers).forEach(key => {
                        outputChannel.appendLine(`  ${key}: ${response.headers[key]}`);
                    });
                }
                
                outputChannel.appendLine(`Body length: ${responseText.length} bytes`);
                outputChannel.appendLine('');
            } else {
                // Always show basic status
                outputChannel.appendLine(`✅ Response received: ${response.ok ? 'Success' : 'Failed'}`);
                outputChannel.appendLine('');
            }
            
            // Try to parse and show structured response
            try {
                let jsonResponse = JSON.parse(responseText);
                
                // Clean invalid characters from the response
                jsonResponse = this.cleanResponseObject(jsonResponse);
                
                // Show full JSON for detailed inspection (debug mode only)
                if (debugMode) {
                    outputChannel.appendLine(`📄 Full Response Body (JSON):`);
                    outputChannel.appendLine(JSON.stringify(jsonResponse, null, 2));
                }
            } catch {
                if (debugMode) {
                    // If not JSON, show first 500 chars of raw text (cleaned)
                    const cleanedText = this.cleanInvalidCharacters(responseText);
                    outputChannel.appendLine(`Body (text):`);
                    outputChannel.appendLine(cleanedText.substring(0, 500) + (cleanedText.length > 500 ? '...' : ''));
                }
            }
            outputChannel.appendLine('');

            if (!response.ok) {
                // Show detailed error information
                outputChannel.appendLine('❌ HTTP ERROR DETAILS:');
                outputChannel.appendLine(`Status: ${response.status} ${response.statusText || ''}`);
                outputChannel.appendLine(`Response Body:`);
                
                // Try to format as JSON first
                try {
                    const errorJson = JSON.parse(responseText);
                    outputChannel.appendLine(JSON.stringify(errorJson, null, 2));
                } catch {
                    // Show as text if not JSON (limit to 1000 chars)
                    const truncated = responseText.length > 1000 ? responseText.substring(0, 1000) + '...' : responseText;
                    outputChannel.appendLine(truncated);
                }
                outputChannel.appendLine('');
                
                throw new Error(`HTTP ${response.status}: ${response.statusText || 'Request failed'}`);
            }

            return response;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Parse response from microservice and extract context JSON
     */
    private async parseResponse(response: any, outputChannel: OutputChannel): Promise<string> {
        try {
            const responseText = response.bodyText || await response.text();
            
            // Try to parse as JSON first
            try {
                const jsonResponse = JSON.parse(responseText) as Record<string, unknown>;
                
                // Check for microservice response structure: { output: { context: { iac_context: [...] } } }
                if (jsonResponse.output && typeof jsonResponse.output === 'object') {
                    const output = jsonResponse.output as Record<string, unknown>;
                    
                    // Log exit code for debugging
                    if (output.exit_code !== undefined) {
                        const exitCode = Number(output.exit_code);
                        outputChannel.appendLine(`Remote scan exit code: ${exitCode}`);
                        
                        // If exit code is not 0, show error details
                        if (exitCode !== 0) {
                            outputChannel.appendLine('');
                            outputChannel.appendLine('⚠️ SCAN EXECUTION ERROR:');
                            outputChannel.appendLine(`Exit code: ${exitCode} (non-zero indicates failure)`);
                            
                            // Show error logs if available
                            if (output.error) {
                                outputChannel.appendLine('Error message:');
                                outputChannel.appendLine(String(output.error));
                            }
                            
                            // Show stdout/stderr if available
                            if (output.stdout) {
                                outputChannel.appendLine('');
                                outputChannel.appendLine('Standard Output:');
                                outputChannel.appendLine(String(output.stdout));
                            }
                            
                            if (output.stderr) {
                                outputChannel.appendLine('');
                                outputChannel.appendLine('Standard Error:');
                                outputChannel.appendLine(String(output.stderr));
                            }
                            outputChannel.appendLine('');
                        }
                    }
                    
                    if (output.context) {
                        // Return the context object which contains iac_context, dependencies_context, etc.
                        outputChannel.appendLine('✓ Context extracted from output.context');
                        return JSON.stringify(output.context);
                    }
                    
                    outputChannel.appendLine('⚠️ Warning: output object found but context is missing');
                    outputChannel.appendLine('Available keys in output:');
                    outputChannel.appendLine(Object.keys(output).join(', '));
                    
                    // Show sample of output structure
                    outputChannel.appendLine('');
                    outputChannel.appendLine('Output structure preview:');
                    const preview = JSON.stringify(output, null, 2);
                    const truncated = preview.length > 500 ? preview.substring(0, 500) + '...' : preview;
                    outputChannel.appendLine(truncated);
                    outputChannel.appendLine('');
                }
                
                // Fallback: Check if response contains context data at root level
                if (jsonResponse.context || jsonResponse.iac_context || 
                    jsonResponse.dependencies_context || jsonResponse.container_context) {
                    outputChannel.appendLine('✓ Context extracted from root level');
                    return JSON.stringify(jsonResponse);
                }
                
                // Last resort: return the full response but log warning with details
                outputChannel.appendLine('⚠️ WARNING: Unexpected response structure');
                outputChannel.appendLine('Expected structure: { output: { context: {...} } }');
                outputChannel.appendLine('Available top-level keys:');
                outputChannel.appendLine(Object.keys(jsonResponse).join(', '));
                outputChannel.appendLine('');
                outputChannel.appendLine('Full response preview:');
                const fullPreview = JSON.stringify(jsonResponse, null, 2);
                const truncatedPreview = fullPreview.length > 1000 ? fullPreview.substring(0, 1000) + '...' : fullPreview;
                outputChannel.appendLine(truncatedPreview);
                outputChannel.appendLine('');
                
                return JSON.stringify(jsonResponse);
            } catch (parseError) {
                // Response might be plain text with JSON embedded
                // Use centralized extraction from ScanContextMapper
                outputChannel.appendLine('⚠️ Response is not valid JSON, attempting to extract context markers...');
                
                // Note: We don't know the scan type here, but the regex is type-agnostic
                // Just extract the raw JSON string and let the UseCase handle the mapping
                const contextRegex = /===== BEGIN CONTEXT OUTPUT =====\s*([\s\S]*?)\s*===== END CONTEXT OUTPUT =====/;
                const match = responseText.match(contextRegex);
                
                if (match && match[1]) {
                    outputChannel.appendLine('✓ Context extracted from text markers');
                    return match[1].trim();
                }
                
                // Could not parse response as JSON or extract context
                outputChannel.appendLine('❌ PARSE ERROR: Response is not valid JSON and does not contain context markers');
                outputChannel.appendLine(`Parse error: ${parseError instanceof Error ? parseError.message : String(parseError)}`);
                outputChannel.appendLine('');
                outputChannel.appendLine('Raw response (first 1000 characters):');
                const rawPreview = responseText.length > 1000 ? responseText.substring(0, 1000) + '...' : responseText;
                outputChannel.appendLine(rawPreview);
                outputChannel.appendLine('');
                
                // Return the full response if we can't extract context
                return responseText;
            }
        } catch (error) {
            const errorMessage = error instanceof Error ? error.message : String(error);
            throw new Error(`Failed to parse response: ${errorMessage}`);
        }
    }

    /**
     * Sets a custom microservice URL
     */
    public setMicroserviceUrl(url: string): void {
        this.microserviceUrl = url;
    }
}
