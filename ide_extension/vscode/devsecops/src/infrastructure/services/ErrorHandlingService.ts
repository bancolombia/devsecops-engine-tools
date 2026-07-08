import { OutputChannel } from "vscode";
import { DockerService } from './DockerService';

// Types and Interfaces
export interface ErrorContext {
    imageTag?: string;
    containerImageName?: string;
    toolVersion?: string;
}

type ErrorHandler = string | ((context: ErrorContext, outputChannel: OutputChannel) => void);

// Error Patterns
export const ERROR_PATTERNS = {
    docker: DockerService.getErrorPatterns(),
    network: [
        'context deadline exceeded',
        'i/o timeout',
        'connection refused',
        'no route to host',
        'no such host',
        'network is unreachable',
        'TLS handshake timeout',
        'dial tcp'
    ],
    configuration: [
        'no dependencies token provided',
        'invalid configuration',
        'unknown flag',
        'unknown shorthand flag',
        'invalid docker command'
    ],
    general: [
        'scan error',
        'engine_core error',
        'error executing container command',
        'failed to ensure scanner image',
        'container not found',
        'scan timed out',
        'command failed'
    ],
    microservice: [
        'HTTP 503',
        'HTTP 502',
        'HTTP 504',
        'Service Unavailable',
        'upstream connect error',
        'disconnect/reset before headers',
        'connection termination',
        'ENOTFOUND',
        'getaddrinfo'
    ],
    certificate: [
        'self signed certificate'
    ]
} as const;

export type ErrorCategory = keyof typeof ERROR_PATTERNS;

const NETWORK_ERROR_MESSAGES: Record<string, ErrorHandler> = {
    "context deadline exceeded": "🛜 VPN disconnected during download: Connection timeout detected. Please reconnect to VPN and try again.",
    "i/o timeout": "🌐 Network timeout: Unable to reach Docker registry. Please check your VPN connection and registry availability.",
    "connection refused": "🌐 Network connection refused: Unable to reach the registry. Verify VPN is active and properly configured.",
    "no route to host": "🌐 Network routing error: Cannot reach registry host. Check VPN connection and network configuration.",
    "no such host": "🌐 DNS lookup failed: Cannot resolve hostname. Ensure VPN is connected to access internal registry.",
    "network is unreachable": "🌐 Network unreachable: VPN may be inactive or disconnected. Please verify network connectivity.",
    "TLS handshake timeout": "🛜 VPN connection issue: TLS handshake timeout. Reconnect to VPN and retry.",
    "dial tcp": "🌐 Network connection error: Cannot establish connection to registry. Ensure VPN is active."
};

/**
 * ErrorHandlingService - Consolidated service for error handling and log analysis
 * Combines functionality from LogAnalysisService, NetworkErrorHandler, and ErrorPatterns
 */
export class ErrorHandlingService {
    
    // ===== Log Analysis Methods =====

    public static hasErrors(logs: string[]): boolean {
        if (!logs || logs.length === 0) {
            return false;
        }

        return logs.some(log => {
            const logLower = log.toLowerCase();
            return ERROR_PATTERNS.general.some(pattern => logLower.includes(pattern));
        });
    }

    public static extractExceptionMessage(
        logs: string[],
        findingsCount: number,
        providedMessage?: string
    ): string {
        if (providedMessage) {
            return providedMessage;
        }

        if (logs && logs.length > 0) {
            const foundMessage = logs.find(log =>
                log.includes('Found') && log.includes('issues in scan')
            );
            if (foundMessage) {
                return foundMessage;
            }

            const errorMessage = logs.find(log =>
                log.includes('Error') ||
                log.includes('Failed') ||
                log.includes('timeout')
            );
            if (errorMessage) {
                return errorMessage;
            }
        }

        return `Found ${findingsCount} issues in scan`;
    }

    public static getErrorMessages(logs: string[]): string[] {
        if (!logs || logs.length === 0) {
            return [];
        }

        return logs.filter(log =>
            log.includes('Error') ||
            log.includes('Failed') ||
            log.includes('timeout') ||
            log.includes('SCAN Error')
        );
    }

    public static indicatesSuccess(logs: string[]): boolean {
        if (!logs || logs.length === 0) {
            return false;
        }

        const successPatterns = [
            'Successfully extracted context data',
            '✔Succeeded',
            'PHASE: COMPLETED'
        ];

        return logs.some(log =>
            successPatterns.some(pattern => log.includes(pattern))
        );
    }

    public static hasDockerErrors(logs: string[]): boolean {
        return this.hasErrorCategory(logs, 'docker');
    }

    public static hasCriticalDockerErrors(logs: string[]): boolean {
        if (!logs || logs.length === 0) {
            return false;
        }

        const criticalDockerPatterns = [
            'Cannot connect to the Docker daemon',
            'Docker is not running',
            'docker: command not found',
            'error during connect'
        ];

        return logs.some(log => {
            const logLower = log.toLowerCase();
            return criticalDockerPatterns.some(pattern =>
                logLower.includes(pattern.toLowerCase())
            );
        });
    }

    public static hasNetworkErrors(logs: string[]): boolean {
        return this.hasErrorCategory(logs, 'network');
    }

    public static hasConfigurationErrors(logs: string[]): boolean {
        return this.hasErrorCategory(logs, 'configuration');
    }

    public static hasMicroserviceErrors(logs: string[]): boolean {
        return this.hasErrorCategory(logs, 'microservice');
    }

    public static hasCertificateErrors(logs: string[]): boolean {
        return this.hasErrorCategory(logs, 'certificate');
    }

    /**
     * Checks if a single error message string indicates microservice unavailability.
     * Used by scan commands to determine which user-facing message to show.
     */
    public static isVpnError(errorMessage: string): boolean {
        const lower = errorMessage.toLowerCase();
        return lower.includes('enotfound') || lower.includes('getaddrinfo');
    }

    public static isSelfSignedCertificateError(errorMessage: string): boolean {
        return errorMessage.toLowerCase().includes('self signed certificate');
    }

    public static isMicroserviceError(errorMessage: string): boolean {
        const lower = errorMessage.toLowerCase();
        return lower.includes('http 503') ||
            lower.includes('http 502') ||
            lower.includes('http 504') ||
            lower.includes('service unavailable') ||
            lower.includes('upstream connect error') ||
            lower.includes('connection termination');
    }

    private static hasErrorCategory(logs: string[], category: keyof typeof ERROR_PATTERNS): boolean {
        if (!logs || logs.length === 0) {
            return false;
        }

        return logs.some(log => {
            const logLower = log.toLowerCase();
            return ERROR_PATTERNS[category].some(pattern =>
                logLower.includes(pattern.toLowerCase())
            );
        });
    }

    // ===== Network Error Handler Methods =====

    private lastNetworkErrorKey: string | null = null;
    private lastNetworkErrorDetected: boolean = false;

    public static getNetworkErrorPatterns(): string[] {
        return Object.keys(NETWORK_ERROR_MESSAGES);
    }

    public hasNetworkError(): boolean {
        return this.lastNetworkErrorDetected;
    }

    // Alias for compatibility with existing code
    handle(errorMessage: string, outputChannel: OutputChannel, context: ErrorContext = {}, logCapture?: (message: string) => void): void {
        this.handleNetworkError(errorMessage, outputChannel, context, logCapture);
    }

    // Alias for compatibility with existing code
    reset(): void {
        this.resetNetworkError();
    }

    handleNetworkError(errorMessage: string, outputChannel: OutputChannel, context: ErrorContext = {}, logCapture?: (message: string) => void): void {
        const errorKey = this.findMatchingNetworkErrorKey(errorMessage);

        if (errorKey) {
            if (this.isDuplicateNetworkError(errorKey)) {
                return;
            }
            this.lastNetworkErrorKey = errorKey;
            this.lastNetworkErrorDetected = true;
            this.executeNetworkErrorHandler(errorKey, context, outputChannel, logCapture);
            return;
        }

        this.handleGenericNetworkError(errorMessage, context, outputChannel);
        this.lastNetworkErrorDetected = false;
    }

    resetNetworkError(): void {
        this.lastNetworkErrorKey = null;
        this.lastNetworkErrorDetected = false;
    }

    private findMatchingNetworkErrorKey(errorMessage: string): string | null {
        for (const key in NETWORK_ERROR_MESSAGES) {
            if (errorMessage.includes(key)) {
                return key;
            }
        }
        return null;
    }

    private isDuplicateNetworkError(errorKey: string): boolean {
        return this.lastNetworkErrorKey === errorKey;
    }

    private executeNetworkErrorHandler(errorKey: string, context: ErrorContext, outputChannel: OutputChannel, logCapture?: (message: string) => void): void {
        const handler = NETWORK_ERROR_MESSAGES[errorKey];
        if (typeof handler === "string") {
            outputChannel.appendLine(handler);
            if (logCapture) {
                logCapture(handler);
            }
        } else {
            handler(context, outputChannel);
        }
    }

    private handleGenericNetworkError(errorMessage: string, context: ErrorContext, outputChannel: OutputChannel): void {
        this.lastNetworkErrorKey = null;
        outputChannel.appendLine(`🌐 Network error: ${errorMessage}. Please check your VPN and internet connection.`);
    }
}
