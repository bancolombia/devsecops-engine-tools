
export interface IMetricsData {
    tool: string;
    scan_component: string;
    scan_date: string;
    findings_severity_very_critical: string;
    findings_severity_critical: string;
    findings_severity_high: string;
    findings_severity_medium_low: string;
    findings_severity_unknown: string;
    total_findings: string;
    exception_log: string;
    scan_status: 'Success with findings' | 'Success with no findings' | 'Error: Docker inactive' | 'Error: VPN inactive' | 'Error: Configuration issues' | 'Error: Microservice unavailable' | 'Error: SSL certificate' | 'Error: Unknown';
    execution_mode: 'local-docker' | 'remote-microservice';
    scan_duration_s: string;
    // Only present when a previous successful scan exists for the same component
    findings_delta?: string;
}

export interface IMetricsInput {
    tool?: string;
    scan_component: string;
    findings: any[];
    severityCounts: {
        very_critical: string;
        critical: string;
        high: string;
        medium_low: string;
        unknown: string;
    } | null;
    scan_success: boolean;
    output_logs: string[];
    exception_message?: string;
    execution_mode: 'local-docker' | 'remote-microservice';
    scan_duration_ms: number;
}
