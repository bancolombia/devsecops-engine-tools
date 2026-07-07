import * as vscode from 'vscode';
import { findingDetailWebview } from './FindingDetail';
import { Finding } from "../../../domain/model/Finding";
import { AiMetricsService } from '../../../infrastructure/services/AiMetricsService';

let vulnPanels: Map<string, vscode.WebviewPanel> = new Map();

export function showVulnContextWebview(finding: Finding, sourceType?: string, allFindings: Finding[] = []): void {
    const panelId = `vulnContext-${finding.getId()}-${new Date().getTime()}`;

    if (vulnPanels.has(panelId)) {
        const existingPanel = vulnPanels.get(panelId);
        existingPanel?.reveal(vscode.ViewColumn.Beside);
    } else {
        // Determine icon based on severity to match tree view
        const severity = (finding.getSeverity() || "unknown").toLowerCase();
        let icon: vscode.ThemeIcon;
        
        switch (severity) {
            case "critical":
                icon = new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
                break;
            case "high":
                icon = new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground"));
                break;
            case "medium":
                icon = new vscode.ThemeIcon("info", new vscode.ThemeColor("editorWarning.foreground"));
                break;
            case "low":
                icon = new vscode.ThemeIcon("circle-outline", new vscode.ThemeColor("terminal.ansiGreen"));
                break;
            default:
                icon = new vscode.ThemeIcon("shield", new vscode.ThemeColor("foreground"));
        }

        const vulnPanel = vscode.window.createWebviewPanel(
            'vulnContext',
            `Finding: ${finding.getId()}`,
            vscode.ViewColumn.Beside,
            { enableScripts: true, retainContextWhenHidden: true }
        );

        // Set the icon for the webview panel tab
        vulnPanel.iconPath = icon;

        // Determine sourceType from finding module if not provided
        const actualSourceType = sourceType || getSourceTypeFromModule(finding.getModule());
        vulnPanel.webview.html = findingDetailWebview(finding, actualSourceType, allFindings);

        // Setup message handler for Copilot buttons
        setupMessageHandler(vulnPanel, finding, allFindings);

        vulnPanel.onDidDispose(() => {
            vulnPanels.delete(panelId);
        });

        vulnPanels.set(panelId, vulnPanel);
    }
}

function getSourceTypeFromModule(module: string): string {
    switch (module) {
        case 'engine_iac':
            return 'iac';
        case 'engine_container':
        case 'engine_image':
            return 'image';
        case 'engine_dependencies':
            return 'dependencies';
        case 'engine_secrets':
            return 'secrets';
        default:
            return 'unknown';
    }
}

function setupMessageHandler(panel: vscode.WebviewPanel, finding: Finding, allFindings: Finding[] = []): void {
    // Handle messages from the webview
    panel.webview.onDidReceiveMessage(
        async (message) => {
            switch (message.command) {
                case 'fixWithCopilot':
                    AiMetricsService.track('fix_with_copilot', finding, 'webview');
                    await vscode.commands.executeCommand('devsecops.fixVulnerabilityWithCopilot', {
                        finding: finding,
                        sourceType: message.sourceType
                    });
                    break;
                case 'explainWithCopilot':
                    AiMetricsService.track('explain_with_copilot', finding, 'webview');
                    await vscode.commands.executeCommand('devsecops.explainVulnerabilityWithCopilot', {
                        finding: finding,
                        sourceType: message.sourceType
                    });
                    break;
                case 'generateDependencyUpdate':
                    AiMetricsService.track('generate_dependency_update', finding, 'webview');
                    await vscode.commands.executeCommand('devsecops.generateDependencyUpdate', {
                        finding: finding,
                        allFindings: allFindings
                    });
                    break;
            }
        }
    );
}

// Generic alias for all practices
export const showGeneralFindingWebview = showVulnContextWebview;

export function disposeVulnPanel(): void {
    vulnPanels.forEach(panel => {
        panel.dispose();
    });
    vulnPanels.clear();
}

