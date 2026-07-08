import { Finding } from "../../../domain/model/Finding";

export function findingDetailWebview(finding: Finding, sourceType?: string, allFindings: Finding[] = []): string {
    const severity = (finding.getSeverity() || "unknown").toLowerCase();
    let codicon = "codicon-warning";
    let color = "#cca700";

    switch (severity) {
        case "critical":
            codicon = "codicon-error";
            color = "#e51400";
            break;
        case "high":
            codicon = "codicon-warning";
            color = "#ff8c00";
            break;
        case "medium":
            codicon = "codicon-info";
            color = "#cca700";
            break;
        case "low":
            codicon = "codicon-circle-outline";
            color = "#16a34a";
            break;
        default:
            codicon = "codicon-shield";
            color = "#858585";
    }

    function scanInfoRow(label: string, value: string | undefined): string {
        return `<div class="scan-row"><span class="scan-label">${label}:</span> <span class="scan-value">${value || "-"}</span></div>`;
    }

    // Generate Copilot buttons based on source type
    function generateCopilotButtons(): string {
        let buttons = `
            <div class="copilot-actions">
                <h3>🤖 AI Assistant Actions</h3>
                <div class="button-group">
                    <button class="copilot-button fix-button" onclick="fixWithCopilot()">
                        <span class="codicon codicon-lightbulb"></span>
                        Fix with Copilot
                    </button>
                    <button class="copilot-button explain-button" onclick="explainWithCopilot()">
                        <span class="codicon codicon-info"></span>
                        Explain Vulnerability
                    </button>`;
        
        if (sourceType === 'dependencies') {
            const dependencyFindingsCount = Math.max(
                allFindings.filter(f => f.getModule() === "engine_dependencies").length,
                1
            );
            buttons += `
                    <button class="copilot-button update-button" onclick="generateDependencyUpdate()" title="Generates one consolidated solution to fix all ${dependencyFindingsCount} dependency vulnerabilities found in this scan">
                        <span class="codicon codicon-package"></span>
                        Generate Update Solution
                    </button>`;
        }
        
        if (sourceType === 'image') {
            const imageFindingsCount = Math.max(
                allFindings.filter(f => f.getModule() === "engine_container" || f.getModule() === "engine_image").length,
                1
            );
            buttons += `
                    <button class="copilot-button update-button" onclick="generateImageUpdate()" title="Generates one consolidated solution to fix all ${imageFindingsCount} image vulnerabilities found in this scan">
                        <span class="codicon codicon-package"></span>
                        Generate Update Solution
                    </button>`;
        }
        
        buttons += `
                </div>
            </div>`;
        
        return buttons;
    }


    return  `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link href="https://microsoft.github.io/vscode-codicons/dist/codicon.css" rel="stylesheet" />
    <style>
        /* Global Styles - Unified Design System */
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
            padding: 1.5em; 
            background: var(--vscode-editor-background);
            color: var(--vscode-editor-foreground);
            line-height: 1.6;
        }
        
        /* Title Bar - Unified Header */
        .title-bar {
            display: flex;
            align-items: center;
            font-size: 1.4em;
            margin-bottom: 1em;
            padding: 1em;
            border-radius: 12px;
            border: 2px solid var(--vscode-panel-border);
        }
        .vuln-icon {
            font-size: 1.8em; 
            color: ${color};
            margin-right: 0.8em;
            filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.3));
        } 
        
        /* Tabs - Unified Navigation */
        .tabs {
            display: flex;
            margin-bottom: 1.5em;
            background: var(--vscode-editor-background);
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            border: 2px solid var(--vscode-panel-border);
        }
        .tab {
            flex: 1;
            padding: 1em 1.5em;
            cursor: pointer;
            border: none;
            background: var(--vscode-button-secondaryBackground);
            font-size: 0.95em;
            font-weight: 500;
            outline: none;
            color: var(--vscode-button-secondaryForeground);
            transition: all 0.3s ease;
            position: relative;
        }
        .tab:hover {
            background: #ffffff;
            color: #333333;
            transform: translateY(-1px);
        }
        .tab.selected {
            background: #007acc;
            color: #ffffff;
            font-weight: 600;
            box-shadow: inset 0 -3px 0 #005a9e;
        }
        
        /* Content Sections - Unified Cards */
        .section {
            display: none;
            background: var(--vscode-editor-background);
            border: 2px solid var(--vscode-panel-border);
            border-radius: 12px;
            padding: 1.5em;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            margin-bottom: 1em;
        }
        .section.active {
            display: block;
        }
        .section h3 {
            margin-top: 0;
            margin-bottom: 1em;
            color: #007acc;
            font-size: 1.2em;
            font-weight: 600;
            border-bottom: 2px solid #007acc;
            padding-bottom: 0.5em;
        }
        
        /* Scan Rows - Unified Info Display */
        .scan-row {
            margin: 0.8em 0;
            padding: 0.6em;
            background: var(--vscode-input-background);
            border-radius: 6px;
            border-left: 4px solid #007acc;
        }
        .scan-label {
            font-weight: 600;
            color: #007acc;
            min-width: 160px;
            display: inline-block;
        }
        .scan-value {
            color: var(--vscode-editor-foreground);
            font-family: var(--vscode-editor-font-family);
        }
        
        /* Copilot Actions - Unified Container */
        .copilot-actions {
            margin: 2em 0;
            padding: 1.5em;
            background: linear-gradient(135deg, var(--vscode-inputValidation-infoBackground), var(--vscode-button-secondaryBackground));
            border: 2px solid var(--vscode-inputValidation-infoBorder);
            border-radius: 12px;
            box-shadow: 0 6px 16px rgba(0, 0, 0, 0.15);
        }
        .copilot-actions h3 {
            margin-top: 0;
            margin-bottom: 1em;
            color: #007acc;
            font-size: 1.3em;
            font-weight: 600;
            text-align: center;
            border-bottom: 2px solid #007acc;
            padding-bottom: 0.5em;
        }
        .button-group {
            display: flex;
            gap: 1em;
            flex-wrap: wrap;
            justify-content: center;
        }
        
        /* Copilot Buttons - Enhanced Unified Design */
        .copilot-button {
            display: flex;
            align-items: center;
            gap: 0.6em;
            padding: 0.8em 1.4em;
            border: 2px solid transparent;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.95em;
            font-weight: 600;
            transition: all 0.3s ease;
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.15);
            text-decoration: none;
            min-width: 180px;
            justify-content: center;
        }
        .copilot-button:hover {
            background: #ffffff !important;
            color: #333333 !important;
            transform: translateY(-3px);
            box-shadow: 0 8px 16px rgba(0, 0, 0, 0.25);
            border-color: #cccccc;
        }
        .copilot-button .codicon {
            font-size: 1.2em;
        }
        .fix-button {
            background: linear-gradient(135deg, #007acc, #005a9e);
            color: #ffffff;
            border-color: #005a9e;
        }
        .explain-button {
            background: linear-gradient(135deg, #8a2be2, #6a1b9a);
            color: #ffffff;
            border-color: #6a1b9a;
        }
        .update-button {
            background: linear-gradient(135deg, #ff8c00, #e67300);
            color: #ffffff;
            border-color: #e67300;
        }
        
        /* Links - Unified Style */
        a {
            color: #007acc;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.2s ease;
        }
        a:hover {
            color: #005a9e;
            text-decoration: underline;
        }
        
        /* Lists - Unified Style */
        ul {
            padding-left: 1.5em;
        }
        li {
            margin: 0.5em 0;
            color: var(--vscode-editor-foreground);
        }
    </style>
</head>
<body>
    <div class="title-bar">
        <span class="codicon ${codicon} vuln-icon"></span>
        <span>${finding.getId() || "Unknown Vulnerability"}</span>
    </div>
    <div class="tabs">
        <button class="tab selected" id="descTab">Description</button>
        <button class="tab" id="scanTab">Scan Info</button>
        <button class="tab" id="remTab">Remediation Info</button>
    </div>
    
    ${generateCopilotButtons()}
    
    <div class="section active" id="descSection">
        <h3>Description</h3>
        <p>${finding.getDescription() || "No description available."}</p>
    </div>
    <div class="section" id="scanSection">
        <h3>Scan Info</h3>
        ${scanInfoRow("Severity", finding.getSeverity())}
        ${scanInfoRow("Priority", finding.getPriority())}
        ${scanInfoRow("Where", finding.getWhere())}
        ${scanInfoRow("Module", finding.getModule())}
        ${scanInfoRow("Tool", finding.getTool())}
        ${
            finding.getAllAdditionalFields() && Object.keys(finding.getAllAdditionalFields()).length > 0
            ? `${Object.entries(finding.getAllAdditionalFields() || {})
                .filter(([key]) => !key.endsWith('_prompt'))
                .map(([key, value]) => scanInfoRow(key, value)).join("")}`
            : "<p>No additional fields available.</p>"
        }
    </div>
    <div class="section" id="remSection">
        <h3>References</h3>
        ${
            finding.getReferences() && finding.getReferences().length > 0
                ? `<ul>${finding.getReferences().map((ref: string) => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join("")}</ul>`
                : "<p>No remediation info available.</p>"
        }
 
    </div>
    <script>
        const descTab = document.getElementById('descTab');
        const scanTab = document.getElementById('scanTab');
        const remTab = document.getElementById('remTab');
        const descSection = document.getElementById('descSection');
        const scanSection = document.getElementById('scanSection');
        const remSection = document.getElementById('remSection');
        function selectTab(tab, section) {
            [descTab, scanTab, remTab].forEach(t => t.classList.remove('selected'));
            [descSection, scanSection, remSection].forEach(s => s.classList.remove('active'));
            tab.classList.add('selected');
            section.classList.add('active');
        }
        descTab.onclick = () => selectTab(descTab, descSection);
        scanTab.onclick = () => selectTab(scanTab, scanSection);
        remTab.onclick = () => selectTab(remTab, remSection);
        
        // Initialize VS Code API
        const vscode = acquireVsCodeApi();
        
        // Copilot button functions - make them global so onclick can find them
        window.fixWithCopilot = function() {
            vscode.postMessage({
                command: 'fixWithCopilot',
                sourceType: '${sourceType || 'unknown'}'
            });
        }
        
        window.explainWithCopilot = function() {
            vscode.postMessage({
                command: 'explainWithCopilot',
                sourceType: '${sourceType || 'unknown'}'
            });
        }
        
        window.generateDependencyUpdate = function() {
            vscode.postMessage({
                command: 'generateDependencyUpdate'
            });
        }

        window.generateImageUpdate = function() {
            vscode.postMessage({
                command: 'generateImageUpdate'
            });
        }
    </script>
</body>
</html>
    `;
}