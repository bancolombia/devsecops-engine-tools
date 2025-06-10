export interface IContextInfo {
    severity?: string;
    id?: string;
    description?: string;
    vulnerabilityStatus?: string;
    installedVersion?: string;
    fixedVersion?: string;
    targetImage?: string;
    packageName?: string;
    cvssScore?: string;
    references?: string[];
}

export function findingDetailWebview(contextInfo: IContextInfo): string {
    const severity = (contextInfo.severity || "unknown").toLowerCase();
    let codicon = "codicon-warning";
    let color = "#cca700";

    switch (severity) {
        case "critical":
        case "high":
            codicon = "codicon-error";
            color = "#e51400";
            break;
        case "medium":
            codicon = "codicon-warning";
            color = "#cca700";
            break;
        case "low":
            codicon = "codicon-info";
            color = "#007acc";
            break;
        default:
            codicon = "codicon-error";
            color = "#e51400";
    }

    function scanInfoRow(label: string, value: string | undefined): string {
        return `<div class="scan-row"><span class="scan-label">${label}:</span> <span class="scan-value">${value || "-"}</span></div>`;
    }


    return  `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <link href="https://microsoft.github.io/vscode-codicons/dist/codicon.css" rel="stylesheet" />
    <style>
        body { font-family: sans-serif; padding: 1.5em; }
        .title-bar {
            display: flex;
            align-items: center;
            font-size: 1.5em;
            margin-bottom: 0.5em;
        }
        .vuln-icon {
            font-size: 10rem; 
            color: ${color};
            margin-right: 0.5em;
            vertical-align: middle;
        } 
        .tabs {
            display: flex;
            margin-bottom: 1em;
        }
        .tab {
            padding: 0.5em 1.5em;
            cursor: pointer;
            border: none;
            background: none;
            font-size: 1em;
            outline: none;
            color: #fff;
            border-bottom: none;
            transition: background 0.2s;
        }
        .tab.selected {
            border-bottom: 3px solid #007acc;
            font-weight: bold;
        }
        .section {
            display: none;
        }
        .section.active {
            display: block;
        }
        .scan-row {
            margin: 0.4em 0;
        }
        .scan-label {
            font-weight: bold;
            color: #fff;
            min-width: 160px;
            display: inline-block;
        }
        .scan-value {
            color: #fff;
        }
    </style>
</head>
<body>
    <div class="title-bar">
        <span class="codicon ${codicon} vuln-icon"></span>
        <span>${contextInfo.id || "Unknown Vulnerability"}</span>
    </div>
    <div class="tabs">
        <button class="tab selected" id="descTab">Description</button>
        <button class="tab" id="scanTab">Scan Info</button>
        <button class="tab" id="remTab">Remediation Info</button>
    </div>
    <div class="section active" id="descSection">
        <h3>Description</h3>
        <p>${contextInfo.description || "No description available."}</p>
    </div>
    <div class="section" id="scanSection">
        <h3>Scan Info</h3>
        ${scanInfoRow("Severity", contextInfo.severity)}
        ${scanInfoRow("Vulnerability Status", contextInfo.vulnerabilityStatus)}
        ${scanInfoRow("Installed Version", contextInfo.installedVersion)}
        ${scanInfoRow("Fixed Version", contextInfo.fixedVersion)}
        ${scanInfoRow("Target Image", contextInfo.targetImage)}
        ${scanInfoRow("Package Name", contextInfo.packageName)}
        ${scanInfoRow("CVSS 3", contextInfo.cvssScore)}
    </div>
    <div class="section" id="remSection">
        <h3>References</h3>
${
            contextInfo.references && contextInfo.references.length > 0
                ? `<ul>${contextInfo.references.map((ref: string) => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join("")}</ul>`
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
    </script>
</body>
</html>
    `;
}