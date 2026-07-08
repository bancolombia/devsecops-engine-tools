import * as vscode from "vscode";
import { DiagnosticService } from "./tree/DiagnosticService";
import { PracticesTreeDataProvider } from "./tree/PracticesTreeDataProvider";
import { ResultsTreeDataProvider } from "./tree/ResultsTreeDataProvider";
import { registerIacScanCommand } from "./commands/IacScanCommand";
import { Finding } from "./domain/model/Finding";
import { SecurityCodeActionProvider } from "./actions/SecurityCodeActionProvider";
import { registerImageScanCommand } from "./commands/ImageScanCommand";
import { registerDependenciesScanCommand } from "./commands/DependenciesScanCommand";
import { registerCopilotCommands } from "./commands/copilotCommands";
import { registerVulnerabilityCopilotCommands } from "./commands/vulnerabilityCopilotCommands";
import { showVulnContextWebview, disposeVulnPanel, showGeneralFindingWebview } from './tree/results/finding/FindingWebview';
import { getClassificationModel } from './domain/model/ClassificationModel';

export function activate(context: vscode.ExtensionContext): void {

  DiagnosticService.initialize();

  // Register Practices view
  const practicesProvider = new PracticesTreeDataProvider();
  vscode.window.registerTreeDataProvider("devsecops-practices", practicesProvider);
  vscode.window.createTreeView("devsecops-practices", {
    treeDataProvider: practicesProvider,
    showCollapseAll: false,
    canSelectMany: false,
  });

  // Register Results view
  const resultsProvider = new ResultsTreeDataProvider(context);
  vscode.window.registerTreeDataProvider("devsecops-results", resultsProvider);
  vscode.window.createTreeView("devsecops-results", {
    treeDataProvider: resultsProvider,
    showCollapseAll: true,
    canSelectMany: false,
  });

  const iacScanDisposable = registerIacScanCommand(context, resultsProvider);
  const imageScanDisposable = registerImageScanCommand(context, resultsProvider);
  const dependenciesScanDisposable = registerDependenciesScanCommand(context, resultsProvider);

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { scheme: 'file' },
    new SecurityCodeActionProvider(),
    {
      providedCodeActionKinds: SecurityCodeActionProvider.providedCodeActionKinds
    }
  );

  registerCopilotCommands(context);
  registerVulnerabilityCopilotCommands(context);

  const openWithDiagnosticDisposable = vscode.commands.registerCommand(
    "devsecops.openWithDiagnostic",
    (finding: Finding, filePath: string, lineNumberStart: number, _lineNumberEnd: number) => {
      DiagnosticService.showFindingInFile(finding, filePath, lineNumberStart);
    }
  );

  const showVulnContextDisposable = vscode.commands.registerCommand(
    "devsecops.showVulnContext",
    (finding: Finding, sourceType?: string, allFindings?: Finding[]) => {
      showVulnContextWebview(finding, sourceType, allFindings);
    }
  );

  const showGeneralFindingWebviewDisposable = vscode.commands.registerCommand(
    "devsecops.showGeneralFindingWebview",
    (findingItem: any) => {
      const finding = findingItem.finding ?? findingItem;
      showGeneralFindingWebview(finding);
    }
  );

  const deleteScanResultDisposable = vscode.commands.registerCommand(
    "devsecops.deleteScanResult",
    async (scanResultItem: any) => {
      const result = await vscode.window.showWarningMessage(
        `Are you sure you want to delete the scan result "${scanResultItem.label}"?`,
        { modal: true },
        "Delete",
      );

      if (result === "Delete") {
        resultsProvider.deleteScanResult(scanResultItem);
        vscode.window.showInformationMessage(`Scan result "${scanResultItem.label}" has been deleted.`);
      }
    }
  );

  const filterBySeverityDisposable = vscode.commands.registerCommand(
    "devsecops.filterBySeverity",
    async () => {
      const classificationModel = getClassificationModel();
      const currentFilter = resultsProvider.getFilterState();
      
      let severityOptions: { label: string, picked: boolean }[];
      let title: string;
      
      if (classificationModel === "priority") {
        // Priority-based options 
        title = "Filter Findings by Priority";
        severityOptions = [
          { label: "Very Critical", picked: currentFilter.severities.includes("very critical") },
          { label: "Critical", picked: currentFilter.severities.includes("critical") },
          { label: "High", picked: currentFilter.severities.includes("high") },
          { label: "Medium Low", picked: currentFilter.severities.includes("medium low") }
        ];
      } else {
        // Severity-based options
        title = "Filter Findings by Severity";
        severityOptions = [
          { label: "Critical", picked: currentFilter.severities.includes("critical") },
          { label: "High", picked: currentFilter.severities.includes("high") },
          { label: "Medium", picked: currentFilter.severities.includes("medium") },
          { label: "Low", picked: currentFilter.severities.includes("low") }
        ];
      }

      const selected = await vscode.window.showQuickPick(severityOptions, {
        canPickMany: true,
        placeHolder: "Select items to show (leave empty to show all)",
        title: title
      });

      if (selected !== undefined) {
        const severities = selected.map(item => item.label.toLowerCase());
        resultsProvider.setFilterSeverities(severities);
      }
    }
  );

  const toggleSortDisposable = vscode.commands.registerCommand(
    "devsecops.toggleSort",
    () => {
      resultsProvider.toggleSort();
    }
  );

  const clearFiltersDisposable = vscode.commands.registerCommand(
    "devsecops.clearFilters",
    () => {
      resultsProvider.clearFilters();
      vscode.window.showInformationMessage('All filters and sorting cleared');
    }
  );

  context.subscriptions.push(iacScanDisposable);
  context.subscriptions.push(imageScanDisposable);
  context.subscriptions.push(dependenciesScanDisposable);
  context.subscriptions.push(openWithDiagnosticDisposable);
  context.subscriptions.push(codeActionProvider);
  context.subscriptions.push(showVulnContextDisposable);
  context.subscriptions.push(showGeneralFindingWebviewDisposable);
  context.subscriptions.push(deleteScanResultDisposable);
  context.subscriptions.push(filterBySeverityDisposable);
  context.subscriptions.push(toggleSortDisposable);
  context.subscriptions.push(clearFiltersDisposable);


  context.subscriptions.push({
    dispose: () => {
      DiagnosticService.dispose();
    }
  });
}

export function deactivate(): void {
  disposeVulnPanel();
  DiagnosticService.dispose();
}