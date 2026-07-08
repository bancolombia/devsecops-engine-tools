import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "../../../domain/model/Finding";
import { getClassificationModel } from "../../../domain/model/ClassificationModel";

export class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    private readonly scanPath?: string,
    private readonly sourceType?: "iac" | "image" | "dependencies",
    public readonly allFindings: Finding[] = []
  ) {
    super(finding.getDescription() || "Unknown Issue", vscode.TreeItemCollapsibleState.None);
    
    // Use effective severity based on classification model configuration
    const effectiveSeverity = finding.getEffectiveSeverity();
    const classificationModel = getClassificationModel();
    const classificationLabel = classificationModel === "priority" ? "Priority" : "Severity";
    
    this.label = finding.getId() || "Unknown Issue";
    this.description = effectiveSeverity || "Unknown";
    this.tooltip = `
    ${finding.getDescription()}\n
    ${classificationLabel}: ${effectiveSeverity}\n
    Location: ${finding.getWhere() || "N/A"}
    Validation Rule Code: ${finding.getValidationRuleCode() || "N/A"}`;

    // Set context value based on module for right-click menu
    if (sourceType === "dependencies") {
      this.contextValue = "findingItem-dependencies";
    } else if (sourceType === "image") {
      this.contextValue = "findingItem-image";
    } else if (finding.getModule() === "engine_iac") {
      this.contextValue = "engine_iac";
    } else if (finding.getModule() === "engine_secrets") {
      this.contextValue = "engine_secrets";
    } else {
      this.contextValue = "findingItem";
    }

    const severityIcons: Record<string, vscode.ThemeIcon> = {
      "very critical": new vscode.ThemeIcon("alert", new vscode.ThemeColor("errorForeground")),
      critical: new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
      high: new vscode.ThemeIcon("warning", new vscode.ThemeColor("list.warningForeground")),
      medium: new vscode.ThemeIcon("info", new vscode.ThemeColor("editorWarning.foreground")),
      "medium low": new vscode.ThemeIcon("circle-outline", new vscode.ThemeColor("terminal.ansiGreen")),
      low: new vscode.ThemeIcon("circle-outline", new vscode.ThemeColor("terminal.ansiGreen")),
    };

    this.iconPath =
      severityIcons[effectiveSeverity.toLowerCase()] ||
      new vscode.ThemeIcon("shield", new vscode.ThemeColor("foreground"));

    this.command = {
      command: "devsecops.showVulnContext",
      title: "Show Vulnerability Context",
      arguments: [finding, sourceType, allFindings], // Pass the full finding/context object, sourceType and all findings of this scan
    };

    const fileInfo = this.extractFileInfo(finding.getWhere());
    
    if (fileInfo.filePath && ["engine_iac"].includes(finding.getModule())) {
      this.command = {
        title: "Open File",
        command: "devsecops.openWithDiagnostic",
        arguments: [
          finding,
          fileInfo.filePath,
          fileInfo.lineNumber || 1,
          fileInfo.lineNumberEnd || fileInfo.lineNumber || 1,
        ],
      };
    }
  }

  private extractFileInfo(where: string): {
    filePath: string | null;
    lineNumber: number | null;
    lineNumberEnd: number | null;
  } {
    if (!where) {
      return { filePath: null, lineNumber: null, lineNumberEnd: null };
    }

    let lineNumber: number | null = null;
    let lineNumberEnd: number | null = null;

    // Check for line range pattern (line 10-15)
    const lineRangeMatch = where.match(/\(line\s+(\d+)-(\d+)\)/);
    if (lineRangeMatch) {
      lineNumber = parseInt(lineRangeMatch[1], 10);
      lineNumberEnd = parseInt(lineRangeMatch[2], 10);
    } else {
      // Fall back to trying single line pattern (line 181)
      const singleLineMatch = where.match(/\(line\s+(\d+)\)/);
      if (singleLineMatch) {
        lineNumber = parseInt(singleLineMatch[1], 10);
        lineNumberEnd = lineNumber; // Same as start for single line
      }
    }

    let filePath: string | null = null;

    const pathMatch = where.match(/\/(ms_artifact|extracted)(\/.+?)(?::|$|\s)/);
    if (pathMatch && pathMatch[2] && this.scanPath) {
      filePath = path.join(this.scanPath, pathMatch[2].substring(1));
    } else {
      const genericPathMatch = where.match(/([^\s/]+(?:\.[^\s/]+)*)\s*(?:\(line|$|\s)/);
      if (genericPathMatch && this.scanPath) {
        filePath = path.join(this.scanPath, genericPathMatch[1]);
      }
    }

    return { filePath, lineNumber, lineNumberEnd };
  }
}
