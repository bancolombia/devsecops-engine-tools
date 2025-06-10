import * as vscode from "vscode";
import * as path from "path";
import { Finding } from "../../../domain/model/Finding";

export class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    private readonly scanPath?: string
  ) {
    super(finding.getDescription() || "Unknown Issue", vscode.TreeItemCollapsibleState.None);
    this.label = finding.getId() || "Unknown Issue";
    this.description = finding.getSeverity() || "Unknown";
    this.tooltip = `${finding.getDescription()}\nSeverity: ${finding.getSeverity()}\nResource: ${finding.getResource() || "Unknown"}\nLocation: ${finding.getWhere() || "Unknown"}`;
    
    const severityIcons: Record<string, vscode.ThemeIcon> = {
      "high": new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground")),
      "medium": new vscode.ThemeIcon("warning", new vscode.ThemeColor("editorWarning.foreground")),
      "low": new vscode.ThemeIcon("info", new vscode.ThemeColor("editorInfo.foreground")),
    };
    
    this.iconPath = severityIcons[finding.getSeverity().toLowerCase()] || 
      new vscode.ThemeIcon("error", new vscode.ThemeColor("errorForeground"));
      
    this.command = {
      command: "devsecops.showVulnContext",
      title: "Show Vulnerability Context",
      arguments: [finding] // Pass the full finding/context object
    };
    
    const fileInfo = this.extractFileInfo(finding.getWhere());
    
    if (fileInfo.filePath) {
      this.command = {
        title: "Open File",
        command: "devsecops.openWithDiagnostic",
        arguments: [
          finding,
          fileInfo.filePath,
          fileInfo.lineNumber || 1,
          fileInfo.lineNumberEnd || fileInfo.lineNumber || 1
        ]
      };
    }
  }

  private extractFileInfo(where: string): { filePath: string | null; lineNumber: number | null; lineNumberEnd: number | null } {
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
    
    const pathMatch = where.match(/\/ms_artifact(\/.+?)(?::|$|\s)/);
    if (pathMatch && pathMatch[1] && this.scanPath) {
      filePath = path.join(this.scanPath, pathMatch[1].substring(1));
    } else {
      const genericPathMatch = where.match(/\/([/\w.-]+)(?::|$|\s)/);
      if (genericPathMatch && this.scanPath) {
        filePath = path.join(this.scanPath, genericPathMatch[1]);
      }
    }
    
    return { filePath, lineNumber, lineNumberEnd };
  }
}