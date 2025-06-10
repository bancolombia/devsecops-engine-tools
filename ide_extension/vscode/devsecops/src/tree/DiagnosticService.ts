import * as vscode from "vscode";
import { Finding } from "../domain/model/Finding";

export class DiagnosticService {
  private static diagnosticCollection: vscode.DiagnosticCollection | undefined;
  private static findingMap: Map<string, Finding> = new Map();

  public static initialize(): void {
    if (!this.diagnosticCollection) {
      this.diagnosticCollection = vscode.languages.createDiagnosticCollection("devsecops");
    }
  }

  public static showFindingInFile(finding: Finding, filePath: string, lineNumberStart: number, lineNumberEnd: number = lineNumberStart): void {
    this.initialize();
    
    const fileUri = vscode.Uri.file(filePath);
    
    // Create a range that spans from the first character of the start line
    // to the last character of the end line
    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(
        new vscode.Position(lineNumberStart - 1, 0),
        new vscode.Position(lineNumberEnd - 1, 100) // Assuming max line length of 100
      ),
      finding.getDescription(),
      vscode.DiagnosticSeverity.Error
    );
    
    diagnostic.source = "devsecops";
    diagnostic.code = finding.getId();
    
    const key = `${fileUri.toString()}:${finding.getId()}`;
    this.findingMap.set(key, finding);
    
    this.diagnosticCollection?.set(fileUri, [diagnostic]);
    
    void vscode.window.showTextDocument(fileUri, {
      selection: new vscode.Range(lineNumberStart - 1, 0, lineNumberStart - 1, 0),
      preview: true
    });
  }

  public static getFindingForDiagnostic(fileUri: vscode.Uri, diagnosticCode: string): Finding | undefined {
    const key = `${fileUri.toString()}:${diagnosticCode}`;
    return this.findingMap.get(key);
  }

  public static clearDiagnostics(): void {
    this.diagnosticCollection?.clear();
    this.findingMap.clear();
  }

  public static dispose(): void {
    this.diagnosticCollection?.dispose();
    this.findingMap.clear();
  }
}