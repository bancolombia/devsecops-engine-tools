import * as vscode from 'vscode';

const diagnosticCollection = vscode.languages.createDiagnosticCollection('iacVulnerabilities');

export function setDiagnostics(filePath: string, lines: number[], message: string): void {
    const uri = vscode.Uri.file(filePath);
    const diagnostics: vscode.Diagnostic[] = lines.map(line => {
        const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
        return new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Warning);
    });
    diagnosticCollection.set(uri, diagnostics);
}

export function clearDiagnostics(): void {
    diagnosticCollection.clear();
}