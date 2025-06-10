import * as vscode from 'vscode';

export class SecurityCodeActionProvider implements vscode.CodeActionProvider {
  public static readonly providedCodeActionKinds = [
    vscode.CodeActionKind.QuickFix
  ];

  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range | vscode.Selection,
    context: vscode.CodeActionContext,
  ): vscode.ProviderResult<(vscode.CodeAction | vscode.Command)[]> {
    const actions: vscode.CodeAction[] = [];

    // Process each diagnostic
    context.diagnostics
      .filter(diagnostic => diagnostic.source === 'devsecops')
      .forEach(diagnostic => {
        // Create "Fix with Copilot" action
        const fixAction = new vscode.CodeAction(
          'Fix with Copilot',
          vscode.CodeActionKind.QuickFix
        );
        fixAction.command = {
          title: 'Fix with Copilot',
          command: 'devsecops.fixWithCopilot',
          arguments: [document, diagnostic]
        };
        actions.push(fixAction);

        // Create "Explain with Copilot" action
        const explainAction = new vscode.CodeAction(
          'Explain with Copilot',
          vscode.CodeActionKind.QuickFix
        );
        explainAction.command = {
          title: 'Explain with Copilot',
          command: 'devsecops.explainWithCopilot',
          arguments: [document, diagnostic]
        };
        actions.push(explainAction);
      });

    return actions;
  }
}