import * as vscode from 'vscode';

export function registerCopilotCommands(context: vscode.ExtensionContext): void {
  const fixCommand = vscode.commands.registerCommand(
    'devsecops.fixWithCopilot',
    async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {

      const editor = await vscode.window.showTextDocument(document);
      editor.selection = new vscode.Selection(
        diagnostic.range.start,
        diagnostic.range.end
      );
      editor.revealRange(diagnostic.range);

      const issueId = diagnostic.code?.toString() || '';
      const issueDescription = diagnostic.message;
      const copilotExtension = vscode.extensions.getExtension('GitHub.copilot');
      const copilotChatExtension = vscode.extensions.getExtension('GitHub.copilot-chat');
      
      if (copilotExtension && copilotExtension.isActive) {
        try {
          await vscode.commands
            .executeCommand("github.copilot.chat.fix +when:!editorReadonly && !github.copilot.interactiveSession.disabled");
          setTimeout(() => {
            const prompt = `Fix this security issue: ${issueId} - ${issueDescription}`;
            void vscode.env.clipboard.writeText(prompt);
            void vscode.commands.executeCommand('editor.action.clipboardPasteAction');
          }, 500);
        } catch (error) {
          if (copilotChatExtension && copilotChatExtension.isActive) {
            await vscode.commands.executeCommand('github.copilot.chat.explain.palette');
            setTimeout(() => {
              const chatInput = `/fix This code has a security issue: ${issueId} - ${issueDescription}`;
              void vscode.env.clipboard.writeText(chatInput);
              void vscode.commands.executeCommand('editor.action.clipboardPasteAction');
            }, 500);
          } else {
            void vscode.window.showInformationMessage('Please install GitHub Copilot and GitHub Copilot Chat extensions to use this feature');
          }
        }
      } else {
        void vscode.window.showInformationMessage('GitHub Copilot extension is required for this feature');
      }
    }
  );

  const explainCommand = vscode.commands.registerCommand(
    'devsecops.explainWithCopilot',
    async (document: vscode.TextDocument, diagnostic: vscode.Diagnostic) => {
      const editor = await vscode.window.showTextDocument(document);
      editor.selection = new vscode.Selection(
        diagnostic.range.start,
        diagnostic.range.end
      );
      editor.revealRange(diagnostic.range);
    
      const issueId = diagnostic.code?.toString() || '';
      const issueDescription = diagnostic.message;
      
      const copilotChatExtension = vscode.extensions.getExtension('GitHub.copilot-chat');
      
      if (copilotChatExtension && copilotChatExtension.isActive) {
        try {
          await vscode.commands.executeCommand('github.copilot.chat.focus');
          
          setTimeout(() => {
            const chatInput = '/explain This code has a security issue: ' + 
              `${issueId} - ${issueDescription}. Can you explain why this is a problem ` +
              'and how to fix it securely?';
            
            void vscode.env.clipboard.writeText(chatInput);
            void vscode.commands.executeCommand('editor.action.clipboardPasteAction');
          }, 500);
        } catch (error) {
          void vscode.window.showErrorMessage(`Error using Copilot Chat: ${String(error)}`);
        }
      } else {
        void vscode.window.showInformationMessage('GitHub Copilot Chat extension is required for this feature');
      }
    }
  );

  context.subscriptions.push(fixCommand, explainCommand);
}