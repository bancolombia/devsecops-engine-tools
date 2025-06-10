import * as vscode from "vscode";

export class CategoryTreeItem extends vscode.TreeItem {
  constructor(
    public readonly label: string,
    public readonly collapsibleState: vscode.TreeItemCollapsibleState,
    public readonly children: vscode.TreeItem[]
  ) {
    super(label, collapsibleState);
  }
}