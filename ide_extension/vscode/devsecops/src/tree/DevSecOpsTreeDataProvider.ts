import * as vscode from "vscode";
import { ScanResultItem } from "./results/ScanResultItem";
import { CategoryTreeItem } from "./CategoryTreeItem";
import { FindingItem } from "./results/finding/FindingItem";
import { Finding } from "../domain/model/Finding";

export class DevSecOpsTreeDataProvider
  implements vscode.TreeDataProvider<vscode.TreeItem>
{
  private _onDidChangeTreeData: vscode.EventEmitter<
    vscode.TreeItem | undefined | null | void
  > = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<
    vscode.TreeItem | undefined | null | void
  > = this._onDidChangeTreeData.event;
  private categories: CategoryTreeItem[] = [];
  private extensionPath: string;
  private scanResults: ScanResultItem[] = [];

  constructor(private context: vscode.ExtensionContext) {
    this.extensionPath = context.extensionPath;
    this.getItems();
  }

  public refresh(): void {
    this.getItems();
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  // In your addScanResult method
  public addScanResult(
    label: string,
    findings: Finding[],
    sourceType: "iac" | "image",
    scanPath?: string
  ): void {
    const timestamp = new Date();
    const findingItems = findings.map((f) => new FindingItem(f, scanPath));

    this.scanResults.unshift(
      new ScanResultItem(label, sourceType, timestamp, findingItems)
    );

    this.refresh();
  }

  getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
    if (!element) {
      return Promise.resolve(this.categories);
    }

    if (element instanceof CategoryTreeItem) {
      return Promise.resolve(element.children);
    }

    if (element instanceof ScanResultItem) {
      return Promise.resolve(element.children);
    }

    return Promise.resolve([]);
  }

  private getItems(): void {
    const iacScanItems: vscode.TreeItem[] = [];
    const imageScanItems: vscode.TreeItem[] = [];

    const imageScanItem = new vscode.TreeItem(
      "Image Scan",
      vscode.TreeItemCollapsibleState.None
    );
    imageScanItem.command = {
      command: "devsecops.imageScan",
      title: "IMAGE_SCAN",
      arguments: [imageScanItem],
    };
    imageScanItem.iconPath = new vscode.ThemeIcon("breakpoints-view-icon");
    imageScanItem.tooltip = "Scan a docker image";
    imageScanItems.push(imageScanItem);

    const iacScanItem = new vscode.TreeItem(
      "Infrastructure as Code Scan",
      vscode.TreeItemCollapsibleState.None
    );
    iacScanItem.command = {
      command: "devsecops.iacScan",
      title: "IAC_SCAN",
      arguments: [iacScanItem],
    };
    iacScanItem.iconPath = new vscode.ThemeIcon("breakpoints-view-icon");
    iacScanItem.tooltip =
      "Scan a folder for IaC vulnerabilities like k8s or dockerfiles";
    iacScanItems.push(iacScanItem);

    this.categories = [
      new CategoryTreeItem(
        "Infrastructure as code scans",
        vscode.TreeItemCollapsibleState.Expanded,
        iacScanItems
      ),
      new CategoryTreeItem(
        "Containers scans",
        vscode.TreeItemCollapsibleState.Collapsed,
        imageScanItems
      ),
      new CategoryTreeItem(
        "Scan results",
        vscode.TreeItemCollapsibleState.Expanded,
        this.scanResults
      ),
    ];
  }
}
