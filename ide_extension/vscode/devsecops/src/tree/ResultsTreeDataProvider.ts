import * as vscode from "vscode";
import { ScanResultItem } from "./results/ScanResultItem";
import { Finding } from "../domain/model/Finding";
import { FindingItem } from "./results/finding/FindingItem";

export class ResultsTreeDataProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private _onDidChangeTreeData: vscode.EventEmitter<vscode.TreeItem | undefined | null | void> = new vscode.EventEmitter<vscode.TreeItem | undefined | null | void>();
  readonly onDidChangeTreeData: vscode.Event<vscode.TreeItem | undefined | null | void> = this._onDidChangeTreeData.event;
  private scanResults: ScanResultItem[] = [];
  private filterSeverities: Set<string> = new Set();
  private sortBySeverity: boolean = false;

  constructor(private context: vscode.ExtensionContext) {}

  public refresh(): void {
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: vscode.TreeItem): Thenable<vscode.TreeItem[]> {
    if (!element) {
      return Promise.resolve(this.scanResults);
    }

    if (element instanceof ScanResultItem) {
      const children = element.getFilteredAndSortedChildren(
        this.filterSeverities,
        this.sortBySeverity
      );
      return Promise.resolve(children);
    }

    return Promise.resolve([]);
  }

  public addScanResult(
    label: string,
    findings: Finding[],
    sourceType: "iac" | "image" | "dependencies",
    scanPath?: string,
    outputChannel?: vscode.OutputChannel
  ): void {
    const timestamp = new Date();

    // Look for a previous scan with the same label and type
    const previousScan = this.findExistingScan(label, sourceType);

    let findingItems: FindingItem[];
    let comparisonSummary: { delta: number, oldCount: number, newCount: number } | undefined;

    if (previousScan && previousScan.children.length > 0) {
      // We have a previous scan - perform comparison
      const previousFindings = previousScan.children.filter(
        (child): child is FindingItem => child instanceof FindingItem
      );

      const comparison = this.compareFindings(findings, previousFindings, sourceType, scanPath);
      findingItems = comparison.items;
      comparisonSummary = comparison.summary;

      // Remove the previous scan to keep only one per label+sourceType
      const previousIndex = this.scanResults.indexOf(previousScan);
      if (previousIndex > -1) {
        previousScan.dispose(); // Clean up output channel
        this.scanResults.splice(previousIndex, 1);
      }
    } else {
      // No previous scan or it was empty - just create regular finding items
      findingItems = findings.map((f) => new FindingItem(f, scanPath, sourceType, findings));
    }

    const scanItem = new ScanResultItem(label, sourceType, timestamp, findingItems, false, undefined, outputChannel);
    scanItem.comparisonSummary = comparisonSummary;

    this.scanResults.unshift(scanItem);
    this.refresh();
  }

  /**
   * Adds a loading placeholder scan result
   * @returns The scan ID to use for updating later
   */
  public addLoadingScanResult(
    label: string,
    sourceType: "iac" | "image" | "dependencies",
    outputChannel?: vscode.OutputChannel
  ): string {
    const timestamp = new Date();
    const scanItem = new ScanResultItem(label, sourceType, timestamp, [], true, undefined, outputChannel);

    this.scanResults.unshift(scanItem);
    this.refresh();

    return scanItem.scanId;
  }

  /**
   * Updates a loading scan result with actual findings
   * Automatically compares with previous scan if one exists for the same label+sourceType
   */
  public updateScanResult(
    scanId: string,
    findings: Finding[],
    sourceType: "iac" | "image" | "dependencies",
    scanPath?: string
  ): void {
    const scanItem = this.scanResults.find(item => item.scanId === scanId);
    
    if (!scanItem) {
      return;
    }

    // Look for a previous scan with the same label and type (excluding current one)
    const previousScan = this.scanResults.find(item => 
      item.scanId !== scanId && 
      this.getScanKey(item.label, item.sourceType) === this.getScanKey(scanItem.label, sourceType)
    );

    let findingItems: FindingItem[];
    let comparisonSummary: { delta: number, oldCount: number, newCount: number } | undefined;

    if (previousScan && previousScan.children.length > 0) {
      // We have a previous scan - perform comparison
      const previousFindings = previousScan.children.filter(
        (child): child is FindingItem => child instanceof FindingItem
      );

      const comparison = this.compareFindings(findings, previousFindings, sourceType, scanPath);
      findingItems = comparison.items;
      comparisonSummary = comparison.summary;

      // Remove the previous scan to keep only one per label+sourceType
      const previousIndex = this.scanResults.indexOf(previousScan);
      if (previousIndex > -1) {
        previousScan.dispose(); // Clean up output channel
        this.scanResults.splice(previousIndex, 1);
      }
    } else {
      // No previous scan or it was empty - just create regular finding items
      findingItems = findings.map((f) => new FindingItem(f, scanPath, sourceType, findings));
    }

    // Update the scan item with the findings
    scanItem.updateWithResults(findingItems, comparisonSummary);
    this.refresh();
  }

  /**
   * Updates a scan result to show it failed with an error
   */
  public updateScanResultWithError(scanId: string, errorMessage: string): void {
    const scanItem = this.scanResults.find(item => item.scanId === scanId);
    
    if (scanItem) {
      scanItem.updateWithError(errorMessage);
      this.refresh();
    }
  }

  /**
   * Removes a scan result by its ID (useful if scan fails)
   * @param scanId - The ID of the scan result to remove
   * @param keepOutputChannel - If true, keeps the output channel open to preserve logs (useful for debugging errors)
   */
  public removeScanResult(scanId: string, keepOutputChannel: boolean = false): void {
    const index = this.scanResults.findIndex(item => item.scanId === scanId);
    if (index > -1) {
      const scanItem = this.scanResults[index];
      scanItem.dispose(keepOutputChannel); // Optionally preserve the output channel
      this.scanResults.splice(index, 1);
      this.refresh();
    }
  }

  public deleteScanResult(scanResult: ScanResultItem): void {
    const index = this.scanResults.indexOf(scanResult);
    if (index > -1) {
      scanResult.dispose(); // Dispose the output channel
      this.scanResults.splice(index, 1);
      this.refresh();
    }
  }

  /**
   * Set severity filters
   */
  public setFilterSeverities(severities: string[]): void {
    this.filterSeverities = new Set(severities.map(s => s.toLowerCase()));
    this.updateScanResultDescriptions();
    this.refresh();
  }

  /**
   * Toggle severity-based sorting
   */
  public toggleSort(): void {
    this.sortBySeverity = !this.sortBySeverity;
    this.updateScanResultDescriptions();
    this.refresh();
  }

  /**
   * Clear all filters and sorting
   */
  public clearFilters(): void {
    this.filterSeverities.clear();
    this.sortBySeverity = false;
    this.updateScanResultDescriptions();
    this.refresh();
  }

  /**
   * Get current filter state
   */
  public getFilterState(): { severities: string[]; sorted: boolean } {
    return {
      severities: Array.from(this.filterSeverities),
      sorted: this.sortBySeverity
    };
  }

  /**
   * Update descriptions of all scan results to reflect active filters
   */
  private updateScanResultDescriptions(): void {
    this.scanResults.forEach(scanResult => {
      scanResult.updateDescription(this.filterSeverities, this.sortBySeverity);
    });
  }

  /**
   * Generate a unique key for a scan based on label and source type
   * e.g., "Dependencies: my-project|dependencies" or "Image: nginx:latest|image"
   */
  private getScanKey(label: string, sourceType: string): string {
    return `${label}|${sourceType}`;
  }

  /**
   * Find an existing scan result by label and source type
   */
  private findExistingScan(label: string, sourceType: string): ScanResultItem | undefined {
    const key = this.getScanKey(label, sourceType);
    return this.scanResults.find(scan => 
      this.getScanKey(scan.label, scan.sourceType) === key
    );
  }

  /**
   * Compare two sets of findings and calculate the delta
   * @param newFindings - Current scan findings
   * @param oldFindings - Previous scan findings (from FindingItems)
   * @param sourceType - Type of scan
   * @param scanPath - Optional path for the scan
   * @returns Array of FindingItems with delta summary
   */
  private compareFindings(
    newFindings: Finding[],
    oldFindings: FindingItem[],
    sourceType: "iac" | "image" | "dependencies",
    scanPath?: string
  ): { items: FindingItem[], summary: { delta: number, oldCount: number, newCount: number } } {
    const oldCount = oldFindings.length;
    const newCount = newFindings.length;
    const delta = newCount - oldCount;

    // Create finding items without comparison status
    const findingItems = newFindings.map((f) => new FindingItem(f, scanPath, sourceType, newFindings));

    return {
      items: findingItems,
      summary: {
        delta: delta,
        oldCount: oldCount,
        newCount: newCount
      }
    };
  }
}
