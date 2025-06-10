import * as assert from "assert";
import * as vscode from "vscode";
import * as sinon from "sinon";
import { DevSecOpsTreeDataProvider } from "../../../tree/DevSecOpsTreeDataProvider";
import { CategoryTreeItem } from "../../../tree/CategoryTreeItem";
import { ScanResultItem } from "../../../tree/results/ScanResultItem";
import { FindingItem } from "../../../tree/results/finding/FindingItem";
import { Finding } from "../../../domain/model/Finding";

suite("DevSecOpsTreeDataProvider Tests", () => {
  let treeDataProvider: DevSecOpsTreeDataProvider;
  let mockContext: vscode.ExtensionContext;

  setup(() => {
    // Create a mock ExtensionContext
    mockContext = {
      subscriptions: [],
      extensionPath: "/test/path",
      extensionUri: vscode.Uri.parse("file:///test/path"),
      globalState: {
        get: () => undefined,
        update: async () => {},
        keys: () => [],
      } as any,
      workspaceState: {
        get: () => undefined,
        update: async () => {},
        keys: () => [],
      } as any,
      secrets: {
        get: async () => undefined,
        store: async () => {},
        delete: async () => {},
        onDidChange: ((listener: any, thisArgs?: any, disposables?: any) => {
          return { dispose() {} };
        }) as vscode.Event<vscode.SecretStorageChangeEvent>,
      },
      extensionMode: vscode.ExtensionMode.Development,
      logPath: "",
      storagePath: "",
      globalStoragePath: "",
      logUri: vscode.Uri.parse("file:///test/log"),
      storageUri: vscode.Uri.parse("file:///test/storage"),
      globalStorageUri: vscode.Uri.parse("file:///test/global-storage"),
      asAbsolutePath: (relativePath) => `/test/path/${relativePath}`,
      environmentVariableCollection: {
        persistent: true,
        replace: () => {},
        append: () => {},
        prepend: () => {},
        get: () => undefined,
        forEach: () => {},
        clear: () => {},
        delete: () => {},
      } as any,
      extension: {} as any,
      languageModelAccessInformation: {} as any,
    };

    treeDataProvider = new DevSecOpsTreeDataProvider(mockContext);
  });

  teardown(() => {
    sinon.restore();
  });

  test("Constructor should initialize properties correctly", () => {
    // Verify that extensionPath was set
    assert.strictEqual((treeDataProvider as any).extensionPath, "/test/path");

    // Verify that categories were initialized by getItems()
    const categories = (treeDataProvider as any).categories;
    assert.strictEqual(Array.isArray(categories), true);
    assert.strictEqual(categories.length, 3);

    // Check category names
    assert.strictEqual(categories[0].label, "Infrastructure as code scans");
    assert.strictEqual(categories[1].label, "Containers scans");
    assert.strictEqual(categories[2].label, "Scan results");
  });

  test("refresh method should call getItems and fire change event", () => {
    // Arrange
    const getItemsSpy = sinon.spy(treeDataProvider as any, "getItems");
    const fireSpy = sinon.spy((treeDataProvider as any)._onDidChangeTreeData, "fire");

    // Act
    treeDataProvider.refresh();

    // Assert
    assert.strictEqual(getItemsSpy.calledOnce, true);
    assert.strictEqual(fireSpy.calledOnce, true);
  });

  test("getTreeItem should return the same element", () => {
    // Create a sample tree item
    const sampleItem = new vscode.TreeItem("Sample");

    // Call getTreeItem
    const result = treeDataProvider.getTreeItem(sampleItem);

    // Verify it returns the same item
    assert.strictEqual(result, sampleItem);
  });

  test("getChildren should return scan result children when scan result is provided", async () => {
    // Arrange
    const mockFinding: Finding = {
      id: "test-id",
      severity: "high",
      customVulnId: "custom-id",
      checkName: "test-check",
      checkClass: "test-class",
      where: "file.js:10",
      resource: "resource-name",
      description: "Test description",
      module: "test-module",
      tool: "test-tool",
      references: ["ref1", "ref2"],

      // All the getter methods
      getId: () => "test-id",
      getCustomVulnId: () => "custom-id",
      getCheckName: () => "test-check",
      getCheckClass: () => "test-class",
      getSeverity: () => "high",
      getWhere: () => "file.js:10",
      getResource: () => "resource-name",
      getDescription: () => "Test description",
      getModule: () => "test-module",
      getTool: () => "test-tool",
      getReferences: () => ["ref1", "ref2"],
    } as unknown as Finding;

    treeDataProvider.addScanResult("Test Scan", [mockFinding], "iac", "/test/path");
    const scanResults = (treeDataProvider as any).scanResults;

    // Act
    const children = await treeDataProvider.getChildren(scanResults[0]);

    // Assert
    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0] instanceof FindingItem, true);
  });

  test("getChildren should return categories when no element is provided", async () => {
    // Act
    const children = await treeDataProvider.getChildren();

    // Assert
    const categories = (treeDataProvider as any).categories;
    assert.strictEqual(children, categories);
    assert.strictEqual(children.length, 3);
  });

  test("getChildren should return category children when category is provided", async () => {
    // Arrange - get a category
    const categories = (treeDataProvider as any).categories;
    const category = categories[0]; // Infrastructure as code scans

    // Act
    const children = await treeDataProvider.getChildren(category);

    // Assert
    assert.strictEqual(Array.isArray(children), true);
    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0].label, "Infrastructure as Code Scan");
  });

  test("getChildren should return scan result children when scan result is provided", async () => {
    // Arrange
    // Arrange
    const mockFinding: Finding = {
      id: "test-id",
      severity: "high",
      customVulnId: "custom-id",
      checkName: "test-check",
      checkClass: "test-class",
      where: "file.js:10",
      resource: "resource-name",
      description: "Test description",
      module: "test-module",
      tool: "test-tool",
      references: ["ref1", "ref2"],

      // All the getter methods
      getId: () => "test-id",
      getCustomVulnId: () => "custom-id",
      getCheckName: () => "test-check",
      getCheckClass: () => "test-class",
      getSeverity: () => "high",
      getWhere: () => "file.js:10",
      getResource: () => "resource-name",
      getDescription: () => "Test description",
      getModule: () => "test-module",
      getTool: () => "test-tool",
      getReferences: () => ["ref1", "ref2"],
    } as unknown as Finding;

    treeDataProvider.addScanResult("Test Scan", [mockFinding], "iac", "/test/path");
    const scanResults = (treeDataProvider as any).scanResults;

    // Act
    const children = await treeDataProvider.getChildren(scanResults[0]);

    // Assert
    assert.strictEqual(children.length, 1);
    assert.strictEqual(children[0] instanceof FindingItem, true);
  });

  test("getChildren should return empty array for unknown elements", async () => {
    // Arrange
    const unknownElement = new vscode.TreeItem("unknown");

    // Act
    const children = await treeDataProvider.getChildren(unknownElement);

    // Assert
    assert.strictEqual(Array.isArray(children), true);
    assert.strictEqual(children.length, 0);
  });

  test("getItems should create correct tree structure", () => {
    // Call getItems via refresh (as getItems is private)
    treeDataProvider.refresh();

    // Get the categories
    const categories = (treeDataProvider as any).categories;

    // Check the first category (Infrastructure as code scans)
    assert.strictEqual(categories[0].label, "Infrastructure as code scans");
    assert.strictEqual(categories[0].collapsibleState, vscode.TreeItemCollapsibleState.Expanded);
    assert.strictEqual(categories[0].children.length, 1);

    // Check the IAC scan item
    const iacItem = categories[0].children[0];
    assert.strictEqual(iacItem.label, "Infrastructure as Code Scan");
    assert.strictEqual(iacItem.command?.command, "devsecops.iacScan");
    assert.strictEqual(
      iacItem.tooltip,
      "Scan a folder for IaC vulnerabilities like k8s or dockerfiles"
    );

    // Check the second category (Containers scans)
    assert.strictEqual(categories[1].label, "Containers scans");
    assert.strictEqual(categories[1].collapsibleState, vscode.TreeItemCollapsibleState.Collapsed);
    assert.strictEqual(categories[1].children.length, 1);

    // Check the image scan item
    const imageItem = categories[1].children[0];
    assert.strictEqual(imageItem.label, "Image Scan");
    assert.strictEqual(imageItem.command?.command, "devsecops.imageScan");
    assert.strictEqual(imageItem.tooltip, "Scan a docker image");

    // Check the third category (Scan results)
    assert.strictEqual(categories[2].label, "Scan results");
    assert.strictEqual(categories[2].collapsibleState, vscode.TreeItemCollapsibleState.Expanded);
  });
});
