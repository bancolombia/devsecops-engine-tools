import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  try {
    // The folder containing the Extension Manifest package.json
    const extensionDevelopmentPath = path.resolve(__dirname, '../../');
    
    // The path to the compiled extension tests
    const extensionTestsPath = path.resolve(__dirname, './suite/index');
    
    // Download VS Code, unzip it and run the integration test
    await runTests({ 
      extensionDevelopmentPath, 
      extensionTestsPath,
      launchArgs: [
        '--user-data-dir', '/tmp/vscode-test-workspace',
        '--disable-extensions'
      ] 
    });
  } catch (err) {
    console.error('Failed to run tests', err);
    process.exit(1);
  }
}

void main();