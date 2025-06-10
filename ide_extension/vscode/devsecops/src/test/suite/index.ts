import * as path from 'path';
import Mocha from 'mocha';

export function run(): Promise<void> {
  // Create the mocha test
  const mocha = new Mocha({
    ui: 'tdd',
    color: true
  });

  const testsRoot = path.resolve(__dirname, '.');
  
  // Manually add test files
  mocha.addFile(path.resolve(testsRoot, './extension.test.js'));
  mocha.addFile(path.resolve(testsRoot, './tree/DevSecOpsTreeDataProvider.test.js'));
  
  return new Promise((resolve, reject) => {
    try {
      // Run the mocha test
      mocha.run((failures: number) => {
        if (failures > 0) {
          reject(new Error(`${failures} tests failed.`));
        } else {
          resolve();
        }
      });
    } catch (err) {
      console.error(err);
      reject(err);
    }
  });
}