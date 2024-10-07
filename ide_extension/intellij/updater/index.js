const { exec } = require('child_process');
const fs = require('fs');

// Regular expression to match Gradle dependencies
const dependencyRegex = /(\w[\w.-]*:\w[\w.-]*):(\d+\.\d+\.\d+)/;
// Regular expression to match Gradle plugins
const pluginRegex = /id\("(.+?)"\) version "(\d+(\.\d+)+)"/;

async function fetchDependencyLatestVersion(dependency) {
  const [groupId, artifactId] = dependency.split(':');
  const url = `https://search.maven.org/solrsearch/select?q=g:${groupId}+AND+a:${artifactId}&rows=10&wt=json&core=gav`;
  console.log(`Fetching version for ${dependency} from ${url}`);

  try {
    const response = await fetch(url);
    if (response.ok) {
      const body = await response.json();
      const stableVersions = body.response.docs
        .map(doc => doc.v)
        .filter(version => !/-(alpha|beta|rc|m|snapshot|cr|dev)/i.test(version));
      return stableVersions.length > 0 ? stableVersions[0] : null;
    }
  } catch (error) {
    console.error(`Error fetching version for ${dependency}: ${error.message}`);
  }
  return null;
}

async function fetchLatestPluginVersion(pluginId) {
  const pluginIdPath = pluginId.replace(/\./g, '/');
  const url = `https://plugins.gradle.org/m2/${pluginIdPath}/${pluginId}.gradle.plugin/maven-metadata.xml`;

  console.log(`Fetching plugin version for ${pluginId} from ${url}`);

  try {
    const response = await fetch(url);
    if (response.ok) {
      const body = await response.text();
      const match = body.match(/<version>(.+?)<\/version>/);
      if (match) {
        console.log(`Fetched plugin version for ${pluginId}:${match[1]}`);
        return match[1];
      }
    }
  } catch (error) {
    console.error(`Error fetching plugin version for ${pluginId}: ${error.message}`);
  }
  return null;
}

async function updateDependencyLine(line) {
  let updatedLine = line;

  const match = line.match(dependencyRegex);
  if (match) {
    const dependency = match[1];
    const currentVersion = match[2];
    console.log(`Found dependency: ${dependency}:${currentVersion}`);

    const latestVersion = await fetchDependencyLatestVersion(dependency);
    if (latestVersion) {
      console.log(`Updating ${dependency} from ${currentVersion} to ${latestVersion}`);
      updatedLine = line.replace(currentVersion, latestVersion);
    }
  } else {
    const pluginMatch = line.match(pluginRegex);
    if (pluginMatch) {
      const pluginId = pluginMatch[1];
      const currentVersion = pluginMatch[2];
      console.log(`Found plugin: ${pluginId}:${currentVersion}`);

      const latestPluginVersion = await fetchLatestPluginVersion(pluginId);
      if (latestPluginVersion) {
        console.log(`Updating ${pluginId} from ${currentVersion} to ${latestPluginVersion}`);
        updatedLine = line.replace(currentVersion, latestPluginVersion);
      }
    }
  }
  return updatedLine;
}

async function updateFileByLines(filePath, processLine) {
  const fileContent = fs.readFileSync(filePath, 'utf8');
  const lines = fileContent.split('\n');
  const updatedLines = [];

  for (const line of lines) {
    updatedLines.push(await processLine(line));
  }

  fs.writeFileSync(filePath, updatedLines.join('\n'), 'utf8');
  console.log(`File ${filePath} updated successfully!`);
}

function wildCardBuild(build) {
  return build.split(".")[0] + ".*";
}

function extractICVersion(data) {
  const latestRelease = data.filter((item) => item.code === "IIU")[0].releases.filter((release) => release.type === "release")[0];
  return { version: latestRelease.version, build: wildCardBuild(latestRelease.build) };
}

async function getIntellijCommunityVersion() {
  const response = await fetch("https://data.services.jetbrains.com/products?code=IIU%2CIIC&release.type=release");
  if (response.ok) {
    const data = await response.json();
    return extractICVersion(data);
  }
  throw new Error("Failed to fetch IntelliJ Community version", response.status);
}

async function getGradleVersion() {
  const response = await fetch("https://services.gradle.org/versions/current");
  if (response.ok) {
    const data = await response.json();
    return data.version;
  }
  throw new Error("Failed to fetch latest gradle version", response.status);
}

function updateGradleProperties({ intellijVersion, gradleVersion }) {
  return async function (line) {
    let updatedLine = line;
    if (line.startsWith("platformVersion")) {
      updatedLine = `platformVersion=${intellijVersion.version}`;
    } else if (line.startsWith("pluginUntilBuild")) {
      updatedLine = `pluginUntilBuild=${intellijVersion.build}`;
    } else if (line.startsWith("gradleVersion")) {
      updatedLine = `gradleVersion=${gradleVersion}`;
    }
    return updatedLine;
  }
}

function gradleWrapper() {
  exec('./gradlew wrapper', (error, stdout, stderr) => {
    if (error) {
      console.error(`Error executing command: ${error.message}`);
      return;
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }
    console.log(stdout);
  });
}

async function update() {
  updateFileByLines('build.gradle.kts', updateDependencyLine)
    .catch(console.error);
  const intellijVersion = await getIntellijCommunityVersion();
  console.log(`IntelliJ Community version: ${intellijVersion.version} (${intellijVersion.build})`);
  const gradleVersion = await getGradleVersion();
  console.log(`Gradle version: ${gradleVersion}`);
  updateFileByLines('gradle.properties', updateGradleProperties({ intellijVersion, gradleVersion }))
    .catch(console.error);
  console.log("Updating gradle wrapper");
  gradleWrapper();
}

update();
