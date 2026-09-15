const fs = require('fs');
const path = require('path');

const actionYmlPath = path.join(__dirname, 'action.yml');

let content = fs.readFileSync(actionYmlPath, 'utf8');

const versionMatch = content.match(/version:\s*'([\d.]+)'/);
if (versionMatch) {
  const currentVersion = versionMatch[1];
  const parts = currentVersion.split('.').map(Number);
  parts[2] = (parts[2] || 0) + 1;
  const newVersion = parts.join('.');
  content = content.replace(/version:\s*'[\d.]+'/, `version: '${newVersion}'`);
  fs.writeFileSync(actionYmlPath, content, 'utf8');
  console.log(`Version bumped from ${currentVersion} to ${newVersion}`);
} else {
  console.log('Version not found in action.yml');
  process.exit(1);
}
