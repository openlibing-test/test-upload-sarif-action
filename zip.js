const AdmZip = require("adm-zip");
const fs = require("fs");
const path = require("path");

const action = fs.readFileSync(path.join(__dirname, "action.yml")).toString();
const newVersionAction = action.replace(
  /version:\s?'?(\d{1,2})\.(\d{1,2})\.(\d{1,2})'?/,
  (match, grep1, grep2, grep3) => `version: ${grep1}.${grep2}.${parseInt(grep3) + 1}`
);
fs.writeFileSync("action.yml", newVersionAction);

const zip = new AdmZip();
zip.addLocalFile("./README.md");
zip.addLocalFile("./action.yml");
zip.addLocalFolder("./dist", "./dist");
zip.writeZip("./openlibing-upload-sarif.zip");

console.log("ZIP package created: openlibing-upload-sarif.zip");
