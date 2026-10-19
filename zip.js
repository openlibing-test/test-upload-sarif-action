const AdmZip = require("adm-zip");

const zip = new AdmZip();
zip.addLocalFile("./README.md");
zip.addLocalFile("./action.yml");
zip.addLocalFolder("./dist", "./dist");
zip.writeZip("./openlibing-upload-sarif.zip");

console.log("ZIP package created: openlibing-upload-sarif.zip");
