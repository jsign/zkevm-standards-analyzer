import { readFile } from "node:fs/promises";
import Ajv2020 from "ajv/dist/2020.js";

const reportPath = process.argv[2];
if (!reportPath) {
  throw new Error("usage: node scripts/validate-report.mjs <report.json>");
}

const schema = JSON.parse(
  await readFile(new URL("../src/report.schema.json", import.meta.url), "utf8"),
);
const report = JSON.parse(await readFile(reportPath, "utf8"));
const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addFormat("uint32", {
  type: "number",
  validate: (value) =>
    Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff,
});
ajv.addFormat("uint64", {
  type: "number",
  validate: (value) => Number.isInteger(value) && value >= 0,
});
const validate = ajv.compile(schema);

if (!validate(report)) {
  throw new Error(ajv.errorsText(validate.errors, { separator: "\n" }));
}

console.log(`validated ReportV1 for ${report.release.tag}`);

