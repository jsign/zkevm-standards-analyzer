import Ajv2020 from "ajv/dist/2020";
import reportSchema from "./report.schema.json";
import type { ReportV1 } from "./types";

const ajv = new Ajv2020({ allErrors: true, strict: false });
ajv.addFormat("uint16", {
  type: "number",
  validate: (value: number) =>
    Number.isInteger(value) && value >= 0 && value <= 0xffff,
});
ajv.addFormat("uint32", {
  type: "number",
  validate: (value: number) =>
    Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff,
});
ajv.addFormat("uint64", {
  type: "number",
  validate: (value: number) => Number.isInteger(value) && value >= 0,
});
const validateReport = ajv.compile(reportSchema);

export function parseReport(value: unknown): ReportV1 {
  if (!validateReport(value)) {
    const details = ajv.errorsText(validateReport.errors, { separator: "\n" });
    throw new Error(`Analysis report does not match schema:\n${details}`);
  }
  return value as unknown as ReportV1;
}
