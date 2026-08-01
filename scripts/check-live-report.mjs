import { readFile } from "node:fs/promises";

const reportPath = process.argv[2];
if (!reportPath) {
  throw new Error("usage: node scripts/check-live-report.mjs <report.json>");
}

const report = JSON.parse(await readFile(reportPath, "utf8"));
const assert = (condition, message) => {
  if (!condition) throw new Error(message);
};
const primary = report.artifacts.filter((artifact) => artifact.variant === "primary");
const profiling = report.artifacts.filter(
  (artifact) => artifact.variant === "profiling",
);

assert(report.schema_version === "1", "expected ReportV1");
assert(report.release.tag === "v0.14.1", "expected the v0.14.1 fixture release");
assert(report.artifacts.length === 9, "expected all nine published ELF assets");
assert(primary.length === 7, "expected seven primary ELF assets");
assert(profiling.length === 2, "expected two profiling variants");
assert(
  report.standards.stale_paths.length === 0,
  "v0.14.1 acceptance statuses require a reviewed standards snapshot",
);

const findings = [
  ...report.artifacts.flatMap((artifact) => artifact.findings),
  ...report.platforms.flatMap((platform) => platform.findings),
  ...report.readiness,
];
const aggregated = {
  pass: 0,
  fail: 0,
  warning: 0,
  unknown: 0,
  not_applicable: 0,
};
for (const finding of findings) aggregated[finding.status] += 1;
assert(
  JSON.stringify(aggregated) === JSON.stringify(report.summary),
  "summary evidence counts must equal the atomic findings",
);

const openvm = primary.filter((artifact) => artifact.zkvm === "openvm");
assert(openvm.length === 2, "expected both OpenVM primary artifacts");
for (const artifact of openvm) {
  assert(
    artifact.findings.some(
      (finding) =>
        finding.rule_id === "elf.header.class64" && finding.status === "fail",
    ),
    `${artifact.id} should report the ELF64 requirement failure`,
  );
}

const zesu = primary.find(
  (artifact) => artifact.guest === "zesu" && artifact.zkvm === "zisk",
);
assert(zesu, "expected the Zesu/ZisK primary artifact");
assert(
  zesu.findings.some(
    (finding) =>
      finding.rule_id === "elf.permissions.wx" && finding.status === "fail",
  ),
  "Zesu/ZisK should report the W+X segment failure",
);

console.log(
  `accepted ${report.release.tag}: ${primary.length} primary, ${profiling.length} profiling`,
);
