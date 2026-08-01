import { useState } from "react";
import { EvidenceCounts, FindingList, PageHeader, shortSha } from "../components";
import type {
  EvidenceCounts as Counts,
  Finding,
  FindingStatus,
  ReportV1,
} from "../types";

export function StandardsPage({ report }: { report: ReportV1 }) {
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const all = [
    ...report.artifacts.flatMap((artifact) => artifact.findings),
    ...report.platforms.flatMap((platform) => platform.findings),
    ...report.readiness,
  ];
  const paths = [...new Set(all.map((finding) => finding.standard_path))].sort();

  return (
    <>
      <PageHeader
        eyebrow="Merged main only"
        title="Standards coverage"
        description="Each normative area stays visible, including requirements that need runtime or manual evidence. Repeated artifact results are summarized per source document."
        aside={
          <div className="snapshot-box">
            <span>Resolved commit</span>
            <strong>{shortSha(report.standards.commit)}</strong>
            <small>{paths.length} referenced documents</small>
          </div>
        }
      />
      {report.standards.stale_paths.length > 0 && (
        <div className="stale-banner" role="alert">
          <strong>Rule catalog stale</strong>
          <span>{report.standards.stale_paths.join(", ")}</span>
        </div>
      )}
      <div className="filter-bar" aria-label="Filter standards findings">
        <span>Status</span>
        {(
          [
            "all",
            "fail",
            "warning",
            "pass",
            "unknown",
            "not_applicable",
          ] as const
        ).map((status) => (
          <button
            type="button"
            key={status}
            aria-pressed={statusFilter === status}
            onClick={() => setStatusFilter(status)}
          >
            {status === "all" ? "All" : status.replace("_", " ")}
          </button>
        ))}
      </div>
      <div className="standards-list">
        {paths.length === 0 && (
          <p className="empty-state" role="status">
            The report contains no cataloged standards findings.
          </p>
        )}
        {paths.map((path) => {
          const findings = all.filter(
            (finding) =>
              finding.standard_path === path &&
              (statusFilter === "all" || finding.status === statusFilter),
          );
          const unique = uniqueRules(findings);
          return (
            <section className="standard-section" key={path}>
              <div className="standard-heading">
                <div>
                  <p className="eyebrow">{path.split("/")[0]}</p>
                  <h2>{documentName(path)}</h2>
                  <code>{path}</code>
                </div>
                <EvidenceCounts counts={countFindings(findings)} />
              </div>
              <div className="subject-groups">
                {[...new Set(unique.map((finding) => finding.subject))].map(
                  (subject) => (
                    <section key={subject}>
                      <h3>{subjectLabel(subject)}</h3>
                      <FindingList
                        findings={unique.filter(
                          (finding) => finding.subject === subject,
                        )}
                        compact
                      />
                    </section>
                  ),
                )}
              </div>
            </section>
          );
        })}
      </div>
    </>
  );
}

function subjectLabel(subject: Finding["subject"]): string {
  return {
    artifact: "Published artifact",
    release: "Release",
    toolchain: "Toolchain",
    guest_project: "Guest project",
    zkvm_runtime: "zkVM runtime",
  }[subject];
}

function uniqueRules(findings: Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = unique.get(finding.rule_id);
    if (!existing || rank(finding.status) > rank(existing.status)) {
      unique.set(finding.rule_id, finding);
    }
  }
  return [...unique.values()];
}

function countFindings(findings: Finding[]): Counts {
  const counts: Counts = {
    pass: 0,
    fail: 0,
    warning: 0,
    unknown: 0,
    not_applicable: 0,
  };
  for (const finding of findings) counts[finding.status] += 1;
  return counts;
}

function rank(status: Finding["status"]): number {
  return { not_applicable: 0, pass: 1, unknown: 2, warning: 3, fail: 4 }[status];
}

function documentName(path: string): string {
  const parent = path.split("/").at(-2);
  if (path.includes("guest-handbook")) return "Guest program handbook";
  return (parent ?? path)
    .split("-")
    .map((word) => word[0].toUpperCase() + word.slice(1))
    .join(" ");
}
