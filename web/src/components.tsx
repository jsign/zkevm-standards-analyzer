import type { ReactNode } from "react";
import { Link } from "./router";
import type {
  ArtifactReport,
  EvidenceCounts as Counts,
  Finding,
  FindingStatus,
} from "./types";

export const STATUS_LABELS: Record<FindingStatus, string> = {
  pass: "Pass",
  fail: "Fail",
  warning: "Warning",
  unknown: "Unknown",
  not_applicable: "N/A",
};

const FINDING_STATUS_ORDER: Record<FindingStatus, number> = {
  fail: 0,
  warning: 1,
  pass: 2,
  unknown: 3,
  not_applicable: 4,
};

export function Layout({
  children,
  currentPath = "/",
}: {
  children: ReactNode;
  currentPath?: string;
}) {
  return (
    <div className="site-shell">
      <header className="topbar">
        <Link className="brand" to="/" aria-label="zkEVM Standards Analyzer home">
          <span className="brand-mark" aria-hidden="true">
            ZK
          </span>
          <span>
            <strong>Standards Analyzer</strong>
            <small>Published ELF evidence</small>
          </span>
        </Link>
        <nav aria-label="Primary navigation">
          <Link to="/" className={currentPath === "/" ? "active" : undefined}>
            Overview
          </Link>
          <Link
            to="/standards"
            className={currentPath === "/standards" ? "active" : undefined}
          >
            Standards
          </Link>
          <Link
            to="/readiness"
            className={currentPath === "/readiness" ? "active" : undefined}
          >
            Readiness
          </Link>
        </nav>
        <a
          className="repo-link"
          href="https://github.com/jsign/zkevm-standards-analyzer"
        >
          GitHub <span aria-hidden="true">↗</span>
        </a>
      </header>
      <main>{children}</main>
      <footer>
        <span>Evidence, not certification.</span>
        <span>
          Sources:{" "}
          <a href="https://github.com/eth-act/ere-guests">ere-guests</a> ·{" "}
          <a href="https://github.com/eth-act/zkevm-standards">
            zkevm-standards
          </a>
        </span>
      </footer>
    </div>
  );
}

export function StatusBadge({
  status,
  count,
}: {
  status: FindingStatus;
  count?: number;
}) {
  return (
    <span className={`status status-${status}`}>
      <span className="status-dot" aria-hidden="true" />
      {STATUS_LABELS[status]}
      {count !== undefined ? ` ${count}` : ""}
    </span>
  );
}

export function EvidenceCounts({ counts }: { counts: Counts }) {
  const items: FindingStatus[] = [
    "fail",
    "warning",
    "pass",
    "unknown",
    "not_applicable",
  ];
  return (
    <div className="evidence-counts" aria-label="Evidence counts">
      {items.map((status) => (
        <div className={`count count-${status}`} key={status}>
          <span>{STATUS_LABELS[status]}</span>
          <strong>{counts[status]}</strong>
        </div>
      ))}
    </div>
  );
}

export function artifactCounts(artifact: ArtifactReport): Counts {
  const counts: Counts = {
    pass: 0,
    fail: 0,
    warning: 0,
    unknown: 0,
    not_applicable: 0,
  };
  for (const finding of artifact.findings) counts[finding.status] += 1;
  return counts;
}

export function FindingList({
  findings,
  compact = false,
}: {
  findings: Finding[];
  compact?: boolean;
}) {
  if (findings.length === 0) {
    return <p className="empty-state">No findings in this group.</p>;
  }
  const sortedFindings = [...findings].sort(
    (left, right) =>
      FINDING_STATUS_ORDER[left.status] - FINDING_STATUS_ORDER[right.status],
  );
  return (
    <div className={`finding-list ${compact ? "finding-list-compact" : ""}`}>
      {sortedFindings.map((finding, index) => (
        <article className="finding" key={`${finding.rule_id}-${index}`}>
          <div className="finding-main">
            <StatusBadge status={finding.status} />
            <div>
              <h3>{finding.title}</h3>
              <p>{finding.explanation}</p>
              {!compact && (
                <>
                  <div className="finding-meta">
                    <span>{finding.rule_id}</span>
                    <span>{finding.method}</span>
                    <span>{finding.confidence} confidence</span>
                    <span>{finding.subject}</span>
                  </div>
                  {Object.keys(finding.evidence).length > 0 && (
                    <details className="finding-evidence">
                      <summary>Observed evidence</summary>
                      <pre>{JSON.stringify(finding.evidence, null, 2)}</pre>
                    </details>
                  )}
                </>
              )}
            </div>
          </div>
          <a href={finding.source_url} aria-label={`Source for ${finding.title}`}>
            Source <span aria-hidden="true">↗</span>
          </a>
        </article>
      ))}
    </div>
  );
}

export function ArtifactCell({ artifact }: { artifact: ArtifactReport }) {
  const highlightedFindings = artifact.findings.filter(
    (finding) => finding.status === "fail" || finding.status === "warning",
  );

  return (
    <Link className="artifact-cell" to={`/artifact/${encodeURIComponent(artifact.id)}`}>
      <span className="artifact-name">
        View evidence <span aria-hidden="true">→</span>
        <span className="visually-hidden">
          {" "}for {artifact.guest} on {artifact.zkvm}
        </span>
      </span>
      <span className="artifact-cell-findings">
        {highlightedFindings.map((finding) => (
          <span
            className={`artifact-rule artifact-rule-${finding.status}`}
            key={finding.rule_id}
            title={finding.rule_id}
          >
            <span className="artifact-rule-dot" aria-hidden="true" />
            {finding.title}
          </span>
        ))}
        {highlightedFindings.length === 0 && (
          <span className="artifact-clear">No failures or warnings</span>
        )}
      </span>
    </Link>
  );
}

export function PageHeader({
  eyebrow,
  title,
  description,
  aside,
}: {
  eyebrow: string;
  title: string;
  description: string;
  aside?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h1>{title}</h1>
        <p className="lede">{description}</p>
      </div>
      {aside && <div className="page-header-aside">{aside}</div>}
    </header>
  );
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
}

export function shortSha(sha: string): string {
  return sha.slice(0, 8);
}
