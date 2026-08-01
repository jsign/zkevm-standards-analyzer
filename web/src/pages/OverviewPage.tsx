import { Link } from "../router";
import {
  ArtifactCell,
  EvidenceCounts,
  FindingList,
  PageHeader,
  artifactCounts,
  formatBytes,
  shortSha,
} from "../components";
import type { ArtifactReport, ReportV1 } from "../types";

export function OverviewPage({ report }: { report: ReportV1 }) {
  const primary = report.artifacts.filter((artifact) => artifact.variant === "primary");
  const profiling = report.artifacts.filter(
    (artifact) => artifact.variant === "profiling",
  );
  const guests = [...new Set(primary.map((artifact) => artifact.guest))];
  const zkvmColumns = [
    ...new Map(
      primary.map((artifact) => [
        `${artifact.zkvm}:${artifact.zkvm_version}`,
        { zkvm: artifact.zkvm, version: artifact.zkvm_version },
      ] as const),
    ).values(),
  ];
  const critical = primary
    .flatMap((artifact) =>
      artifact.findings
        .filter((finding) => finding.status === "fail")
        .map((finding) => ({ artifact, finding })),
    )
    .slice(0, 6);

  return (
    <>
      {report.standards.stale_paths.length > 0 && (
        <div className="stale-banner" role="alert">
          <strong>Rule review required.</strong>
          <span>
            {report.standards.stale_paths.length} referenced standards file
            {report.standards.stale_paths.length === 1 ? " has" : "s have"} changed.
            Affected checks are marked unknown.
          </span>
          <Link to="/standards">Review coverage</Link>
        </div>
      )}
      <PageHeader
        eyebrow={`Latest published release · ${new Date(report.release.published_at).toLocaleDateString()}`}
        title={`${report.release.tag} evidence report`}
        description="Static ELF and publication evidence for guest programs targeting Ethereum zkVMs. Unknowns are shown deliberately where runtime or manual assessment is required."
        aside={
          <div className="snapshot-box">
            <span>Standards snapshot</span>
            <a
              href={`https://github.com/eth-act/zkevm-standards/commit/${report.standards.commit}`}
            >
              {shortSha(report.standards.commit)} <span aria-hidden="true">↗</span>
            </a>
            <small>main · analyzed {new Date(report.generated_at).toLocaleString()}</small>
            <small>
              {report.standards.stale_paths.length === 0
                ? "Rule catalog current"
                : `${report.standards.stale_paths.length} stale source paths`}
            </small>
          </div>
        }
      />

      <EvidenceCounts counts={report.summary} />
      <div className="report-meta" aria-label="Report metadata">
        <span>
          Analyzer <strong>v{report.analyzer.version}</strong>
          {report.analyzer.commit && (
            <code>{shortSha(report.analyzer.commit)}</code>
          )}
        </span>
        <span>
          Ere commit{" "}
          <a
            href={`https://github.com/eth-act/ere-guests/commit/${report.release.commit}`}
          >
            {shortSha(report.release.commit)}
          </a>
        </span>
        <span>
          Compiler <strong>{report.release.compiler ?? "unavailable"}</strong>
        </span>
        {report.release.workflow_url && (
          <a href={report.release.workflow_url}>
            Public release workflow <span aria-hidden="true">↗</span>
          </a>
        )}
      </div>

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Release matrix</p>
            <h2>Guest × zkVM</h2>
          </div>
          <a href={report.release.url}>
            Open release <span aria-hidden="true">↗</span>
          </a>
        </div>
        <div className="matrix-wrap">
          <table className="matrix-table">
            <caption className="visually-hidden">
              Primary guest ELF artifacts grouped by guest and zkVM
            </caption>
            <thead>
              <tr>
                <th scope="col">Guest</th>
                {zkvmColumns.map(({ zkvm, version }) => (
                  <th
                    scope="col"
                    key={`${zkvm}:${version}`}
                    aria-label={`${zkvm} ${version}`}
                  >
                    <span>{zkvm}</span>
                    <small>{version}</small>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {guests.map((guest) => (
                <tr key={guest}>
                  <th scope="row">
                    <strong>{guest}</strong>
                    <small>
                      {primary.find((artifact) => artifact.guest === guest)
                        ?.guest_version ?? "version unavailable"}
                    </small>
                  </th>
                  {zkvmColumns.map(({ zkvm, version }) => {
                    const artifact = primary.find(
                      (item) =>
                        item.guest === guest &&
                        item.zkvm === zkvm &&
                        item.zkvm_version === version,
                    );
                    return (
                      <td key={`${zkvm}:${version}`}>
                        {artifact ? (
                          <ArtifactCell artifact={artifact} />
                        ) : (
                          <span className="matrix-empty">Not published</span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {profiling.length > 0 && (
          <details className="variants">
            <summary>{profiling.length} profiling variants</summary>
            <div>
              {profiling.map((artifact) => (
                <Link
                  key={artifact.id}
                  to={`/artifact/${encodeURIComponent(artifact.id)}`}
                >
                  <span>{artifact.guest} / {artifact.zkvm}</span>
                  <small>
                    {artifact.analysis
                      ? formatBytes(artifact.analysis.metrics.asset_bytes)
                      : "analysis unavailable"}
                  </small>
                </Link>
              ))}
            </div>
          </details>
        )}
      </section>

      <div className="overview-grid">
        <section className="section-block">
          <div className="section-heading">
            <div>
              <p className="eyebrow">Attention</p>
              <h2>Static failures</h2>
            </div>
          </div>
          {critical.length ? (
            <FindingList
              compact
              findings={critical.map(({ finding }) => finding)}
            />
          ) : (
            <p className="empty-state">No static failures were observed.</p>
          )}
        </section>

        <aside className="method-note">
          <p className="eyebrow">How to read this</p>
          <h2>No score by design</h2>
          <p>
            A pass means the available evidence satisfies one atomic check. It
            does not turn unknown runtime behavior into compliance.
          </p>
          <dl>
            <div>
              <dt>{primary.length}</dt>
              <dd>primary ELFs</dd>
            </div>
            <div>
              <dt>
                {primary.filter((artifact) => artifactCounts(artifact).fail > 0).length}
              </dt>
              <dd>with static failures</dd>
            </div>
            <div>
              <dt>{report.platforms.length}</dt>
              <dd>zkVM targets</dd>
            </div>
          </dl>
          <Link to="/standards">See automation coverage →</Link>
        </aside>
      </div>
    </>
  );
}
