import {
  FindingList,
  PageHeader,
  StatusBadge,
  formatBytes,
} from "../components";
import type { ReportV1 } from "../types";

export function ReadinessPage({ report }: { report: ReportV1 }) {
  const primary = report.artifacts.filter((artifact) => artifact.variant === "primary");
  return (
    <>
      <PageHeader
        eyebrow="Guest handbook"
        title="Release readiness"
        description="Publication and repository evidence is separated from criteria that still need runtime tests, formal-verification guidance, benchmarks, or human assessment."
      />
      <div className="readiness-links" aria-label="Release evidence links">
        <span>
          Public key{" "}
          {report.artifacts.some(
            (artifact) => artifact.provenance.public_key_url,
          ) ? (
            <a
              href={
                report.artifacts.find(
                  (artifact) => artifact.provenance.public_key_url,
                )!.provenance.public_key_url!
              }
            >
              published ↗
            </a>
          ) : (
            <strong>not found</strong>
          )}
        </span>
        <span>
          Release CI{" "}
          {report.release.workflow_url ? (
            <a href={report.release.workflow_url}>successful workflow ↗</a>
          ) : (
            <strong>not discovered</strong>
          )}
        </span>
        <span>Workflow evidence is not an artifact attestation.</span>
      </div>

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Release-level rubric</p>
            <h2>Known gaps stay visible</h2>
          </div>
        </div>
        <FindingList findings={report.readiness} />
      </section>

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Published assets</p>
            <h2>Provenance inventory</h2>
          </div>
          <span className="quiet-label">Cryptographic verification deferred</span>
        </div>
        <div className="table-scroll">
          <table className="data-table provenance-table">
            <caption className="visually-hidden">
              Release asset and provenance readiness evidence
            </caption>
            <thead>
              <tr>
                <th scope="col">Guest / zkVM</th>
                <th scope="col">ELF</th>
                <th scope="col">Digest</th>
                <th scope="col">ELF signature</th>
                <th scope="col">VK</th>
                <th scope="col">VK signature</th>
                <th scope="col">License</th>
                <th scope="col">Upstream</th>
              </tr>
            </thead>
            <tbody>
              {primary.map((artifact) => {
                const vk = artifact.provenance.verification_key;
                const licenses = artifact.provenance.licenses;
                return (
                  <tr key={artifact.id}>
                    <th scope="row">
                      {artifact.guest}
                      <small>{artifact.zkvm}</small>
                    </th>
                    <td>
                      <a href={artifact.provenance.elf.url}>
                        {formatBytes(artifact.provenance.elf.size)}
                      </a>
                    </td>
                    <td>
                      <StatusBadge
                        status={
                          artifact.provenance.elf.digest_matches === true
                            ? "pass"
                            : artifact.provenance.elf.digest_matches === false
                              ? "fail"
                              : "unknown"
                        }
                      />
                    </td>
                    <td>
                      <StatusBadge
                        status={
                          artifact.provenance.elf.signature_published ? "pass" : "fail"
                        }
                      />
                    </td>
                    <td>
                      <StatusBadge status={vk ? "pass" : "fail"} />
                    </td>
                    <td>
                      <StatusBadge
                        status={vk?.signature_published ? "pass" : "fail"}
                      />
                    </td>
                    <td>
                      <StatusBadge
                        status={
                          licenses.mit && licenses.apache_2 ? "pass" : "fail"
                        }
                      />
                    </td>
                    <td>
                      {artifact.origin === "compiled" ? (
                        <StatusBadge status="not_applicable" />
                      ) : artifact.provenance.source?.matches_hub_asset === true ? (
                        <a href={artifact.provenance.source.release_url}>
                          <StatusBadge status="pass" />
                        </a>
                      ) : artifact.provenance.source?.matches_hub_asset === false ? (
                        <StatusBadge status="fail" />
                      ) : (
                        <StatusBadge status="unknown" />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="table-note">
          A “Pass” in signature columns means the corresponding <code>.minisig</code>
          file is published. v1 does not authenticate its key or verify its contents.
        </p>
      </section>

      <section className="section-block">
        <div className="section-heading">
          <div>
            <p className="eyebrow">Runtime boundary</p>
            <h2>Platform evidence still required</h2>
          </div>
        </div>
        <div className="platform-columns">
          {report.platforms.map((platform) => (
            <div key={platform.zkvm}>
              <h3>{platform.zkvm}</h3>
              <FindingList findings={platform.findings} compact />
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
