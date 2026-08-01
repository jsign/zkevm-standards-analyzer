import { Layout } from "./components";
import { useReport } from "./report";
import { useHashPath } from "./router";
import { ArtifactPage } from "./pages/ArtifactPage";
import { OverviewPage } from "./pages/OverviewPage";
import { ReadinessPage } from "./pages/ReadinessPage";
import { StandardsPage } from "./pages/StandardsPage";

export function App() {
  const result = useReport();
  const path = useHashPath();
  const artifactMatch = path.match(/^\/artifact\/(.+)$/);
  const artifactId = artifactMatch ? decodeArtifactId(artifactMatch[1]) : null;
  return (
    <Layout currentPath={path}>
      {result.state === "loading" && (
        <div className="loading-state" role="status">
          <span className="loader" />
          <div>
            <strong>Loading analysis</strong>
            <span>Validating the generated evidence report…</span>
          </div>
        </div>
      )}
      {result.state === "error" && (
        <div className="fatal-state" role="alert">
          <p className="eyebrow">Report unavailable</p>
          <h1>The analysis data could not be loaded.</h1>
          <p>{result.error.message}</p>
          <code>
            Generate it with: cargo run -p zkevm-analyzer -- analyze --output
            web/public/data/report.json
          </code>
        </div>
      )}
      {result.state === "ready" && (
        <>
          {path === "/" && <OverviewPage report={result.report} />}
          {path === "/standards" && <StandardsPage report={result.report} />}
          {path === "/readiness" && <ReadinessPage report={result.report} />}
          {artifactId && (
            <ArtifactPage
              report={result.report}
              artifactId={artifactId}
            />
          )}
          {!["/", "/standards", "/readiness"].includes(path) &&
            !artifactId && <OverviewPage report={result.report} />}
        </>
      )}
    </Layout>
  );
}

function decodeArtifactId(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}
