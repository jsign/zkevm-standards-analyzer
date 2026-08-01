import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { ArtifactPage } from "./pages/ArtifactPage";
import { OverviewPage } from "./pages/OverviewPage";
import { StandardsPage } from "./pages/StandardsPage";
import { fixtureAnalysis, fixtureReport } from "./test/fixture";

afterEach(() => vi.unstubAllGlobals());

describe("overview", () => {
  it("shows release identity and evidence without a compliance score", () => {
    render(
      <OverviewPage report={fixtureReport} />,
    );
    expect(screen.getByRole("heading", { name: /v0.14.1 evidence report/i })).toBeInTheDocument();
    expect(screen.getByText("No score by design")).toBeInTheDocument();
    expect(screen.getByText("reth", { selector: "strong" })).toBeInTheDocument();
    expect(
      screen.getByRole("columnheader", { name: /openvm v2\.0\.0/i }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("v2.0.0")).toHaveLength(1);
    expect(screen.queryByText(/compliance percentage/i)).not.toBeInTheDocument();
  });

  it("shows the standards drift banner without hiding raw release data", () => {
    const stale = {
      ...fixtureReport,
      standards: {
        ...fixtureReport.standards,
        stale_paths: ["standards/riscv-target/target.md"],
      },
    };
    render(<OverviewPage report={stale} />);
    expect(screen.getByRole("alert")).toHaveTextContent("Rule review required");
    expect(screen.getByRole("table")).toBeInTheDocument();
  });
});

describe("standards", () => {
  it("filters findings by status with keyboard-accessible buttons", () => {
    render(<StandardsPage report={fixtureReport} />);
    fireEvent.click(screen.getByRole("button", { name: "pass" }));
    expect(screen.getByRole("button", { name: "pass" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.queryByText("The artifact is not ELF64.")).not.toBeInTheDocument();
  });
});

describe("artifact ELF structure", () => {
  it("shows the ELF hierarchy and nests program segments under their table", () => {
    const report = {
      ...fixtureReport,
      artifacts: [
        {
          ...fixtureReport.artifacts[0],
          analysis: fixtureAnalysis,
        },
      ],
    };

    render(
      <ArtifactPage
        report={report}
        artifactId={fixtureReport.artifacts[0].id}
      />,
    );

    expect(
      screen.getByRole("heading", { name: "ELF structure" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "ELF header" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Program header table" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Program segments" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Section header table" }),
    ).toBeInTheDocument();
    expect(screen.getByText("2 entries")).toBeInTheDocument();
    expect(screen.getByText("Load segments").nextElementSibling).toHaveTextContent("2");
    expect(screen.getByText("10 sections")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Sections" })).toBeInTheDocument();
    expect(screen.getByText(".text")).toBeInTheDocument();
    expect(screen.getByText(".symtab")).toBeInTheDocument();
    expect(screen.getByText("RISC-V architecture attributes")).toBeInTheDocument();
  });
});

describe("application states", () => {
  it("renders a useful report loading error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 404 }),
    );
    render(<App />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "could not be loaded",
    );
    await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
  });
});
