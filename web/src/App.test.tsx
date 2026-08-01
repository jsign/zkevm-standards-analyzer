import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";
import { OverviewPage } from "./pages/OverviewPage";
import { StandardsPage } from "./pages/StandardsPage";
import { fixtureReport } from "./test/fixture";

afterEach(() => vi.unstubAllGlobals());

describe("overview", () => {
  it("shows release identity and evidence without a compliance score", () => {
    render(
      <OverviewPage report={fixtureReport} />,
    );
    expect(screen.getByRole("heading", { name: /v0.14.1 evidence report/i })).toBeInTheDocument();
    expect(screen.getByText("No score by design")).toBeInTheDocument();
    expect(screen.getByText("reth", { selector: "strong" })).toBeInTheDocument();
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
