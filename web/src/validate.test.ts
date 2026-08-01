import { describe, expect, it } from "vitest";
import { artifactCounts } from "./components";
import { fixtureReport } from "./test/fixture";
import { parseReport } from "./validate";

describe("ReportV1 contract", () => {
  it("accepts the checked fixture", () => {
    expect(parseReport(fixtureReport)).toEqual(fixtureReport);
  });

  it("rejects malformed report data", () => {
    expect(() => parseReport({ schema_version: "1" })).toThrow(
      /does not match schema/,
    );
  });

  it("aggregates artifact evidence statuses", () => {
    expect(artifactCounts(fixtureReport.artifacts[0])).toEqual({
      pass: 0,
      fail: 1,
      warning: 0,
      unknown: 0,
      not_applicable: 0,
    });
  });
});
