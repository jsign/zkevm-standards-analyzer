import { describe, expect, it } from "vitest";
import {
  classifyRiscvTargetComponent,
  decodeRiscvArchitecture,
} from "./riscv";

describe("RISC-V architecture decoder", () => {
  it("decodes every ISA component observed in the generated report", () => {
    expect(
      decodeRiscvArchitecture(
        "rv64i2p1_m2p0_a2p1_zicclsm1p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0",
      ),
    ).toMatchObject([
      { label: "RV64I", version: "2.1" },
      { label: "M", version: "2.0" },
      { label: "A", version: "2.1" },
      {
        label: "Zicclsm",
        version: "1.0",
        referenceLabel: "RISC-V Profiles",
      },
      { label: "Zmmul", version: "1.0" },
      { label: "Zaamo", version: "1.0" },
      { label: "Zalrsc", version: "1.0" },
      { label: "Zca", version: "1.0" },
    ]);
  });

  it("supports compact, unversioned march-style declarations", () => {
    expect(decodeRiscvArchitecture("rv64im_zicsr")).toMatchObject([
      { label: "RV64I", version: null },
      { label: "M", version: null },
      { label: "Zicsr", version: null },
    ]);
  });

  it("distinguishes explicitly excluded extensions from profile additions", () => {
    expect(classifyRiscvTargetComponent("c")).toMatchObject({
      status: "excluded",
    });
    expect(classifyRiscvTargetComponent("Zca")).toMatchObject({
      status: "excluded",
    });
    expect(classifyRiscvTargetComponent("f")).toMatchObject({
      status: "excluded",
    });
    expect(classifyRiscvTargetComponent("d")).toMatchObject({
      status: "excluded",
    });
    expect(classifyRiscvTargetComponent("a")).toMatchObject({
      status: "outside-minimal",
    });
    expect(classifyRiscvTargetComponent("Zaamo")).toMatchObject({
      status: "outside-minimal",
    });
    expect(classifyRiscvTargetComponent("m")).toBeNull();
    expect(classifyRiscvTargetComponent("Zmmul")).toBeNull();
    expect(classifyRiscvTargetComponent("Zicclsm")).toBeNull();
  });
});
