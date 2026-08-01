import { describe, expect, it } from "vitest";
import { decodeRiscvArchitecture } from "./riscv";

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
});
