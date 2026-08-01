export type RiscvIsaComponent = {
  id: string;
  label: string;
  version: string | null;
  description: string;
  referenceLabel: string;
  referenceUrl: string;
};

export type RiscvTargetPolicy = {
  status: "excluded" | "outside-minimal";
  label: string;
  description: string;
};

type ExtensionReference = Omit<RiscvIsaComponent, "id" | "label" | "version">;

const UNPRIVILEGED_ISA = "https://docs.riscv.org/reference/isa/unpriv";
const NAMING_REFERENCE = `${UNPRIVILEGED_ISA}/naming.html`;

const EXTENSION_REFERENCES: Record<string, ExtensionReference> = {
  m: {
    description: "Integer multiplication and division; includes Zmmul.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/m-st-ext.html`,
  },
  a: {
    description: "Atomic instructions, comprising Zaamo and Zalrsc.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/a-st-ext.html`,
  },
  f: {
    description: "Single-precision floating-point instructions.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/f-st-ext.html`,
  },
  d: {
    description: "Double-precision floating-point instructions.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/d-st-ext.html`,
  },
  c: {
    description: "Compressed 16-bit instruction encodings.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/c-st-ext.html`,
  },
  v: {
    description: "Vector instructions.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/v-st-ext.html`,
  },
  zicsr: {
    description: "Control and status register instructions.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/zicsr.html`,
  },
  zifencei: {
    description: "Instruction-fetch fence.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/zifencei.html`,
  },
  zmmul: {
    description: "Integer multiplication subset of M, without division.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/m-st-ext.html`,
  },
  zaamo: {
    description: "Atomic read-modify-write memory operations.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/a-st-ext.html`,
  },
  zalrsc: {
    description: "Load-reserved/store-conditional atomic operations.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/a-st-ext.html`,
  },
  zca: {
    description: "Core compressed instructions, excluding floating-point loads and stores.",
    referenceLabel: "RISC-V ISA",
    referenceUrl: `${UNPRIVILEGED_ISA}/zc.html`,
  },
  zicclsm: {
    description: "Main memory supports misaligned regular loads and stores.",
    referenceLabel: "RISC-V Profiles",
    referenceUrl:
      "https://docs.riscv.org/reference/rva20-rvi20-rva22/v1.0/extensions.html",
  },
};

export const RISCV_ARCH_ATTRIBUTE_REFERENCE =
  "https://riscv-non-isa.github.io/riscv-elf-psabi-doc/#tag_riscv_arch";

const MINIMAL_TARGET_EXTENSIONS = new Set(["m", "zicclsm", "zmmul"]);

export function decodeRiscvArchitecture(architecture: string): RiscvIsaComponent[] {
  const [baseToken, ...extensionTokens] = architecture.toLowerCase().split("_");
  const baseMatch = baseToken.match(/^rv(32|64)([ie])(\d+(?:p\d+)*)?(.*)$/);
  if (!baseMatch) {
    return [];
  }

  const [, xlen, baseName, baseVersion, compactExtensions] = baseMatch;
  const components = [
    makeBaseComponent(xlen, baseName, baseVersion ?? null),
  ];

  for (const match of compactExtensions.matchAll(/([a-z])(\d+(?:p\d+)*)?/g)) {
    components.push(makeExtensionComponent(match[1], match[2] ?? null));
  }

  for (const token of extensionTokens.filter(Boolean)) {
    const parsed = token.match(/^(.+?)(\d+(?:p\d+)+)$/);
    const name = parsed?.[1] ?? token;
    const version = parsed?.[2] ?? null;
    components.push(makeExtensionComponent(name, version));
  }

  return components;
}

export function classifyRiscvTargetComponent(
  componentId: string,
): RiscvTargetPolicy | null {
  const id = componentId.toLowerCase();

  if (id.startsWith("rv") || MINIMAL_TARGET_EXTENSIONS.has(id)) {
    return null;
  }

  if (id === "c" || id.startsWith("zc")) {
    return {
      status: "excluded",
      label: "Excluded by standard",
      description:
        "Compressed instruction extensions are explicitly excluded by the target standard.",
    };
  }

  if (id === "f" || id === "d") {
    return {
      status: "excluded",
      label: "Excluded by standard",
      description:
        "F and D floating-point extensions are explicitly excluded by the soft-float target standard.",
    };
  }

  return {
    status: "outside-minimal",
    label: "Outside minimal target",
    description:
      "This extension is not part of the standard's minimal RV64IM_Zicclsm target; its presence is not an incompatibility on its own.",
  };
}

function makeBaseComponent(
  xlen: string,
  name: string,
  version: string | null,
): RiscvIsaComponent {
  const reduced = name === "e";
  return {
    id: `rv${xlen}${name}`,
    label: `RV${xlen}${name.toUpperCase()}`,
    version: formatVersion(version),
    description: reduced
      ? `${xlen}-bit reduced-register base integer ISA.`
      : `${xlen}-bit base integer ISA.`,
    referenceLabel: "RISC-V ISA",
    referenceUrl: reduced
      ? `${UNPRIVILEGED_ISA}/rv32e.html`
      : `${UNPRIVILEGED_ISA}/rv${xlen}.html`,
  };
}

function makeExtensionComponent(
  name: string,
  version: string | null,
): RiscvIsaComponent {
  const reference = EXTENSION_REFERENCES[name] ?? fallbackReference(name);
  return {
    id: name,
    label: formatExtensionName(name),
    version: formatVersion(version),
    ...reference,
  };
}

function fallbackReference(name: string): ExtensionReference {
  let description = "Standard ISA extension.";
  if (name.startsWith("s")) {
    description = "Supervisor-level ISA extension.";
  } else if (name.startsWith("x")) {
    description = "Non-standard ISA extension.";
  }
  return {
    description,
    referenceLabel: "Naming reference",
    referenceUrl: NAMING_REFERENCE,
  };
}

function formatExtensionName(name: string) {
  return name.length === 1
    ? name.toUpperCase()
    : `${name[0].toUpperCase()}${name.slice(1)}`;
}

function formatVersion(version: string | null) {
  return version?.replaceAll("p", ".") ?? null;
}
