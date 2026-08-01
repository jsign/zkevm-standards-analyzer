use std::{collections::BTreeMap, fs, path::Path};

use anyhow::Context;
use capstone::{
    Capstone,
    arch::{
        BuildsCapstone, BuildsCapstoneExtraMode,
        riscv::{ArchExtraMode, ArchMode},
    },
};
use goblin::elf::{
    Elf,
    header::{ELFCLASS64, ELFDATA2LSB, EM_RISCV, ET_EXEC, machine_to_str},
    program_header::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, pt_to_str},
    section_header::{SHF_ALLOC, SHF_EXECINSTR, SHF_WRITE, SHT_NOBITS},
};

use crate::model::{
    AcceleratorEvidence, Confidence, ElfAnalysis, ElfChecks, ElfHeader, ElfMetrics,
    InstructionCensus, MnemonicCount, ProgramHeader, SymbolEvidence,
};

pub fn analyze_elf(path: &Path, accelerator_patterns: &[String]) -> anyhow::Result<ElfAnalysis> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let elf = Elf::parse(&bytes).context("asset is not a parseable ELF")?;
    let load_segments = elf
        .program_headers
        .iter()
        .filter(|header| header.p_type == PT_LOAD)
        .collect::<Vec<_>>();
    let load_metrics = summarize_load_segments(&load_segments);
    let load_checks = evaluate_load_segments(&load_segments, bytes.len() as u64, elf.entry);

    let symbols = collect_symbols(&elf);
    let riscv_arch = extract_riscv_arch(&elf, &bytes);
    let instructions = instruction_census(&elf, &bytes)?;
    let accelerators = accelerator_evidence(&elf, accelerator_patterns);
    let code_data_separated = code_data_separated(&elf);
    let header_checks = evaluate_header(&elf, &bytes);

    let program_headers = elf
        .program_headers
        .iter()
        .map(|header| ProgramHeader {
            kind: pt_to_str(header.p_type).to_string(),
            offset: header.p_offset,
            virtual_address: header.p_vaddr,
            physical_address: header.p_paddr,
            file_size: header.p_filesz,
            memory_size: header.p_memsz,
            flags: flags_string(header.p_flags),
            alignment: header.p_align,
        })
        .collect();

    let has_debug_sections = elf.section_headers.iter().any(|header| {
        elf.shdr_strtab
            .get_at(header.sh_name)
            .is_some_and(|name| name.starts_with(".debug") || name.starts_with(".zdebug"))
    });

    let checks = ElfChecks {
        magic: header_checks.magic,
        elf64: header_checks.elf64,
        little_endian: header_checks.little_endian,
        riscv_machine: header_checks.riscv_machine,
        executable_type: header_checks.executable_type,
        statically_linked: header_checks.statically_linked,
        load_ranges_in_file: load_checks.ranges_in_file,
        file_size_within_memory_size: load_checks.file_size_within_memory_size,
        vma_equals_lma: load_checks.vma_equals_lma,
        alignment_valid: load_checks.alignment_valid,
        load_segments_do_not_overlap: load_checks.do_not_overlap,
        write_xor_execute: load_checks.write_xor_execute,
        executable_permissions_valid: load_checks.executable_permissions_valid,
        entry_aligned: load_checks.entry_aligned,
        entry_in_executable_segment: load_checks.entry_in_executable_segment,
        code_data_separated,
        entry_matches_start: symbols.start.map(|address| address == elf.entry),
    };

    Ok(ElfAnalysis {
        metrics: ElfMetrics {
            asset_bytes: bytes.len() as u64,
            load_file_bytes: load_metrics.file_bytes,
            load_memory_bytes: load_metrics.memory_bytes,
            executable_bytes: load_metrics.executable_bytes,
            read_only_bytes: load_metrics.read_only_bytes,
            writable_bytes: load_metrics.writable_bytes,
            bss_zero_fill_bytes: load_metrics.bss_zero_fill_bytes,
            program_header_count: elf.program_headers.len() as u64,
            section_count: elf.section_headers.len() as u64,
            symbol_count: elf.syms.len() as u64,
            stripped: elf.syms.is_empty(),
            has_debug_sections,
        },
        header: ElfHeader {
            class: if elf.is_64 { "ELF64" } else { "ELF32" }.to_string(),
            little_endian: elf.little_endian,
            elf_type: goblin::elf::header::et_to_str(elf.header.e_type).to_string(),
            machine: machine_to_str(elf.header.e_machine).to_string(),
            entry: elf.entry,
            entry_hex: format!("0x{:X}", elf.entry),
            flags: elf.header.e_flags,
            riscv_arch,
        },
        program_headers,
        symbols,
        instructions,
        accelerators,
        checks,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct HeaderChecks {
    magic: bool,
    elf64: bool,
    little_endian: bool,
    riscv_machine: bool,
    executable_type: bool,
    statically_linked: bool,
}

fn evaluate_header(elf: &Elf<'_>, bytes: &[u8]) -> HeaderChecks {
    HeaderChecks {
        magic: bytes.starts_with(b"\x7fELF"),
        elf64: elf.header.e_ident[goblin::elf::header::EI_CLASS] == ELFCLASS64,
        little_endian: elf.header.e_ident[goblin::elf::header::EI_DATA] == ELFDATA2LSB,
        riscv_machine: elf.header.e_machine == EM_RISCV,
        executable_type: elf.header.e_type == ET_EXEC,
        statically_linked: !elf
            .program_headers
            .iter()
            .any(|header| matches!(header.p_type, PT_INTERP | PT_DYNAMIC)),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct LoadMetrics {
    file_bytes: u64,
    memory_bytes: u64,
    executable_bytes: u64,
    read_only_bytes: u64,
    writable_bytes: u64,
    bss_zero_fill_bytes: u64,
}

fn summarize_load_segments(
    load_segments: &[&goblin::elf::program_header::ProgramHeader],
) -> LoadMetrics {
    let mut metrics = LoadMetrics::default();
    for segment in load_segments {
        metrics.file_bytes = metrics.file_bytes.saturating_add(segment.p_filesz);
        metrics.memory_bytes = metrics.memory_bytes.saturating_add(segment.p_memsz);
        metrics.bss_zero_fill_bytes = metrics
            .bss_zero_fill_bytes
            .saturating_add(segment.p_memsz.saturating_sub(segment.p_filesz));
        if segment.p_flags & PF_X != 0 {
            metrics.executable_bytes = metrics.executable_bytes.saturating_add(segment.p_memsz);
        } else if segment.p_flags & PF_W != 0 {
            metrics.writable_bytes = metrics.writable_bytes.saturating_add(segment.p_memsz);
        } else if segment.p_flags & PF_R != 0 {
            metrics.read_only_bytes = metrics.read_only_bytes.saturating_add(segment.p_memsz);
        }
    }
    metrics
}

#[derive(Debug, PartialEq, Eq)]
struct LoadChecks {
    ranges_in_file: bool,
    file_size_within_memory_size: bool,
    vma_equals_lma: bool,
    alignment_valid: bool,
    do_not_overlap: bool,
    write_xor_execute: bool,
    executable_permissions_valid: bool,
    entry_aligned: bool,
    entry_in_executable_segment: bool,
}

fn evaluate_load_segments(
    load_segments: &[&goblin::elf::program_header::ProgramHeader],
    file_len: u64,
    entry: u64,
) -> LoadChecks {
    LoadChecks {
        ranges_in_file: load_segments.iter().all(|segment| {
            segment
                .p_offset
                .checked_add(segment.p_filesz)
                .is_some_and(|end| end <= file_len)
        }),
        file_size_within_memory_size: load_segments
            .iter()
            .all(|segment| segment.p_filesz <= segment.p_memsz),
        vma_equals_lma: load_segments
            .iter()
            .all(|segment| segment.p_vaddr == segment.p_paddr),
        alignment_valid: load_segments.iter().all(|segment| {
            segment.p_align <= 1
                || (segment.p_align.is_power_of_two()
                    && segment.p_vaddr % segment.p_align == segment.p_offset % segment.p_align)
        }),
        do_not_overlap: segments_do_not_overlap(load_segments),
        write_xor_execute: load_segments
            .iter()
            .all(|segment| segment.p_flags & (PF_W | PF_X) != (PF_W | PF_X)),
        executable_permissions_valid: load_segments
            .iter()
            .all(|segment| segment.p_flags & PF_X == 0 || segment.p_flags & !(PF_R | PF_X) == 0),
        entry_aligned: entry.is_multiple_of(4),
        entry_in_executable_segment: load_segments.iter().any(|segment| {
            segment.p_flags & PF_X != 0
                && entry >= segment.p_vaddr
                && segment
                    .p_vaddr
                    .checked_add(segment.p_memsz)
                    .is_some_and(|end| entry < end)
        }),
    }
}

fn collect_symbols(elf: &Elf<'_>) -> SymbolEvidence {
    let mut evidence = SymbolEvidence {
        start: None,
        main: None,
        heap_start: None,
        heap_end: None,
        read_input: false,
        write_output: false,
    };
    for symbol in &elf.syms {
        let Some(name) = elf.strtab.get_at(symbol.st_name) else {
            continue;
        };
        match name {
            "_start" => evidence.start = Some(symbol.st_value),
            "main" => evidence.main = Some(symbol.st_value),
            "_heap_start" => evidence.heap_start = Some(symbol.st_value),
            "_heap_end" => evidence.heap_end = Some(symbol.st_value),
            "read_input" => evidence.read_input = true,
            "write_output" => evidence.write_output = true,
            _ => {}
        }
    }
    evidence
}

fn accelerator_evidence(elf: &Elf<'_>, platform_patterns: &[String]) -> AcceleratorEvidence {
    let mut standard = Vec::new();
    let mut platform = Vec::new();
    let crypto_terms = [
        "keccak", "sha256", "secp", "bn254", "bls12", "kzg", "poseidon", "acceler",
    ];
    for symbol in &elf.syms {
        let Some(name) = elf.strtab.get_at(symbol.st_name) else {
            continue;
        };
        if name.starts_with("zkvm_") {
            standard.push(name.to_string());
        } else {
            let lower = name.to_ascii_lowercase();
            if platform_patterns
                .iter()
                .any(|pattern| lower.contains(&pattern.to_ascii_lowercase()))
                && crypto_terms.iter().any(|term| lower.contains(term))
            {
                platform.push(truncate_symbol(name));
            }
        }
    }
    standard.sort();
    standard.dedup();
    platform.sort();
    platform.dedup();
    platform.truncate(80);
    AcceleratorEvidence {
        standard_symbols: standard,
        platform_symbols: platform,
        note: "Static linked-symbol evidence only; this does not prove a function is reachable or called for any input.".to_string(),
    }
}

fn instruction_census(elf: &Elf<'_>, bytes: &[u8]) -> anyhow::Result<InstructionCensus> {
    let mut regions = Vec::new();
    for section in &elf.section_headers {
        if section.sh_flags & (SHF_EXECINSTR as u64) == 0
            || section.sh_type == SHT_NOBITS
            || section.sh_size == 0
        {
            continue;
        }
        if let Some(range) = checked_file_range(section.sh_offset, section.sh_size, bytes.len()) {
            regions.push((range, section.sh_addr));
        }
    }
    let (source, confidence) = if regions.is_empty() {
        for segment in &elf.program_headers {
            if segment.p_type == PT_LOAD
                && segment.p_flags & PF_X != 0
                && segment.p_filesz > 0
                && let Some(range) =
                    checked_file_range(segment.p_offset, segment.p_filesz, bytes.len())
            {
                regions.push((range, segment.p_vaddr));
            }
        }
        ("executable_segments".to_string(), Confidence::Low)
    } else {
        ("executable_sections".to_string(), Confidence::High)
    };

    let mode = if elf.is_64 {
        ArchMode::RiscV64
    } else {
        ArchMode::RiscV32
    };
    let capstone = Capstone::new()
        .riscv()
        .mode(mode)
        .extra_mode([ArchExtraMode::RiscVC].into_iter())
        .build()
        .context("failed to initialize the RISC-V decoder")?;

    let mut decoded_instructions = 0_u64;
    let mut decoded_bytes = 0_u64;
    let mut undecodable_bytes = 0_u64;
    let mut compressed = 0_u64;
    let mut atomic = 0_u64;
    let mut floating_point = 0_u64;
    let mut privileged_or_syscall = 0_u64;
    let mut mnemonics = BTreeMap::<String, u64>::new();

    for (range, address) in regions {
        let region = &bytes[range];
        let mut offset = 0_usize;
        while offset < region.len() {
            let instructions = capstone
                .disasm_count(&region[offset..], address + offset as u64, 4096)
                .context("RISC-V decoder failed")?;
            if instructions.is_empty() {
                let step = riscv_instruction_length(&region[offset..]);
                undecodable_bytes += step as u64;
                offset += step;
                continue;
            }
            let mut consumed = 0_usize;
            for instruction in instructions.iter() {
                let length = instruction.bytes().len();
                if length == 0 {
                    continue;
                }
                consumed += length;
                decoded_instructions += 1;
                decoded_bytes += length as u64;
                let mnemonic = instruction.mnemonic().unwrap_or("unknown");
                *mnemonics.entry(mnemonic.to_string()).or_default() += 1;
                let classification = classify_mnemonic(mnemonic, length);
                compressed += u64::from(classification.compressed);
                atomic += u64::from(classification.atomic);
                floating_point += u64::from(classification.floating_point);
                privileged_or_syscall += u64::from(classification.privileged_or_syscall);
            }
            if consumed == 0 {
                let step = riscv_instruction_length(&region[offset..]);
                undecodable_bytes += step as u64;
                offset += step;
            } else {
                offset += consumed;
            }
        }
    }

    let mut top_mnemonics = mnemonics
        .into_iter()
        .map(|(mnemonic, count)| MnemonicCount { mnemonic, count })
        .collect::<Vec<_>>();
    top_mnemonics.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.mnemonic.cmp(&right.mnemonic))
    });
    top_mnemonics.truncate(20);

    Ok(InstructionCensus {
        source,
        confidence,
        decoded_instructions,
        decoded_bytes,
        undecodable_bytes,
        compressed,
        atomic,
        floating_point,
        privileged_or_syscall,
        top_mnemonics,
    })
}

fn riscv_instruction_length(bytes: &[u8]) -> usize {
    if bytes.len() < 2 {
        return bytes.len();
    }
    let halfword = u16::from_le_bytes([bytes[0], bytes[1]]);
    let expected = if halfword & 0b11 != 0b11 {
        2
    } else if halfword & 0b1_1100 != 0b1_1100 {
        4
    } else if halfword & 0b11_1111 == 0b01_1111 {
        6
    } else if halfword & 0b111_1111 == 0b011_1111 {
        8
    } else {
        2 + 2 * (((halfword >> 12) & 0b111) as usize)
    };
    expected.min(bytes.len())
}

#[derive(Default)]
struct InstructionClassification {
    compressed: bool,
    atomic: bool,
    floating_point: bool,
    privileged_or_syscall: bool,
}

fn classify_mnemonic(mnemonic: &str, length: usize) -> InstructionClassification {
    let lower = mnemonic.to_ascii_lowercase();
    let atomic = lower.starts_with("amo") || lower.starts_with("lr.") || lower.starts_with("sc.");
    let float_prefixes = [
        "fadd", "fsub", "fmul", "fdiv", "fsqrt", "fmadd", "fmsub", "fnm", "flw", "fld", "fsw",
        "fsd", "fcvt", "fmv", "fclass", "feq", "flt", "fle", "fmin", "fmax",
    ];
    let privileged = ["ecall", "mret", "sret", "uret", "wfi", "sfence", "hfence"];
    InstructionClassification {
        compressed: length == 2 || lower.starts_with("c."),
        atomic,
        floating_point: float_prefixes
            .iter()
            .any(|prefix| lower.starts_with(prefix)),
        privileged_or_syscall: privileged.iter().any(|prefix| lower.starts_with(prefix))
            || lower.starts_with("csr"),
    }
}

fn code_data_separated(elf: &Elf<'_>) -> Option<bool> {
    if elf.section_headers.is_empty() {
        return None;
    }
    let executable_segments = elf
        .program_headers
        .iter()
        .filter(|segment| segment.p_type == PT_LOAD && segment.p_flags & PF_X != 0)
        .collect::<Vec<_>>();
    for section in &elf.section_headers {
        let flags = section.sh_flags;
        let is_read_only_data = flags & (SHF_ALLOC as u64) != 0
            && flags & (SHF_WRITE as u64) == 0
            && flags & (SHF_EXECINSTR as u64) == 0
            && section.sh_size > 0;
        if !is_read_only_data {
            continue;
        }
        let section_end = section.sh_addr.checked_add(section.sh_size)?;
        if executable_segments.iter().any(|segment| {
            let Some(segment_end) = segment.p_vaddr.checked_add(segment.p_memsz) else {
                return false;
            };
            section.sh_addr < segment_end && section_end > segment.p_vaddr
        }) {
            return Some(false);
        }
    }
    Some(true)
}

fn segments_do_not_overlap(segments: &[&goblin::elf::program_header::ProgramHeader]) -> bool {
    let mut ranges = Vec::new();
    for segment in segments {
        let Some(end) = segment.p_vaddr.checked_add(segment.p_memsz) else {
            return false;
        };
        if segment.p_memsz > 0 {
            ranges.push((segment.p_vaddr, end));
        }
    }
    ranges.sort_unstable();
    ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0)
}

fn extract_riscv_arch(elf: &Elf<'_>, bytes: &[u8]) -> Option<String> {
    let section = elf.section_headers.iter().find(|header| {
        elf.shdr_strtab
            .get_at(header.sh_name)
            .is_some_and(|name| name == ".riscv.attributes")
    })?;
    let range = checked_file_range(section.sh_offset, section.sh_size, bytes.len())?;
    extract_arch_ascii(&bytes[range])
}

fn extract_arch_ascii(bytes: &[u8]) -> Option<String> {
    for index in 0..bytes.len().saturating_sub(3) {
        if bytes.get(index..index + 2) == Some(b"rv")
            && matches!(bytes.get(index + 2), Some(b'3' | b'6'))
        {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == 0)
                .map(|length| index + length)
                .unwrap_or(bytes.len());
            if let Ok(candidate) = std::str::from_utf8(&bytes[index..end])
                && (candidate.starts_with("rv32") || candidate.starts_with("rv64"))
            {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

fn checked_file_range(offset: u64, size: u64, file_len: usize) -> Option<std::ops::Range<usize>> {
    let end = offset.checked_add(size)?;
    if end > file_len as u64 {
        return None;
    }
    Some(offset as usize..end as usize)
}

fn flags_string(flags: u32) -> String {
    [(PF_R, 'R'), (PF_W, 'W'), (PF_X, 'X')]
        .into_iter()
        .filter_map(|(mask, label)| (flags & mask != 0).then_some(label))
        .collect()
}

fn truncate_symbol(name: &str) -> String {
    const MAX: usize = 200;
    if name.len() <= MAX {
        return name.to_string();
    }
    let mut boundary = MAX;
    while !name.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}…", &name[..boundary])
}

#[cfg(test)]
mod tests {
    use goblin::elf::program_header::{PF_R, PF_W, PF_X, ProgramHeader};
    use goblin::elf::{
        Elf,
        header::{EM_RISCV, ET_EXEC},
    };

    use super::{
        LoadMetrics, classify_mnemonic, evaluate_header, evaluate_load_segments,
        extract_arch_ascii, riscv_instruction_length, summarize_load_segments,
    };

    #[test]
    fn extracts_riscv_arch_attribute() {
        let data = b"\0garbage\0rv64i2p1_m2p0_a2p1_zicclsm1p0\0tail";
        assert_eq!(
            extract_arch_ascii(data).as_deref(),
            Some("rv64i2p1_m2p0_a2p1_zicclsm1p0")
        );
        assert!(extract_arch_ascii(b"not-an-attribute").is_none());
        assert_eq!(
            extract_arch_ascii(b"rv64\xff\0junk\0rv32i2p1_m2p0\0").as_deref(),
            Some("rv32i2p1_m2p0")
        );
    }

    #[test]
    fn classifies_instruction_families() {
        assert!(classify_mnemonic("c.addi", 2).compressed);
        assert!(classify_mnemonic("amoadd.w", 4).atomic);
        assert!(classify_mnemonic("fadd.d", 4).floating_point);
        assert!(classify_mnemonic("ecall", 4).privileged_or_syscall);
        assert!(!classify_mnemonic("addi", 4).privileged_or_syscall);
    }

    #[test]
    fn derives_riscv_instruction_lengths_for_decoder_recovery() {
        assert_eq!(riscv_instruction_length(&[0x01, 0x00]), 2);
        assert_eq!(riscv_instruction_length(&[0x13, 0x00, 0x00, 0x00]), 4);
        assert_eq!(
            riscv_instruction_length(&[0x1f, 0x00, 0x00, 0x00, 0x00, 0x00]),
            6
        );
        assert_eq!(riscv_instruction_length(&[0x13]), 1);
    }

    #[test]
    fn detects_invalid_load_ranges_sizes_addresses_alignment_and_overlap() {
        let first = ProgramHeader {
            p_offset: 96,
            p_vaddr: 0x1001,
            p_paddr: 0x2000,
            p_filesz: 16,
            p_memsz: 8,
            p_align: 0x1000,
            p_flags: PF_R | PF_X,
            ..ProgramHeader::default()
        };
        let second = ProgramHeader {
            p_offset: u64::MAX,
            p_vaddr: 0x1004,
            p_paddr: 0x1004,
            p_filesz: 2,
            p_memsz: 16,
            p_align: 4,
            p_flags: PF_R,
            ..ProgramHeader::default()
        };
        let checks = evaluate_load_segments(&[&first, &second], 100, 0x1002);
        assert!(!checks.ranges_in_file);
        assert!(!checks.file_size_within_memory_size);
        assert!(!checks.vma_equals_lma);
        assert!(!checks.alignment_valid);
        assert!(!checks.do_not_overlap);
        assert!(!checks.entry_aligned);
        assert!(checks.entry_in_executable_segment);
    }

    #[test]
    fn detects_writable_executable_segments_and_bad_entry_points() {
        let segment = ProgramHeader {
            p_offset: 0,
            p_vaddr: 0x1000,
            p_paddr: 0x1000,
            p_filesz: 32,
            p_memsz: 64,
            p_align: 0x1000,
            p_flags: PF_R | PF_W | PF_X,
            ..ProgramHeader::default()
        };
        let checks = evaluate_load_segments(&[&segment], 64, 0x2000);
        assert!(!checks.write_xor_execute);
        assert!(!checks.executable_permissions_valid);
        assert!(!checks.entry_in_executable_segment);
    }

    #[test]
    fn summarizes_load_image_and_bss_bytes() {
        let executable = ProgramHeader {
            p_filesz: 32,
            p_memsz: 48,
            p_flags: PF_R | PF_X,
            ..ProgramHeader::default()
        };
        let writable = ProgramHeader {
            p_filesz: 8,
            p_memsz: 24,
            p_flags: PF_R | PF_W,
            ..ProgramHeader::default()
        };
        assert_eq!(
            summarize_load_segments(&[&executable, &writable]),
            LoadMetrics {
                file_bytes: 40,
                memory_bytes: 72,
                executable_bytes: 48,
                read_only_bytes: 0,
                writable_bytes: 24,
                bss_zero_fill_bytes: 32,
            }
        );
    }

    #[test]
    fn evaluates_elf32_elf64_endianness_machine_and_type_headers() {
        let elf64_bytes = minimal_elf_header(true, true, ET_EXEC, EM_RISCV);
        let elf64 = Elf::parse(&elf64_bytes).unwrap();
        let checks = evaluate_header(&elf64, &elf64_bytes);
        assert!(checks.magic);
        assert!(checks.elf64);
        assert!(checks.little_endian);
        assert!(checks.riscv_machine);
        assert!(checks.executable_type);
        assert!(checks.statically_linked);

        let elf32_bytes = minimal_elf_header(false, true, ET_EXEC, EM_RISCV);
        let elf32 = Elf::parse(&elf32_bytes).unwrap();
        assert!(!evaluate_header(&elf32, &elf32_bytes).elf64);

        let incompatible = minimal_elf_header(true, false, 3, 62);
        let elf = Elf::parse(&incompatible).unwrap();
        let checks = evaluate_header(&elf, &incompatible);
        assert!(!checks.little_endian);
        assert!(!checks.riscv_machine);
        assert!(!checks.executable_type);
    }

    fn minimal_elf_header(
        is_64: bool,
        little_endian: bool,
        elf_type: u16,
        machine: u16,
    ) -> Vec<u8> {
        let header_size = if is_64 { 64 } else { 52 };
        let mut bytes = vec![0_u8; header_size];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = if is_64 { 2 } else { 1 };
        bytes[5] = if little_endian { 1 } else { 2 };
        bytes[6] = 1;
        put_u16(&mut bytes[16..18], elf_type, little_endian);
        put_u16(&mut bytes[18..20], machine, little_endian);
        put_u32(&mut bytes[20..24], 1, little_endian);
        if is_64 {
            put_u16(&mut bytes[52..54], 64, little_endian);
            put_u16(&mut bytes[54..56], 56, little_endian);
            put_u16(&mut bytes[58..60], 64, little_endian);
        } else {
            put_u16(&mut bytes[40..42], 52, little_endian);
            put_u16(&mut bytes[42..44], 32, little_endian);
            put_u16(&mut bytes[46..48], 40, little_endian);
        }
        bytes
    }

    fn put_u16(target: &mut [u8], value: u16, little_endian: bool) {
        let bytes = if little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        target.copy_from_slice(&bytes);
    }

    fn put_u32(target: &mut [u8], value: u32, little_endian: bool) {
        let bytes = if little_endian {
            value.to_le_bytes()
        } else {
            value.to_be_bytes()
        };
        target.copy_from_slice(&bytes);
    }
}
