use anyhow::{anyhow, Result};
use capstone::prelude::*;
use goblin::mach::Mach;
use goblin::Object;
use std::env;
use std::fs;
use std::path::Path;

fn main() -> Result<()> {
	let cs = Capstone::new()
		.arm64()
		.mode(arch::arm64::ArchMode::Arm)
		.detail(true)
		.build()
		.expect("Failed to create capstone handler");
	let (instruction_code, addr) = fetch_instructions()?;

	let inst = cs
		.disasm_all(&instruction_code, addr)
		.expect("Failed to disassemble instructions");
	for i in inst.iter() {
		println!();
		println!("{}", i);

		let detail: InsnDetail = cs.insn_detail(i).expect("Failed to get insn detail");
		let arch_detail: ArchDetail = detail.arch_detail();
		let ops = arch_detail.operands();

		let output: &[(&str, String)] = &[
			("insn id:", format!("{:?}", i.id().0)),
			("bytes:", format!("{:?}", i.bytes())),
			("read regs:", reg_names(&cs, detail.regs_read())),
			("write regs:", reg_names(&cs, detail.regs_write())),
			("insn groups:", group_names(&cs, detail.groups())),
		];

		for &(name, ref message) in output.iter() {
			println!("{:4}{:12} {}", "", &name, message);
		}

		println!("{:4}operands: {}", "", ops.len());
		for op in ops {
			println!("{:8}{:?}", "", op);
		}
	}

	Ok(())
}

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
	let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
	names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
	let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
	names.join(", ")
}

fn fetch_instructions() -> Result<(Vec<u8>, u64)> {
	let args: Vec<String> = env::args().collect();
	let arg = &args[1];
	let path = Path::new(arg.as_str());
	let buffer = fs::read(path)?;
	match Object::parse(&buffer)? {
		Object::Mach(mach) => match &mach {
			Mach::Binary(actual_mach) => {
				let text_block_name: [u8; 16] = [95, 95, 84, 69, 88, 84, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
				let text_segment = actual_mach
					.segments
					.iter()
					.find(|x| x.segname == text_block_name)
					.expect("Could not find __TEXT segment");

				let text_section_name = [95, 95, 116, 101, 120, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
				let instructions = text_segment
					.sections()?
					.iter()
					.find(|&(x, _)| x.sectname == text_section_name)
					.map(|(y, x)| (x.to_vec(), y.addr))
					.expect("Could not find __text section");

				Ok(instructions)
			}
			_ => Err(anyhow!("For later (Fat)")),
		},
		_ => Err(anyhow!("Not implemented/unsupported")),
	}
}
