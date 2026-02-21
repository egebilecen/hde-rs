use std::{ffi::c_void, fmt::Debug};

extern "C" {
    pub fn hde32_disasm(code: *const c_void, hs: *mut hde32s) -> u32;
}

#[repr(C)]
pub struct hde32s {
    pub len: u8,
    pub p_rep: u8,
    pub p_lock: u8,
    pub p_seg: u8,
    pub p_66: u8,
    pub p_67: u8,
    pub opcode: u8,
    pub opcode2: u8,
    pub modrm: u8,
    pub modrm_mod: u8,
    pub modrm_reg: u8,
    pub modrm_rm: u8,
    pub sib: u8,
    pub sib_scale: u8,
    pub sib_index: u8,
    pub sib_base: u8,
    pub imm: imm_union,
    pub disp: disp_union,
    pub flags: u32,
}

impl Debug for hde32s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("hde32s")
            .field("len", &self.len)
            .field("p_rep", &self.p_rep)
            .field("p_lock", &self.p_lock)
            .field("p_seg", &self.p_seg)
            .field("p_66", &self.p_66)
            .field("p_67", &self.p_67)
            .field("opcode", &self.opcode)
            .field("opcode2", &self.opcode2)
            .field("modrm", &self.modrm)
            .field("modrm_mod", &self.modrm_mod)
            .field("modrm_reg", &self.modrm_reg)
            .field("modrm_rm", &self.modrm_rm)
            .field("sib", &self.sib)
            .field("sib_scale", &self.sib_scale)
            .field("sib_index", &self.sib_index)
            .field("sib_base", &self.sib_base)
            .field("imm", &"imm")
            .field("disp", &"disp")
            .field("flags", &self.flags)
            .finish()
    }
}

#[repr(C)]
pub union imm_union {
    pub imm8: u8,
    pub imm16: u16,
    pub imm32: u32,
}

#[repr(C)]
pub union disp_union {
    pub disp8: u8,
    pub disp16: u16,
    pub disp32: u32,
}

pub const F_MODRM: u32 = 0x00000001;
pub const F_SIB: u32 = 0x00000002;
pub const F_IMM8: u32 = 0x00000004;
pub const F_IMM16: u32 = 0x00000008;
pub const F_IMM32: u32 = 0x00000010;
pub const F_DISP8: u32 = 0x00000020;
pub const F_DISP16: u32 = 0x00000040;
pub const F_DISP32: u32 = 0x00000080;
pub const F_RELATIVE: u32 = 0x00000100;
pub const F_2IMM16: u32 = 0x00000800;
pub const F_ERROR: u32 = 0x00001000;
pub const F_ERROR_OPCODE: u32 = 0x00002000;
pub const F_ERROR_LENGTH: u32 = 0x00004000;
pub const F_ERROR_LOCK: u32 = 0x00008000;
pub const F_ERROR_OPERAND: u32 = 0x00010000;
pub const F_PREFIX_REPNZ: u32 = 0x01000000;
pub const F_PREFIX_REPX: u32 = 0x02000000;
pub const F_PREFIX_REP: u32 = 0x03000000;
pub const F_PREFIX_66: u32 = 0x04000000;
pub const F_PREFIX_67: u32 = 0x08000000;
pub const F_PREFIX_LOCK: u32 = 0x10000000;
pub const F_PREFIX_SEG: u32 = 0x20000000;
pub const F_PREFIX_ANY: u32 = 0x3f000000;

pub const PREFIX_SEGMENT_CS: u8 = 0x2e;
pub const PREFIX_SEGMENT_SS: u8 = 0x36;
pub const PREFIX_SEGMENT_DS: u8 = 0x3e;
pub const PREFIX_SEGMENT_ES: u8 = 0x26;
pub const PREFIX_SEGMENT_FS: u8 = 0x64;
pub const PREFIX_SEGMENT_GS: u8 = 0x65;
pub const PREFIX_LOCK: u8 = 0xf0;
pub const PREFIX_REPNZ: u8 = 0xf2;
pub const PREFIX_REPX: u8 = 0xf3;
pub const PREFIX_OPERAND_SIZE: u8 = 0x66;
pub const PREFIX_ADDRESS_SIZE: u8 = 0x67;
