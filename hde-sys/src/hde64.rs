use std::{ffi::c_void, fmt::Debug};

extern "C" {
    pub fn hde64_disasm(code: *const c_void, hs: *mut hde64s) -> u32;
}

#[repr(C)]
pub struct hde64s {
    pub len: u8,          // length of command
    pub p_rep: u8,        // rep/repz (0xf3) & repnz (0xf2) prefix
    pub p_lock: u8,       // lock prefix: 0xf0
    pub p_seg: u8,        // segment prefix: 0x26,0x2e,0x36,0x3e,0x64,0x65
    pub p_66: u8,         // operand-size override prefix: 0x66
    pub p_67: u8,         // address-size override prefix: 0x67
    pub rex: u8,          // REX prefix
    pub rex_w: u8,        // REX.W
    pub rex_r: u8,        // REX.R
    pub rex_x: u8,        // REX.X
    pub rex_b: u8,        // REX.B
    pub opcode: u8,       // opcode
    pub opcode2: u8,      // second opcode (if first opcode is 0x0f)
    pub modrm: u8,        // ModR/M byte
    pub modrm_mod: u8,    // ModR/M.mod
    pub modrm_reg: u8,    // ModR/M.reg
    pub modrm_rm: u8,     // ModR/M.r/m
    pub sib: u8,          // SIB byte
    pub sib_scale: u8,    // SIB.scale
    pub sib_index: u8,    // SIB.index
    pub sib_base: u8,     // SIB.base
    pub imm: imm_union,   // immediate value
    pub disp: disp_union, // displacement
    pub flags: u32,       // flags
}

impl Debug for hde64s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("hde64s")
            .field("len", &self.len)
            .field("p_rep", &self.p_rep)
            .field("p_lock", &self.p_lock)
            .field("p_seg", &self.p_seg)
            .field("p_66", &self.p_66)
            .field("p_67", &self.p_67)
            .field("rex", &self.rex)
            .field("rex_w", &self.rex_w)
            .field("rex_r", &self.rex_r)
            .field("rex_x", &self.rex_x)
            .field("rex_b", &self.rex_b)
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

/// immediate value
#[repr(C)]
pub union imm_union {
    pub imm8: u8,
    pub imm16: u16,
    pub imm32: u32,
    pub imm64: u64,
}

/// displacement
#[repr(C)]
pub union disp_union {
    pub disp8: u8,
    pub disp16: u16,
    pub disp32: u32,
}

pub const F_MODRM: u32 = 0x00000001; // ModR/M exists
pub const F_SIB: u32 = 0x00000002; // SIB exists
pub const F_IMM8: u32 = 0x00000004; // immediate value imm8 exists
pub const F_IMM16: u32 = 0x00000008; // immediate value imm16 exists
pub const F_IMM32: u32 = 0x00000010; // immediate value imm32 exists
pub const F_IMM64: u32 = 0x00000020; // immediate value imm64 exists
pub const F_DISP8: u32 = 0x00000040; // displacement disp8 exists
pub const F_DISP16: u32 = 0x00000080; // displacement disp16 exists
pub const F_DISP32: u32 = 0x00000100; // displacement disp32 exists
pub const F_RELATIVE: u32 = 0x00000200; // relative address rel8 exists
pub const F_ERROR: u32 = 0x00001000; // error exists
pub const F_ERROR_OPCODE: u32 = 0x00002000; // invalid opcode
pub const F_ERROR_LENGTH: u32 = 0x00004000; // length of command more than 15
pub const F_ERROR_LOCK: u32 = 0x00008000; // prefix lock isn't allowed
pub const F_ERROR_OPERAND: u32 = 0x00010000; // operand isn't allowed
pub const F_PREFIX_REPNZ: u32 = 0x01000000; // repnz prefix exists
pub const F_PREFIX_REPX: u32 = 0x02000000; // rep(z) prefix exists
pub const F_PREFIX_REP: u32 = 0x03000000; // rep(z) or repnz prefix exists
pub const F_PREFIX_66: u32 = 0x04000000; // 0x66 prefix exists
pub const F_PREFIX_67: u32 = 0x08000000; // 0x67 prefix exists
pub const F_PREFIX_LOCK: u32 = 0x10000000; // lock prefix exists
pub const F_PREFIX_SEG: u32 = 0x20000000; // segment prefix exists
pub const F_PREFIX_REX: u32 = 0x40000000; // REX prefix exists
pub const F_PREFIX_ANY: u32 = 0x7f000000; // any prefix esists

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

#[cfg(test)]
mod tests {
    use super::*;

    fn space_hex_to_bytes(text_hex: &str) -> Result<Vec<u8>, String> {
        text_hex
            .split_whitespace()
            .map(|byte_str| {
                if byte_str == "**" || byte_str == "??" || byte_str == "?" {
                    Ok(0xFF_u8)
                } else {
                    u8::from_str_radix(byte_str, 16)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }

    #[test]
    fn test_hde64s() {
        let codes = space_hex_to_bytes("45 33 C0 48 8D 81 08 10  00 00 48 8D 15 B7 FF AA 00 66 44 89 01 48 3B D0  74 0A 44 89 81 04 10 00 00 44 88 00").unwrap();
        let mut hs: hde64s = unsafe { std::mem::zeroed() };
        let code = codes.as_ptr() as *const c_void;
        let len = unsafe { hde64_disasm(code, &mut hs) };

        assert_eq!(len, 3);
        eprintln!("{:#?}", hs);
    }

    #[test]
    fn test_hde64s_multi() {
        let mut results = Vec::new();
        let codes = space_hex_to_bytes("45 33 C0 48 8D 81 08 10  00 00 48 8D 15 B7 FF AA 00 66 44 89 01 48 3B D0  74 0A 44 89 81 04 10 00 00 44 88 00").unwrap();
        let code = codes.as_ptr() as *const c_void;
        let mut offset = 0;
        while offset < codes.len() {
            let mut hs: hde64s = unsafe { std::mem::zeroed() };
            unsafe { hde64_disasm(code.wrapping_byte_add(offset), &mut hs) };
            offset += hs.len as usize;
            results.push(hs);
        }

        assert_eq!(results.len(), 8);
    }

    #[test]
    fn test_hde64s_bad_code() {
        // bad code: invalid jmp length
        // error expected: jmp 78 56 34 12
        // real:
        //   EB 78    jmp +78
        //   56       push rsi
        //   32 12    xor al, 12
        // no error
        //
        {
            let mut results = Vec::new();
            let codes = space_hex_to_bytes("EB 78 56 34 12").unwrap();
            let code = codes.as_ptr() as *const c_void;
            let mut offset = 0;
            while offset < codes.len() {
                let mut hs: hde64s = unsafe { std::mem::zeroed() };
                unsafe { hde64_disasm(code.wrapping_byte_add(offset), &mut hs) };
                offset += hs.len as usize;
                results.push(hs);
            }

            assert_eq!(results.len(), 3);
        }
    }
}
