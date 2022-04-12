use bitflags::bitflags;

type CycleCount = u8;

#[derive(Copy, Clone, Debug)]
enum AddressingMode {
    Immediate,
    ZeroPage,
    ZeroPageX,
    ZeroPageY,
    Absolute,
    AbsoluteX,
    AbsoluteY,
    Indirect,
    IndirectX,
    IndirectY,
    Relative,
    Accumulator,
    Implicit,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Operation {
    ADC,
    AND,
    ASL,
    BCC,
    BCS,
    BEQ,
    BIT,
    BMI,
    BNE,
    BPL,
    BRK,
    BVC,
    BVS,
    CLC,
    CLD,
    CLI,
    CLV,
    CMP,
    CPX,
    CPY,
    DEC,
    DEX,
    DEY,
    EOR,
    INC,
    INX,
    INY,
    JMP,
    JSR,
    LDA,
    LDX,
    LDY,
    LSR,
    NOP,
    ORA,
    PHA,
    PHP,
    PLA,
    PLP,
    ROL,
    ROR,
    RTI,
    RTS,
    SBC,
    SEC,
    SED,
    SEI,
    STA,
    STX,
    STY,
    TAX,
    TAY,
    TSX,
    TXA,
    TXS,
    TYA,
    // "Extra" opcodes
    KIL,
    ISC,
    DCP,
    AXS,
    LAS,
    LAX,
    AHX,
    SAX,
    XAA,
    SHX,
    RRA,
    TAS,
    SHY,
    ARR,
    SRE,
    ALR,
    RLA,
    ANC,
    SLO,
}

use AddressingMode::*;
use Operation::*;

const PROGRAMM_ROM_START: usize = 0x8000;
// Opcode table: http://www.oxyron.de/html/opcodes02.html
const OPCODE_TABLE: [(Operation, AddressingMode, CycleCount, CycleCount);256] =
    // TODO Audit each record to see that it was input correctly
    // (Operation, addressing mode, clock cycles, extra clock cycles if page boundary crossed)
    [   // 0x
        (BRK, Implicit, 7, 0), // x0
        (ORA, IndirectX, 6, 0), // x1
        (KIL, Implicit, 0, 0), // x2
        (SLO, IndirectX, 8, 0), // x3
        (NOP, ZeroPage,  3, 0), // x4
        (ORA, ZeroPage,  3, 0), // x5
        (ASL, ZeroPage,  5, 0), // x6
        (SLO, ZeroPage,  5, 0), // x7
        (PHP, Implicit, 3, 0), // x8
        (ORA, Immediate, 2, 0), // x9
        (ASL, Accumulator, 2, 0), // xA
        (ANC, Immediate, 2, 0), // xB
        (NOP, Absolute, 4, 0), // xC
        (ORA, Absolute, 4, 0), // xD
        (ASL, Absolute, 6, 0), // xE
        (SLO, Absolute, 6, 0), // xF
        // 1x
        (BPL, Relative, 2, 1), // x0
        (ORA, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (SLO, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (ORA, ZeroPageX, 4, 0), // x5
        (ASL, ZeroPageX, 6, 0), // x6
        (SLO, ZeroPageX, 6, 0), // x7
        (CLC, Implicit, 2, 0), // x8
        (ORA, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (SLO, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (ORA, AbsoluteX, 4, 1), // xD
        (ASL, AbsoluteX, 7, 0), // xE
        (SLO, AbsoluteX, 7, 0), // xF
        // 2x
        (JSR, Absolute, 6, 0), // x0
        (AND, IndirectX, 6, 0), // x1
        (KIL, Implicit, 0, 0), // x2
        (RLA, IndirectX, 8, 0), // x3
        (BIT, ZeroPage,  3, 0), // x4
        (AND, ZeroPage,  3, 0), // x5
        (ROL, ZeroPage,  5, 0), // x6
        (RLA, ZeroPage,  5, 0), // x7
        (PLP, Implicit, 4, 0), // x8
        (AND, Immediate, 2, 0), // x9
        (ROL, Accumulator, 2, 0), // xA
        (ANC, Immediate, 2, 0), // xB
        (BIT, Absolute, 4, 0), // xC
        (AND, Absolute, 4, 0), // xD
        (ROL, Absolute, 6, 0), // xE
        (RLA, Absolute, 6, 0), // xF
        // 3x
        (BMI, Relative, 2, 1), // x0
        (AND, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (RLA, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (AND, ZeroPageX, 4, 0), // x5
        (ROL, ZeroPageX, 6, 0), // x6
        (RLA, ZeroPageX, 6, 0), // x7
        (SEC, Implicit, 2, 0), // x8
        (AND, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (RLA, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (AND, AbsoluteX, 4, 1), // xD
        (ROL, AbsoluteX, 7, 0), // xE
        (RLA, AbsoluteX, 7, 0), // xF
        // 4x
        (RTI, Implicit, 6, 0), // x0
        (EOR, IndirectX, 6, 0), // x1
        (KIL, Implicit, 0, 0), // x2
        (SRE, IndirectX, 8, 0), // x3
        (NOP, ZeroPage,  3, 0), // x4
        (EOR, ZeroPage,  3, 0), // x5
        (LSR, ZeroPage,  5, 0), // x6
        (SRE, ZeroPage,  5, 0), // x7
        (PHA, Implicit, 3, 0), // x8
        (EOR, Immediate, 2, 0), // x9
        (LSR, Implicit, 2, 0), // xA
        (ALR, Immediate, 2, 0), // xB
        (JMP, Absolute, 3, 0), // xC
        (EOR, Absolute, 4, 0), // xD
        (LSR, Absolute, 6, 0), // xE
        (SRE, Absolute, 6, 0), // xF
        // 5x
        (BVC, Relative, 2, 1), // x0
        (EOR, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (SRE, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (EOR, ZeroPageX, 4, 0), // x5
        (LSR, ZeroPageX, 6, 0), // x6
        (SRE, ZeroPageX, 6, 0), // x7
        (CLI, Implicit, 2, 0), // x8
        (EOR, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (SRE, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (EOR, AbsoluteX, 4, 1), // xD
        (LSR, AbsoluteX, 7, 0), // xE
        (SRE, AbsoluteX, 7, 0), // xF
        // 6x
        (RTS, Implicit, 6, 0), // x0
        (ADC, IndirectX, 6, 0), // x1
        (KIL, Implicit, 0, 0), // x2
        (RRA, IndirectX, 8, 0), // x3
        (NOP, ZeroPage,  3, 0), // x4
        (ADC, ZeroPage,  3, 0), // x5
        (ROR, ZeroPage,  5, 0), // x6
        (RRA, ZeroPage,  5, 0), // x7
        (PLA, Implicit, 4, 0), // x8
        (ADC, Immediate, 2, 0), // x9
        (ROR, Implicit, 2, 0), // xA
        (ARR, Immediate, 2, 0), // xB
        (JMP, Indirect, 5, 0), // xC
        (ADC, Absolute, 4, 0), // xD
        (ROR, Absolute, 6, 0), // xE
        (RRA, Absolute, 6, 0), // xF
        // 7x
        (BVS, Relative, 2, 1), // x0
        (ADC, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (RRA, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (ADC, ZeroPageX, 4, 0), // x5
        (ROR, ZeroPageX, 6, 0), // x6
        (RRA, ZeroPageX, 6, 0), // x7
        (SEI, Implicit, 2, 0), // x8
        (ADC, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (RRA, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (ADC, AbsoluteX, 4, 1), // xD
        (ROR, AbsoluteX, 7, 0), // xE
        (RRA, AbsoluteX, 7, 0), // xF
        // 8x
        (NOP, Immediate, 2, 0), // x0
        (STA, IndirectX, 6, 0), // x1
        (NOP, Immediate, 2, 0), // x2
        (SAX, IndirectX, 6, 0), // x3
        (STY, ZeroPage,  3, 0), // x4
        (STA, ZeroPage,  3, 0), // x5
        (STX, ZeroPage,  3, 0), // x6
        (SAX, ZeroPage,  3, 0), // x7
        (DEY, Implicit, 2, 0), // x8
        (NOP, Immediate, 2, 0), // x9
        (TXA, Implicit, 2, 0), // xA
        (XAA, Immediate, 2, 1), // xB
        (STY, Absolute, 4, 0), // xC
        (STA, Absolute, 4, 0), // xD
        (STX, Absolute, 4, 0), // xE
        (SAX, Absolute, 4, 0), // xF
        // 9x
        (BCC, Relative, 2, 1), // x0
        (STA, IndirectY, 6, 0), // x1
        (KIL, Implicit, 0, 0), // x2
        (AHX, IndirectY, 6, 0), // x3
        (STY, ZeroPageX, 4, 0), // x4
        (STA, ZeroPageX, 4, 0), // x5
        (STX, ZeroPageY, 4, 0), // x6
        (SAX, ZeroPageY, 4, 0), // x7
        (TYA, Implicit, 2, 0), // x8
        (STA, AbsoluteY, 5, 0), // x9
        (TXS, Implicit, 2, 0), // xA
        (TAS, AbsoluteY, 5, 0), // xB
        (SHY, AbsoluteX, 5, 0), // xC
        (STA, AbsoluteX, 5, 0), // xD
        (SHX, AbsoluteY, 5, 0), // xE
        (AHX, AbsoluteY, 5, 0), // xF
        // Ax
        (LDY, Immediate, 2, 0), // x0
        (LDA, IndirectX, 6, 0), // x1
        (LDX, Immediate, 2, 0), // x2
        (LAX, IndirectX, 6, 0), // x3
        (LDY, ZeroPage,  3, 0), // x4
        (LDA, ZeroPage,  3, 0), // x5
        (LDX, ZeroPage,  3, 0), // x6
        (LAX, ZeroPage,  3, 0), // x7
        (TAY, Implicit, 2, 0), // x8
        (LDA, Immediate, 2, 0), // x9
        (TAX, Implicit, 2, 0), // xA
        (LAX, Immediate, 2, 0), // xB
        (LDY, Absolute, 4, 0), // xC
        (LDA, Absolute, 4, 0), // xD
        (LDX, Absolute, 4, 0), // xE
        (LAX, Absolute, 4, 0), // xF
        // Bx
        (BCS, Relative, 2, 1), // x0
        (LDA, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (LAX, IndirectY, 5, 1), // x3
        (LDY, ZeroPageX, 4, 0), // x4
        (LDA, ZeroPageX, 4, 0), // x5
        (LDX, ZeroPageY, 4, 0), // x6
        (LAX, ZeroPageY, 4, 0), // x7
        (CLV, Implicit, 2, 0), // x8
        (LDA, AbsoluteY, 4, 1), // x9
        (TSX, Implicit, 2, 0), // xA
        (LAS, AbsoluteY, 4, 1), // xB
        (LDY, AbsoluteX, 4, 1), // xC
        (LDA, AbsoluteX, 4, 1), // xD
        (LDX, AbsoluteY, 4, 1), // xE
        (LAX, AbsoluteY, 4, 1), // xF
        // Cx
        (CPY, Immediate, 2, 0), // x0
        (CMP, IndirectX, 6, 0), // x1
        (NOP, Immediate, 2, 0), // x2
        (DCP, IndirectX, 8, 0), // x3
        (CPY, ZeroPage,  3, 0), // x4
        (CMP, ZeroPage,  3, 0), // x5
        (DEC, ZeroPage,  5, 0), // x6
        (DCP, ZeroPage,  5, 0), // x7
        (INY, Implicit, 2, 0), // x8
        (CMP, Immediate, 2, 0), // x9
        (DEX, Implicit, 2, 0), // xA
        (AXS, Immediate, 2, 0), // xB
        (CPY, Absolute, 4, 0), // xC
        (CMP, Absolute, 4, 0), // xD
        (DEC, Absolute, 6, 0), // xE
        (DCP, Absolute, 6, 0), // xF
        // Dx
        (BNE, Relative, 2, 1), // x0
        (CMP, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (DCP, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (CMP, ZeroPageX, 4, 0), // x5
        (DEC, ZeroPageX, 6, 0), // x6
        (DCP, ZeroPageX, 6, 0), // x7
        (CLD, Implicit, 2, 0), // x8
        (CMP, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (DCP, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (CMP, AbsoluteX, 4, 1), // xD
        (DEC, AbsoluteX, 7, 0), // xE
        (DCP, AbsoluteX, 7, 0), // xF
        // Ex
        (CPX, Immediate, 2, 0), // x0
        (SBC, IndirectX, 6, 0), // x1
        (NOP, Immediate, 2, 0), // x2
        (ISC, IndirectX, 8, 0), // x3
        (CPX, ZeroPage,  3, 0), // x4
        (SBC, ZeroPage,  3, 0), // x5
        (INC, ZeroPage,  5, 0), // x6
        (ISC, ZeroPage,  5, 0), // x7
        (INX, Implicit, 2, 0), // x8
        (SBC, Immediate, 2, 0), // x9
        (NOP, Implicit, 2, 0), // xA
        (SBC, Immediate, 2, 0), // xB
        (CPX, Absolute, 4, 0), // xC
        (SBC, Absolute, 4, 0), // xD
        (INC, Absolute, 6, 0), // xE
        (ISC, Absolute, 6, 0), // xF
        // Fx
        (BEQ, Relative, 2, 1), // x0
        (SBC, IndirectY, 5, 1), // x1
        (KIL, Implicit, 0, 0), // x2
        (ISC, IndirectY, 8, 0), // x3
        (NOP, ZeroPageX, 4, 0), // x4
        (SBC, ZeroPageX, 4, 0), // x5
        (INC, ZeroPageX, 6, 0), // x6
        (ISC, ZeroPageX, 6, 0), // x7
        (SED, Implicit, 2, 0), // x8
        (SBC, AbsoluteY, 4, 1), // x9
        (NOP, Implicit, 2, 0), // xA
        (ISC, AbsoluteY, 7, 0), // xB
        (NOP, AbsoluteX, 4, 1), // xC
        (SBC, AbsoluteX, 4, 1), // xD
        (INC, AbsoluteX, 7, 0), // xE
        (ISC, AbsoluteX, 7, 0), // xF
        ];


#[allow(non_snake_case)]
pub struct CPU {
    pub PC: u16,
    pub SP: u8, 
    pub A: u8,
    pub X: u8,
    pub Y: u8,
    pub flags: Flags,
    pub total_cycles: usize,
    pub cycles: u8,
    memory: [u8; 0xFFFF]
}

bitflags!{
    // #[derive(Serialize, Deserialize)]
    #[allow(non_snake_case)]
    pub struct Flags: u8 {
        const CARRY             = 0b00000001;
        const ZERO              = 0b00000010;
        const INTERRUPT_DISABLE = 0b00000100;
        const DECIMAL_MODE      = 0b00001000;
        const BREAK             = 0b00010000;
        const BREAK2            = 0b00100000;
        const OVERFLOW          = 0b01000000;
        const NEGATIVE          = 0b10000000;
    }
}

impl Flags {
    pub fn clear(&mut self) {
        self.bits = 0; 
    }
    pub fn op_result_flags_set(&mut self, result: u8) {
        if result == 0 {
            *self = *self | Self::ZERO;
        } else {
            self.bits = self.bits & 0b1111_1101;
        }

        if result & 0b1000_0000 != 0 {
            *self = * self | Self::NEGATIVE;
        } else {
            self.bits = self.bits & 0b0111_1111;
        }
    }
}

impl Default for Flags{
    fn default() -> Self {
        Self {
            bits: 0
        } 
    }
}

impl Default for CPU{
    fn default() -> Self {
        Self {
            PC: 0,
            SP: 0,
            A: 0,
            X: 0,
            Y: 0,
            flags: Flags::default(),
            total_cycles: 0,
            cycles: 0,
            memory: [0;0xFFFF]
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct Instruction {
    op: Operation,
    mode: AddressingMode,
    mode_args: u16,
    mode_address: Option<u16>,
    // write_target: WriteTarget,
    num_clocks: u8,
    oops_cycle: bool
}

impl Instruction {
    fn should_update_registers(&self) -> bool {
        match self.op {
            LDA | TAX | INX => true,
            _ => false
        }
    }
}

impl CPU {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn reset(&mut self) {
        self.X = 0;
        self.Y = 0;
        self.flags = Flags::default();
        self.PC = self.read_mem_16(0xFFFC)
    }
    fn wirte_mem(&mut self, addr: u16, data: u8) {
        self.memory[addr as usize] = data;
    }
    fn wirte_mem_16(&mut self, addr: u16, data: u16) {
        let [begin, end] = data.to_le_bytes();
        self.memory[addr as usize] = begin;
        self.memory[addr as usize +1] = end;
    }
    fn read_mem_16(&self, addr: u16) -> u16 {
        let begin = self.memory[addr as usize] as u16;
        let end = self.memory[addr as usize + 1] as u16;
        (end << 8) | begin
    }
    fn read_mem(&self, addr: u16) -> u8 {
        self.memory[addr as usize]
    }
    fn load_programm(&mut self, programm: Vec<u8>) {
        self.memory[PROGRAMM_ROM_START..PROGRAMM_ROM_START + programm.len()].copy_from_slice(&programm[..]);
        self.wirte_mem_16(0xFFFC, 0x8000);
        //self.PC = PROGRAMM_ROM_START as u16;
    }
    pub fn load_and_run_programm(&mut self, programm: Vec<u8>) {
        self.load_programm(programm);
        self.reset();
        self.exec()
    }

    // fn load_mem(&self, addr: u16) -> u8 {
    //     self.program[addr as usize]
    // }
    fn should_generate_read(&self, op: Operation) -> bool {
        match op {
            STA => false,
            STX => false,
            STY => false,
            _ => true,
        }
    }
        // Returns the instruction arguments and the number of bytes after the opcode they took to store.
        fn decode_addressing_mode(
            &self,
            mode: AddressingMode,
            ptr: u16,
            read: bool,
        ) -> (u16, Option<u16>, u16, bool) {
            match mode {
                // (Value, Address, Additional Bytes, "oops" cycle)
                Immediate => {
                    let v = if read { self.read_mem(ptr) as u16 } else { 0xDEAD };
                    (v, Some(ptr), 1, false)
                }
                ZeroPage => {
                    let addr = self.read_mem(ptr) as u16;
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 1, false)
                }
                ZeroPageX => {
                    let addr = self.read_mem(ptr).wrapping_add(self.X) as u16;
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 1, false)
                }
                ZeroPageY => {
                    let addr = self.read_mem(ptr).wrapping_add(self.Y) as u16;
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 1, false)
                }
                Absolute => {
                    let addr = self.read_mem_16(ptr);
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 2, false)
                }
                AbsoluteX => {
                    let addr = self.read_mem_16(ptr).wrapping_add(self.X as u16);
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 2, true)
                }
                AbsoluteY => {
                    let addr = self.read_mem_16(ptr).wrapping_add(self.Y as u16);
                    let v = if read { self.read_mem(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 2, true)
                }
                Indirect => {
                    let addr = self.read_mem_16(ptr);
                    let result_ptr = self.read_mem_16(addr);
                    (0xDEAD, Some(result_ptr), 2, false)
                }
                IndirectX => {
                    let zp_addr = self.read_mem(ptr).wrapping_add(self.X) as u16;
                    let addr = self.read_mem_16(zp_addr);
                    let v = if read { self.read_mem_16(addr) as u16 } else { 0xDEAD };
                    (v, Some(addr), 1, false)
                }
                // IndirectY => {
                //     let zp_addr = self.peek(ptr);
                //     let addr = self.peek_zero16(zp_addr).wrapping_add(self.y as u16);
                //     let v = if read { self.peek(addr) as u16 } else { 0xDEAD };
                //     (v, Some(addr), 1, true)
                // }
                // Relative => {
                //     let v = if read { self.peek(ptr) as u16 } else { 0xDEAD };
                //     (v, Some(ptr), 1, false)
                // }
                // Accumulator => (self.acc as u16, None, 0, false),
                Implicit => (0xDEAD, None, 0, false),
                _ => {
                    todo!()
                }
            }
        }
    fn decode_innstruction(&self) -> (Instruction, u16) {
        let ptr = self.PC;
        let addr = self.read_mem(self.PC);
        let (opcode, addressing_mode, clocks, _page_clocks) = OPCODE_TABLE[addr as usize];
        let generate_read = self.should_generate_read(opcode);
        let (mode_args, mode_address, num_arg_bytes, oops_cycle) =
        self.decode_addressing_mode(addressing_mode, ptr.wrapping_add(1), generate_read);
        return (Instruction{
            op: opcode,
            mode: addressing_mode,
            num_clocks: clocks,
            mode_args,
            mode_address: mode_address,
            oops_cycle
        }, 1 + num_arg_bytes)
    }
    pub fn exec(&mut self) {
        loop {
            let (instruction, num_bytes) = self.decode_innstruction();
            self.PC = self.PC.wrapping_add(num_bytes);
            self.exec_instruction(instruction);
            if instruction.op == BRK {
                break
            }
            
        }
    }
    fn exec_instruction(&mut self, instruction: Instruction) {
        let mut result:u8 = 0;

        match instruction.op {
            LDA => {
                self.A = instruction.mode_args as u8;
                result = self.A;
            },
            LDX => {
                self.X = instruction.mode_args as u8;
                result = self.X;
            },
            LDY => {
                self.Y = instruction.mode_args as u8;
                result = self.Y;
            },
            BRK => {
                return;
            },
            TAX => {
                self.X = self.A;
                result = self.X;
            },
            STA => {
                self.wirte_mem(instruction.mode_address.unwrap(), self.A);
            },
            STX => {
                self.wirte_mem(instruction.mode_address.unwrap(), self.X);
            },
            STY => {
                self.wirte_mem(instruction.mode_address.unwrap(), self.Y);
            },
            INX => {
                self.X = self.X.wrapping_add(1);
                result = self.X;
            }
            _ => {
                todo!()
            }
        }
        if instruction.should_update_registers() {
            self.flags.op_result_flags_set(result)
        }


    }
 }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ololo() {
        let mut flags = Flags::CARRY;
        flags.clear();
        assert!(flags.is_empty());
        flags.bits = 0b00001000;
        assert_eq!(flags, Flags::DECIMAL_MODE);
        flags = flags | Flags::CARRY;
        assert_eq!(flags.bits, 0b00001001);
    }
    #[test]
    fn test_lda() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa9, 0x05, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.A, 5)
    }
    #[test]
    fn test_ldx() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa2, 0x05, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.X, 5)
    }
    #[test]
    fn test_ldy() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa0, 0x05, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.Y, 5);
    //    assert_eq!(cpu.Y, cpu.read_mem(0x00));
    }
    #[test]
    fn test_zero_page() {
        let mut cpu = CPU::new();
        cpu.load_and_run_programm(vec![0xa9, 0x05, 0x85, 0x00, 0x00]);
        assert_eq!(cpu.flags.bits, 0b000_000);
        assert_eq!(cpu.A, 5);
        assert_eq!(cpu.A, cpu.read_mem(0x00));
    }
    #[test]
    fn test_indirect_x_lda() {
        let mut cpu = CPU::new();
        cpu.load_and_run_programm(vec![0xa2, 0x01, 0xa9, 0x05, 0x85, 0x01, 0xa9, 0x07, 0x85, 0x02, 0xa0, 0x0a, 0x8c, 0x05, 0x07, 0xa1, 0x00]);
        assert_eq!(cpu.flags.bits, 0b000_000);
        assert_eq!(cpu.Y, cpu.A);
        assert_eq!(cpu.A, 0x0a);
    }
    #[test]
    fn test_zero_page_x() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa2, 0x04, 0xa0, 0x06, 0x94, 0x00, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.Y, 6);
       assert_eq!(cpu.Y, cpu.read_mem(0x04));
    }
    #[test]
    fn test_zero_page_y() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa2, 0x04, 0xa0, 0x06, 0x96, 0x00, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.X, 4);
       assert_eq!(cpu.X, cpu.read_mem(0x06));
    }

    #[test]
    fn test_absolute() {
        let mut cpu = CPU::new();
        cpu.load_and_run_programm(vec![0xa9, 0x05, 0x8D, 0x30, 0x00, 0x00]);
        assert_eq!(cpu.flags.bits, 0b000_000);
        assert_eq!(cpu.A, 5);
        assert_eq!(cpu.A, cpu.read_mem(0x0030));
    }
    #[test]
    fn test_sta() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa9, 0x05, 0x85, 0x00, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.A, 5);
       assert_eq!(cpu.A, cpu.read_mem(0x00));
    }
    #[test]
    fn test_stx() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa2, 0x05, 0x86, 0x00, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.X, 5);
       assert_eq!(cpu.X, cpu.read_mem(0x00));
    }
    #[test]
    fn test_sty() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa0, 0x05, 0x84, 0x00, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_000);
       assert_eq!(cpu.Y, 5);
       assert_eq!(cpu.Y, cpu.read_mem(0x00));
    }
    #[test]
    fn test_lda_zero_flag() {
        let mut cpu = CPU::new();
        cpu.load_and_run_programm(vec![0xa9, 0x00, 0x00]);
        assert_eq!(cpu.flags, Flags::ZERO);
     }

     #[test]
     fn test_lda_negative_flag() {
         let mut cpu = CPU::new();
         cpu.load_and_run_programm(vec![0xa9, 0xF0, 0x00]);
         assert!(!cpu.flags.contains(Flags::ZERO));
         assert!(cpu.flags.contains(Flags::NEGATIVE));
      }

      #[test]
      fn test_tax() {
        let mut cpu = CPU::new();
        cpu.load_and_run_programm(vec![0xa9, 0x05, 0xAA, 0x00]);
        assert_eq!(cpu.flags.bits, 0b000_000);
        assert_eq!(cpu.X, 5);
        assert_eq!(cpu.A, 5);
     }

     #[test]
     fn test_tax_zero() {
       let mut cpu = CPU::new();
       cpu.load_and_run_programm(vec![0xa9, 0x00, 0xAA, 0x00]);
       assert_eq!(cpu.flags.bits, 0b000_010);
       assert_eq!(cpu.X, 0);
       assert_eq!(cpu.A, 0);
    }

    #[test]
    fn test_tax_negative() {
      let mut cpu = CPU::new();
      cpu.load_and_run_programm(vec![0xa9, 0xfa, 0xAA, 0x00]);
      assert!(!cpu.flags.contains(Flags::ZERO));
      assert!(cpu.flags.contains(Flags::NEGATIVE));
      assert_eq!(cpu.X, 0xfa);
      assert_eq!(cpu.A, 0xfa);
   }

   #[test]
   fn test_inx() {
     let mut cpu = CPU::new();
     cpu.load_and_run_programm(vec![0xa9, 0x05, 0xAA, 0xE8, 0x00]);
     assert_eq!(cpu.flags.bits, 0b000_000);
     assert_eq!(cpu.X, 6);
     assert_eq!(cpu.A, 5);
  }

  #[test]
  fn test_inx_zero() {
    let mut cpu = CPU::new();
    cpu.load_and_run_programm(vec![0xa9, 0xff, 0xAA, 0xE8, 0x00]);
    assert!(cpu.flags.contains(Flags::ZERO));
    assert!(!cpu.flags.contains(Flags::NEGATIVE));
 }
}