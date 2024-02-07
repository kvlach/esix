#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim86.h"

#define FLAG_WIDE (1 << 0)
#define FLAG_PRINT_WORD_BYTE (1 << 1)

typedef unsigned char byte;

int16_t combine_bytes(byte low, byte high) {
	return (int16_t)(((uint16_t)high << 8) | (uint8_t)low);
}

int16_t sign_extend(int8_t n) {
	if (n > 0) {
		return combine_bytes(n, 0);
	}
	return combine_bytes(n, 0b11111111);
}

char *buf;
int i = 0;

char peek() { return buf[++i]; }

const char *opcodes_fmt[91] = {
    "mov",  "push",  "pop",    "xchg", "in",    "out",  "xlat", "lea",
    "lds",  "les",   "lahf",   "sahf", "pushf", "popf", "add",  "adc",
    "inc",  "aaa",   "daa",    "sub",  "sbb",   "dec",  "neg",  "cmp",
    "aas",  "das",   "mul",    "imul", "aam",   "div",  "idiv", "aad",
    "cbw",  "cwd",   "not",    "shl",  "shr",   "sar",  "rol",  "ror",
    "rcl",  "rcr",   "and",    "test", "or",    "xor",  "rep",  "movs",
    "cmps", "scas",  "lods",   "stos", "call",  "jmp",  "ret",  "retf",
    "je",   "jl",    "jle",    "jb",   "jbe",   "jp",   "jo",   "js",
    "jne",  "jnl",   "jg",     "jnb",  "ja",    "jnp",  "jno",  "jns",
    "loop", "loopz", "loopnz", "jcxz", "int",   "into", "iret", "clc",
    "cmc",  "stc",   "cld",    "std",  "cli",   "sti",  "hlt",  "wait",
    "esc",  "lock",  "segment",
};

const char *opcode_fmt(const opcode op) {
	return opcodes_fmt[op];
}

const register_ registers[16] = {
    REGISTER_AL, REGISTER_CL, REGISTER_DL, REGISTER_BL,
    REGISTER_AH, REGISTER_CH, REGISTER_DH, REGISTER_BH,
    REGISTER_AX, REGISTER_CX, REGISTER_DX, REGISTER_BX,
    REGISTER_SP, REGISTER_BP, REGISTER_SI, REGISTER_DI,
};

const register_ segment_registers[4] = {
    SEGMENT_REGISTER_ES,
    SEGMENT_REGISTER_CS,
    SEGMENT_REGISTER_SS,
    SEGMENT_REGISTER_DS,
};

const char *registers_fmt[20] = {
    "al", "cl", "dl", "bl",
    "ah", "ch", "dh", "bh",
    "ax", "cx", "dx", "bx",
    "sp", "bp", "si", "di",
    "es", "cs", "ss", "ds",
};

register_ register_match(const byte b, const bool w) {
	return registers[(w << 3) | (b & 0b111)];
}

register_ segment_register_match(const byte b) {
	return segment_registers[b & 0b11];
}

const char *register_fmt(const register_ r) {
	return registers_fmt[r];
}

const mode modes[4] = {
    MODE_MEMORY_NO_DISPLACEMENT,
    MODE_MEMORY_8BIT_DISPLACEMENT,
    MODE_MEMORY_16BIT_DISPLACEMENT,
    MODE_REGISTER,
};

mode mode_match(const byte b) {
	return modes[b >> 6];
}

const effective_addr effective_addrs[8] = {
    EFFECTIVE_ADDR_BX_SI,
    EFFECTIVE_ADDR_BX_DI,
    EFFECTIVE_ADDR_BP_SI,
    EFFECTIVE_ADDR_BP_DI,
    EFFECTIVE_ADDR_SI,
    EFFECTIVE_ADDR_DI,
    EFFECTIVE_ADDR_BP,
    EFFECTIVE_ADDR_BX,
};

const char *effective_addrs_fmt[8] = {
    "bx + si",
    "bx + di",
    "bp + si",
    "bp + di",
    "si",
    "di",
    "bp",
    "bx",
};

effective_addr effective_addr_match(byte b, const mode mod) {
	b &= 0b111;
	if (mod == MODE_MEMORY_NO_DISPLACEMENT && b == 0b110) {
		return EFFECTIVE_ADDR_DIRECT_ADDR;
	}
	return effective_addrs[b];
}

char *effective_addr_fmt(effective_addr ea, mode mod, int16_t disp, int flags) {
	// Max number of required bytes:
	//   "word " or "byte " -> 5 bytes
	//   "[]" -> 2 bytes
	//   "bx + si" -> 7 bytes
	//   " + " or " - " -> 3 bytes
	//   2**16 = 65536 -> 5 bytes
	// A total of 17 bytes.
	char *fmt = (char *)malloc(22);
	if (fmt == NULL) {
		return NULL;
	}

	if (flags & FLAG_PRINT_WORD_BYTE) {
		if (flags & FLAG_WIDE) {
			strcat(fmt, "word ");
		} else {
			strcat(fmt, "byte ");
		}
	}

	if (ea == EFFECTIVE_ADDR_DIRECT_ADDR) {
		sprintf(fmt+strlen(fmt), "[%d]", disp);
		return fmt;
	}

	const char *ea_fmt = effective_addrs_fmt[ea];

	if (mod == MODE_MEMORY_NO_DISPLACEMENT || disp == 0) {
		sprintf(fmt+strlen(fmt), "[%s]", ea_fmt);
	} else if (disp > 0) {
		sprintf(fmt+strlen(fmt), "[%s + %d]", ea_fmt, disp);
	} else {
		sprintf(fmt+strlen(fmt), "[%s - %d]", ea_fmt, -disp);
	}

	return fmt;
}

typedef struct {
	mode mod;
	register_ reg;
	effective_addr ea;
	int16_t disp;
	int flags;
} register_memory;

register_memory register_memory_match(byte b, const bool w) {
	mode mod = mode_match(b);

	effective_addr ea = effective_addr_match(b, mod);

	if (mod == MODE_MEMORY_16BIT_DISPLACEMENT || ea == EFFECTIVE_ADDR_DIRECT_ADDR) {
		byte low = peek();
		byte high = peek();
		return (register_memory){
		    .mod   = mod,
		    .ea    = ea,
		    .disp  = combine_bytes(low, high),
		    .flags = w == 1 ? FLAG_WIDE : 0,
		};
	}

	if (mod == MODE_MEMORY_8BIT_DISPLACEMENT) {
		return (register_memory){
		    .mod   = mod,
		    .ea    = ea,
		    .disp  = peek(),
		    .flags = w == 1 ? FLAG_WIDE : 0,
		};
	}

	if (mod == MODE_MEMORY_NO_DISPLACEMENT) {
		return (register_memory){ .mod = mod, .ea = ea, .flags = w == 1 ? FLAG_WIDE : 0 };
	}

	return (register_memory){ .mod = mod, .reg = register_match(b, w) };
}

const char *register_memory_fmt(register_memory r_m, int flags) {
	if (r_m.mod == MODE_REGISTER) {
		return register_fmt(r_m.reg);
	}
	return effective_addr_fmt(r_m.ea, r_m.mod, r_m.disp, r_m.flags | flags);
}

byte get_high(u_int8_t low) {
	if (low > 0) {
		return 0;
	}
	return 0b11111111;
}

int16_t read_bytes(const bool w) {
	byte low = peek();
	byte high;
	if (w == 0) {
		high = get_high(low);
	} else {
		high = peek();
	}
	return combine_bytes(low, high);
}

int nth(byte b, int n) { return (b >> n) & 1; }

byte b;

void reg_mem_with_reg_either(const opcode op, const bool sr) {
	// little endian
	bool d = nth(b, 1);
	bool w = nth(b, 0);

	b = peek();
	register_ reg;
	if (sr == true) {
		reg = segment_register_match(b >> 3);
	} else {
		reg = register_match(b >> 3, w);
	}
	register_memory r_m = register_memory_match(b, w);

	if (d == 0) {
		printf("%s %s, %s\n", opcode_fmt(op), register_memory_fmt(r_m, 0), register_fmt(reg));
	} else {
		printf("%s %s, %s\n", opcode_fmt(op), register_fmt(reg), register_memory_fmt(r_m, 0));
	}
}

void immediate_to_reg_mem(const opcode op) {
	// little endian
	bool w = nth(b, 0);

	b = peek();
	register_memory r_m = register_memory_match(b, w);
	int16_t n = read_bytes(w);

	printf("%s %s, %d\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE), n);
}

void immediate_to_reg_mem_sign(const opcode op) {
	// little endian
	bool w = nth(b, 0);
	bool s = nth(b, 1);

	b = peek();
	register_memory r_m = register_memory_match(b, w);

	byte data1 = peek();
	byte data2;

	int16_t n;
	if (s == 0 && w == 1) {
		n = combine_bytes(data1, peek());
	} else if (s == 1) {
		n = sign_extend(data1);
	} else {
		n = (int16_t)data1;
	}

	printf("%s %s, %d\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE), n);
}

void immediate_to_accumulator(opcode op) {
	bool w = nth(b, 0);

	int16_t n = read_bytes(w);

	if (w == 0) {
		printf("%s al, %d\n", opcode_fmt(op), n);
	} else {
		printf("%s ax, %d\n", opcode_fmt(op), n);
	}

}

void jump(opcode op) {
	int32_t offset = (int32_t)peek() + 2;
	if (offset == 0) {
		// $+0 must be written exactly like this for NASM to parse it correctly
		printf("%s $+0\n", opcode_fmt(op));
	} else {
		printf("%s $%d\n", opcode_fmt(op), offset);
	}
}

void w_reg_mem(const opcode op) {
	bool w = nth(b, 0);
	b = peek();
	register_memory r_m = register_memory_match(b, w);
	printf("%s %s\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE));
}

void reg_mem_far(const opcode op) {
	b = peek();
	register_memory r_m = register_memory_match(b, 1);
	printf("%s far %s\n", opcode_fmt(op), register_memory_fmt(r_m, 0));
}

void seg_reg_print(const opcode op) {
	register_ sr = segment_register_match(b >> 3);
	printf("%s %s\n", opcode_fmt(op), register_fmt(sr));
}

void reg_print(const opcode op) {
	register_ reg = register_match(b, 1);
	printf("%s %s\n", opcode_fmt(op), register_fmt(reg));
}

void v_w_reg_mem(const opcode op) {
	bool v = nth(b, 1);
	bool w = nth(b, 0);

	b = peek();

	register_memory r_m = register_memory_match(b, w);

	if (v) {
		printf("%s %s, cl\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE));
	} else {
		printf("%s %s, 1\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE));
	}
}

void str(const opcode op) {
	bool w = nth(b, 0);
	if (w == 0) {
		printf("%sb\n", opcode_fmt(op));
	} else {
		printf("%sw\n", opcode_fmt(op));
	}
}

void direct_segment(const opcode op) {
	printf("%s %d\n", opcode_fmt(op), read_bytes(1)+i+1);
}

void direct_intersegment(const opcode op) {
	int16_t ip = read_bytes(1);
	int16_t cs = read_bytes(1);
	printf("%s %d:%d\n", opcode_fmt(op), cs, ip);
}

instruction instructions[256] = { 0 };

instruction instruction_match() {
	instruction inst = INST_NULL;
	uint8_t mask = 0b11111111;
	while (inst == INST_NULL) {
		// We only need up to 4 shifts, 0b11110000 == 240
		if (mask < 240) {
			break;
		}
		inst = instructions[b & mask];
		mask <<= 1;
	}

	byte next = buf[i+1];

	switch (inst) {
	case INST_128:
	case INST_208:
	case INST_246:
	case INST_254:
		return instructions[((next & 0b00111000) >> 3) + inst];
	case INST_AAM:
		if (next == 0b00001010) {
			return INST_AAM;
		}
		// TODO: is it an error if nothing is matched here?
	}

	switch (inst) {
	case INST_128:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: return INST_ADD_IMM_RM;
		case 0b00001000: return INST_OR_IMM_RM;
		case 0b00010000: return INST_ADC_IMM_RM;
		case 0b00011000: return INST_SBB_IMM_RM;
		case 0b00100000: return INST_AND_IMM_RM;
		case 0b00101000: return INST_SUB_IMM_RM;
		case 0b00110000: return INST_XOR_IMM_RM;
		case 0b00111000: return INST_CMP_IMM_RM;
		}
		break;

	case INST_208:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: return INST_ROL;
		case 0b00001000: return INST_ROR;
		case 0b00010000: return INST_RCL;
		case 0b00011000: return INST_RCR;
		case 0b00100000: return INST_SHL_SAL;
		case 0b00101000: return INST_SHR;
		case 0b00111000: return INST_SAR;
		}
		break;

	case INST_246:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: return INST_TEST_IMM_RM;
		case 0b00010000: return INST_NOT;
		case 0b00011000: return INST_NEG;
		case 0b00100000: return INST_MUL;
		case 0b00101000: return INST_IMUL;
		case 0b00110000: return INST_DIV;
		case 0b00111000: return INST_IDIV;
		}
		break;

	case INST_254:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: return INST_INC_RM;
		case 0b00001000: return INST_DEC_RM;
		}
		break;

	}

	if (inst == INST_NULL) {
		inst = instructions[b & 0b11100111];
	}

	return inst;

	// first 8 bits
	switch (b & 0b11111111) {
	case 0b11010111: return INST_XLAT;
	case 0b10001101: return INST_LEA;
	case 0b11000101: return INST_LDS;
	case 0b11000100: return INST_LES;
	case 0b10011111: return INST_LAHF;
	case 0b10011110: return INST_SAHF;
	case 0b10011100: return INST_PUSHF;
	case 0b10011101: return INST_POPF;
	case 0b00110111: return INST_AAA;
	case 0b00100111: return INST_DAA;
	case 0b00111111: return INST_AAS;
	case 0b00101111: return INST_DAS;
	case 0b10011000: return INST_CBW;
	case 0b10011001: return INST_CWD;
	case 0b11000011: return INST_RET_SEG;
	case 0b11000010: return INST_RET_SEG_IMM_TO_SP;
	case 0b11001011: return INST_RET_ISEG;
	case 0b11001010: return INST_RET_ISEG_IMM_TO_SP;
	case 0b11101000: return INST_CALL_DIRECT_SEG;
	case 0b10011010: return INST_CALL_DIRECT_ISEG;
	case 0b11101001: return INST_JMP_DIRECT_SEG;
	case 0b11101010: return INST_JMP_DIRECT_ISEG;
	case 0b01110100: return INST_JE_JZ;
	case 0b01111100: return INST_JL_JNGE;
	case 0b01111110: return INST_JLE_JNG;
	case 0b01110010: return INST_JB_JNAE;
	case 0b01110110: return INST_JBE_JNA;
	case 0b01111010: return INST_JP_JPE;
	case 0b01110000: return INST_JO;
	case 0b01111000: return INST_JS;
	case 0b01110101: return INST_JNE_JNZ;
	case 0b01111101: return INST_JNL_JGE;
	case 0b01111111: return INST_JNLE_JG;
	case 0b01110011: return INST_JNB_JAE;
	case 0b01110111: return INST_JNBE_JA;
	case 0b01111011: return INST_JNP_JPO;
	case 0b01110001: return INST_JNO;
	case 0b01111001: return INST_JNS;
	case 0b11100010: return INST_LOOP;
	case 0b11100001: return INST_LOOPZ_LOOPE;
	case 0b11100000: return INST_LOOPNZ_LOOPNE;
	case 0b11100011: return INST_JCXZ;
	case 0b11001101: return INST_INT_TYPE_SPECIFIED;
	case 0b11001100: return INST_INT_TYPE_3;
	case 0b11001110: return INST_INTO;
	case 0b11001111: return INST_IRET;
	case 0b11111000: return INST_CLC;
	case 0b11110101: return INST_CMC;
	case 0b11111001: return INST_STC;
	case 0b11111100: return INST_CLD;
	case 0b11111101: return INST_STD;
	case 0b11111010: return INST_CLI;
	case 0b11111011: return INST_STI;
	case 0b11110100: return INST_HLT;
	case 0b10011011: return INST_WAIT;
	case 0b11110000: return INST_LOCK;

	case 0b11111111:
		switch (buf[i+1] & 0b00111000) {
		case 0b00110000: return INST_PUSH_RM;
		case 0b00010000: return INST_CALL_INDIRECT_SEG;
		case 0b00011000: return INST_CALL_INDIRECT_ISEG;
		case 0b00100000: return INST_JMP_INDIRECT_SEG;
		case 0b00101000: return INST_JMP_INDIRECT_ISEG;
		}
		break;

	case 0b10001111:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: return INST_POP_RM;
		}
		break;

	case 0b11010100:
		switch (buf[i+1] & 0b11111111) {
		case 0b00001010: return INST_AAM;
		}
		break;

	case 0b11010101:
		switch (buf[i+1] & 0b11111111) {
		case 0b00001010: return INST_AAD;
		}
		break;

	case 0b10001110:
		switch (buf[i+1] & 0b00100000) {
		case 0b00000000: return INST_MOV_RM_SR;
		}
		break;
	case 0b10001100:
		switch (buf[i+1] & 0b00100000) {
		case 0b00000000: return INST_MOV_SR_RM;
		}
		break;
	}

	// first 7 bits
	switch (b & 0b11111110) {
	case 0b11000110: return INST_MOV_IMM_RM;
	case 0b10000110: return INST_XCHG_RM_REG;
	case 0b11100100: return INST_IN_VARIABLE_PORT;
	case 0b11101100: return INST_IN_FIXED_PORT;
	case 0b11100110: return INST_OUT_VARIABLE_PORT;
	case 0b11101110: return INST_OUT_FIXED_PORT;
	case 0b00000100: return INST_ADD_IMM_ACC;
	case 0b00010100: return INST_ADC_IMM_ACC;
	case 0b00101100: return INST_SUB_IMM_ACC;
	case 0b00011100: return INST_SBB_IMM_ACC;
	case 0b00111100: return INST_CMP_IMM_ACC;
	case 0b10100000: return INST_MOV_MEM_ACC;
	case 0b10100010: return INST_MOV_ACC_MEM;
	case 0b00100100: return INST_AND_IMM_ACC;
	case 0b10101000: return INST_TEST_IMM_ACC;
	case 0b00001100: return INST_OR_IMM_ACC;
	case 0b00110100: return INST_XOR_IMM_ACC;
	case 0b11110010: return INST_REP;
	case 0b10100100: return INST_MOVS;
	case 0b10100110: return INST_CMPS;
	case 0b10101110: return INST_SCAS;
	case 0b10101100: return INST_LODS;
	case 0b10101010: return INST_STOS;
	}

	// first 6 bits
	switch (b & 0b11111100) {
	case 0b10001000: return INST_MOV_RM_REG;
	case 0b00000000: return INST_ADD_RM_REG;
	case 0b00010000: return INST_ADC_RM_REG;
	case 0b00101000: return INST_SUB_RM_REG;
	case 0b00011000: return INST_SBB_RM_REG;
	case 0b00111000: return INST_CMP_RM_REG;
	case 0b00100000: return INST_AND_RM_REG;
	case 0b10000100: return INST_TEST_RM_REG;
	case 0b00001000: return INST_OR_RM_REG;
	case 0b00110000: return INST_XOR_RM_REG;
	}

	switch (b & 0b11100111) {
	case 0b00000110: return INST_PUSH_SR;
	case 0b00000111: return INST_POP_SR;
	}

	// first 5 bits
	switch (b & 0b11111000) {
	case 0b01010000: return INST_PUSH_REG;
	case 0b01011000: return INST_POP_REG;
	case 0b10010000: return INST_XCHG_REG_ACC;
	case 0b01000000: return INST_INC_REG;
	case 0b01001000: return INST_DEC_REG;
	}

	// first 4 bits
	switch (b & 0b11110000) {
	case 0b10110000: return INST_MOV_IMM_REG;
	}
}

void disassemble_instruction() {
	mode mod;
	register_ reg;
	bool w;

	// first 8 bits
	switch (b & 0b11111111) {
	case 0b11111111:
		switch (buf[i+1] & 0b00111000) {
		case 0b00110000: w_reg_mem(OPCODE_PUSH); return;
		case 0b00010000: w_reg_mem(OPCODE_CALL); return;
		case 0b00011000: reg_mem_far(OPCODE_CALL); return;
		case 0b00100000: w_reg_mem(OPCODE_JMP); return;
		case 0b00101000: reg_mem_far(OPCODE_JMP); return;
		}
		break;
	case 0b10001111:
		if ((buf[i+1] & 0b00111000) == 0b00000000) {
			w_reg_mem(OPCODE_POP);
			return;
		}
		break;
	case 0b11010111: printf("%s\n", opcode_fmt(OPCODE_XLAT)); return;

		// xor to flip the pretend d bit
	case 0b10001101: b^=0b10; reg_mem_with_reg_either(OPCODE_LEA, false); return;
	case 0b11000101: b^=0b10; reg_mem_with_reg_either(OPCODE_LDS, false); return;

		// xor to flip the pretend d and w bits
	case 0b11000100: b^=0b11, reg_mem_with_reg_either(OPCODE_LES, false); return;

	case 0b10011111: printf("%s\n", opcode_fmt(OPCODE_LAHF)); return;
	case 0b10011110: printf("%s\n", opcode_fmt(OPCODE_SAHF)); return;
	case 0b10011100: printf("%s\n", opcode_fmt(OPCODE_PUSHF)); return;
	case 0b10011101: printf("%s\n", opcode_fmt(OPCODE_POPF)); return;

	case 0b00110111: printf("%s\n", opcode_fmt(OPCODE_AAA)); return;
	case 0b00100111: printf("%s\n", opcode_fmt(OPCODE_DAA)); return;

	case 0b00111111: printf("%s\n", opcode_fmt(OPCODE_AAS)); return;
	case 0b00101111: printf("%s\n", opcode_fmt(OPCODE_DAS)); return;

	case 0b11010100:
		switch (buf[i+1] & 0b11111111) {
		case 0b00001010: printf("%s\n", opcode_fmt(OPCODE_AAM)); i++; return;
		}
		break;

	case 0b11010101:
		switch (buf[i+1] & 0b11111111) {
		case 0b00001010: printf("%s\n", opcode_fmt(OPCODE_AAD)); i++; return;
		}
		break;

	case 0b10011000: printf("%s\n", opcode_fmt(OPCODE_CBW)); return;
	case 0b10011001: printf("%s\n", opcode_fmt(OPCODE_CWD)); return;

	case 0b11000011: printf("%s\n", opcode_fmt(OPCODE_RET)); return;
	case 0b11000010: printf("%s %d\n", opcode_fmt(OPCODE_RET), read_bytes(1)); return;
	case 0b11001011: printf("%s\n", opcode_fmt(OPCODE_RETF)); return;
	case 0b11001010: printf("%s %d\n", opcode_fmt(OPCODE_RETF), read_bytes(1)); return;

	case 0b11101000: direct_segment(OPCODE_CALL); return;
	case 0b10011010: direct_intersegment(OPCODE_CALL); return;
	case 0b11101001: direct_segment(OPCODE_JMP); return;
	case 0b11101010: direct_intersegment(OPCODE_JMP); return;

	case 0b01110100: jump(OPCODE_JE); return;
	case 0b01111100: jump(OPCODE_JL); return;
	case 0b01111110: jump(OPCODE_JLE); return;
	case 0b01110010: jump(OPCODE_JB); return;
	case 0b01110110: jump(OPCODE_JBE); return;
	case 0b01111010: jump(OPCODE_JP); return;
	case 0b01110000: jump(OPCODE_JO); return;
	case 0b01111000: jump(OPCODE_JS); return;
	case 0b01110101: jump(OPCODE_JNE); return;
	case 0b01111101: jump(OPCODE_JNL); return;
	case 0b01111111: jump(OPCODE_JG); return;
	case 0b01110011: jump(OPCODE_JNB); return;
	case 0b01110111: jump(OPCODE_JA); return;
	case 0b01111011: jump(OPCODE_JNP); return;
	case 0b01110001: jump(OPCODE_JNO); return;
	case 0b01111001: jump(OPCODE_JNS); return;
	case 0b11100010: jump(OPCODE_LOOP); return;
	case 0b11100001: jump(OPCODE_LOOPZ); return;
	case 0b11100000: jump(OPCODE_LOOPNZ); return;
	case 0b11100011: jump(OPCODE_JCXZ); return;

	case 0b11001101: printf("%s %d\n", opcode_fmt(OPCODE_INT), peek()); return;
	case 0b11001100: printf("%s3\n", opcode_fmt(OPCODE_INT)); return;
	case 0b11001110: printf("%s\n", opcode_fmt(OPCODE_INTO)); return;
	case 0b11001111: printf("%s\n", opcode_fmt(OPCODE_IRET)); return;
	case 0b11111000: printf("%s\n", opcode_fmt(OPCODE_CLC)); return;
	case 0b11110101: printf("%s\n", opcode_fmt(OPCODE_CMC)); return;
	case 0b11111001: printf("%s\n", opcode_fmt(OPCODE_STC)); return;
	case 0b11111100: printf("%s\n", opcode_fmt(OPCODE_CLD)); return;
	case 0b11111101: printf("%s\n", opcode_fmt(OPCODE_STD)); return;
	case 0b11111010: printf("%s\n", opcode_fmt(OPCODE_CLI)); return;
	case 0b11111011: printf("%s\n", opcode_fmt(OPCODE_STI)); return;
	case 0b11110100: printf("%s\n", opcode_fmt(OPCODE_HLT)); return;
	case 0b10011011: printf("%s\n", opcode_fmt(OPCODE_WAIT)); return;
	case 0b11110000: printf("%s ", opcode_fmt(OPCODE_LOCK)); return;
	}

	// first 7 bits
	switch (b & 0b11111110) {
	case 0b11000110: immediate_to_reg_mem(OPCODE_MOV); return;
	case 0b10000110:
		// nasm is picky about the order of operands, so we
		// always flip the pretend d-bit except when MODE_REGISTER
		mod = mode_match(buf[i+1]);
		b ^= ((mod != MODE_REGISTER) << 1);
		reg_mem_with_reg_either(OPCODE_XCHG, false);
		return;

	case 0b11100100: immediate_to_accumulator(OPCODE_IN); return;
	case 0b11101100:
		// little endian
		w = nth(b, 0);
		if (w == 0) {
			printf("%s al, dx\n", opcode_fmt(OPCODE_IN));
		} else {
			printf("%s ax, dx\n", opcode_fmt(OPCODE_IN));
		}
		return;

	case 0b11100110:
		// little endian
		w = nth(b, 0);
		if (w == 0) {
			printf("%s %d, al\n", opcode_fmt(OPCODE_OUT), (byte)peek());
		} else {
			printf("%s %d, ax\n", opcode_fmt(OPCODE_OUT), (byte)peek());
		}
		return;
	case 0b11101110:
		// little endian
		w = nth(b, 0);
		if (w == 0) {
			printf("%s dx, al\n", opcode_fmt(OPCODE_OUT));
		} else {
			printf("%s dx, ax\n", opcode_fmt(OPCODE_OUT));
		}
		return;

	case 0b00000100: immediate_to_accumulator(OPCODE_ADD); return;
	case 0b00010100: immediate_to_accumulator(OPCODE_ADC); return;

	case 0b11111110:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: w_reg_mem(OPCODE_INC); return;
		case 0b00001000: w_reg_mem(OPCODE_DEC); return;
		}
		break;

	case 0b00101100: immediate_to_accumulator(OPCODE_SUB); return;
	case 0b00011100: immediate_to_accumulator(OPCODE_SBB); return;

	case 0b11110110:
		switch (buf[i+1] & 0b00111000) {
		case 0b00011000: w_reg_mem(OPCODE_NEG); return;
		case 0b00100000: w_reg_mem(OPCODE_MUL); return;
		case 0b00101000: w_reg_mem(OPCODE_IMUL); return;
		case 0b00110000: w_reg_mem(OPCODE_DIV); return;
		case 0b00111000: w_reg_mem(OPCODE_IDIV); return;
		case 0b00010000: w_reg_mem(OPCODE_NOT); return;
		case 0b00000000: immediate_to_reg_mem(OPCODE_TEST); return;
		}
		break;

	case 0b00111100: immediate_to_accumulator(OPCODE_CMP); return;

	case 0b10100000: // Memory to accumulator
		w = nth(b, 0);
		printf("%s ax, [%d]\n", opcode_fmt(OPCODE_MOV), read_bytes(w));
		return;

	case 0b10100010: // Accumulator to memory
		w = nth(b, 0);
		printf("%s [%d], ax\n", opcode_fmt(OPCODE_MOV), read_bytes(w));
		return;

	case 0b10000000:
		switch (buf[i+1] & 0b00111000) {
		case 0b00100000: immediate_to_reg_mem(OPCODE_AND); return;
		case 0b00001000: immediate_to_reg_mem(OPCODE_OR); return;
		case 0b00110000: immediate_to_reg_mem(OPCODE_XOR); return;
		}
		break;

	case 0b00100100: immediate_to_accumulator(OPCODE_AND); return;
	case 0b10101000: immediate_to_accumulator(OPCODE_TEST); return;
	case 0b00001100: immediate_to_accumulator(OPCODE_OR); return;
	case 0b00110100: immediate_to_accumulator(OPCODE_XOR); return;

	case 0b11110010: printf("%s ", opcode_fmt(OPCODE_REP)); return;
	case 0b10100100: str(OPCODE_MOVS); return;
	case 0b10100110: str(OPCODE_CMPS); return;
	case 0b10101110: str(OPCODE_SCAS); return;
	case 0b10101100: str(OPCODE_LODS); return;
	case 0b10101010: str(OPCODE_STOS); return;
	}

	// first 6 bits
	switch (b & 0b11111100) {
	case 0b10000000:
		switch (buf[i+1] & 0b00111000) {
		case 0b00000000: immediate_to_reg_mem_sign(OPCODE_ADD); return;
		case 0b00010000: immediate_to_reg_mem_sign(OPCODE_ADC); return;
		case 0b00101000: immediate_to_reg_mem_sign(OPCODE_SUB); return;
		case 0b00011000: immediate_to_reg_mem_sign(OPCODE_SBB); return;
		case 0b00111000: immediate_to_reg_mem_sign(OPCODE_CMP); return;
		}
		break;

	case 0b10001000: reg_mem_with_reg_either(OPCODE_MOV, false); return;
	case 0b00000000: reg_mem_with_reg_either(OPCODE_ADD, false); return;
	case 0b00010000: reg_mem_with_reg_either(OPCODE_ADC, false); return;
	case 0b00101000: reg_mem_with_reg_either(OPCODE_SUB, false); return;
	case 0b00011000: reg_mem_with_reg_either(OPCODE_SBB, false); return;
	case 0b00111000: reg_mem_with_reg_either(OPCODE_CMP, false); return;

	case 0b11010000:
		switch (buf[i+1] & 0b00111000) {
		case 0b00100000: v_w_reg_mem(OPCODE_SHL); return;
		case 0b00101000: v_w_reg_mem(OPCODE_SHR); return;
		case 0b00111000: v_w_reg_mem(OPCODE_SAR); return;
		case 0b00000000: v_w_reg_mem(OPCODE_ROL); return;
		case 0b00001000: v_w_reg_mem(OPCODE_ROR); return;
		case 0b00010000: v_w_reg_mem(OPCODE_RCL); return;
		case 0b00011000: v_w_reg_mem(OPCODE_RCR); return;
		}
		break;

	case 0b00100000: reg_mem_with_reg_either(OPCODE_AND, false); return;
	case 0b10000100: reg_mem_with_reg_either(OPCODE_TEST, false); return;
	case 0b00001000: reg_mem_with_reg_either(OPCODE_OR, false); return;
	case 0b00110000: reg_mem_with_reg_either(OPCODE_XOR, false); return;
	}

	switch (b & 0b11100111) {
	case 0b00000110: seg_reg_print(OPCODE_PUSH); return;
	case 0b00000111: seg_reg_print(OPCODE_POP); return;
	}

	switch (b & 0b11111101) {
		// implicit d-bit split into two instructions in the manual
	case 0b10001100:
		switch (buf[i+1] & 0b00100000) {
		case 0b00000000: reg_mem_with_reg_either(OPCODE_MOV, true); return;
		}
		break;
	}

	// first 5 bits
	switch (b & 0b11111000) {
	case 0b01010000: reg_print(OPCODE_PUSH); return;
	case 0b01011000: reg_print(OPCODE_POP); return;
	case 0b10010000:
		reg = register_match(b, 1);
		printf("%s ax, %s\n", opcode_fmt(OPCODE_XCHG), register_fmt(reg));
		return;
	case 0b01000000: reg_print(OPCODE_INC); return;
	case 0b01001000: reg_print(OPCODE_DEC); return;
	}

	// first 4 bits
	switch (b & 0b11110000) {
	case 0b10110000: // Immediate to register
		w = nth(b, 3);
		reg = register_match(b, w);
		printf("%s %s, %d\n", opcode_fmt(OPCODE_MOV), register_fmt(reg), read_bytes(w));
		return;
	}
}

void disassemble(long fsize) {
	printf("bits 16\n\n");
	for (i = 0; i < fsize; i++) {
		b = buf[i];
		disassemble_instruction();
	}

}

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("Expected filename\n");
		return 1;
	}

	FILE *f = fopen(argv[1], "r");
	if (f == NULL) {
		printf("File can't be opened, does it exist?\n");
		goto err;
	}

	fseek(f, 0, SEEK_END);
	long fsize = ftell(f);
	rewind(f);

	buf = (char *)malloc(fsize);
	if (buf == NULL) {
		printf("malloc failed\n");
		goto err;
	}
	if (fread(buf, 1, fsize, f) != fsize) {
		printf("Couldn't read file\n");
		goto err;
	}

	disassemble(fsize);

	fclose(f);
	free(buf);
	return 0;

err:
	fclose(f);
	free(buf);
	return 1;
}
