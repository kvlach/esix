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

byte get_b2(u_int8_t b1) {
	if (b1 > 0) {
		return 0;
	}
	return 0b11111111;
}

int nth(byte b, int n) { return (b >> n) & 1; }

void reg_mem_with_reg_either(const opcode op, byte b, const bool sr) {
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

void immediate_to_reg_mem(const opcode op, byte b) {
	// little endian
	bool w = nth(b, 0);

	b = peek();

	byte data1 = peek();
	byte data2;
	if (w == 0) {
		data2 = get_b2(data1);
	} else {
		data2 = peek();
	}

	int16_t n = combine_bytes(data1, data2);
	register_memory r_m = register_memory_match(b, w);

	printf("%s %s, %d\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE), n);
}

void immediate_to_reg_mem_sign(const opcode op, byte b) {
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

void immediate_to_accumulator(opcode op, byte b) {
	bool w = nth(b, 0);

	byte b1 = peek();
	byte b2;
	if (w == 0) {
		b2 = get_b2(b1);
		printf("%s al, %d\n", opcode_fmt(op), combine_bytes(b1, b2));
	} else {
		b2 = peek();
		printf("%s ax, %d\n", opcode_fmt(op), combine_bytes(b1, b2));
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

void w_reg_mem(const opcode op, byte b) {
	bool w = nth(b, 0);
	b = peek();
	register_memory r_m = register_memory_match(b, w);
	printf("%s %s\n", opcode_fmt(op), register_memory_fmt(r_m, FLAG_PRINT_WORD_BYTE));
}

void reg_mem_far(const opcode op) {
	const byte b = peek();
	register_memory r_m = register_memory_match(b, 1);
	printf("%s far %s\n", opcode_fmt(op), register_memory_fmt(r_m, 0));
}

void seg_reg_print(const opcode op, const byte b) {
	register_ sr = segment_register_match(b >> 3);
	printf("%s %s\n", opcode_fmt(op), register_fmt(sr));
}

void reg_print(const opcode op, const byte b) {
	register_ reg = register_match(b, 1);
	printf("%s %s\n", opcode_fmt(op), register_fmt(reg));
}

void v_w_reg_mem(const opcode op, byte b) {
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

void str(const opcode op, const byte b) {
	bool w = nth(b, 0);
	if (w == 0) {
		printf("%sb\n", opcode_fmt(op));
	} else {
		printf("%sw\n", opcode_fmt(op));
	}
}

void direct_segment(const opcode op) {
	byte b1 = peek();
	byte b2 = peek();
	printf("%s %d\n", opcode_fmt(op), combine_bytes(b1, b2)+i+1);
}

void direct_intersegment(const opcode op) {
	byte ip_lo = peek();
	byte ip_hi = peek();
	byte cs_lo = peek();
	byte cs_hi = peek();
	printf("%s %d:%d\n", opcode_fmt(op), combine_bytes(cs_lo, cs_hi), combine_bytes(ip_lo, ip_hi));
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

	printf("bits 16\n\n");

	opcode op;
	mode mod;
	register_ reg;
	bool w;
	byte b1, b2;
	while (i < fsize) {
		char b = buf[i];

		// first 8 bits
		switch (b & 0b11111111) {
		case 0b11111111:
			switch (buf[i+1] & 0b00111000) {
			case 0b00110000: w_reg_mem(OPCODE_PUSH, b); goto next;
			case 0b00010000: w_reg_mem(OPCODE_CALL, b); goto next;
			case 0b00011000: reg_mem_far(OPCODE_CALL); goto next;
			case 0b00100000: w_reg_mem(OPCODE_JMP, b); goto next;
			case 0b00101000: reg_mem_far(OPCODE_JMP); goto next;
			}
			break;
		case 0b10001111:
			if ((buf[i+1] & 0b00111000) == 0b00000000) {
				w_reg_mem(OPCODE_POP, b);
				goto next;
			}
			break;
		case 0b11010111: printf("%s\n", opcode_fmt(OPCODE_XLAT)); goto next;

		// xor to flip the pretend d bit
		case 0b10001101: reg_mem_with_reg_either(OPCODE_LEA, b^0b10, false); goto next;
		case 0b11000101: reg_mem_with_reg_either(OPCODE_LDS, b^0b10, false); goto next;

		// xor to flip the pretend d and w bits
		case 0b11000100: reg_mem_with_reg_either(OPCODE_LES, b^0b11, false); goto next;

		case 0b10011111: printf("%s\n", opcode_fmt(OPCODE_LAHF)); goto next;
		case 0b10011110: printf("%s\n", opcode_fmt(OPCODE_SAHF)); goto next;
		case 0b10011100: printf("%s\n", opcode_fmt(OPCODE_PUSHF)); goto next;
		case 0b10011101: printf("%s\n", opcode_fmt(OPCODE_POPF)); goto next;

		case 0b00110111: printf("%s\n", opcode_fmt(OPCODE_AAA)); goto next;
		case 0b00100111: printf("%s\n", opcode_fmt(OPCODE_DAA)); goto next;

		case 0b00111111: printf("%s\n", opcode_fmt(OPCODE_AAS)); goto next;
		case 0b00101111: printf("%s\n", opcode_fmt(OPCODE_DAS)); goto next;

		case 0b11010100:
			switch (buf[i+1] & 0b11111111) {
			case 0b00001010: printf("%s\n", opcode_fmt(OPCODE_AAM)); i++; goto next;
			}
			break;

		case 0b11010101:
			switch (buf[i+1] & 0b11111111) {
			case 0b00001010: printf("%s\n", opcode_fmt(OPCODE_AAD)); i++; goto next;
			}
			break;

		case 0b10011000: printf("%s\n", opcode_fmt(OPCODE_CBW)); goto next;
		case 0b10011001: printf("%s\n", opcode_fmt(OPCODE_CWD)); goto next;

		case 0b11000011: printf("%s\n", opcode_fmt(OPCODE_RET)); goto next;
		case 0b11000010:
			b1 = peek();
			b2 = peek();
			printf("%s %d\n", opcode_fmt(OPCODE_RET), combine_bytes(b1, b2));
			goto next;
		case 0b11001011: printf("%s\n", opcode_fmt(OPCODE_RETF)); goto next;
		case 0b11001010:
			b1 = peek();
			b2 = peek();
			printf("%s %d\n", opcode_fmt(OPCODE_RETF), combine_bytes(b1, b2));
			goto next;

		case 0b11101000: direct_segment(OPCODE_CALL); goto next;
		case 0b10011010: direct_intersegment(OPCODE_CALL); goto next;
		case 0b11101001: direct_segment(OPCODE_JMP); goto next;
		case 0b11101010: direct_intersegment(OPCODE_JMP); goto next;

		case 0b01110100: jump(OPCODE_JE); goto next;
		case 0b01111100: jump(OPCODE_JL); goto next;
		case 0b01111110: jump(OPCODE_JLE); goto next;
		case 0b01110010: jump(OPCODE_JB); goto next;
		case 0b01110110: jump(OPCODE_JBE); goto next;
		case 0b01111010: jump(OPCODE_JP); goto next;
		case 0b01110000: jump(OPCODE_JO); goto next;
		case 0b01111000: jump(OPCODE_JS); goto next;
		case 0b01110101: jump(OPCODE_JNE); goto next;
		case 0b01111101: jump(OPCODE_JNL); goto next;
		case 0b01111111: jump(OPCODE_JG); goto next;
		case 0b01110011: jump(OPCODE_JNB); goto next;
		case 0b01110111: jump(OPCODE_JA); goto next;
		case 0b01111011: jump(OPCODE_JNP); goto next;
		case 0b01110001: jump(OPCODE_JNO); goto next;
		case 0b01111001: jump(OPCODE_JNS); goto next;
		case 0b11100010: jump(OPCODE_LOOP); goto next;
		case 0b11100001: jump(OPCODE_LOOPZ); goto next;
		case 0b11100000: jump(OPCODE_LOOPNZ); goto next;
		case 0b11100011: jump(OPCODE_JCXZ); goto next;

		case 0b11001101: printf("%s %d\n", opcode_fmt(OPCODE_INT), peek()); goto next;
		case 0b11001100: printf("%s3\n", opcode_fmt(OPCODE_INT)); goto next;
		case 0b11001110: printf("%s\n", opcode_fmt(OPCODE_INTO)); goto next;
		case 0b11001111: printf("%s\n", opcode_fmt(OPCODE_IRET)); goto next;
		case 0b11111000: printf("%s\n", opcode_fmt(OPCODE_CLC)); goto next;
		case 0b11110101: printf("%s\n", opcode_fmt(OPCODE_CMC)); goto next;
		case 0b11111001: printf("%s\n", opcode_fmt(OPCODE_STC)); goto next;
		case 0b11111100: printf("%s\n", opcode_fmt(OPCODE_CLD)); goto next;
		case 0b11111101: printf("%s\n", opcode_fmt(OPCODE_STD)); goto next;
		case 0b11111010: printf("%s\n", opcode_fmt(OPCODE_CLI)); goto next;
		case 0b11111011: printf("%s\n", opcode_fmt(OPCODE_STI)); goto next;
		case 0b11110100: printf("%s\n", opcode_fmt(OPCODE_HLT)); goto next;
		case 0b10011011: printf("%s\n", opcode_fmt(OPCODE_WAIT)); goto next;
		case 0b11110000: printf("%s ", opcode_fmt(OPCODE_LOCK)); goto next;
		}

		// first 7 bits
		switch (b & 0b11111110) {
		case 0b11000110: immediate_to_reg_mem(OPCODE_MOV, b); goto next;
		case 0b10000110:
			// nasm is picky about the order of operands, so we
			// always flip the pretend d-bit except when MODE_REGISTER
			mod = mode_match(buf[i+1]);
			reg_mem_with_reg_either(OPCODE_XCHG, b^((mod != MODE_REGISTER) << 1), false);
			goto next;

		case 0b11100100:
			// little endian
			w = nth(b, 0);
			if (w == 0) {
				printf("%s al, %d\n", opcode_fmt(OPCODE_IN), (byte)peek());
			} else {
				printf("%s ax, %d\n", opcode_fmt(OPCODE_IN), (byte)peek());
			}
			goto next;
		case 0b11101100:
			// little endian
			w = nth(b, 0);
			if (w == 0) {
				printf("%s al, dx\n", opcode_fmt(OPCODE_IN));
			} else {
				printf("%s ax, dx\n", opcode_fmt(OPCODE_IN));
			}
			goto next;

		case 0b11100110:
			// little endian
			w = nth(b, 0);
			if (w == 0) {
				printf("%s %d, al\n", opcode_fmt(OPCODE_OUT), (byte)peek());
			} else {
				printf("%s %d, ax\n", opcode_fmt(OPCODE_OUT), (byte)peek());
			}
			goto next;
		case 0b11101110:
			// little endian
			w = nth(b, 0);
			if (w == 0) {
				printf("%s dx, al\n", opcode_fmt(OPCODE_OUT));
			} else {
				printf("%s dx, ax\n", opcode_fmt(OPCODE_OUT));
			}
			goto next;

		case 0b00000100: immediate_to_accumulator(OPCODE_ADD, b); goto next;
		case 0b00010100: immediate_to_accumulator(OPCODE_ADC, b); goto next;

		case 0b11111110:
			switch (buf[i+1] & 0b00111000) {
			case 0b00000000: w_reg_mem(OPCODE_INC, b); goto next;
			case 0b00001000: w_reg_mem(OPCODE_DEC, b); goto next;
			}
			break;

		case 0b00101100: immediate_to_accumulator(OPCODE_SUB, b); goto next;
		case 0b00011100: immediate_to_accumulator(OPCODE_SBB, b); goto next;

		case 0b11110110:
			switch (buf[i+1] & 0b00111000) {
			case 0b00011000: w_reg_mem(OPCODE_NEG, b); goto next;
			case 0b00100000: w_reg_mem(OPCODE_MUL, b); goto next;
			case 0b00101000: w_reg_mem(OPCODE_IMUL, b); goto next;
			case 0b00110000: w_reg_mem(OPCODE_DIV, b); goto next;
			case 0b00111000: w_reg_mem(OPCODE_IDIV, b); goto next;
			case 0b00010000: w_reg_mem(OPCODE_NOT, b); goto next;
			case 0b00000000: immediate_to_reg_mem(OPCODE_TEST, b); goto next;
			}
			break;

		case 0b00111100: immediate_to_accumulator(OPCODE_CMP, b); goto next;

		case 0b10100000: // Memory to accumulator
			op = OPCODE_MOV;

			w = nth(b, 0);

			b1 = peek();
			if (w == 0) {
				b2 = get_b2(b1);
			} else {
				b2 = peek();
			}

			printf("%s ax, [%d]\n", opcode_fmt(op),
			       combine_bytes(b1, b2));

			goto next;

		case 0b10100010: // Accumulator to memory
			op = OPCODE_MOV;

			w = nth(b, 0);

			b1 = peek();
			if (w == 0) {
				b2 = get_b2(b1);
			} else {
				b2 = peek();
			}

			printf("%s [%d], ax\n", opcode_fmt(op),
			       combine_bytes(b1, b2));

			goto next;

		case 0b10000000:
			switch (buf[i+1] & 0b00111000) {
			case 0b00100000: immediate_to_reg_mem(OPCODE_AND, b); goto next;
			case 0b00001000: immediate_to_reg_mem(OPCODE_OR, b); goto next;
			case 0b00110000: immediate_to_reg_mem(OPCODE_XOR, b); goto next;
			}
			break;

		case 0b00100100: immediate_to_accumulator(OPCODE_AND, b); goto next;
		case 0b10101000: immediate_to_accumulator(OPCODE_TEST, b); goto next;
		case 0b00001100: immediate_to_accumulator(OPCODE_OR, b); goto next;
		case 0b00110100: immediate_to_accumulator(OPCODE_XOR, b); goto next;

		case 0b11110010: printf("%s ", opcode_fmt(OPCODE_REP)); goto next;
		case 0b10100100: str(OPCODE_MOVS, b); goto next;
		case 0b10100110: str(OPCODE_CMPS, b); goto next;
		case 0b10101110: str(OPCODE_SCAS, b); goto next;
		case 0b10101100: str(OPCODE_LODS, b); goto next;
		case 0b10101010: str(OPCODE_STOS, b); goto next;
		}

		// first 6 bits
		switch (b & 0b11111100) {
		case 0b10000000:
			switch (buf[i+1] & 0b00111000) {
			case 0b00000000: immediate_to_reg_mem_sign(OPCODE_ADD, b); goto next;
			case 0b00010000: immediate_to_reg_mem_sign(OPCODE_ADC, b); goto next;
			case 0b00101000: immediate_to_reg_mem_sign(OPCODE_SUB, b); goto next;
			case 0b00011000: immediate_to_reg_mem_sign(OPCODE_SBB, b); goto next;
			case 0b00111000: immediate_to_reg_mem_sign(OPCODE_CMP, b); goto next;
			}
			break;

		case 0b10001000: reg_mem_with_reg_either(OPCODE_MOV, b, false); goto next;
		case 0b00000000: reg_mem_with_reg_either(OPCODE_ADD, b, false); goto next;
		case 0b00010000: reg_mem_with_reg_either(OPCODE_ADC, b, false); goto next;
		case 0b00101000: reg_mem_with_reg_either(OPCODE_SUB, b, false); goto next;
		case 0b00011000: reg_mem_with_reg_either(OPCODE_SBB, b, false); goto next;
		case 0b00111000: reg_mem_with_reg_either(OPCODE_CMP, b, false); goto next;

		case 0b11010000:
			switch (buf[i+1] & 0b00111000) {
			case 0b00100000: v_w_reg_mem(OPCODE_SHL, b); goto next;
			case 0b00101000: v_w_reg_mem(OPCODE_SHR, b); goto next;
			case 0b00111000: v_w_reg_mem(OPCODE_SAR, b); goto next;
			case 0b00000000: v_w_reg_mem(OPCODE_ROL, b); goto next;
			case 0b00001000: v_w_reg_mem(OPCODE_ROR, b); goto next;
			case 0b00010000: v_w_reg_mem(OPCODE_RCL, b); goto next;
			case 0b00011000: v_w_reg_mem(OPCODE_RCR, b); goto next;
			}
			break;

		case 0b00100000: reg_mem_with_reg_either(OPCODE_AND, b, false); goto next;
		case 0b10000100: reg_mem_with_reg_either(OPCODE_TEST, b, false); goto next;
		case 0b00001000: reg_mem_with_reg_either(OPCODE_OR, b, false); goto next;
		case 0b00110000: reg_mem_with_reg_either(OPCODE_XOR, b, false); goto next;
		}

		switch (b & 0b11100111) {
		case 0b00000110: seg_reg_print(OPCODE_PUSH, b); goto next;
		case 0b00000111: seg_reg_print(OPCODE_POP, b); goto next;
		}

		switch (b & 0b11111101) {
		// implicit d-bit split into two instructions in the manual
		case 0b10001100:
			switch (buf[i+1] & 0b00100000) {
			case 0b00000000: reg_mem_with_reg_either(OPCODE_MOV, b, true); goto next;
			}
			break;
		}

		// first 5 bits
		switch (b & 0b11111000) {
		case 0b01010000: reg_print(OPCODE_PUSH, b); goto next;
		case 0b01011000: reg_print(OPCODE_POP, b); goto next;
		case 0b10010000:
			reg = register_match(b, 1);
			printf("%s ax, %s\n", opcode_fmt(OPCODE_XCHG), register_fmt(reg));
			goto next;
		case 0b01000000: reg_print(OPCODE_INC, b); goto next;
		case 0b01001000: reg_print(OPCODE_DEC, b); goto next;
		}

		// first 4 bits
		switch (b & 0b11110000) {
		case 0b10110000: // Immediate to register
			op = OPCODE_MOV;

			w = nth(b, 3);
			reg = register_match(b, w);

			b1 = peek();
			if (w == 0) {
				b2 = get_b2(b1);
			} else {
				b2 = peek();
			}

			printf("%s %s, %d\n", opcode_fmt(op), register_fmt(reg),
			       combine_bytes(b1, b2));
			goto next;
		}
	next:
		i++;
	}

	fclose(f);
	free(buf);
	return 0;

err:
	fclose(f);
	free(buf);
	return 1;
}
