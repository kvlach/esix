#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sim86.h"

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

const char *opcodes_fmt[90] = {
	"mov",    "push",     "pop",   "xchg",  "in",     "out",   "xlat",  "lea",
	"lds",    "les",      "lahf",  "sahf",  "pushf",  "popf",  "add",   "adc",
	"inc",    "aaa",      "daa",   "sub",   "sbb",    "dec",   "neg",   "cmp",
	"aas",    "das",      "mul",   "imul",  "aam",    "div",   "idiv",  "aad",
	"cbw",    "cwd",      "not",   "shl",   "shr",    "sar",   "rol",   "ror",
	"rcl",    "rcr",      "and",   "test",  "or",     "xor",   "rep",   "movs",
	"cmps",   "scas",     "lods",  "stos",  "call",   "jmp",   "ret",   "je",
	"jl",     "jle",      "jb",    "jbe",   "jp",     "jo",    "js",    "jne",
	"jnl",    "jg",       "jnb",   "ja",    "jnp",    "jno",   "jns",   "loop",
	"loopz",  "loopnz",   "jcxz",  "int",   "into",   "iret",  "clc",   "cmc",
	"stc",    "cld",      "std",   "cli",   "sti",    "hlt",   "wait",  "esc",
	"lock",   "segment",
};

const char *opcode_fmt(const opcode op) {
	return opcodes_fmt[op];
}

const register_ registers[16] = {
    REGISTER_AL, REGISTER_CL, REGISTER_DL, REGISTER_BL,
    REGISTER_AH, REGISTER_CH, REGISTER_DH, REGISTER_BH,
    REGISTER_AX, REGISTER_CX, REGISTER_DX, REGISTER_BX,
    REGISTER_SP, REGISTER_BP, REGISTER_SI, REGISTER_DI};

const char *registers_fmt[16] = {
    "al", "cl", "dl", "bl",
    "ah", "ch", "dh", "bh",
    "ax", "cx", "dx", "bx",
    "sp", "bp", "si", "di"};

register_ register_match(const byte b, const bool w) {
	return registers[(w << 3) | (b & 0b111)];
}

const char *register_fmt(const register_ r) {
	return registers_fmt[r];
}

const segment_register segment_registers[4] = {
    SEGMENT_REGISTER_ES,
    SEGMENT_REGISTER_CS,
    SEGMENT_REGISTER_SS,
    SEGMENT_REGISTER_DS,
};

const char *segment_registers_fmt[4] = { "es", "cs", "ss", "ds" };

segment_register segment_register_match(const byte b) {
	return segment_registers[b];
}

const char *segment_register_fmt(const segment_register sr) {
	return segment_registers_fmt[sr];
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
	b &= 0b00000111;
	if (mod == MODE_MEMORY_NO_DISPLACEMENT && b == 0b00000110) {
		return EFFECTIVE_ADDR_DIRECT_ADDR;
	}
	return effective_addrs[b];
}

char *effective_addr_fmt(effective_addr ea, mode mod, int16_t disp) {
	// Max number of required bytes:
	//   "[]" -> 2 bytes
	//   "bx + si" -> 7 bytes
	//   " + " or " - " -> 3 bytes
	//   2**16 = 65536 -> 5 bytes
	// A total of 17 bytes.
	char *fmt = (char *)malloc(17);
	if (fmt == NULL) {
		return NULL;
	}

	if (ea == EFFECTIVE_ADDR_DIRECT_ADDR) {
		sprintf(fmt, "[%d]", disp);
		return fmt;
	}

	const char *ea_fmt = effective_addrs_fmt[ea];

	if (mod == MODE_MEMORY_NO_DISPLACEMENT || disp == 0) {
		sprintf(fmt, "[%s]", ea_fmt);
	} else if (disp > 0) {
		sprintf(fmt, "[%s + %d]", ea_fmt, disp);
	} else {
		sprintf(fmt, "[%s - %d]", ea_fmt, -disp);
	}

	return fmt;
}

typedef struct {
	mode mod;
	register_ reg;
	effective_addr ea;
	int16_t disp;
} register_memory;

register_memory register_memory_match(byte b, const mode mod, const bool w) {
	effective_addr ea = effective_addr_match(b, mod);

	if (mod == MODE_MEMORY_16BIT_DISPLACEMENT || ea == EFFECTIVE_ADDR_DIRECT_ADDR) {
		byte low = peek();
		byte high = peek();
		return (register_memory){ .mod = mod, .ea = ea, .disp = combine_bytes(low, high) };
	}

	if (mod == MODE_MEMORY_8BIT_DISPLACEMENT) {
		return (register_memory){ .mod = mod, .ea = ea, .disp = peek() };
	}

	if (mod == MODE_MEMORY_NO_DISPLACEMENT) {
		return (register_memory){ .mod = mod, .ea = ea };
	}

	// else MODE_REGISTER
	return (register_memory){ .mod = mod, .reg = register_match(b, w) };
}

const char *register_memory_fmt(register_memory r_m) {
	if (r_m.mod == MODE_REGISTER) {
		return register_fmt(r_m.reg);
	}
	return effective_addr_fmt(r_m.ea, r_m.mod, r_m.disp);
}

byte get_b2(u_int8_t b1) {
	if (b1 > 0) {
		return 0;
	}
	return 0b11111111;
}

int nth(byte b, int n) { return (b >> n) & 1; }

void printBits(char ch) {
	for (int i = 7; i >= 0; --i) {
		putchar((ch & (1 << i)) ? '1' : '0');
	}
	putchar('\n');
}

void reg_mem_with_reg_either(const opcode op, byte b) {
	// little endian
	bool d = nth(b, 1);
	bool w = nth(b, 0);

	b = peek();
	mode mod = mode_match(b);
	register_ reg = register_match(b >> 3, w);
	register_memory r_m = register_memory_match(b, mod, w);

	if (d == 0) {
		printf("%s %s, %s\n", opcode_fmt(op), register_memory_fmt(r_m), register_fmt(reg));
	} else {
		printf("%s %s, %s\n", opcode_fmt(op), register_fmt(reg), register_memory_fmt(r_m));
	}
}

void immediate_to_reg_mem(const opcode op, byte b) {
	// little endian
	bool w = nth(b, 0);

	b = peek();
	mode mod = mode_match(b);
	register_memory r_m = register_memory_match(b, mod, w);

	byte data1 = peek();
	byte data2;
	if (w == 0) {
		data2 = get_b2(data1);
	} else {
		data2 = peek();
	}

	int16_t n = combine_bytes(data1, data2);

	if (w == 0) {
		printf("%s %s, byte %d\n", opcode_fmt(op), register_memory_fmt(r_m), n);
	} else {
		printf("%s %s, word %d\n", opcode_fmt(op), register_memory_fmt(r_m), n);
	}
}

void immediate_to_reg_mem_sign(const opcode op, byte b) {
	// little endian
	bool w = nth(b, 0);
	bool s = nth(b, 1);

	b = peek();
	mode mod = mode_match(b);
	register_memory r_m = register_memory_match(b, mod, w);

	byte data1 = peek();
	byte data2;

	int16_t n;
	if (s == 0 && w == 1) {
		n = combine_bytes(data1, peek());
	} else if (s == 1) {
		n = sign_extend(data1);
	} else {
//		data2 = get_b2(data1);
//		n = combine_bytes(data1, data2);
		n = (int16_t)data1;
	}

	if (w == 0) {
		printf("%s %s, byte %d\n", opcode_fmt(op), register_memory_fmt(r_m), n);
	} else {
		printf("%s %s, word %d\n", opcode_fmt(op), register_memory_fmt(r_m), n);
	}
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

void reg_mem_print(const opcode op, const byte b) {
	mode mod = mode_match(b);
	register_memory r_m = register_memory_match(b, mod, 1);
	printf("%s word %s\n", opcode_fmt(op), register_memory_fmt(r_m));
}

void reg_mem_wide_print(const opcode op, byte b) {
	// little endian
	bool w = nth(b, 0);
	b = peek();
	mode mod = mode_match(b);
	register_memory r_m = register_memory_match(b, mod, w);
	if (w == 0) {
		printf("%s byte %s\n", opcode_fmt(op), register_memory_fmt(r_m));
	} else {
		printf("%s word %s\n", opcode_fmt(op), register_memory_fmt(r_m));
	}
}

void seg_reg_print(const opcode op, const byte b) {
	segment_register sr = segment_register_match((b & 0b00011000) >> 3);
	printf("%s %s\n", opcode_fmt(op), segment_register_fmt(sr));
}

void reg_print(const opcode op, const byte b) {
	register_ reg = register_match(b, 1);
	printf("%s %s\n", opcode_fmt(op), register_fmt(reg));
}

void v_w_reg_mem(const opcode op, byte b) {
	bool v = nth(b, 1);
	bool w = nth(b, 0);

	b = peek();

	mode mod = mode_match(b);
	register_memory r_m = register_memory_match(b, mod, w);
	if (w == 0 && v == 0) {
		printf("%s byte %s, 1\n", opcode_fmt(op), register_memory_fmt(r_m));
	} else if (w == 0 && v == 1) {
		printf("%s byte %s, cl\n", opcode_fmt(op), register_memory_fmt(r_m));
	} else if (w == 1 && v == 0) {
		printf("%s word %s, 1\n", opcode_fmt(op), register_memory_fmt(r_m));
	} else {
		printf("%s word %s, cl\n", opcode_fmt(op), register_memory_fmt(r_m));
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
	register_ reg;
	segment_register sr;
	bool w;
	byte b1, b2;
	while (i < fsize) {
		char b = buf[i];

		// first 8 bits
		switch (b & 0b11111111) {
		case 0b11111111:
			switch (buf[i+1] & 0b00111000) {
			case 0b00110000: reg_mem_print(OPCODE_PUSH, peek()); goto next;
			case 0b00010000: reg_mem_print(OPCODE_CALL, peek()); goto next;
			case 0b00100000: reg_mem_print(OPCODE_JMP, peek()); goto next;
			}
			break;
		case 0b10001111:
			if ((buf[i+1] & 0b00111000) == 0b00000000) {
				reg_mem_print(OPCODE_POP, peek());
				goto next;
			}
			break;
		case 0b11010111: printf("%s\n", opcode_fmt(OPCODE_XLAT)); goto next;

		// xor to flip the pretend d bit
		case 0b10001101: reg_mem_with_reg_either(OPCODE_LEA, b^0b10); goto next;
		case 0b11000101: reg_mem_with_reg_either(OPCODE_LDS, b^0b10); goto next;

		// xor to flip the pretend d and w bits
		case 0b11000100: reg_mem_with_reg_either(OPCODE_LES, b^0b11); goto next;

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
		}

		// first 7 bits
		switch (b & 0b11111110) {
		case 0b11000110: immediate_to_reg_mem(OPCODE_MOV, b); goto next;
		case 0b10000110: reg_mem_with_reg_either(OPCODE_XCHG, b); goto next;

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
			case 0b00000000: reg_mem_wide_print(OPCODE_INC, b); goto next;
			case 0b00001000: reg_mem_wide_print(OPCODE_DEC, b); goto next;
			}
			break;

		case 0b00101100: immediate_to_accumulator(OPCODE_SUB, b); goto next;
		case 0b00011100: immediate_to_accumulator(OPCODE_SBB, b); goto next;

		case 0b11110110:
			switch (buf[i+1] & 0b00111000) {
			case 0b00011000: reg_mem_wide_print(OPCODE_NEG, b); goto next;
			case 0b00100000: reg_mem_wide_print(OPCODE_MUL, b); goto next;
			case 0b00101000: reg_mem_wide_print(OPCODE_IMUL, b); goto next;
			case 0b00110000: reg_mem_wide_print(OPCODE_DIV, b); goto next;
			case 0b00111000: reg_mem_wide_print(OPCODE_IDIV, b); goto next;
			case 0b00010000: reg_mem_wide_print(OPCODE_NOT, b); goto next;
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

		case 0b10001000: reg_mem_with_reg_either(OPCODE_MOV, b); goto next;
		case 0b00000000: reg_mem_with_reg_either(OPCODE_ADD, b); goto next;
		case 0b00010000: reg_mem_with_reg_either(OPCODE_ADC, b); goto next;
		case 0b00101000: reg_mem_with_reg_either(OPCODE_SUB, b); goto next;
		case 0b00011000: reg_mem_with_reg_either(OPCODE_SBB, b); goto next;
		case 0b00111000: reg_mem_with_reg_either(OPCODE_CMP, b); goto next;

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

		case 0b00100000: reg_mem_with_reg_either(OPCODE_AND, b); goto next;
		case 0b10000100: reg_mem_with_reg_either(OPCODE_TEST, b); goto next;
		case 0b00001000: reg_mem_with_reg_either(OPCODE_OR, b); goto next;
		case 0b00110000: reg_mem_with_reg_either(OPCODE_XOR, b); goto next;
		}

		switch (b & 0b11100111) {
		case 0b00000110: seg_reg_print(OPCODE_PUSH, b); goto next;
		case 0b00000111: seg_reg_print(OPCODE_POP, b); goto next;
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
