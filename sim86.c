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

const char *opcode_fmt(const opcode op) {
	switch (op) {
	case OPCODE_MOV:    return "mov";
	case OPCODE_ADD:    return "add";
	case OPCODE_CMP:    return "cmp";
	case OPCODE_SUB:    return "sub";
	case OPCODE_JE:     return "je";
	case OPCODE_JL:     return "jl";
	case OPCODE_JLE:    return "jle";
	case OPCODE_JB:     return "jb";
	case OPCODE_JBE:    return "jbe";
	case OPCODE_JP:     return "jp";
	case OPCODE_JO:     return "jo";
	case OPCODE_JS:     return "js";
	case OPCODE_JNE:    return "jne";
	case OPCODE_JNL:    return "jnl";
	case OPCODE_JG:     return "jg";
	case OPCODE_JNB:    return "jnb";
	case OPCODE_JA:     return "ja";
	case OPCODE_JNP:    return "jnp";
	case OPCODE_JNO:    return "jno";
	case OPCODE_JNS:    return "jns";
	case OPCODE_LOOP:   return "loop";
	case OPCODE_LOOPZ:  return "loopz";
	case OPCODE_LOOPNZ: return "loopnz";
	case OPCODE_JCXZ:   return "jcxz";
	}
}

register_ registers[16] = {REGISTER_AL, REGISTER_CL, REGISTER_DL, REGISTER_BL,
			   REGISTER_AH, REGISTER_CH, REGISTER_DH, REGISTER_BH,
			   REGISTER_AX, REGISTER_CX, REGISTER_DX, REGISTER_BX,
			   REGISTER_SP, REGISTER_BP, REGISTER_SI, REGISTER_DI};

register_ register_match(const byte b, const bool w) {
	return registers[b | w << 3];
}

const char *register_fmt(const register_ r) {
	switch (r) {
	case REGISTER_AL: return "al";
	case REGISTER_CL: return "cl";
	case REGISTER_DL: return "dl";
	case REGISTER_BL: return "bl";
	case REGISTER_AH: return "ah";
	case REGISTER_CH: return "ch";
	case REGISTER_DH: return "dh";
	case REGISTER_BH: return "bh";
	case REGISTER_AX: return "ax";
	case REGISTER_CX: return "cx";
	case REGISTER_DX: return "dx";
	case REGISTER_BX: return "bx";
	case REGISTER_SP: return "sp";
	case REGISTER_BP: return "bp";
	case REGISTER_SI: return "si";
	case REGISTER_DI: return "di";
	}
}

mode modes[4] = {
    MODE_MEMORY_NO_DISPLACEMENT,
    MODE_MEMORY_8BIT_DISPLACEMENT,
    MODE_MEMORY_16BIT_DISPLACEMENT,
    MODE_REGISTER,
};

mode mode_match(const byte b) {
	return modes[b >> 6];
}

effective_addr effective_addrs[8] = {
    EFFECTIVE_ADDR_BX_SI,
    EFFECTIVE_ADDR_BX_DI,
    EFFECTIVE_ADDR_BP_SI,
    EFFECTIVE_ADDR_BP_DI,
    EFFECTIVE_ADDR_SI,
    EFFECTIVE_ADDR_DI,
    EFFECTIVE_ADDR_BP,
    EFFECTIVE_ADDR_BX,
};

effective_addr effective_addr_match(byte b, const mode mod) {
	b &= 0b00000111;
	if (mod == MODE_MEMORY_NO_DISPLACEMENT && b == 0b00000110) {
		return EFFECTIVE_ADDR_DIRECT_ADDR;
	}
	return effective_addrs[b];
}

char *effective_addr_fmt(effective_addr ea, mode mod, int16_t disp) {
	// TODO: more sensible number of bytes
	char *fmt = (char *)malloc(100);
	if (fmt == NULL) {
		return NULL;
	}

	switch (ea) {
	case EFFECTIVE_ADDR_BX_SI: sprintf(fmt, "[bx + si"); break;
	case EFFECTIVE_ADDR_BX_DI: sprintf(fmt, "[bx + di"); break;
	case EFFECTIVE_ADDR_BP_SI: sprintf(fmt, "[bp + si"); break;
	case EFFECTIVE_ADDR_BP_DI: sprintf(fmt, "[bp + di"); break;
	case EFFECTIVE_ADDR_SI:   sprintf(fmt, "[si");      break;
	case EFFECTIVE_ADDR_DI:   sprintf(fmt, "[di");      break;
	case EFFECTIVE_ADDR_BP:   sprintf(fmt, "[bp");      break;
	case EFFECTIVE_ADDR_BX:   sprintf(fmt, "[bx");      break;
	}

	switch (mod) {
	case MODE_MEMORY_NO_DISPLACEMENT:
		if (ea == EFFECTIVE_ADDR_DIRECT_ADDR) {
			sprintf(fmt + strlen(fmt), "[%d]", disp);
		} else {
			strcat(fmt, "]");
		}
		break;

	case MODE_MEMORY_8BIT_DISPLACEMENT:
	case MODE_MEMORY_16BIT_DISPLACEMENT:
		if (disp == 0) {
			strcat(fmt, "]");
		} else if (disp > 0) {
			sprintf(fmt + strlen(fmt), " + %d]", disp);
		} else {
			sprintf(fmt + strlen(fmt), " - %d]", -disp);
		}
		break;
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
	b &= 0b00000111;
	b |= w << 3;
	return (register_memory){ .mod = mod, .reg = registers[b] };
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
	register_ reg = register_match(((b & 0b00111000) >> 3), w);
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
	bool w;
	byte b1, b2;
	while (i < fsize) {
		char b = buf[i];

		// first 8 bits
		switch (b & 0b11111111) {
		case 0b01110100: jump(OPCODE_JE); break;
		case 0b01111100: jump(OPCODE_JL); break;
		case 0b01111110: jump(OPCODE_JLE); break;
		case 0b01110010: jump(OPCODE_JB); break;
		case 0b01110110: jump(OPCODE_JBE); break;
		case 0b01111010: jump(OPCODE_JP); break;
		case 0b01110000: jump(OPCODE_JO); break;
		case 0b01111000: jump(OPCODE_JS); break;
		case 0b01110101: jump(OPCODE_JNE); break;
		case 0b01111101: jump(OPCODE_JNL); break;
		case 0b01111111: jump(OPCODE_JG); break;
		case 0b01110011: jump(OPCODE_JNB); break;
		case 0b01110111: jump(OPCODE_JA); break;
		case 0b01111011: jump(OPCODE_JNP); break;
		case 0b01110001: jump(OPCODE_JNO); break;
		case 0b01111001: jump(OPCODE_JNS); break;
		case 0b11100010: jump(OPCODE_LOOP); break;
		case 0b11100001: jump(OPCODE_LOOPZ); break;
		case 0b11100000: jump(OPCODE_LOOPNZ); break;
		case 0b11100011: jump(OPCODE_JCXZ); break;
		}

		// first 7 bits
		switch (b & 0b11111110) {
		case 0b11000110: immediate_to_reg_mem(OPCODE_MOV, b); break;

		case 0b00000100: immediate_to_accumulator(OPCODE_ADD, b); break;
		case 0b00101100: immediate_to_accumulator(OPCODE_SUB, b); break;
		case 0b00111100: immediate_to_accumulator(OPCODE_CMP, b); break;

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

			break;

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

			break;
		}

		// first 6 bits
		switch (b & 0b11111100) {
		case 0b10000000:
			switch (buf[i+1] & 0b00111000) {
			case 0b00101000: immediate_to_reg_mem_sign(OPCODE_SUB, b); break;
			case 0b00111000: immediate_to_reg_mem_sign(OPCODE_CMP, b); break;
			case 0b00000000: immediate_to_reg_mem_sign(OPCODE_ADD, b); break;
			}
			break;

		case 0b10001000: reg_mem_with_reg_either(OPCODE_MOV, b); break;
		case 0b00111000: reg_mem_with_reg_either(OPCODE_CMP, b); break;
		case 0b00101000: reg_mem_with_reg_either(OPCODE_SUB, b); break;
		case 0b00000000: reg_mem_with_reg_either(OPCODE_ADD, b); break;
		}

		// first 4 bits
		switch (b & 0b11110000) {
		case 0b10110000: // Immediate to register
			op = OPCODE_MOV;

			w = nth(b, 3);
			reg = register_match(b & 0b00000111, w);

			b1 = peek();
			if (w == 0) {
				b2 = get_b2(b1);
			} else {
				b2 = peek();
			}

			printf("%s %s, %d\n", opcode_fmt(op), register_fmt(reg),
			       combine_bytes(b1, b2));
			break;
		}

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