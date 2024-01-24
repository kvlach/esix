#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef enum {
	AL,
	CL,
	DL,
	BL,
	AH,
	CH,
	DH,
	BH,
	AX,
	CX,
	DX,
	BX,
	SP,
	BP,
	SI,
	DI,
} Register;

Register registers[16] = {AL, CL, DL, BL, AH, CH, DH, BH,
			  AX, CX, DX, BX, SP, BP, SI, DI};

const char *register_fmt(const Register r) {
	switch (r) {
	case AL: return "al";
	case CL: return "cl";
	case DL: return "dl";
	case BL: return "bl";
	case AH: return "ah";
	case CH: return "ch";
	case DH: return "dh";
	case BH: return "bh";
	case AX: return "ax";
	case CX: return "cx";
	case DX: return "dx";
	case BX: return "bx";
	case SP: return "sp";
	case BP: return "bp";
	case SI: return "si";
	case DI: return "di";
	}
}

typedef enum {
	MOV,
	ADD,
	CMP,
	SUB,
	JE,
	JL,
	JLE,
	JB,
	JBE,
	JP,
	JO,
	JS,
	JNE,
	JNL,
	JG,
	JNB,
	JA,
	JNP,
	JNO,
	JNS,
	LOOP,
	LOOPZ,
	LOOPNZ,
	JCXZ,
} opcode;

const char *opcode_fmt(const opcode op) {
	switch (op) {
	case MOV: return "mov";
	case ADD: return "add";
	case CMP: return "cmp";
	case SUB: return "sub";
	case JE:    return "je";
	case JL:    return "jl";
	case JLE:   return "jle";
	case JB:    return "jb";
	case JBE:   return "jbe";
	case JP:    return "jp";
	case JO:    return "jo";
	case JS:    return "js";
	case JNE:   return "jne";
	case JNL:   return "jnl";
	case JG:    return "jg";
	case JNB:   return "jnb";
	case JA:    return "ja";
	case JNP:   return "jnp";
	case JNO:   return "jno";
	case JNS:   return "jns";
	case LOOP:  return "loop";
	case LOOPZ: return "loopz";
	case LOOPNZ:return "loopnz";
	case JCXZ:  return "jcxz";
	}
}

typedef enum {
	MODE_MEMORY_NO_DISPLACEMENT,
	MODE_MEMORY_8BIT_DISPLACEMENT,
	MODE_MEMORY_16BIT_DISPLACEMENT,
	MODE_REGISTER,
} mode;

mode modes[4] = {
    MODE_MEMORY_NO_DISPLACEMENT,
    MODE_MEMORY_8BIT_DISPLACEMENT,
    MODE_MEMORY_16BIT_DISPLACEMENT,
    MODE_REGISTER,
};

mode mode_match(const char b) {
	return modes[(b & 0b11000000) >> 6];
}

Register match_register(char b, const bool w) {
	b |= w << 3;
	return registers[b];
}

Register match_register_memory(char b, const mode mod, const bool w) {
	switch (mod) {
	case MODE_MEMORY_NO_DISPLACEMENT:
	case MODE_MEMORY_8BIT_DISPLACEMENT:
	case MODE_MEMORY_16BIT_DISPLACEMENT:
		break;
	case MODE_REGISTER:
		b &= 0b00000111;
		b |= w << 3;
		return registers[b];
	}
}

typedef enum {
	BX_SI,
	BX_DI,
	BP_SI,
	BP_DI,
	SI_,
	DI_,
	BP_,
	BX_,
	DIRECT_ADDR,
} effective_addr;

effective_addr effective_addrs[8] = {
    BX_SI, BX_DI, BP_SI, BP_DI, SI_, DI_, BP_, BX_,
};

effective_addr effective_addr_match(char b, const mode mod) {
	b &= 0b00000111;
	if (mod == MODE_MEMORY_NO_DISPLACEMENT && b == 0b00000110) {
		return DIRECT_ADDR;
	}
	return effective_addrs[b];
}

int16_t combine_bytes(char low, char high) {
	return (int16_t)(((uint16_t)high << 8) | (uint8_t)low);
}

char *effective_addr_fmt(effective_addr ea, mode mod, char b1, char b2) {
	// TODO: more sensible number of bytes
	// TODO: is a malloc even needed here? Just char[100]
	char *fmt = (char *)malloc(100);
	if (fmt == NULL) {
		// TODO: Handle memory allocation failure
		return NULL;
	}

	switch (ea) {
	case BX_SI: sprintf(fmt, "[bx + si"); break;
	case BX_DI: sprintf(fmt, "[bx + di"); break;
	case BP_SI: sprintf(fmt, "[bp + si"); break;
	case BP_DI: sprintf(fmt, "[bp + di"); break;
	case SI_:   sprintf(fmt, "[si");      break;
	case DI_:   sprintf(fmt, "[di");      break;
	case BP_:   sprintf(fmt, "[bp");      break;
	case BX_:   sprintf(fmt, "[bx");      break;
	}

	switch (mod) {
	case MODE_MEMORY_NO_DISPLACEMENT:
		if (ea == DIRECT_ADDR) {
			sprintf(fmt + strlen(fmt), "[%d]",
				combine_bytes(b1, b2));
		} else {
			strcat(fmt, "]");
		}
		break;
	case MODE_MEMORY_8BIT_DISPLACEMENT:
		if (b1 == 0) {
			strcat(fmt, "]");
			break;
		}
		// Has been sign extended
	case MODE_MEMORY_16BIT_DISPLACEMENT:
		int16_t n = combine_bytes(b1, b2);

		if (n > 0) {
			sprintf(fmt + strlen(fmt), " + %d]", n);
		} else {
			sprintf(fmt + strlen(fmt), " - %d]", -n);
		}
		break;
	}
	return fmt;
}

const char *register_memory_fmt(Register r, mode mod, effective_addr ea, char b1, char b2) {
	if (mod == MODE_REGISTER) {
		return register_fmt(r);
	}
	return effective_addr_fmt(ea, mod, b1, b2);
}

int16_t sign_extend(int8_t n) {
	if (n > 0) {
		return combine_bytes(n, 0);
	}
	return combine_bytes(n, (char)0b11111111);
}

char get_b2(int8_t b1) {
	if (b1 > 0) {
		return 0;
	}
	return (char)0b11111111;
}

int nth(char c, int n) { return (c >> n) & 1; }

void printBits(char ch) {
	for (int i = 7; i >= 0; --i) {
		putchar((ch & (1 << i)) ? '1' : '0');
	}
	putchar('\n');
}

char *buf;
int i = 0;

char peek() { return buf[++i]; }

void reg_mem_with_reg_either(const opcode op, char b) {
	// little endian
	bool d = nth(b, 1);
	bool w = nth(b, 0);

	b = peek();
	mode mod = mode_match(b);

	effective_addr ea;
	if (mod != MODE_REGISTER) {
		ea = effective_addr_match(b, mod);
	}

	char b1, b2;
	if (mod == MODE_MEMORY_8BIT_DISPLACEMENT) {
		b1 = peek();
		b2 = get_b2(b1);
	}
	if (mod == MODE_MEMORY_16BIT_DISPLACEMENT || ea == DIRECT_ADDR) {
		b1 = peek();
		b2 = peek();
	}

	Register reg = match_register((char)((b & 0b00111000) >> 3), w);
	Register r_m = match_register_memory(b, mod, w);

	if (d == 0) {
		printf("%s %s, %s\n", opcode_fmt(op),
		       register_memory_fmt(r_m, mod, ea, b1, b2), register_fmt(reg));
	} else {
		printf("%s %s, %s\n", opcode_fmt(op), register_fmt(reg),
		       register_memory_fmt(r_m, mod, ea, b1, b2));
	}
}

void immediate_to_reg_mem(const opcode op, char b) {
	// little endian
	bool w = nth(b, 0);

	b = peek();
	mode mod = mode_match(b);

	effective_addr ea;
	if (mod != MODE_REGISTER) {
		ea = effective_addr_match(b, mod);
	}

	char b1, b2;
	if (mod == MODE_MEMORY_8BIT_DISPLACEMENT) {
		b1 = peek();
		b2 = get_b2(b1);
	}

	if (mod == MODE_MEMORY_16BIT_DISPLACEMENT || ea == DIRECT_ADDR) {
		b1 = peek();
		b2 = peek();
	}

	Register r_m = match_register_memory(b, mod, w);

	char data1 = peek();
	char data2;
	if (w == 0) {
		data2 = get_b2(data1);
	} else {
		data2 = peek();
	}

	int16_t n = combine_bytes(data1, data2);

	if (w == 0) {
		printf("%s %s, byte %d\n", opcode_fmt(op),
		       register_memory_fmt(r_m, mod, ea, b1, b2), n);
	} else {
		printf("%s %s, word %d\n", opcode_fmt(op),
		       register_memory_fmt(r_m, mod, ea, b1, b2), n);
	}
}

void immediate_to_reg_mem_sign(const opcode op, char b) {
	// little endian
	bool w = nth(b, 0);
	bool s = nth(b, 1);

	b = peek();
	mode mod = mode_match(b);

	effective_addr ea;
	if (mod != MODE_REGISTER) {
		ea = effective_addr_match(b, mod);
	}

	char b1, b2;
	if (mod == MODE_MEMORY_8BIT_DISPLACEMENT) {
		b1 = peek();
		b2 = get_b2(b1);
	}

	if (mod == MODE_MEMORY_16BIT_DISPLACEMENT || ea == DIRECT_ADDR) {
		b1 = peek();
		b2 = peek();
	}

	Register r_m = match_register_memory(b, mod, w);

	char data1 = peek();
	char data2;

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
		printf("%s %s, byte %d\n", opcode_fmt(op),
		       register_memory_fmt(r_m, mod, ea, b1, b2), n);
	} else {
		printf("%s %s, word %d\n", opcode_fmt(op),
		       register_memory_fmt(r_m, mod, ea, b1, b2), n);
	}
}

void immediate_to_accumulator(opcode op, char b) {
	bool w = nth(b, 0);

	char b1 = peek();
	char b2;
	if (w == 0) {
		b2 = get_b2(b1);
		printf("%s al, %d\n", opcode_fmt(op),
		       combine_bytes(b1, b2));
	} else {
		b2 = peek();
		printf("%s ax, %d\n", opcode_fmt(op),
		       combine_bytes(b1, b2));
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
	mode mod;
	effective_addr ea;
	Register reg, r_m;
	bool w, d;

	char b1;
	char b2;
	while (i < fsize) {
		char b = buf[i];

		// first 8 bits
		switch (b & 0b11111111) {
		case 0b01110100: jump(JE); break;
		case 0b01111100: jump(JL); break;
		case 0b01111110: jump(JLE); break;
		case 0b01110010: jump(JB); break;
		case 0b01110110: jump(JBE); break;
		case 0b01111010: jump(JP); break;
		case 0b01110000: jump(JO); break;
		case 0b01111000: jump(JS); break;
		case 0b01110101: jump(JNE); break;
		case 0b01111101: jump(JNL); break;
		case 0b01111111: jump(JG); break;
		case 0b01110011: jump(JNB); break;
		case 0b01110111: jump(JA); break;
		case 0b01111011: jump(JNP); break;
		case 0b01110001: jump(JNO); break;
		case 0b01111001: jump(JNS); break;
		case 0b11100010: jump(LOOP); break;
		case 0b11100001: jump(LOOPZ); break;
		case 0b11100000: jump(LOOPNZ); break;
		case 0b11100011: jump(JCXZ); break;
		}

		// first 7 bits
		switch (b & 0b11111110) {
		case 0b11000110: immediate_to_reg_mem(MOV, b); break;

		case 0b00000100: immediate_to_accumulator(ADD, b); break;
		case 0b00101100: immediate_to_accumulator(SUB, b); break;
		case 0b00111100: immediate_to_accumulator(CMP, b); break;

		case 0b10100000: // Memory to accumulator
			op = MOV;

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
			op = MOV;

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
			case 0b00101000: immediate_to_reg_mem_sign(SUB, b); break;
			case 0b00111000: immediate_to_reg_mem_sign(CMP, b); break;
			case 0b00000000: immediate_to_reg_mem_sign(ADD, b); break;
			}
			break;

		case 0b10001000: reg_mem_with_reg_either(MOV, b); break;
		case 0b00111000: reg_mem_with_reg_either(CMP, b); break;
		case 0b00101000: reg_mem_with_reg_either(SUB, b); break;
		case 0b00000000: reg_mem_with_reg_either(ADD, b); break;
		}

		// first 4 bits
		switch (b & 0b11110000) {
		case 0b10110000: // Immediate to register
			op = MOV;

			w = nth(b, 3);
			reg = match_register((char)(b & 0b00000111), w);

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
