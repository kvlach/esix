#include <stdbool.h>
#include <stdio.h>

char in[200];
int i = 0;
int len = 0;

char peek() { return in[++i]; }

enum opcodes {
	MOV,
};

const char *fmt_opcode(enum opcodes oc) {
	switch (oc) {
	case MOV:
		return "mov";
	}
}

enum registers {
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
};

const char *fmt_register(enum registers r) {
	switch (r) {
	case AL:
		return "al";
	case CL:
		return "cl";
	case DL:
		return "dl";
	case BL:
		return "bl";
	case AH:
		return "ah";
	case CH:
		return "ch";
	case DH:
		return "dh";
	case BH:
		return "bh";
	case AX:
		return "ax";
	case CX:
		return "cx";
	case DX:
		return "dx";
	case BX:
		return "bx";
	case SP:
		return "sp";
	case BP:
		return "bp";
	case SI:
		return "si";
	case DI:
		return "di";
	}
}

enum mov_mode {
	MOV_MODE_MEMORY_NO_DISPLACEMENT,
	MOV_MODE_MEMORY_8BIT_DISPLACEMENT,
	MOV_MODE_MEMORY_16BIT_DISPLACEMENT,
	MOV_MODE_REGISTER,
};

enum mov_mode mov_modes[4] = {
    MOV_MODE_MEMORY_NO_DISPLACEMENT,
    MOV_MODE_MEMORY_8BIT_DISPLACEMENT,
    MOV_MODE_MEMORY_16BIT_DISPLACEMENT,
    MOV_MODE_REGISTER,
};

enum mov_mode mov_match_mode(char b) {
	return mov_modes[(b & 0b11000000) >> 6];
}

const char *mov_fmt_mode(enum mov_mode mod) {
	switch (mod) {
	case MOV_MODE_MEMORY_NO_DISPLACEMENT:
		return "MOV_MODE_MEMORY_NO_DISPLACEMENT";
	case MOV_MODE_MEMORY_8BIT_DISPLACEMENT:
		return "MOV_MODE_MEMORY_8_BIT_DISPLACEMENT";
	case MOV_MODE_MEMORY_16BIT_DISPLACEMENT:
		return "MOV_MODE_MEMORY_16_BIT_DISPLACEMENT";
	case MOV_MODE_REGISTER:
		return "MOV_MODE_REGISTER";
	}
}

enum registers mov_registers[16] = {AL, CL, DL, BL, AH, CH, DH, BH,
				    AX, CX, DX, BX, SP, BP, SI, DI};

enum registers match_register(char b, bool w) {
	b = (b & 0b00111000) >> 3;
	b |= w << 3;
	return mov_registers[b];
}

enum registers mov_match_register_memory(char b, enum mov_mode mod, bool w) {
	switch (mod) {
	case MOV_MODE_MEMORY_NO_DISPLACEMENT:
		break;
	case MOV_MODE_MEMORY_8BIT_DISPLACEMENT:
		break;
	case MOV_MODE_MEMORY_16BIT_DISPLACEMENT:
		break;
	case MOV_MODE_REGISTER:
		b &= 0b00000111;
		b |= w << 3;
		return mov_registers[b];
	}
}

int nth(char c, int n) { return (c >> n) & 1; }

void printBits(char ch) {
	for (int i = 7; i >= 0; --i) {
		putchar((ch & (1 << i)) ? '1' : '0');
	}
	putchar('\n');
}

int main(int argc, char *argv[]) {
	FILE *ptr;
	char ch;

	if (argc < 2) {
		printf("Expected filename\n");
		return 1;
	}

	ptr = fopen(argv[1], "r");

	if (NULL == ptr) {
		printf("File can't be opened, does it exist?\n");
		return 1;
	}

	do {
		ch = fgetc(ptr);
		in[len] = ch;
		len++;
	} while (ch != EOF);

	enum opcodes opcode;
	while (i < len) {
		char b = in[i];

		switch (b & 0b11110000) {
		default:
			break;
		}

		// check first 6 bytes for opcode
		switch (b & 0b11111100) {
		case 0b10001000:
			opcode = MOV;
			// little endian
			bool d = nth(b, 1);
			bool w = nth(b, 0);

			b = peek();
			enum mov_mode mod = mov_match_mode(b);
			enum registers reg = match_register(b, w);
			enum registers r_m =
			    mov_match_register_memory(b, mod, w);

			printf("%s %s, %s\n", fmt_opcode(opcode),
			       fmt_register(r_m), fmt_register(reg));

			break;

		default:
			printf("unexcpeted opcode\n");
			goto err;
		}

		i++;
	}

	fclose(ptr);
	return 0;

err:
	fclose(ptr);
	return 1;
}
