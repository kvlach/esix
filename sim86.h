#ifndef SIM86_H
#define SIM86_H

typedef enum {
	OPCODE_MOV,
	OPCODE_ADD,
	OPCODE_CMP,
	OPCODE_SUB,
	OPCODE_JE,
	OPCODE_JL,
	OPCODE_JLE,
	OPCODE_JB,
	OPCODE_JBE,
	OPCODE_JP,
	OPCODE_JO,
	OPCODE_JS,
	OPCODE_JNE,
	OPCODE_JNL,
	OPCODE_JG,
	OPCODE_JNB,
	OPCODE_JA,
	OPCODE_JNP,
	OPCODE_JNO,
	OPCODE_JNS,
	OPCODE_LOOP,
	OPCODE_LOOPZ,
	OPCODE_LOOPNZ,
	OPCODE_JCXZ,
} opcode;

typedef enum {
	REGISTER_AL,
	REGISTER_CL,
	REGISTER_DL,
	REGISTER_BL,
	REGISTER_AH,
	REGISTER_CH,
	REGISTER_DH,
	REGISTER_BH,
	REGISTER_AX,
	REGISTER_CX,
	REGISTER_DX,
	REGISTER_BX,
	REGISTER_SP,
	REGISTER_BP,
	REGISTER_SI,
	REGISTER_DI,
} register_;

typedef enum {
	MODE_MEMORY_NO_DISPLACEMENT,
	MODE_MEMORY_8BIT_DISPLACEMENT,
	MODE_MEMORY_16BIT_DISPLACEMENT,
	MODE_REGISTER,
} mode;

typedef enum {
	EFFECTIVE_ADDR_BX_SI,
	EFFECTIVE_ADDR_BX_DI,
	EFFECTIVE_ADDR_BP_SI,
	EFFECTIVE_ADDR_BP_DI,
	EFFECTIVE_ADDR_SI,
	EFFECTIVE_ADDR_DI,
	EFFECTIVE_ADDR_BP,
	EFFECTIVE_ADDR_BX,
	EFFECTIVE_ADDR_DIRECT_ADDR,
} effective_addr;

#endif // SIM86_H
