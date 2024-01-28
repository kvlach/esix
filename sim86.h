#ifndef SIM86_H
#define SIM86_H

typedef enum {
	OPCODE_MOV,
	OPCODE_PUSH,
	OPCODE_POP,
	OPCODE_XCHG,
	OPCODE_IN,
	OPCODE_OUT,
	OPCODE_XLAT,
	OPCODE_LEA,
	OPCODE_LDS,
	OPCODE_LES,
	OPCODE_LAHF,
	OPCODE_SAHF,
	OPCODE_PUSHF,
	OPCODE_POPF,
	OPCODE_ADD,
	OPCODE_ADC,
	OPCODE_INC,
	OPCODE_AAA,
	OPCODE_DAA,
	OPCODE_SUB,
	OPCODE_SBB,
	OPCODE_DEC,
	OPCODE_NEG,
	OPCODE_CMP,
	OPCODE_AAS,
	OPCODE_DAS,
	OPCODE_MUL,
	OPCODE_IMUL,
	OPCODE_AAM,
	OPCODE_DIV,
	OPCODE_IDIV,
	OPCODE_AAD,
	OPCODE_CBW,
	OPCODE_CWD,
	OPCODE_NOT,
	OPCODE_SHL,
	OPCODE_SHR,
	OPCODE_SAR,
	OPCODE_ROL,
	OPCODE_ROR,
	OPCODE_RCL,
	OPCODE_RCR,
	OPCODE_AND,
	OPCODE_TEST,
	OPCODE_OR,
	OPCODE_XOR,
	OPCODE_REP,
	OPCODE_MOVS,
	OPCODE_CMPS,
	OPCODE_SCAS,
	OPCODE_LODS,
	OPCODE_STDS,
	OPCODE_CALL,
	OPCODE_JMP,
	OPCODE_RET,
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
	OPCODE_INT,
	OPCODE_INTO,
	OPCODE_IRET,
	OPCODE_CLC,
	OPCODE_CMC,
	OPCODE_STC,
	OPCODE_CLD,
	OPCODE_STD,
	OPCODE_CLI,
	OPCODE_STI,
	OPCODE_HLT,
	OPCODE_WAIT,
	OPCODE_ESC,
	OPCODE_LOCK,
	OPCODE_SEGMENT,
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
	SEGMENT_REGISTER_ES,
	SEGMENT_REGISTER_CS,
	SEGMENT_REGISTER_SS,
	SEGMENT_REGISTER_DS,
} segment_register;

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
