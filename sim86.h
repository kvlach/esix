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
	OPCODE_STOS,
	OPCODE_CALL,
	OPCODE_JMP,
	OPCODE_RET,
	OPCODE_RETF,
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
	SEGMENT_REGISTER_ES,
	SEGMENT_REGISTER_CS,
	SEGMENT_REGISTER_SS,
	SEGMENT_REGISTER_DS,
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

// REG  -> register
// RM   -> register/memory
// SR   -> segment register
// IMM  -> immediate
// ACC  -> accumulator
// SEG  -> segment
// ISEG -> intersegment
typedef enum {
	INST_MOV_RM_REG,
	INST_MOV_IMM_RM,
	INST_MOV_IMM_REG,
	INST_MOV_MEM_ACC,
	INST_MOV_ACC_MEM,
	INST_MOV_RM_SR,
	INST_MOV_SR_RM,
	INST_PUSH_RM,
	INST_PUSH_REG,
	INST_PUSH_SR,
	INST_POP_RM,
	INST_POP_REG,
	INST_POP_SR,
	INST_XCHG_RM_REG,
	INST_XCHG_REG_ACC,
	INST_IN_FIXED_PORT,
	INST_IN_VARIABLE_PORT,
	INST_OUT_FIXED_PORT,
	INST_OUT_VARIABLE_PORT,
	INST_XLAT,
	INST_LEA,
	INST_LDS,
	INST_LES,
	INST_LAHF,
	INST_SAHF,
	INST_PUSHF,
	INST_POPF,
	INST_ADD_RM_REG,
	INST_ADD_IMM_RM,
	INST_ADD_IMM_ACC,
	INST_ADC_RM_REG,
	INST_ADC_IMM_RM,
	INST_ADC_IMM_ACC,
	INST_INC_RM,
	INST_INC_REG,
	INST_AAA,
	INST_DAA,
	INST_SUB_RM_REG,
	INST_SUB_IMM_RM,
	INST_SUB_IMM_ACC,
	INST_SBB_RM_REG,
	INST_SBB_IMM_RM,
	INST_SBB_IMM_ACC,
	INST_DEC_RM,
	INST_DEC_REG,
	INST_NEG,
	INST_CMP_RM_REG,
	INST_CMP_IMM_RM,
	INST_CMP_IMM_ACC,
	INST_AAS,
	INST_DAS,
	INST_MUL,
	INST_IMUL,
	INST_AAM,
	INST_DIV,
	INST_IDIV,
	INST_AAD,
	INST_CBW,
	INST_CWD,
	INST_NOT,
	INST_SHL_SAL,
	INST_SHR,
	INST_SAR,
	INST_ROL,
	INST_ROR,
	INST_RCL,
	INST_RCR,
	INST_AND_RM_REG,
	INST_AND_IMM_RM,
	INST_AND_IMM_ACC,
	INST_TEST_RM_REG,
	INST_TEST_IMM_RM,
	INST_TEST_IMM_ACC,
	INST_OR_RM_REG,
	INST_OR_IMM_RM,
	INST_OR_IMM_ACC,
	INST_XOR_RM_REG,
	INST_XOR_IMM_RM,
	INST_XOR_IMM_ACC,
	INST_REP,
	INST_MOVS,
	INST_CMPS,
	INST_SCAS,
	INST_LODS,
	INST_STOS, // written as STDS in the manual, which is wrong
	INST_CALL_DIRECT_SEG,
	INST_CALL_INDIRECT_SEG,
	INST_CALL_DIRECT_ISEG,
	INST_CALL_INDIRECT_ISEG,
	INST_JMP_DIRECT_SEG,
	INST_JMP_DIRECT_SEG_SHORT,
	INST_JMP_INDIRECT_SEG,
	INST_JMP_DIRECT_ISEG,
	INST_JMP_INDIRECT_ISEG,
	INST_RET_SEG,
	INST_RET_SEG_IMM_TO_SP,
	INST_RET_ISEG,
	INST_RET_ISEG_IMM_TO_SP,
	INST_JE_JZ,
	INST_JL_JNGE,
	INST_JLE_JNG,
	INST_JB_JNAE,
	INST_JBE_JNA,
	INST_JP_JPE,
	INST_JO,
	INST_JS,
	INST_JNE_JNZ,
	INST_JNL_JGE,
	INST_JNLE_JG,
	INST_JNB_JAE,
	INST_JNBE_JA,
	INST_JNP_JPO,
	INST_JNO,
	INST_JNS,
	INST_LOOP,
	INST_LOOPZ_LOOPE,
	INST_LOOPNZ_LOOPNE,
	INST_JCXZ,
	INST_INT_TYPE_SPECIFIED,
	INST_INT_TYPE_3,
	INST_INTO,
	INST_IRET,
	INST_CLC,
	INST_CMC,
	INST_STC,
	INST_CLD,
	INST_STD,
	INST_CLI,
	INST_STI,
	INST_HLT,
	INST_WAIT,
	INST_ESC,
	INST_LOCK,
	INST_SEGMENT,

} instruction;

#endif // SIM86_H
