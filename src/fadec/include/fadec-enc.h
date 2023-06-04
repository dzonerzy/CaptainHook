
#ifndef FD_FADEC_ENC_H_
#define FD_FADEC_ENC_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FE_AX = 0x100, FE_CX, FE_DX, FE_BX, FE_SP, FE_BP, FE_SI, FE_DI,
    FE_R8, FE_R9, FE_R10, FE_R11, FE_R12, FE_R13, FE_R14, FE_R15, FE_IP,
    FE_AH = 0x204, FE_CH, FE_DH, FE_BH,
    FE_ES = 0x300, FE_CS, FE_SS, FE_DS, FE_FS, FE_GS,
    FE_ST0 = 0x400, FE_ST1, FE_ST2, FE_ST3, FE_ST4, FE_ST5, FE_ST6, FE_ST7,
    FE_MM0 = 0x500, FE_MM1, FE_MM2, FE_MM3, FE_MM4, FE_MM5, FE_MM6, FE_MM7,
    FE_XMM0 = 0x600, FE_XMM1, FE_XMM2, FE_XMM3, FE_XMM4, FE_XMM5, FE_XMM6, FE_XMM7,
    FE_XMM8, FE_XMM9, FE_XMM10, FE_XMM11, FE_XMM12, FE_XMM13, FE_XMM14, FE_XMM15,
    FE_K0 = 0x700, FE_K1, FE_K2, FE_K3, FE_K4, FE_K5, FE_K6, FE_K7,
    FE_TMM0 = 0x800, FE_TMM1, FE_TMM2, FE_TMM3, FE_TMM4, FE_TMM5, FE_TMM6, FE_TMM7,
} FeReg;

typedef int64_t FeOp;

/** Construct a memory operand. Unused parts can be set to 0 and will be
 * ignored. FE_IP can be used as base register, in which case the offset is
 * interpreted as the offset from the /current/ position -- the size of the
 * encoded instruction will be subtracted during encoding. scale must be 1, 2,
 * 4, or 8; but is ignored if  idx == 0. **/
#define FE_MEM(base,sc,idx,off) (INT64_MIN | ((int64_t) ((base) & 0xfff) << 32) | ((int64_t) ((idx) & 0xfff) << 44) | ((int64_t) ((sc) & 0xf) << 56) | ((off) & 0xffffffff))
#define FE_NOREG 0

/** Add segment override prefix. This may or may not generate prefixes for the
 * ignored prefixes ES/CS/DS/SS in 64-bit mode. **/
#define FE_SEG(seg) ((uint64_t) (((seg) & 0x7) + 1) << 29)
/** Do not use. **/
#define FE_SEG_MASK 0xe0000000
/** Overrides address size. **/
#define FE_ADDR32 0x10000000
/** Used together with a RIP-relative (conditional) jump, this will force the
 * use of the encoding with the largest distance. Useful for reserving a jump
 * when the target offset is still unknown; if the jump is re-encoded later on,
 * FE_JMPL must be specified there, too, so that the encoding lengths match. **/
#define FE_JMPL 0x100000000
#define FE_MASK(kreg) ((uint64_t) ((kreg) & 0x7) << 33)
#define FE_MASKZ(kreg) ((uint64_t) ((kreg) & 0x7) << 33 | 0x1000000000)

#include <fadec-encode-public.inc>

/** Do not use. **/
#define fe_enc64_1(buf, mnem, op0, op1, op2, op3, ...) fe_enc64_impl(buf, mnem, op0, op1, op2, op3)
/** Encode a single instruction for 64-bit mode.
 * \param buf Pointer to the buffer for instruction bytes, must have a size of
 *        15 bytes. The pointer is advanced by the number of bytes used for
 *        encoding the specified instruction.
 * \param mnem Mnemonic, optionally or-ed with FE_SEG(), FE_ADDR32, or FE_JMPL.
 * \param operands... Instruction operands. Immediate operands are passed as
 *        plain value; register operands using the FeReg enum; memory operands
 *        using FE_MEM(); and offset operands for RIP-relative jumps/calls are
 *        specified as _address in buf_, e.g. (intptr_t) jmptgt, the address of
 *        buf and the size of the encoded instruction are subtracted internally.
 * \return Zero for success or a negative value in case of an error.
 **/
#define fe_enc64(buf, ...) fe_enc64_1(buf, __VA_ARGS__, 0, 0, 0, 0, 0)
/** Do not use. **/
int fe_enc64_impl(uint8_t** buf, uint64_t mnem, FeOp op0, FeOp op1, FeOp op2, FeOp op3);

#ifdef __cplusplus
}
#endif

#endif
