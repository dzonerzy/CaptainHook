#include <stdio.h>
#include <stdlib.h>

#include <fcml_intel_dialect.h>
#include <fcml_assembler.h>
#include <fcml_common_utils.h>

int main(int argc, char **argv)
{

    fcml_ceh_error error;

    /* Initializes the Intel dialect instance. */
    fcml_st_dialect *dialect;
    if ((error = fcml_fn_dialect_init_intel(FCML_INTEL_DIALECT_CF_DEFAULT, &dialect)))
    {
        fprintf(stderr, "Can not initialize Intel dialect: %d\n", error);
        exit(1);
    }

    fcml_st_assembler *assembler;
    if ((error = fcml_fn_assembler_init(dialect, &assembler)))
    {
        fprintf(stderr, "Can not initialize assembler: %d\n", error);
        fcml_fn_dialect_free(dialect);
        exit(1);
    }

    fcml_st_instruction instruction = {0};
    instruction.mnemonic = "push";
    instruction.hints = FCML_HINT_NEAR_POINTER;
    // instruction.operands[0] = fcml_fn_cu_operand_addr_b_disp_8(&fcml_reg_RSP, -0x8, FCML_DS_64);
    instruction.operands[0] = fcml_fn_cu_operand_addr_b_disp_16(&fcml_reg_RSP, 0x2c0, FCML_DS_16);
    instruction.operands_count = 1;

    /* Prepares the result. */
    fcml_st_assembler_result asm_result;
    fcml_fn_assembler_result_prepare(&asm_result);

    fcml_st_assembler_context context = {0};
    context.assembler = assembler;
    context.entry_point.ip = 0x401000;
    context.entry_point.op_mode = FCML_OM_64_BIT;

    /* Assembles the given instruction. */
    if ((error = fcml_fn_assemble(&context, &instruction, &asm_result)))
    {
        fprintf(stderr, "Can not assemble instruction: %d\n", error);
        fcml_fn_assembler_free(assembler);
        fcml_fn_dialect_free(dialect);
        exit(1);
    }

    /* Prints the instruction code. */
    if (asm_result.chosen_instruction)
    {
        fcml_st_assembled_instruction *ins_code = asm_result.chosen_instruction;
        int i;
        printf("Chosen instruction code: ");
        for (i = 0; i < ins_code->code_length; i++)
        {
            printf("%02x", ins_code->code[i]);
        }
        printf("\n");
    }
    else
    {
        fprintf(stderr, "Hmm, where is the assembled instruction?\n");
    }

    fcml_fn_assembler_result_free(&asm_result);
    fcml_fn_assembler_free(assembler);
    fcml_fn_dialect_free(dialect);

    return 0;
}