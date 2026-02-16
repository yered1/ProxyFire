/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2006-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 * hde64.c
 */

#include <string.h>
#include "hde64.h"
#include "table64.h"

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = (uint8_t *)hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op_size = 4, a_size = 8, rex_w = 0;

    memset(hs, 0, sizeof(hde64s));

    for (x = 16; x; x--)
        switch (c = *p++) {
          case 0xf3:
            hs->p_rep = c;
            pref |= PRE_F3;
            hs->flags |= F_PREFIX_REPX;
            break;
          case 0xf2:
            hs->p_rep = c;
            pref |= PRE_F2;
            hs->flags |= F_PREFIX_REPNZ;
            break;
          case 0xf0:
            hs->p_lock = c;
            pref |= PRE_LOCK;
            hs->flags |= F_PREFIX_LOCK;
            break;
          case 0x26: case 0x2e: case 0x36:
          case 0x3e: case 0x64: case 0x65:
            hs->p_seg = c;
            pref |= PRE_SEG;
            hs->flags |= F_PREFIX_SEG;
            break;
          case 0x66:
            hs->p_66 = c;
            pref |= PRE_66;
            hs->flags |= F_PREFIX_66;
            op_size = 2;
            break;
          case 0x67:
            hs->p_67 = c;
            pref |= PRE_67;
            hs->flags |= F_PREFIX_67;
            a_size = 4;
            break;
          default:
            goto pref_done;
        }
  pref_done:

    /* REX prefix (0x40-0x4F) */
    if ((c & 0xf0) == 0x40) {
        hs->flags |= F_PREFIX_REX;
        hs->rex = c;
        if ((hs->rex_w = (c & 0x8) != 0) != 0) {
            rex_w = 1;
            op_size = 8;
        }
        hs->rex_r = (c & 4) != 0;
        hs->rex_x = (c & 2) != 0;
        hs->rex_b = (c & 1) != 0;

        if (x == 1)
            goto error_opcode;

        c = *p++;
        hs->opcode = c;

        goto opcode_begin;
    }

    hs->opcode = c;

  opcode_begin:

    if (c == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        /* MOV AL/AX/EAX/RAX,moffs or MOV moffs,AL/AX/EAX/RAX */
        op_size = a_size;
        a_size = 8;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] >> (opcode % 4 * 2) & 3];
    if (cflags == C_ERROR) {
      error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = (uint8_t *)hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] >> (opcode % 4 * 2) & 3] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = (uint8_t *)hde64_table + DELTA_FPU_REG;
                t = t * 8 + m_reg;
                if (((ht[t >> 2] >> (t % 4 * 2)) & 3) != 2)
                    goto error_operand;
            } else {
                ht = (uint8_t *)hde64_table + DELTA_FPU_MODRM;
                if (((ht[t >> 2] >> (t % 4 * 2)) & 3) != 2)
                    goto error_operand;
            }
            goto no_error_operand;
        }

        if (a_size == 4) {
            /* 32-bit addressing in 64-bit mode (67 prefix) */
            if (m_rm == 4 && m_mod != 3) {
                hs->flags |= F_SIB;
                p++;
                hs->sib = c = *(p - 1);
                hs->sib_scale = c >> 6;
                hs->sib_index = (c & 0x3f) >> 3;
                if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                    disp_size = 4;
            }
            if (m_mod == 0) {
                if (m_rm == 5)
                    disp_size = 4;
            } else if (m_mod == 1)
                disp_size = 1;
            else if (m_mod == 2)
                disp_size = 4;
        } else {
            /* 64-bit addressing (default) */
            if (m_rm == 4 && m_mod != 3) {
                hs->flags |= F_SIB;
                p++;
                hs->sib = c = *(p - 1);
                hs->sib_scale = c >> 6;
                hs->sib_index = (c & 0x3f) >> 3;
                if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                    disp_size = 4;
            }
            if (m_mod == 0) {
                if (m_rm == 5)
                    disp_size = 4;
            } else if (m_mod == 1)
                disp_size = 1;
            else if (m_mod == 2)
                disp_size = 4;
        }
    }

    switch (disp_size) {
      case 1:
        hs->flags |= F_DISP8;
        hs->disp.disp8 = *p;
        break;
      case 2:
        hs->flags |= F_DISP16;
        hs->disp.disp16 = *(uint16_t *)p;
        break;
      case 4:
        hs->flags |= F_DISP32;
        hs->disp.disp32 = *(uint32_t *)p;
        break;
    }
    p += disp_size;

    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if (op_size == 2) {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm.imm16 = *(uint16_t *)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (rex_w) {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        } else if (op_size == 2) {
            hs->flags |= F_IMM16;
            hs->imm.imm16 = *(uint16_t *)p;
            p += 2;
        } else {
            hs->flags |= F_IMM32;
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        }
    }

    if (cflags & C_IMM16) {
        hs->flags |= F_IMM16;
        hs->imm.imm16 = *(uint16_t *)p;
        p += 2;
    }
    if (cflags & C_IMM8) {
        hs->flags |= F_IMM8;
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
      rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    } else if (cflags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm.imm8 = *p++;
    }

  disasm_done:

    if (pref & PRE_LOCK) {
        if (!(cflags & C_MODRM)) {
            hs->flags |= F_ERROR | F_ERROR_LOCK;
        } else {
            uint8_t *table_end, op2 = opcode;
            if (hs->opcode2) {
                ht = (uint8_t *)hde64_table + DELTA_OP2_LOCK_OK;
                table_end = (uint8_t *)hde64_table + DELTA_OP_ONLY_MEM;
            } else {
                ht = (uint8_t *)hde64_table + DELTA_OP_LOCK_OK;
                table_end = (uint8_t *)hde64_table + DELTA_OP2_LOCK_OK;
                op2 = (uint8_t)(opcode & -2);
            }
            for (; ht != table_end; ht++)
                if (*ht++ == op2) {
                    if (!((*ht << m_reg) & 0x80))
                        goto no_lock_error;
                    break;
                }
            hs->flags |= F_ERROR | F_ERROR_LOCK;
          no_lock_error:
            ;
        }
    }

    if (hs->opcode2) {
        switch (opcode) {
          case 0x20: case 0x22:
            m_mod = 3;
            if (m_reg > 4 || m_reg == 1)
                goto error_operand;
            else
                goto no_error_operand;
          case 0x21: case 0x23:
            m_mod = 3;
            if (m_reg == 4 || m_reg == 5)
                goto error_operand;
            else
                goto no_error_operand;
        }
    } else {
        switch (opcode) {
          case 0x8c:
            if (m_reg > 5)
                goto error_operand;
            else
                goto no_error_operand;
          case 0x8e:
            if (m_reg == 1 || m_reg > 5)
                goto error_operand;
            else
                goto no_error_operand;
        }
    }

    if (hs->opcode2) {
        uint8_t *table_end;
        ht = (uint8_t *)hde64_table + DELTA_OP2_ONLY_MEM;
        table_end = (uint8_t *)hde64_table + sizeof(hde64_table) - 1;
        for (; ht <= table_end; ht += 3)
            if (*ht++ == opcode) {
                if (*ht++ & pref && !((*ht << m_reg) & 0x80))
                    goto error_operand;
                break;
            }
        goto no_error_operand;
    } else {
        ht = (uint8_t *)hde64_table + DELTA_OP_ONLY_MEM;
        for (; *ht != 0xff; ht += 2)
            if (*ht++ == opcode) {
                if (m_mod != 3) {
                    if (!(*ht & (1 << m_reg)))
                        goto error_operand;
                }
                goto no_error_operand;
            }
    }

    goto no_error_operand;

  error_operand:
    hs->flags |= F_ERROR | F_ERROR_OPERAND;
  no_error_operand:

    c = (uint8_t)(p - (uint8_t *)code);
    if (c > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        c = 15;
    }

    hs->len = c;
    return (unsigned int)c;
}
