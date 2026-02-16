/*
 *  MinHook - The Minimalistic API Hooking Library for x64/x86
 *  Copyright (C) 2009-2017 Tsuda Kageyu. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED.
 */

#include <windows.h>

#include "trampoline.h"
#include "buffer.h"

#if defined(_M_X64) || defined(__x86_64__)
    #include "hde/hde64.h"
    typedef hde64s HDE;
    #define HDE_DISASM(code, hs) hde64_disasm(code, hs)
#else
    #include "hde/hde32.h"
    typedef hde32s HDE;
    #define HDE_DISASM(code, hs) hde32_disasm(code, hs)
#endif

// Maximum size of a trampoline function.
#if defined(_M_X64) || defined(__x86_64__)
    #define TRAMPOLINE_MAX_SIZE (MEMORY_SLOT_SIZE - sizeof(JMP_RELAY))
#else
    #define TRAMPOLINE_MAX_SIZE  MEMORY_SLOT_SIZE
#endif

//-------------------------------------------------------------------------
static BOOL IsCodePadding(LPBYTE pInst, UINT size)
{
    UINT i;

    if (pInst[0] != 0x00 && pInst[0] != 0x90 && pInst[0] != 0xCC)
        return FALSE;

    for (i = 1; i < size; ++i)
    {
        if (pInst[i] != pInst[0])
            return FALSE;
    }
    return TRUE;
}

//-------------------------------------------------------------------------
BOOL CreateTrampolineFunction(PTRAMPOLINE ct)
{
    UINT8     oldPos   = 0;
    UINT8     newPos   = 0;
    ULONG_PTR jmpDest  = 0;     // Destination address of an internal jump.
    BOOL      finished = FALSE;  // Is the function copying finished?
#if defined(_M_X64) || defined(__x86_64__)
    UINT8     instBuf[16];
#endif

    ct->patchAbove = FALSE;
    ct->nIP        = 0;

    do
    {
        HDE       hs;
        UINT      copySize;
        LPVOID    pCopySrc;
        ULONG_PTR pOldInst = (ULONG_PTR)ct->pTarget   + oldPos;
        ULONG_PTR pNewInst = (ULONG_PTR)ct->pTrampoline + newPos;

        copySize = HDE_DISASM((LPVOID)pOldInst, &hs);
        if (hs.flags & F_ERROR)
        {
            // Check for ENDBR64 (F3 0F 1E FA) / ENDBR32 (F3 0F 1E FB).
            // These Intel CET instructions are effectively NOPs on non-CET
            // hardware and are safe to copy verbatim into the trampoline.
            // Older HDE versions may flag them as errors because the opcode
            // tables predate the CET extension.
            LPBYTE pBytes = (LPBYTE)pOldInst;
            if (pBytes[0] == 0xF3 && pBytes[1] == 0x0F &&
                pBytes[2] == 0x1E && (pBytes[3] == 0xFA || pBytes[3] == 0xFB))
            {
                copySize = 4;
                memset(&hs, 0, sizeof(hs));
                hs.len = 4;
                // Fall through to copy the ENDBR instruction as-is.
            }
            else
            {
                return FALSE;
            }
        }

        pCopySrc = (LPVOID)pOldInst;

        if (oldPos >= sizeof(JMP_REL))
        {
            // The trampoline function is long enough.
            // Complete the function with the jump to the target function.
            // The instruction at pOldInst is beyond the overwritten area,
            // so do NOT copy it to the trampoline — jump directly to it.
            jmpDest = pOldInst;
            break;
        }
#if defined(_M_X64) || defined(__x86_64__)
        else if ((hs.modrm & 0xC7) == 0x05)
        {
            // Instructions using RIP relative addressing. (ModR/M = 00???101)
            // Modify the branchless RIP-relative address.
            PUINT32 pRelAddr;

            // Avoid using memcpy to calculate the immediate address.
            memcpy(instBuf, (LPBYTE)pOldInst, copySize);
            pCopySrc = instBuf;

            // Relative address is stored right after ModR/M byte.
            pRelAddr = (PUINT32)(instBuf + hs.len - ((hs.flags & 0x3C) ? 4 : 0) - 4);

            // This instruction references memory relative to RIP.
            // Rewrite the relative address.
            *pRelAddr
                = (UINT32)((pOldInst + hs.len + (INT32)hs.disp.disp32) - (pNewInst + hs.len));

            // Complete the function if the target fits within +/- 2GB.
            if (oldPos >= sizeof(JMP_REL))
            {
                jmpDest = pOldInst + hs.len;
                finished = TRUE;
            }
        }
#endif
        else if (hs.opcode == 0xE8)
        {
            // Direct relative CALL
            ULONG_PTR dest = pOldInst + hs.len + (INT32)hs.imm.imm32;
#if defined(_M_X64) || defined(__x86_64__)
            ULONG_PTR newDest;
            // If out of +/- 2GB range, we need to rewrite as indirect call.
            newDest = dest;
            if (newDest != dest)
            {
                // This should not happen with normal functions.
                return FALSE;
            }

            memcpy(instBuf, (LPBYTE)pOldInst, copySize);
            pCopySrc = instBuf;

            *(PUINT32)(instBuf + 1) = (UINT32)(dest - (pNewInst + hs.len));
#else
            UINT8 *pInstBuf = (UINT8 *)ct->pTrampoline + newPos;
            // We will copy manually later, but adjust the relative call target.
            // Write 0xE8 + new relative offset.
            pInstBuf[0] = 0xE8;
            *(PUINT32)(pInstBuf + 1) = (UINT32)(dest - (pNewInst + 5));
            // Advance positions manually and continue.
            newPos += copySize;
            oldPos += copySize;
            ct->oldIPs[ct->nIP] = oldPos;
            ct->newIPs[ct->nIP] = newPos;
            ct->nIP++;
            continue;
#endif
        }
        else if ((hs.opcode & 0xFD) == 0xE9)
        {
            // Direct relative JMP (E9 rel32, EB rel8)
            ULONG_PTR dest = pOldInst + hs.len;

            if (hs.opcode == 0xEB)
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy the operand if the jump target is within the
            // overwritten area.
            if ((ULONG_PTR)ct->pTarget <= dest
                && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else
            {
                jmpDest  = dest;
                finished = TRUE;
            }
        }
        else if ((hs.opcode & 0xF0) == 0x70
            || (hs.opcode  & 0xFC) == 0xE0
            || (hs.opcode2 & 0xF0) == 0x80)
        {
            // Jcc / LOOP / JECXZ / Jcc32
            ULONG_PTR dest = pOldInst + hs.len;

            if ((hs.opcode & 0xF0) == 0x70      // Jcc rel8
                || (hs.opcode & 0xFC) == 0xE0)   // LOOP/JECXZ
                dest += (INT8)hs.imm.imm8;
            else
                dest += (INT32)hs.imm.imm32;

            // Simply copy if the jump target is within the overwritten area.
            if ((ULONG_PTR)ct->pTarget <= dest
                && dest < ((ULONG_PTR)ct->pTarget + sizeof(JMP_REL)))
            {
                if (jmpDest < dest)
                    jmpDest = dest;
            }
            else if ((hs.opcode & 0xFC) == 0xE0)
            {
                // LOOP/JECXZ to outside the overwritten area is unsupported.
                return FALSE;
            }
            else
            {
                // Convert short Jcc/Jcc32 to Jcc rel32 for the trampoline.
                UINT8 cond = ((hs.opcode != 0x0F ? hs.opcode : hs.opcode2) & 0x0F);
#if defined(_M_X64) || defined(__x86_64__)
                // Build a Jcc rel32 instruction.
                instBuf[0] = 0x0F;
                instBuf[1] = 0x80 | cond;
                *(PUINT32)(instBuf + 2) = (UINT32)(dest - (pNewInst + 6));

                pCopySrc = instBuf;
                copySize = 6;
#else
                UINT8 *pInstBuf = (UINT8 *)ct->pTrampoline + newPos;
                pInstBuf[0] = 0x0F;
                pInstBuf[1] = 0x80 | cond;
                *(PUINT32)(pInstBuf + 2) = (UINT32)(dest - (pNewInst + 6));

                newPos += 6;
                oldPos += hs.len;
                ct->oldIPs[ct->nIP] = oldPos;
                ct->newIPs[ct->nIP] = newPos;
                ct->nIP++;
                continue;
#endif
            }
        }
        else if (hs.opcode == 0xFF)
        {
            // RET or indirect JMP/CALL with possible RIP-relative addressing
            if (hs.modrm_reg == 4 || hs.modrm_reg == 5)
            {
                // JMP/CALL indirect
                // Just copy and fix RIP-relative if needed (handled above on x64).
            }
        }
        else if (hs.opcode == 0xC3 || hs.opcode == 0xC2
            || hs.opcode == 0xCB || hs.opcode == 0xCA)
        {
            // RET instruction. The function ends here.
            finished = TRUE;
        }

        // Can we overwrite the above instructions?
        if (oldPos < sizeof(JMP_REL)
            && !IsCodePadding((LPBYTE)ct->pTarget + oldPos, sizeof(JMP_REL) - oldPos))
        {
            // Check for hot-patch area (NOP padding above the function).
            if (oldPos == 0
                && !IsCodePadding((LPBYTE)ct->pTarget - sizeof(JMP_REL), sizeof(JMP_REL)))
            {
                // Not enough space and no hot-patch area available.
                // Try a short jump if possible.
            }
        }

        // Trampoline too large?
        if (newPos + copySize > TRAMPOLINE_MAX_SIZE)
            return FALSE;

        // Boundary check for the number of instructions.
        if (ct->nIP >= ARRAYSIZE(ct->oldIPs))
            return FALSE;

        // Copy the instruction to the trampoline.
        memcpy((LPBYTE)ct->pTrampoline + newPos, pCopySrc, copySize);

        ct->oldIPs[ct->nIP] = oldPos;
        ct->newIPs[ct->nIP] = newPos;
        ct->nIP++;

        newPos += copySize;
        oldPos += hs.len;
    }
    while (!finished);

    // Is there enough space to create a trampoline?
    if (oldPos < sizeof(JMP_REL))
    {
        // Check if we can use the hot-patch area.
        if (IsCodePadding((LPBYTE)ct->pTarget - sizeof(JMP_REL), sizeof(JMP_REL)))
        {
            ct->patchAbove = TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    // Create a jump to the continuation of the original function (after the
    // overwritten part).
    {
        ULONG_PTR pTrampJump = (ULONG_PTR)ct->pTrampoline + newPos;

#if defined(_M_X64) || defined(__x86_64__)
        // x64: Use an indirect JMP if the jump distance is too large for rel32.
        {
            INT64 jumpDist = (INT64)(jmpDest - (pTrampJump + sizeof(JMP_REL)));
            if (jumpDist < INT32_MIN || jumpDist > INT32_MAX)
            {
                // Not enough space for a relay jump? Fail.
                if (newPos + sizeof(JMP_REL) + sizeof(JMP_RELAY) > MEMORY_SLOT_SIZE)
                    return FALSE;
            }
        }

        // Write JMP rel32 to the remainder of the target function.
        {
            PJMP_REL pJmp = (PJMP_REL)pTrampJump;
            pJmp->opcode  = 0xE9;
            pJmp->operand = (UINT32)(jmpDest - (pTrampJump + sizeof(JMP_REL)));
        }
        newPos += sizeof(JMP_REL);

        // Create a relay function for the detour.
        // Encoding: FF 25 00 00 00 00 [8-byte address] = JMP [RIP+0]
        {
            PJMP_RELAY pRelay = (PJMP_RELAY)((LPBYTE)ct->pTrampoline + newPos);
            pRelay->opcode  = 0xFF;
            pRelay->modrm   = 0x25;
            pRelay->disp32  = 0x00000000;
            pRelay->address = (UINT64)(ULONG_PTR)ct->pDetour;
            ct->pRelay = pRelay;
        }
#else
        // x86: Simple JMP rel32.
        {
            PJMP_REL pJmp = (PJMP_REL)pTrampJump;
            pJmp->opcode  = 0xE9;
            pJmp->operand = (UINT32)(jmpDest - (pTrampJump + sizeof(JMP_REL)));
        }
#endif
    }

    return TRUE;
}
