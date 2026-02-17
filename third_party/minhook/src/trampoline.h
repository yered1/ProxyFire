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

#pragma once

#include <windows.h>

#pragma pack(push, 1)

// Relay function for x64.
// Includes indirect jump via RIP-relative addressing.
// Encoding: FF 25 00 00 00 00 [8-byte absolute address]
// = JMP [RIP+0], followed by the 8-byte target address.
typedef struct _JMP_RELAY
{
    UINT8  opcode;      // FF
    UINT8  modrm;       // 25
    UINT32 disp32;      // 00 00 00 00 (RIP-relative displacement = 0)
    UINT64 address;     // Absolute destination address
} JMP_RELAY, *PJMP_RELAY;

// x86/x64 5-byte relative jump.
typedef struct _JMP_REL
{
    UINT8  opcode;      // E9 : JMP rel32
    UINT32 operand;     // Relative destination address
} JMP_REL, *PJMP_REL;

// x86/x64 2-byte short jump.
typedef struct _JMP_REL_SHORT
{
    UINT8  opcode;      // EB : JMP rel8
    UINT8  operand;     // Relative destination address
} JMP_REL_SHORT, *PJMP_REL_SHORT;

// x86/x64 6-byte CALL.
typedef struct _CALL_ABS
{
    UINT8  opcode0;     // FF 15 xx xx xx xx : CALL [RIP+xxxx] / CALL [xxxx]
    UINT8  opcode1;
    UINT32 operand;
} CALL_ABS;

// x86/x64 JCC instruction.
typedef struct _JCC_REL
{
    UINT8  opcode0;     // 0F 8x : Jcc rel32
    UINT8  opcode1;
    UINT32 operand;     // Relative destination address
} JCC_REL;

// x86/x64 short JCC instruction.
typedef struct _JCC_REL_SHORT
{
    UINT8  opcode;      // 7x : Jcc rel8
    UINT8  operand;     // Relative destination address
} JCC_REL_SHORT;

#pragma pack(pop)

typedef struct _TRAMPOLINE
{
    LPVOID pTarget;         // [In] Address of the target function.
    LPVOID pDetour;         // [In] Address of the detour function.
    LPVOID pTrampoline;     // [In] Buffer address for the trampoline and target relay.

#if defined(_M_X64) || defined(__x86_64__)
    LPVOID pRelay;          // [Out] Address of the relay function.
#endif
    BOOL   patchAbove;      // [Out] Should use the hot patch area.
    UINT   nIP;             // [Out] Number of the instruction boundaries.
    UINT8  oldIPs[8];       // [Out] Instruction boundaries of the target function.
    UINT8  newIPs[8];       // [Out] Instruction boundaries of the trampoline function.
} TRAMPOLINE, *PTRAMPOLINE;

BOOL CreateTrampolineFunction(PTRAMPOLINE ct);
