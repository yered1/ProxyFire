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

// Size of each memory block. (= page size of VirtualAlloc)
#define MEMORY_BLOCK_SIZE 0x1000

// Size of each memory slot.
#define MEMORY_SLOT_SIZE 64

// Max range for seeking a memory block. (= 1024MB)
#define MAX_MEMORY_RANGE 0x40000000

// Memory protection flags to check the executable address.
#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

// Memory slot for the trampoline.
typedef struct _MEMORY_SLOT
{
    union
    {
        struct _MEMORY_SLOT *pNext;
        UINT8 buffer[64];
    };
} MEMORY_SLOT, *PMEMORY_SLOT;

// Memory block that contains memory slots.
typedef struct _MEMORY_BLOCK
{
    struct _MEMORY_BLOCK *pNext;
    PMEMORY_SLOT pFree;         // First free slot
    UINT usedCount;
} MEMORY_BLOCK, *PMEMORY_BLOCK;

// Initializes the internal function buffer.
VOID   InitializeBuffer(VOID);

// Uninitializes the internal function buffer.
VOID   UninitializeBuffer(VOID);

// Allocates a trampoline buffer near pOrigin.
LPVOID AllocateBuffer(LPVOID pOrigin);

// Frees a trampoline buffer.
VOID   FreeBuffer(LPVOID pBuffer);

// Checks if the buffer is executable.
BOOL   IsExecutableAddress(LPVOID pAddress);
