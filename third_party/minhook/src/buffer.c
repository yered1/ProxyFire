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
#include "buffer.h"

#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity);
static LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity);
#endif

// Head of the memory block list.
static PMEMORY_BLOCK g_pMemoryBlocks;

VOID InitializeBuffer(VOID)
{
    // Nothing to do for the initial release.
}

VOID UninitializeBuffer(VOID)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    g_pMemoryBlocks = NULL;

    while (pBlock)
    {
        PMEMORY_BLOCK pNext = pBlock->pNext;
        VirtualFree(pBlock, 0, MEM_RELEASE);
        pBlock = pNext;
    }
}

#if defined(_M_X64) || defined(__x86_64__)
static LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round down to the allocation granularity.
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the previous allocation granularity multiply.
    tryAddr -= dwAllocationGranularity;

    while (tryAddr >= (ULONG_PTR)pMinAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        if ((ULONG_PTR)mbi.AllocationBase < dwAllocationGranularity)
            break;

        tryAddr = (ULONG_PTR)mbi.AllocationBase - dwAllocationGranularity;
    }

    return NULL;
}

static LPVOID FindNextFreeRegion(LPVOID pAddress, LPVOID pMaxAddr, DWORD dwAllocationGranularity)
{
    ULONG_PTR tryAddr = (ULONG_PTR)pAddress;

    // Round up to the next allocation granularity.
    tryAddr += dwAllocationGranularity - 1;
    tryAddr -= tryAddr % dwAllocationGranularity;

    // Start from the next allocation granularity multiply.
    tryAddr += dwAllocationGranularity;

    while (tryAddr <= (ULONG_PTR)pMaxAddr)
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)tryAddr, &mbi, sizeof(mbi)) == 0)
            break;

        if (mbi.State == MEM_FREE)
            return (LPVOID)tryAddr;

        tryAddr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;

        // Round up to the next allocation granularity.
        tryAddr += dwAllocationGranularity - 1;
        tryAddr -= tryAddr % dwAllocationGranularity;
    }

    return NULL;
}
#endif

static PMEMORY_BLOCK GetMemoryBlock(LPVOID pOrigin)
{
    PMEMORY_BLOCK pBlock;
#if defined(_M_X64) || defined(__x86_64__)
    ULONG_PTR minAddr;
    ULONG_PTR maxAddr;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    minAddr = (ULONG_PTR)si.lpMinimumApplicationAddress;
    maxAddr = (ULONG_PTR)si.lpMaximumApplicationAddress;

    // pOrigin +/- 512MB
    if ((ULONG_PTR)pOrigin > MAX_MEMORY_RANGE && minAddr < (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE)
        minAddr = (ULONG_PTR)pOrigin - MAX_MEMORY_RANGE;

    if (maxAddr > (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE)
        maxAddr = (ULONG_PTR)pOrigin + MAX_MEMORY_RANGE;

    // Make room for MEMORY_BLOCK_SIZE.
    if (maxAddr > (ULONG_PTR)(-1) - MEMORY_BLOCK_SIZE)
        maxAddr = (ULONG_PTR)(-1) - MEMORY_BLOCK_SIZE;
#endif

    // Look in already allocated blocks.
    for (pBlock = g_pMemoryBlocks; pBlock != NULL; pBlock = pBlock->pNext)
    {
#if defined(_M_X64) || defined(__x86_64__)
        // Check if the block is in +/- 512MB range.
        if ((ULONG_PTR)pBlock < minAddr || (ULONG_PTR)pBlock >= maxAddr)
            continue;
#endif
        // Check if the block has a free slot.
        if (pBlock->pFree != NULL)
            return pBlock;
    }

#if defined(_M_X64) || defined(__x86_64__)
    // Allocate a new block in range.
    {
        LPVOID pAlloc = pOrigin;
        while ((ULONG_PTR)pAlloc >= minAddr)
        {
            pAlloc = FindPrevFreeRegion(pAlloc, (LPVOID)minAddr, si.dwAllocationGranularity);
            if (pAlloc == NULL)
                break;

            pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pBlock != NULL)
                break;
        }

        if (pBlock == NULL)
        {
            pAlloc = pOrigin;
            while ((ULONG_PTR)pAlloc <= maxAddr)
            {
                pAlloc = FindNextFreeRegion(pAlloc, (LPVOID)maxAddr, si.dwAllocationGranularity);
                if (pAlloc == NULL)
                    break;

                pBlock = (PMEMORY_BLOCK)VirtualAlloc(
                    pAlloc, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (pBlock != NULL)
                    break;
            }
        }
    }
#else
    // In x86 mode, a memory block can be placed anywhere.
    pBlock = (PMEMORY_BLOCK)VirtualAlloc(
        NULL, MEMORY_BLOCK_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif

    if (pBlock != NULL)
    {
        // Build the free list.
        PMEMORY_SLOT pSlot = (PMEMORY_SLOT)((UINT8 *)pBlock + sizeof(MEMORY_BLOCK));
        pBlock->pFree = NULL;
        pBlock->usedCount = 0;

        do
        {
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pSlot++;
        }
        while ((ULONG_PTR)pSlot - (ULONG_PTR)pBlock <= MEMORY_BLOCK_SIZE - MEMORY_SLOT_SIZE);

        pBlock->pNext = g_pMemoryBlocks;
        g_pMemoryBlocks = pBlock;
    }

    return pBlock;
}

LPVOID AllocateBuffer(LPVOID pOrigin)
{
    PMEMORY_SLOT  pSlot;
    PMEMORY_BLOCK pBlock = GetMemoryBlock(pOrigin);
    if (pBlock == NULL)
        return NULL;

    // Remove an entry from the free list.
    pSlot = pBlock->pFree;
    pBlock->pFree = pSlot->pNext;
    pBlock->usedCount++;
#ifdef _DEBUG
    // Fill the slot with INT3 for debugging.
    memset(pSlot, 0xCC, sizeof(MEMORY_SLOT));
#endif
    return pSlot;
}

VOID FreeBuffer(LPVOID pBuffer)
{
    PMEMORY_BLOCK pBlock = g_pMemoryBlocks;
    PMEMORY_BLOCK pPrev = NULL;
    ULONG_PTR pTargetBlock = ((ULONG_PTR)pBuffer / MEMORY_BLOCK_SIZE) * MEMORY_BLOCK_SIZE;

    while (pBlock != NULL)
    {
        if ((ULONG_PTR)pBlock == pTargetBlock)
        {
            PMEMORY_SLOT pSlot = (PMEMORY_SLOT)pBuffer;
#ifdef _DEBUG
            // Clear the slot for debugging.
            memset(pSlot, 0x00, sizeof(MEMORY_SLOT));
#endif
            // Restore to the free list.
            pSlot->pNext = pBlock->pFree;
            pBlock->pFree = pSlot;
            pBlock->usedCount--;

            // Free if unused.
            if (pBlock->usedCount == 0)
            {
                if (pPrev)
                    pPrev->pNext = pBlock->pNext;
                else
                    g_pMemoryBlocks = pBlock->pNext;

                VirtualFree(pBlock, 0, MEM_RELEASE);
            }

            break;
        }

        pPrev = pBlock;
        pBlock = pBlock->pNext;
    }
}

BOOL IsExecutableAddress(LPVOID pAddress)
{
    MEMORY_BASIC_INFORMATION mi;
    VirtualQuery(pAddress, &mi, sizeof(mi));

    return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}
