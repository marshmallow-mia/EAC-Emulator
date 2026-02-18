#pragma once
#include <Windows.h>
#include <cstdint>

// IAT Hook implementation for Utils_HookImport
// This performs Import Address Table (IAT) hooking to redirect function calls
inline void Utils_HookImport(const char* szModuleName, const char* szImportModule, const char* szFunctionName, void* pHookFunction)
{
    if (!szModuleName || !szImportModule || !szFunctionName || !pHookFunction)
        return;

    // Get the base address of the module to hook
    HMODULE hModule = GetModuleHandleA(szModuleName);
    if (!hModule)
        return;

    // Parse PE headers to find the import directory
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)hModule + pDosHeader->e_lfanew);
    if (pNTHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    // Get the import directory
    IMAGE_DATA_DIRECTORY importDirectory = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)hModule + importDirectory.VirtualAddress);

    // Iterate through import descriptors to find the target module
    for (; pImportDesc->Name != 0; pImportDesc++)
    {
        const char* importModuleName = (const char*)((uintptr_t)hModule + pImportDesc->Name);
        
        // Check if this is the module we want to hook
        if (_stricmp(importModuleName, szImportModule) != 0)
            continue;

        // Get the Import Address Table (IAT)
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + pImportDesc->FirstThunk);
        PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + pImportDesc->OriginalFirstThunk);

        // Iterate through the IAT entries
        for (; pOrigThunk->u1.Function != 0; pOrigThunk++, pThunk++)
        {
            // Skip ordinal imports
            if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal))
                continue;

            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hModule + pOrigThunk->u1.AddressOfData);
            const char* functionName = (const char*)pImportByName->Name;

            // Check if this is the function we want to hook
            if (strcmp(functionName, szFunctionName) != 0)
                continue;

            // Change memory protection to allow writing to IAT
            DWORD oldProtect;
            if (!VirtualProtect(&pThunk->u1.Function, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect))
                return;

            // Replace the function pointer in the IAT
            pThunk->u1.Function = (uintptr_t)pHookFunction;

            // Restore original memory protection
            VirtualProtect(&pThunk->u1.Function, sizeof(uintptr_t), oldProtect, &oldProtect);
            
            return; // Hook applied successfully
        }
    }
}
