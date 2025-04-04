#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <iostream>

//PE mapping & loader needs.
#define RELOC_32BIT_FIELD 3
#define RELOC_64BIT_FIELD 0xA

#ifdef _WIN64
#define RELOC_FIELD RELOC_64BIT_FIELD
typedef ULONG_PTR FIELD_PTR;
#else
#define RELOC_FIELD RELOC_32BIT_FIELD
typedef  DWORD_PTR FIELD_PTR;
#endif

typedef struct _BASE_RELOCATION_ENTRY {
    WORD Offset : 12;
    WORD Type : 4;
} BASE_RELOCATION_ENTRY;

/**
 * Get ptr to NT HEADER.
 * @param pImage => PTR to raw PE loaded
 */
inline PIMAGE_NT_HEADERS GetNtHdr(IN PBYTE pImage){
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((BYTE*)pImage + pDos->e_lfanew);
    return pNt;
}

/**
 * Base check on PE file.
 * @param pImage => ptr to raw PE base
 */
inline BOOL IsValidPeFile(IN PBYTE pImage){
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pImage;
    if(pDos->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;
    
    PIMAGE_NT_HEADERS ptNtHdr = (PIMAGE_NT_HEADERS)((BYTE*)pImage + pDos->e_lfanew);
    if(ptNtHdr->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;
    
    return TRUE;
}

/**
 * Manually map pe sections.
 * @param pRawPe => ptr to base address of raw pe
 * @param pBuff  => ptr to base address of allocated mem (virtual)
 * @param pNthdr => ptr to NT header
 */
inline VOID MapSections(IN PBYTE pRawPe, IN PBYTE pBuff, IN PIMAGE_NT_HEADERS pNtHdr){
    //copying header.
    memcpy(pBuff, pRawPe, pNtHdr->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHdr);
    for(WORD i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++){
        memcpy((BYTE*)(pBuff) + pSection[i].VirtualAddress, (BYTE*)(pRawPe) + pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
    }
}

/**
 * Loading PE imports.
 * @param pBuff  => ptr to base buffer containing raw PE
 * @param pNtHdr => ptr to NT header
 */
inline BOOL LoadImports(IN PBYTE pBuff, IN PIMAGE_NT_HEADERS pNtHdr)
{
    IMAGE_DATA_DIRECTORY importsDirectory = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importsDirectory.VirtualAddress == 0) {
        return FALSE;
    }
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (FIELD_PTR)pBuff);

    while (importDescriptor->Name != 0)
    {
        LPCSTR libraryName = reinterpret_cast<LPCSTR>(importDescriptor->Name + (FIELD_PTR)pBuff);
        HMODULE library = LoadLibraryA(libraryName);

        if (library)
        {
            PIMAGE_THUNK_DATA thunk = nullptr;
            thunk = (PIMAGE_THUNK_DATA)((FIELD_PTR)pBuff + importDescriptor->FirstThunk);

            while (thunk->u1.AddressOfData != 0)
            {
                FIELD_PTR functionAddress = 0;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                {
                    LPCSTR functionOrdinal = (LPCSTR)IMAGE_ORDINAL(thunk->u1.Ordinal);
                    functionAddress = (FIELD_PTR)GetProcAddress(library, functionOrdinal);
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((FIELD_PTR)pBuff + thunk->u1.AddressOfData);
                    functionAddress = (FIELD_PTR)GetProcAddress(library, functionName->Name);
                }
                thunk->u1.Function = functionAddress;
                ++thunk;
            }
        }

        importDescriptor++;
    }

    std::cout << "[*] Successfully loaded modules !" << std::endl;
    return TRUE;
}

/**
 * Apply relocations.
 */
inline BOOL Relocate(IN PBYTE pBuff, IN PIMAGE_NT_HEADERS pNtHdr, IN FIELD_PTR newImageBase){
    IMAGE_DATA_DIRECTORY relocationDirectory = pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if(relocationDirectory.VirtualAddress == 0){
        return FALSE;
    }

    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(relocationDirectory.VirtualAddress + (FIELD_PTR)pBuff);
    while(pReloc->VirtualAddress != 0){
        DWORD page = pReloc->VirtualAddress;

        if(pReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)){
            SIZE_T count = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            BASE_RELOCATION_ENTRY* list = (BASE_RELOCATION_ENTRY*)(LPDWORD)(pReloc + 1);

            for(SIZE_T i = 0; i < count; i++){
                if(list[i].Type & RELOC_FIELD){
                    DWORD rva = list[i].Offset + page;

                    PULONG_PTR p = (PULONG_PTR)((LPBYTE)pBuff + rva);
                    *p = ((*p) - pNtHdr->OptionalHeader.ImageBase) + (FIELD_PTR)newImageBase;
                }
            }
        }

        pReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pReloc + pReloc->SizeOfBlock);
    }

    std::cout << "[*] Successfully applied relocations." << std::endl;
    return TRUE;
}

/**
 * Reading PE file from disk & return PTR to base.
 * @param lpPath => path to pe file.
 * @param dwSize => OUT* to size read.
 */
inline BYTE* ReadPeFile(IN LPSTR lpPath, OUT DWORD* dwFileSize){
    HANDLE hFile   = NULL;
    DWORD  dwSize  = 0;
    PBYTE  pBuffer = NULL;

    hFile = CreateFileA(lpPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[!] Error calling CreateFileA with error : %d \n", GetLastError());
        return NULL;
    }

    dwSize = GetFileSize(hFile, NULL);
    if(dwSize == INVALID_FILE_SIZE){
        printf("[!] Error getting size of file. \n");
        goto _EndFunc;
    }

    *dwFileSize = dwSize;

    pBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
    if(pBuffer == NULL){
        printf("[!] Error allocating memory. \n");
        goto _EndFunc;
    }

    //Reading file.
    if(!ReadFile(hFile, pBuffer, dwSize, NULL, NULL)){
        printf("[!] Error calling ReadFile with error : %d \n", GetLastError());
        goto _EndFunc;
    }

_EndFunc:
    if(hFile){
        CloseHandle(hFile);
    }

    return pBuffer;
}