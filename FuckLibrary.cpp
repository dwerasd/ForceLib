#include "ForceLib.h"
#include "th32.h"


#pragma pack(push, 1) // very important !
typedef struct
{
	//BYTE  Int3;
	BYTE  PushOpc1;          // 0x68     = push (dword)
	DWORD PushAddr1;         // address of LibPath
	BYTE  PushOpc2;          // 0x68     = push (dword)
	DWORD PushAddr2;         // address of uniLibPath
	BYTE  CallOpc1;          // 0xE8     = call (dword)
	DWORD CallAddr1;         // address of RtlInitUnicodeStringAPI
	BYTE  PushOpc3;          // 0x68     = push (dword)
	DWORD PushAddr3;         // address of handle
	BYTE  PushOpc4;          // 0x68     = push (dword)
	DWORD PushAddr4;         // address of dll name
	BYTE  PushOpc5;          // 0x68     = push (dword)
	BYTE  PushAddr5;         // 0x00     = null
	BYTE  PushOpc6;          // 0x68     = push (dword)
	BYTE  PushAddr6;         // 0x00     = null
	BYTE  CallOpc2;          // 0xE8     = call (dword)
	DWORD CallAddr2;         // address of LdrLoadDllAPI
	BYTE  RetOpc;            // 0xC2     = ret (word)
	WORD  RetValue;          // return number
	HANDLE handle;
	UNICODE_STRING uniLibPath; // path of the dll to load
	WCHAR LibPath[MAX_PATH];
	BYTE  OrigCode1;
	BYTE  OrigCode2;
	BYTE  OrigCode3;
	BYTE  OrigCode4;
	BYTE  OrigCode5;
	BYTE  JmpOpc;
	DWORD JmpAddr;
} sFuckingLibLoadCodeNT;
#pragma pack(pop) // restore previous packing alignment



BOOL InitFuckingCodeStruct(sFuckingLibLoadCodeNT* LibLoaderCodeNT, WCHAR* sTargetLib, int LibPathLen, DWORD dwCodeStart)
{
	const HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtdll)
		return FALSE;
	DWORD dwLoadLibApiAddr = (DWORD)GetProcAddress(hNtdll, "LdrLoadDll");
	DWORD dwInitUnicodeStrApiAddr = (DWORD)GetProcAddress(hNtdll, "RtlInitUnicodeString");

	if (!dwLoadLibApiAddr || !dwInitUnicodeStrApiAddr)
		return FALSE;

	LibLoaderCodeNT->PushOpc1 = 0x68;
	LibLoaderCodeNT->PushOpc2 = 0x68;
	LibLoaderCodeNT->PushOpc3 = 0x68;
	LibLoaderCodeNT->PushOpc4 = 0x68;
	LibLoaderCodeNT->PushOpc5 = 0x6A;
	LibLoaderCodeNT->PushOpc6 = 0x6A;
	LibLoaderCodeNT->CallOpc1 = 0xE8;
	LibLoaderCodeNT->CallOpc2 = 0xE8;
	LibLoaderCodeNT->CallAddr1 = dwInitUnicodeStrApiAddr - dwCodeStart - offsetof(sFuckingLibLoadCodeNT, PushOpc3);
	LibLoaderCodeNT->CallAddr2 = dwCodeStart + offsetof(sFuckingLibLoadCodeNT, OrigCode1) - dwCodeStart - offsetof(sFuckingLibLoadCodeNT, RetOpc);
	LibLoaderCodeNT->handle = (HANDLE)0x0;
	LibLoaderCodeNT->PushAddr1 = dwCodeStart + offsetof(sFuckingLibLoadCodeNT, LibPath);
	LibLoaderCodeNT->PushAddr2 = dwCodeStart + offsetof(sFuckingLibLoadCodeNT, uniLibPath);
	LibLoaderCodeNT->PushAddr3 = dwCodeStart + offsetof(sFuckingLibLoadCodeNT, handle);
	LibLoaderCodeNT->PushAddr4 = dwCodeStart + offsetof(sFuckingLibLoadCodeNT, uniLibPath);
	LibLoaderCodeNT->PushAddr5 = 0x00;
	LibLoaderCodeNT->PushAddr6 = 0x00;
	LibLoaderCodeNT->RetOpc = 0xC2;
	LibLoaderCodeNT->RetValue = 0x0004;
	memset(LibLoaderCodeNT->LibPath, 0, sizeof(WCHAR) * MAX_PATH);
	memcpy(LibLoaderCodeNT->LibPath, sTargetLib, sizeof(WCHAR) * LibPathLen);
	LibLoaderCodeNT->OrigCode1 = *(BYTE*)dwLoadLibApiAddr;
	LibLoaderCodeNT->OrigCode2 = *(BYTE*)(dwLoadLibApiAddr + 1);
	LibLoaderCodeNT->OrigCode3 = *(BYTE*)(dwLoadLibApiAddr + 2);
	LibLoaderCodeNT->OrigCode4 = *(BYTE*)(dwLoadLibApiAddr + 3);
	LibLoaderCodeNT->OrigCode5 = *(BYTE*)(dwLoadLibApiAddr + 4);
	LibLoaderCodeNT->JmpOpc = 0xE9;
	LibLoaderCodeNT->JmpAddr = dwLoadLibApiAddr + 5 - dwCodeStart - offsetof(sFuckingLibLoadCodeNT, JmpAddr) - 4;

	return TRUE;
}

DWORD dwLibBase32;
DWORD dwCodeStart32, dwCodeEnd32, dwBytesWritten32, dwBytesRead32;
BOOL FuckLibraryNT(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo)
{
	sFuckingLibLoadCodeNT  LibLoadCode;
	DWORD           dwRemoteThreadID;
	HANDLE          hRemoteThread;
	_CodeEntry32      CodeEntry;

	// import NT only stuff manually
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	if (!kernel)
	{
		MessageBoxW(0, L"couldnt get kernel32 handle", 0, 0);
		ExitProcess(1);
	}
	fp_VirtualAllocEx VirtualAllocExPtr = (fp_VirtualAllocEx)GetProcAddress(kernel, "VirtualAllocEx");
	fp_VirtualFreeEx VirtualFreeExPtr = (fp_VirtualFreeEx)GetProcAddress(kernel, "VirtualFreeEx");

	if (!VirtualFreeExPtr || !VirtualAllocExPtr)
	{
		MessageBoxW(0, L"couldnt import virtualallocex", 0, 0);
		ExitProcess(1);
	}

	// get some mem in the target's process memory
	dwCodeStart32 = (DWORD)VirtualAllocExPtr(
		pProcInfo->hProcess,
		NULL,
		sizeof(LibLoadCode),
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!dwCodeStart32)
		return FALSE;

	// path init
	BSTR cwstrLibraryPath;
	int nLen = MultiByteToWideChar(CP_ACP, MB_COMPOSITE, szLibraryPath, strlen(szLibraryPath), NULL, NULL);
	cwstrLibraryPath = SysAllocStringLen(NULL, nLen);
	MultiByteToWideChar(CP_ACP, MB_COMPOSITE, szLibraryPath, strlen(szLibraryPath), cwstrLibraryPath, nLen);

	// init the LibLoadCode struct
	if (!InitFuckingCodeStruct(&LibLoadCode, cwstrLibraryPath, nLen, dwCodeStart32))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart32,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// copy the code into the allocated mem
	if (!WriteProcessMemory(
		pProcInfo->hProcess,
		(VOID*)dwCodeStart32,
		&LibLoadCode,
		sizeof(LibLoadCode),
		&dwBytesWritten32))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart32,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// execute it
	CodeEntry = (_CodeEntry32)dwCodeStart32;
	if (!(hRemoteThread = CreateRemoteThread(
		pProcInfo->hProcess,
		NULL,
		0,
		CodeEntry,
		NULL,
		0,
		&dwRemoteThreadID)))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart32,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// wait until the thread finishes
	WaitForSingleObject(hRemoteThread, INFINITE);
	if (!GetExitCodeThread(hRemoteThread, &dwLibBase32))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart32,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// clean up
	VirtualFreeExPtr(
		pProcInfo->hProcess,
		(VOID*)dwCodeStart32,
		sizeof(LibLoadCode),
		MEM_DECOMMIT);
	CloseHandle(hRemoteThread);

	if (!dwLibBase32)
		return TRUE;
	else
		return FALSE;
}

DWORD FuckLibrary(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo)
{
	if (FuckLibraryNT(szLibraryPath, pProcInfo))
		return 1;
	else
		return 0;
}