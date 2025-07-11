//////
/////                        -=[ ForceLibrary.dll ]=-
////                                by yoda/f2f
///                                version: 1.2
//
//     You are able to use *parts* of this source code in your own programs 
//     if you mention my name.
//     Please report any bugs/comments/suggestions to yoda_f2f@gmx.net
//     Have fun.
//

#include "ForceLib.h"
#include "th32.h"

#pragma warning(disable: 4996) // Disable deprecation warnings for unsafe functions
typedef VOID(WINAPI* RtlInitUnicodeStringFunc)(PUNICODE_STRING DestinationString, PCWSTR SourceString);

#pragma pack(1) // very important !

// this code structs load the dll
typedef struct
{
	//BYTE  Int3;    
	BYTE  PushOpc;           // 0x68     = push (dword)
	DWORD PushAddr;          // address of dll name
	BYTE  CallOpc;           // 0xE8     = call (dword)
	DWORD CallAddr;          // address of LoadLibraryAPI
	WORD  jmp_$;             // 0xEBFE   = jmp eip
	char  LibPath[MAX_PATH]; // path of the dll to load
} sLibLoadCode;

typedef struct
{
	//BYTE  Int3;    
	BYTE  PushOpc;           // 0x68     = push (dword)
	DWORD PushAddr;          // address of dll name
	BYTE  CallOpc;           // 0xE8     = call (dword)
	DWORD CallAddr;          // address of LoadLibraryAPI
	BYTE  RetOpc;            // 0xC2     = ret (word)
	WORD  RetValue;          // return number
	char  LibPath[MAX_PATH]; // path of the dll to load
} sLibLoadCodeNT;

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

typedef struct
{
	BYTE  PushOpc;      // 0x68 = push (dword)
	DWORD PushAddr;     // address of dll name
	BYTE  CallOpc;      // 0xE8 = call (dword)
	DWORD CallAddr;     // address of LoadLibraryAPI
	BYTE  Int3;         // end of code
	char  LibPath[256]; // path of the dll to load
} sLibLoadCodeDBG;

typedef struct
{
	DWORD  dwImageBase;
	DWORD  dwSizeOfImage;
	DWORD  dwEntryPointVA;
} sProcessPEInfo;



// the functions
BOOL   InitCodeStruct(sLibLoadCode* LibLoaderCode,
	sLibLoadCodeNT* LibLoaderCodeNT,
	CHAR* szTargetLib,
	DWORD _dwCodeStart);
BOOL   InitCodeStructDBG(sLibLoadCodeDBG& LibLoaderCode, CHAR* szTargetLib, DWORD _dwCodeStart);
DWORD  GetProcessEntryPoint(DWORD PID);
BOOL   FuckLibraryNT(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo);
BOOL   ForceLibrary95(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo);
BOOL   ForceLibraryNT(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo);
extern "C" BOOL WINAPI TrapEntry(DWORD dwEntryPoint, PROCESS_INFORMATION* pPI);
extern "C" BOOL WINAPI ForceLibraryDBG(CHAR* szTargetLib, DWORD dwEntryPoint, PROCESS_INFORMATION* pPI);
extern "C" DWORD WINAPI PerformCleanup(DWORD dwEntryPoint, PROCESS_INFORMATION* pPI);

// constants
const DWORD                     LOADCODESIZEDBG = sizeof(sLibLoadCodeDBG);
const DWORD                     HEADER_SIZE = 0x2000;
const BYTE                      Int3 = 0xCC;

// global variables
sLibLoadCodeDBG           LibLoadCodeDBG;
DWORD                     dwLibBase;
DWORD                     dwCodeStart, dwCodeEnd, dwBytesWritten, dwBytesRead;
CONTEXT                   TestRegs;

VOID* pCodeEntry;
DWORD                     dwOldProt, dwNewProt;
CONTEXT                   Regs, InitRegs;
BYTE                      bOrgEntry;

DWORD ForceLibrary(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo)
{
	DWORD dwWinVer = GetVersion();

	// get the highest bit
	dwWinVer = dwWinVer >> 31;

	if (!dwWinVer)
		if (ForceLibraryNT(szLibraryPath, pProcInfo))
			return dwLibBase;
		else
			return 0;
	else
		if (ForceLibrary95(szLibraryPath, pProcInfo))
			return dwLibBase;
		else
			return 0;
}

BOOL InitCodeStruct(sLibLoadCode* LibLoaderCode,
	sLibLoadCodeNT* LibLoaderCodeNT,
	CHAR* szTargetLib,
	DWORD _dwCodeStart)
{
	DWORD dwLoadLibApiAddr;

	dwLoadLibApiAddr = (DWORD)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"),
		"LoadLibraryA");
	if (!dwLoadLibApiAddr)
		return FALSE;

	if (LibLoaderCode)
	{
		//LibLoaderCode->Int3             = Int3;
		LibLoaderCode->PushOpc = 0x68;
		LibLoaderCode->CallOpc = 0xE8;
		LibLoaderCode->CallAddr = dwLoadLibApiAddr - _dwCodeStart -
			offsetof(sLibLoadCode, jmp_$);
		strcpy(LibLoaderCode->LibPath, szTargetLib);
		LibLoaderCode->PushAddr = _dwCodeStart + offsetof(sLibLoadCode, LibPath);
		LibLoaderCode->jmp_$ = 0xFEEB;
	}
	else
	{
		//LibLoaderCodeNT->Int3           = Int3;
		LibLoaderCodeNT->PushOpc = 0x68;
		LibLoaderCodeNT->CallOpc = 0xE8;
		LibLoaderCodeNT->CallAddr = dwLoadLibApiAddr - _dwCodeStart -
			offsetof(sLibLoadCodeNT, RetOpc);
		strcpy(LibLoaderCodeNT->LibPath, szTargetLib);
		LibLoaderCodeNT->PushAddr = _dwCodeStart + offsetof(sLibLoadCodeNT, LibPath);
		LibLoaderCodeNT->RetOpc = 0xC2;
		LibLoaderCodeNT->RetValue = 0x0004;
	}
	return TRUE;
}

BOOL InitCodeStructDBG(sLibLoadCodeDBG& LibLoaderCode, CHAR* szTargetLib, DWORD _dwCodeStart)
{
	DWORD dwLoadLibApiAddr;

	LibLoaderCode.Int3 = Int3;
	LibLoaderCode.PushOpc = 0x68;
	LibLoaderCode.CallOpc = 0xE8;
	dwLoadLibApiAddr = (DWORD)GetProcAddress(
		GetModuleHandleW(L"kernel32.dll"),
		"LoadLibraryA");
	if (!dwLoadLibApiAddr)
		return FALSE;
	LibLoaderCode.CallAddr = dwLoadLibApiAddr - _dwCodeStart - offsetof(sLibLoadCodeDBG, Int3);
	strcpy(LibLoaderCode.LibPath, szTargetLib);
	LibLoaderCode.PushAddr = _dwCodeStart + offsetof(sLibLoadCodeDBG, LibPath);
	return TRUE;
}

// returns...
// 0 - error
DWORD GetProcessEntryPoint(DWORD PID)
{
	HANDLE          hSnap;
	tagMODULEENTRY32   ModuleInfo;
	tagPROCESSENTRY32  ProcInfo;
	sProcessPEInfo  ProcPEInfo;
	CHAR            ProcPath[256];
	DWORD           dwMemSize, dwPEHeaderAddr;
	VOID* pHeader;
	HANDLE          hProc;

	// get ToolHelp32 addresses
	if (!GetTh32())
		return FALSE;

	// I - get the process filename
	hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
		return 0;

	// init the ProcInfo struct
	ZeroMemory(&ProcInfo, sizeof(ProcInfo));
	ProcInfo.dwSize = sizeof(ProcInfo);

	// find the to the PID corresponding file path
	_Process32First(hSnap, &ProcInfo);
	ProcPath[0] = 0;
	while (_Process32Next(hSnap, &ProcInfo))
		if (ProcInfo.th32ProcessID == PID)
			strcpy((LPSTR)&ProcPath, ProcInfo.szExeFile);
	CloseHandle(hSnap);
	if (ProcPath[0] == 0)
		return 0;

	// II - find the ImageBase/SizeOfImage
	hSnap = _CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if (hSnap == INVALID_HANDLE_VALUE)
		return 0;

	// init the ModuleInfo and the ProcPEInfo struct
	ZeroMemory(&ModuleInfo, sizeof(ModuleInfo));
	ModuleInfo.dwSize = sizeof(ModuleInfo);
	ZeroMemory(&ProcPEInfo, sizeof(ProcPEInfo));

	_Module32First(hSnap, &ModuleInfo);
	if (stricmp((LPCSTR)&ModuleInfo.szExePath, (LPCSTR)&ProcPath) == 0)
	{
		ProcPEInfo.dwImageBase = (DWORD)ModuleInfo.modBaseAddr;
		ProcPEInfo.dwSizeOfImage = ModuleInfo.modBaseSize;
	}
	while (_Module32Next(hSnap, &ModuleInfo))
	{
		if (stricmp((LPCSTR)&ModuleInfo.szExePath, (LPCSTR)&ProcPath) == 0)
		{
			ProcPEInfo.dwImageBase = (DWORD)ModuleInfo.modBaseAddr;
			ProcPEInfo.dwSizeOfImage = ModuleInfo.modBaseSize;
		}
	}
	CloseHandle(hSnap);
	if (ProcPEInfo.dwImageBase == 0)
		return 0;

	// get the EntryPoint
	if (ProcPEInfo.dwSizeOfImage < HEADER_SIZE)
		dwMemSize = ProcPEInfo.dwSizeOfImage;
	else
		dwMemSize = HEADER_SIZE;
	if (!(hProc = OpenProcess(PROCESS_VM_READ, FALSE, PID)))
		return 0;
	if (!(pHeader = GlobalAlloc(GMEM_FIXED, dwMemSize)))
		return 0;
	if (!ReadProcessMemory(
		hProc,
		(PVOID)ProcPEInfo.dwImageBase,
		pHeader,
		dwMemSize,
		&dwBytesRead))
	{
		GlobalFree(pHeader);
		return 0;
	}
	if (((PIMAGE_DOS_HEADER)pHeader)->e_magic != IMAGE_DOS_SIGNATURE)
	{
		GlobalFree(pHeader);
		return 0;
	}
	dwPEHeaderAddr = ((PIMAGE_DOS_HEADER)pHeader)->e_lfanew;
	if (((PIMAGE_NT_HEADERS)(dwPEHeaderAddr + (DWORD)pHeader))->Signature !=
		IMAGE_NT_SIGNATURE)
	{
		GlobalFree(pHeader);
		return 0;
	}
	ProcPEInfo.dwEntryPointVA = ((PIMAGE_NT_HEADERS)(dwPEHeaderAddr + (DWORD)pHeader))->OptionalHeader \
		.AddressOfEntryPoint + ProcPEInfo.dwImageBase;
	GlobalFree(pHeader);
	return ProcPEInfo.dwEntryPointVA;
}

BOOL ForceLibrary95(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo)
{
	DWORD            dwEntryPoint, dwEWRProt;
	sLibLoadCode     LibLoadCode;

	InitRegs.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	if (!GetThreadContext(pProcInfo->hThread, &InitRegs))
		return FALSE;
	if (!(dwEntryPoint = GetProcessEntryPoint(pProcInfo->dwProcessId)))
		return FALSE;

	// init the LibLoadCode struct
	if (!InitCodeStruct(&LibLoadCode, NULL, szLibraryPath, dwEntryPoint))
		return FALSE;

	// save the code at the EntryPoint
	pCodeEntry = GlobalAlloc(GMEM_FIXED, sizeof(LibLoadCode));
	if (!pCodeEntry)
		return FALSE;
	VirtualProtectEx(
		pProcInfo->hProcess,
		(VOID*)dwEntryPoint,
		sizeof(LibLoadCode),
		PAGE_EXECUTE_READWRITE,
		&dwOldProt);
	if (!ReadProcessMemory(
		pProcInfo->hProcess,
		(VOID*)dwEntryPoint,
		pCodeEntry,
		sizeof(LibLoadCode),
		&dwBytesRead))
	{
		GlobalFree(pCodeEntry);
		return FALSE;
	}

	// write the loader code to the EntryPoint
	if (!WriteProcessMemory(
		pProcInfo->hProcess,
		(VOID*)dwEntryPoint,
		&LibLoadCode,
		sizeof(LibLoadCode),
		&dwBytesWritten))
	{
		GlobalFree(pCodeEntry);
		return FALSE;
	}

	// execute the copied code
	Regs = InitRegs;
	Regs.Eip = dwEntryPoint;
	ResumeThread(pProcInfo->hThread);

	// wait until the thread finishes
	dwCodeEnd = dwEntryPoint + offsetof(sLibLoadCode, jmp_$);
	TestRegs.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
	do
	{
		Sleep(50);
		GetThreadContext(pProcInfo->hThread, &TestRegs);
	} while (TestRegs.Eip != dwCodeEnd);
	dwLibBase = TestRegs.Eax;

	// suspend the thread and restore all !
	SuspendThread(pProcInfo->hThread);
	if (!WriteProcessMemory(
		pProcInfo->hProcess,
		(VOID*)dwEntryPoint,
		pCodeEntry,
		sizeof(LibLoadCode),
		&dwBytesWritten))
	{
		GlobalFree(pCodeEntry);
		return FALSE;
	}
	GlobalFree(pCodeEntry);
	VirtualProtectEx(
		pProcInfo->hProcess,
		(VOID*)dwCodeStart,
		sizeof(LibLoadCode),
		dwOldProt,
		&dwEWRProt);
	InitRegs.Eip = dwEntryPoint;
	if (!SetThreadContext(pProcInfo->hThread, &InitRegs))
		return FALSE;
	return TRUE;
}

BOOL ForceLibraryNT(CHAR* szLibraryPath, PROCESS_INFORMATION* pProcInfo)
{
	sLibLoadCodeNT  LibLoadCode;
	DWORD           dwRemoteThreadID;
	HANDLE          hRemoteThread;
	_CodeEntry32      CodeEntry;


	// import NT only stuff manually
	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	if (!kernel)
	{
		MessageBoxA(0, "couldnt get kernel32 handle", 0, 0);
		ExitProcess(1);
	}
	fp_VirtualAllocEx VirtualAllocExPtr = (fp_VirtualAllocEx)GetProcAddress(kernel, "VirtualAllocEx");
	fp_VirtualFreeEx VirtualFreeExPtr = (fp_VirtualFreeEx)GetProcAddress(kernel, "VirtualFreeEx");

	if (!VirtualFreeExPtr || !VirtualAllocExPtr)
	{
		MessageBoxA(0, "couldnt import virtualallocex", 0, 0);
		ExitProcess(1);
	}



	// get some mem in the target's process memory
	dwCodeStart = (DWORD)VirtualAllocExPtr(
		pProcInfo->hProcess,
		NULL,
		sizeof(LibLoadCode),
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);
	if (!dwCodeStart)
		return FALSE;

	// init the LibLoadCode struct
	if (!InitCodeStruct(0, &LibLoadCode, szLibraryPath, dwCodeStart))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// copy the code into the allocated mem
	if (!WriteProcessMemory(
		pProcInfo->hProcess,
		(VOID*)dwCodeStart,
		&LibLoadCode,
		sizeof(LibLoadCode),
		&dwBytesWritten))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// execute it
	CodeEntry = (_CodeEntry32)dwCodeStart;
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
			(VOID*)dwCodeStart,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// wait until the thread finishes
	WaitForSingleObject(hRemoteThread, INFINITE);
	if (!GetExitCodeThread(hRemoteThread, &dwLibBase))
	{
		VirtualFreeExPtr(
			pProcInfo->hProcess,
			(VOID*)dwCodeStart,
			sizeof(LibLoadCode),
			MEM_DECOMMIT);
		return FALSE;
	}

	// clean up
	VirtualFreeExPtr(
		pProcInfo->hProcess,
		(VOID*)dwCodeStart,
		sizeof(LibLoadCode),
		MEM_DECOMMIT);
	CloseHandle(hRemoteThread);

	if (dwLibBase)
		return TRUE;
	else
		return FALSE;
}

extern "C" BOOL WINAPI TrapEntry(DWORD dwEntryPoint, PROCESS_INFORMATION* pPI)
{
	// simply set a 0CCh at the EntryPoint
	VirtualProtectEx(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		1,
		PAGE_EXECUTE_READWRITE,
		&dwOldProt);
	if (!ReadProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		(VOID*)&bOrgEntry,
		1,
		&dwBytesRead))
		return FALSE;
	if (!WriteProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		(VOID*)&Int3,
		1,
		&dwBytesWritten))
		return FALSE;
	VirtualProtectEx(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		1,
		dwOldProt,
		&dwNewProt);
	return TRUE;
}

extern "C" BOOL WINAPI ForceLibraryDBG(CHAR* szTargetLib,
	DWORD dwEntryPoint,
	PROCESS_INFORMATION* pPI)
{
	// save the regs
	Regs.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	if (!GetThreadContext(pPI->hThread, &Regs))
		return FALSE;
	Regs.Eip = dwEntryPoint;
	InitRegs = Regs;

	// init the LibLoadCodeDBG struct
	if (!InitCodeStructDBG(LibLoadCodeDBG, szTargetLib, dwEntryPoint))
		return FALSE;

	VirtualProtectEx(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		LOADCODESIZEDBG,
		PAGE_EXECUTE_READWRITE,
		&dwOldProt);

	// restore the EntryPoint-byte
	if (!WriteProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		&bOrgEntry,
		1,
		&dwBytesWritten))
		return FALSE;

	// save the code at the EntryPoint
	pCodeEntry = GlobalAlloc(GMEM_FIXED, LOADCODESIZEDBG);
	if (!pCodeEntry)
		return FALSE;
	if (!ReadProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		pCodeEntry,
		LOADCODESIZEDBG,
		&dwBytesRead))
	{
		GlobalFree(pCodeEntry);
		return FALSE;
	}

	// write the loader code to the EntryPoint and restore protection of the code page
	if (!WriteProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		&LibLoadCodeDBG,
		LOADCODESIZEDBG,
		&dwBytesWritten))
	{
		GlobalFree(pCodeEntry);
		return FALSE;
	}

	// prepare the execution of the copied code
	SetThreadContext(pPI->hThread, &Regs);
	return TRUE;
}

extern "C" DWORD WINAPI PerformCleanup(DWORD dwEntryPoint, PROCESS_INFORMATION* pPI)
{
	// grab the result of the "LoadLibraryA" call
	GetThreadContext(pPI->hThread, &Regs);
	dwLibBase = Regs.Eax;

	// restore all !
	if (!WriteProcessMemory(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		pCodeEntry,
		LOADCODESIZEDBG,
		&dwBytesWritten))
	{
		GlobalFree(pCodeEntry);
		return 0;
	}
	GlobalFree(pCodeEntry);
	VirtualProtectEx(
		pPI->hProcess,
		(VOID*)dwEntryPoint,
		LOADCODESIZEDBG,
		dwOldProt,
		&dwNewProt);
	if (!SetThreadContext(pPI->hThread, &InitRegs))
		return 0;
	return dwLibBase;
}

