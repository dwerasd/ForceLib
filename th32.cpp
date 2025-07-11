//
// TH32.c: loads dynamically the ToolHelp32 API's because they
//         aren't available on NT4 ! Much thanks goes to ELiCZ
//         for putting my attention on that fact.
//

#include "th32.h"

// global variables
fp_CreateToolhelp32Snapshot    _CreateToolhelp32Snapshot;
fp_Process32FirstW              _Process32FirstW;
fp_Process32NextW               _Process32NextW;
fp_Module32FirstW               _Module32FirstW;
fp_Module32NextW                _Module32NextW;

fp_Process32First              _Process32First;
fp_Process32Next               _Process32Next;
fp_Module32First               _Module32First;
fp_Module32Next                _Module32Next;


BOOL GetTh32()
{
	// get kernel32 base
	const HMODULE hKrnl = LoadLibraryW(L"Kernel32.dll");
	if (!hKrnl)
		return FALSE;

	// get th32 addresses
	_CreateToolhelp32Snapshot = (fp_CreateToolhelp32Snapshot)GetProcAddress(hKrnl, "CreateToolhelp32Snapshot");
	_Process32FirstW = (fp_Process32FirstW)GetProcAddress(hKrnl, "Process32FirstW");
	_Process32NextW = (fp_Process32NextW)GetProcAddress(hKrnl, "Process32NextW");
	_Module32FirstW = (fp_Module32FirstW)GetProcAddress(hKrnl, "Module32FirstW");
	_Module32NextW = (fp_Module32NextW)GetProcAddress(hKrnl, "Module32NextW");

	_Process32First = (fp_Process32First)GetProcAddress(hKrnl, "Process32First");
	_Process32Next = (fp_Process32Next)GetProcAddress(hKrnl, "Process32Next");
	_Module32First = (fp_Module32First)GetProcAddress(hKrnl, "Module32First");
	_Module32Next = (fp_Module32Next)GetProcAddress(hKrnl, "Module32Next");

	if (!_CreateToolhelp32Snapshot
		|| !_Process32FirstW
		|| !_Process32NextW
		|| !_Module32FirstW
		|| !_Module32NextW
		|| !_Process32First
		|| !_Process32Next
		|| !_Module32First
		|| !_Module32Next
		)
		return FALSE;

	return TRUE;
}