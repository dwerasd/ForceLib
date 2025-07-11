#pragma once


#include <windows.h>
#include <tlhelp32.h>


// ToolHelp32 function prototypes
typedef HANDLE(WINAPI* fp_CreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* fp_Process32FirstW)(HANDLE hSnapshot, tagPROCESSENTRY32W* lppe);
typedef BOOL(WINAPI* fp_Process32NextW)(HANDLE hSnapshot, tagPROCESSENTRY32W* lppe);
typedef BOOL(WINAPI* fp_Module32FirstW)(HANDLE hSnapshot, tagMODULEENTRY32W* lpme);
typedef BOOL(WINAPI* fp_Module32NextW)(HANDLE hSnapshot, tagMODULEENTRY32W* lpme);

typedef BOOL(WINAPI* fp_Process32First)(HANDLE hSnapshot, tagPROCESSENTRY32* lppe);
typedef BOOL(WINAPI* fp_Process32Next)(HANDLE hSnapshot, tagPROCESSENTRY32* lppe);
typedef BOOL(WINAPI* fp_Module32First)(HANDLE hSnapshot, tagMODULEENTRY32* lpme);
typedef BOOL(WINAPI* fp_Module32Next)(HANDLE hSnapshot, tagMODULEENTRY32* lpme);
// Global function pointers for ToolHelp32 functions

extern fp_CreateToolhelp32Snapshot    _CreateToolhelp32Snapshot;

extern fp_Process32FirstW              _Process32FirstW;
extern fp_Process32NextW               _Process32NextW;
extern fp_Module32FirstW               _Module32FirstW;
extern fp_Module32NextW                _Module32NextW;

extern fp_Process32First              _Process32First;
extern fp_Process32Next               _Process32Next;
extern fp_Module32First               _Module32First;
extern fp_Module32Next                _Module32Next;

BOOL GetTh32();
