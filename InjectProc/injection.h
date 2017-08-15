#pragma once
#include <Winternl.h>
#include <string>
#include <tuple>
#include <vector>
#include <memory>
using namespace std;


BOOL FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids);
VOID DbgPrint(char *msg);
BOOL Dll_Injection(TCHAR *dll_name, TCHAR processname[]);
BOOL ProcessReplacement(TCHAR* target, wstring inj_exe);
BOOL HookInjection(TCHAR target[], TCHAR *dll_name);
BOOL APCinjection(TCHAR target[], TCHAR *dll_name);

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms684280(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _NtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

// https://msdn.microsoft.com/en-us/library/windows/hardware/ff567119(v=vs.85).aspx
typedef NTSTATUS(WINAPI* _ZwUnmapViewOfSection)(
	_In_     HANDLE ProcessHandle,
	_In_opt_ PVOID  BaseAddress
	);

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

struct PE_FILE
{
	size_t size_ids{};
	size_t size_dos_stub{};
	size_t size_inh32{};
	size_t size_ish{};
	size_t size_sections{};
	IMAGE_DOS_HEADER ids;
	std::vector<char> MS_DOS_STUB;
	IMAGE_NT_HEADERS64 inh32;
	std::vector<IMAGE_SECTION_HEADER> ish;
	std::vector<shared_ptr<char>> Sections;
	void set_sizes(size_t, size_t, size_t, size_t, size_t);
};

struct LOADED_IMAGE64
{
	PIMAGE_NT_HEADERS64 FileHeader;
	ULONG NumberOfSections;
	PIMAGE_SECTION_HEADER Sections;
};