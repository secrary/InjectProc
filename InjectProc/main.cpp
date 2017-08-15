#include <Windows.h>
#include "Injection.h"
#include <iostream>
#include <filesystem>
#include <atlconv.h>

int main(int argc, char* argv[])
{
	USES_CONVERSION;
	if (argc < 2)
	{
		printf_s( "Usage: ./InjectProc.exe <type of injection> <path/to/exe or process_name> <path/to/dll>\nExample:\n\
		./InjectProc.exe dll_inj path/to/dll.dll notepad.exe\n\
		./InjectProc.exe proc_rpl path/to/target/exe path/to/exe\n\
		./InjectProc.exe hook path/to/target/exe path/to//dll\n\
		./InjectProc.exe APC target/proc/name path/to/dll\n\
		");
		return EXIT_FAILURE;
	}

	string mode = argv[1];
	if (mode == "dll_inj")
		Dll_Injection(A2T(argv[2]), A2T(argv[3]));
	else if (mode == "proc_rpl")
		ProcessReplacement(A2T(argv[2]), A2T(argv[3]));
	else if (mode == "hook")
		// Windows hooks can be considered one of the most powerful features of Windows. 
		// With them, you can trap events that will occur, either in your own process or in other processes. 
		// By "hooking", you tell Windows about a function, filter function also called hook procedure, 
		// that will be called everytime an event you're interested in occurs.
		HookInjection(A2T(argv[2]), A2T(argv[3])); // Inject DLL into remote process
	else if (mode == "APC")
		APCinjection(A2T(argv[2]), A2T(argv[3]));
	else {
		printf_s("Incorrect mode\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}