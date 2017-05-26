# InjectProc

Process injection is a very popular method to hide malicious behavior of code and are heavily used by malware authors.

There are several techniques, which are commonly used:
DLL injection, process replacement (a.k.a process hollowing), hook injection and APC injection.

Most of them use same Windows API functions: 
OpenProcess, VirtualAllocEx, WriteProcessMemory, for detailed information about those functions, use MSDN.

## DLL injection:
* Open target process.
* Allocate space.
* Write code into the remote process.
* Execute the remote code.

## Process replacement:
* Create target process and suspend it.
* Unmap from memory.
* Allocate space.
* Write headers and sections into the remote process.
* Resume remote thread.

## Hook injection:
* Find/Create process.
* Set hook

## APC injection:
* Open process.
* Allocate space.
* Write code into remote threads.
* "Execute" threads using QueueUserAPC.

## Download
[Windows x64 binary](https://github.com/secrary/InfectPE/releases) - Hardcoded MessageBoxA x-code, only for demos.
## Dependencies: 
[vc_redist.x64](https://www.microsoft.com/en-us/download/details.aspx?id=53840) - Microsoft Visual C++ Redistributable
## DEMO
[InjectProc DEMO - Process Injection Techniques](https://vimeo.com/219083062)

# Warning
I create this project for me to better understand how process injection works and 
I think it will be helpful for many beginner malware analysts too. 
