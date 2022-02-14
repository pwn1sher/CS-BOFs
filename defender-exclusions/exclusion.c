/**
* @ A beacon object file to list windows defender exclusions
* @original author & full credits to -	Paul L. (@am0nsec)
* Compile - cl.exe /c /GS- exclusion.c /Fodefender.o
*/

#include <Windows.h>
#include <stdio.h>
#include <winreg.h>
#include "beacon.h"
#include "defender.h"

WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyA(HKEY hKey,LPCSTR lpSubKey,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryInfoKeyA(HKEY hKey,LPSTR lpClass,LPDWORD lpcchClass,LPDWORD lpReserved,LPDWORD lpcSubKeys,LPDWORD lpcbMaxSubKeyLen,LPDWORD lpcbMaxClassLen,LPDWORD lpcValues,LPDWORD lpcbMaxValueNameLen,LPDWORD lpcbMaxValueLen,LPDWORD lpcbSecurityDescriptor,PFILETIME lpftLastWriteTime);

WINADVAPI LONG WINAPI ADVAPI32$RegEnumValueA(HKEY hKey,DWORD dwIndex,LPSTR lpValueName,LPDWORD lpcchValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);


WINBASEAPI void * WINAPI KERNEL32$HeapAlloc (HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapReAlloc (HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree (HANDLE, DWORD, PVOID);


// generic function
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);


#define RtlZeroMemory(Destination,Length) MSVCRT$memset((Destination),0,(Length))


_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdGetAllExclusions(
	_Out_ PDEFENDER_EXCLUSION_LIST pExclusionsList
) {
	if (pExclusionsList == NULL)
		return E_INVALIDARG;

	// Open and handle to the following windows Registry key:
	// Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions
	HKEY hExclusionList = INVALID_HANDLE_VALUE;
	LSTATUS Status = ADVAPI32$RegOpenKeyA(
		HKEY_LOCAL_MACHINE,
		"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions",
		&hExclusionList
	);
	if (Status != ERROR_SUCCESS || hExclusionList == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// Get handle to the process heap for memory allocation
	HANDLE hHeap = KERNEL32$GetProcessHeap();

	// Build a local copy of the final structure.
	DEFENDER_EXCLUSION_LIST ExclusionList = { 0x00 };

	// Prepare local variables
	HRESULT Result = S_OK;
	DWORD dwNumberOfValues = 0x00;

	// Get extensions
	ExclusionList.Extensions = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Extensions,
		"Extensions",
		DefenderExclusionExtensions,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		KERNEL32$HeapFree(hHeap, 0x00, ExclusionList.Extensions);
		ExclusionList.Extensions = NULL;
	}

	// Get IpAddresses
	ExclusionList.IpAddresses = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.IpAddresses,
		"IpAddresses",
		DefenderExclusionIpAddress,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		KERNEL32$HeapFree(hHeap, 0x00, ExclusionList.IpAddresses);
		ExclusionList.IpAddresses = NULL;
	}

	// Get paths
	ExclusionList.Paths = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Paths,
		"Paths",
		DefenderExclusionPaths,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		KERNEL32$HeapFree(hHeap, 0x00, ExclusionList.Paths);
		ExclusionList.Paths = NULL;
	}

	// Get processes
	ExclusionList.Processes = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.Processes,
		"Processes",
		DefenderExclusionProcesses,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		KERNEL32$HeapFree(hHeap, 0x00, ExclusionList.Extensions);
		ExclusionList.Extensions = NULL;
	}

	// Get temporary paths
	ExclusionList.TemporaryPaths = KERNEL32$HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
	Result = DfdpGetExclusionEntries(
		ExclusionList.TemporaryPaths,
		"TemporaryPaths",
		DefenderExclusionTemporaryPaths,
		&hExclusionList,
		&hHeap,
		&dwNumberOfValues
	);
	if (Result != S_OK || dwNumberOfValues == 0x00) {
		KERNEL32$HeapFree(hHeap, 0x00, ExclusionList.TemporaryPaths);
		ExclusionList.TemporaryPaths = NULL;
	}

	// Cleanup and return data
	ADVAPI32$RegCloseKey(hExclusionList);
	*pExclusionsList = ExclusionList;
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdpGetExclusionEntries(
	_In_  PDEFENDER_EXCLUSION_ENTRY     pExclusionEntry,
	_In_  LPCSTR                        szSubKeyName,
	_In_  CONST DEFENDER_EXCLUSION_TYPE Type,
	_In_  CONST PHKEY                   pParentKey,
	_In_  CONST PHANDLE                 phHeap,
	_Out_ PDWORD                        pdwNumberOfValues
) {
	if (pExclusionEntry == NULL
		|| szSubKeyName == NULL
		|| pParentKey == NULL
		|| *pParentKey == INVALID_HANDLE_VALUE
		|| phHeap == NULL)
		return E_INVALIDARG;

	// Open an handle to the subkey
	HKEY hSubKey = INVALID_HANDLE_VALUE;
	LSTATUS Status = ADVAPI32$RegOpenKeyA(
		*pParentKey,
		szSubKeyName,
		&hSubKey
	);
	if (Status != ERROR_SUCCESS || hSubKey == INVALID_HANDLE_VALUE)
		return E_FAIL;

	// Get all the number of values stored in the Registry key
	DWORD dwMaxValueNameLength = 0x00;

	Status = ADVAPI32$RegQueryInfoKeyA(
		hSubKey,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		pdwNumberOfValues,
		&dwMaxValueNameLength,
		NULL,
		NULL,
		NULL
	);
	if (Status != ERROR_SUCCESS) {
		ADVAPI32$RegCloseKey(hSubKey);
		return E_FAIL;
	}
	if (*pdwNumberOfValues == 0x00)
		return S_OK;
	dwMaxValueNameLength++;

	// Save previous entry
	PDEFENDER_EXCLUSION_ENTRY Blink = NULL;

	// Get all the values one by one
	for (DWORD cx = 0x00; cx < *pdwNumberOfValues; cx++) {

		// Allocate memory for a new entry
		PDEFENDER_EXCLUSION_ENTRY ExclusionEntry = NULL;
		if (cx == 0x00) {
			ExclusionEntry = pExclusionEntry;
		}
		else {
			ExclusionEntry = KERNEL32$HeapAlloc(*phHeap, HEAP_ZERO_MEMORY, sizeof(DEFENDER_EXCLUSION_ENTRY));
		}
		ExclusionEntry->Exclusion = KERNEL32$HeapAlloc(*phHeap, HEAP_ZERO_MEMORY, dwMaxValueNameLength);

		// Get the value name
		DWORD dwBufferSize = dwMaxValueNameLength;
		Status = ADVAPI32$RegEnumValueA(hSubKey, cx, ExclusionEntry->Exclusion, &dwBufferSize, NULL, NULL, NULL, NULL);
		if (Status != ERROR_SUCCESS) {
			KERNEL32$HeapFree(*phHeap, 0x00, ExclusionEntry->Exclusion);
			KERNEL32$HeapFree(*phHeap, 0x00, ExclusionEntry);
			ADVAPI32$RegCloseKey(hSubKey);
			return E_FAIL;
		}

		// Allocate memory for the double-linked list
		ExclusionEntry->Type = Type;
		ExclusionEntry->Length = dwBufferSize;

		// Create chain
		if (Blink != NULL) {
			ExclusionEntry->Blink = Blink;
			((PDEFENDER_EXCLUSION_ENTRY)ExclusionEntry->Blink)->Flink = ExclusionEntry;
		}
		Blink = ExclusionEntry;
	}

	ADVAPI32$RegCloseKey(hSubKey);
	return S_OK;



}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DfdpCleanup(
	_In_ PDEFENDER_EXCLUSION_LIST pExclusionsList
) {
	if (pExclusionsList == NULL)
		return E_FAIL;

	// Get handle to process heap
	HANDLE hHeap = KERNEL32$GetProcessHeap();

	// Clean all the memory allocated
	for (DWORD cx = 0x00; cx < (sizeof(DEFENDER_EXCLUSION_LIST) / sizeof(PVOID)); cx++) {
		PDEFENDER_EXCLUSION_ENTRY Entry = *(PUINT64)((PBYTE)pExclusionsList + (8 * cx));
		while (Entry != NULL) {
			KERNEL32$HeapFree(hHeap, 0x00, Entry->Exclusion);
			if (Entry->Blink != NULL)
				KERNEL32$HeapFree(hHeap, 0x00, Entry->Blink);
			if (Entry->Flink == NULL) {
				KERNEL32$HeapFree(hHeap, 0x00, Entry);
				break;
			}
			Entry = Entry->Flink;
		}
	}

	ZeroMemory(pExclusionsList, sizeof(DEFENDER_EXCLUSION_LIST));
	return S_OK;
}


/**
 * @brief Application entry point.
 * @return Application exist status.
*/
void go() {

	// Get the complete list of exclusions
	DEFENDER_EXCLUSION_LIST ExclusionList = { 0x00 };
	HRESULT Result = DfdGetAllExclusions(&ExclusionList);
	if (Result != S_OK)
		BeaconPrintf(CALLBACK_ERROR, "error");

	// Display everything
	PDEFENDER_EXCLUSION_ENTRY ListEntry = ExclusionList.Extensions;

	BeaconPrintf(CALLBACK_OUTPUT,"Type          Value\n");
	for (DWORD cx = 0x00; cx < (sizeof(DEFENDER_EXCLUSION_LIST) / sizeof(PVOID)); cx++) {

		// Get the correct extension type
		PDEFENDER_EXCLUSION_ENTRY Entry = *(PUINT64)((PBYTE)&ExclusionList + (8 * cx));

		while (Entry != NULL) {
			switch (Entry->Type) {
			case DefenderExclusionExtensions:
				BeaconPrintf(CALLBACK_OUTPUT,"%+-11s%s\n", "Extension:", Entry->Exclusion);
				break;
			case DefenderExclusionIpAddress:
				BeaconPrintf(CALLBACK_OUTPUT,"%+-11s%s\n", "IpAddress:", Entry->Exclusion);
				break;
			case DefenderExclusionPaths:
				BeaconPrintf(CALLBACK_OUTPUT,"%+-11s%s\n", "Path:", Entry->Exclusion);
				break;
			case DefenderExclusionProcesses:
				BeaconPrintf(CALLBACK_OUTPUT,"%+-11s%s\n", "Process:", Entry->Exclusion);
				break;
			case DefenderExclusionTemporaryPaths:
				BeaconPrintf(CALLBACK_OUTPUT,"%+-11s%s\n", "TemporaryPaths:", Entry->Exclusion);
				break;
			}
			Entry = Entry->Flink;
		}
	}

	// Cleanup and exit
	DfdpCleanup(&ExclusionList);
	BeaconPrintf(CALLBACK_OUTPUT, "done\n");
}
