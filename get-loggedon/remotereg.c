// Get remote loggedon users on Servers/DC using remote registry query 

#include <windows.h>
#include "beacon.h"


DECLSPEC_IMPORT  PCHAR __cdecl  MSVCRT$strstr(const char *haystack, const char *needle);
WINADVAPI LONG WINAPI ADVAPI32$RegConnectRegistryW( LPCWSTR lpMachineName, HKEY hKey, PHKEY phkResult );
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI ADVAPI32$ConvertStringSidToSidA(LPCSTR   StringSid, PSID   *Sid);
WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(HKEY hKey,DWORD dwIndex,LPSTR lpName,LPDWORD lpcchName,LPDWORD lpReserved,LPSTR lpClass,LPDWORD lpcchClass,PFILETIME lpftLastWriteTime);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupAccountSidA(LPCSTR lpSystemName, PSID Sid, LPSTR Name, LPDWORD cchName, LPSTR ReferencedDomainName, LPDWORD cchReferencedDomainName, PSID_NAME_USE peUse);


 void go(char * args, int len){

  datap  parser;
  LPWSTR computer = NULL;
  BeaconDataParse(&parser, args, len);
  computer  = (LPWSTR)BeaconDataExtract(&parser, NULL);

  LONG lRetVal;
  HKEY  hKey;
  lRetVal = ADVAPI32$RegConnectRegistryW(computer, HKEY_USERS, &hKey);

  
  LONG rc;     // contains error value returned by Regxxx()
  LPTSTR MachineName = NULL;
  DWORD dwSubKeyIndex = 0;   // index into key
  char szSubKey[_MAX_FNAME];
  DWORD dwSubKeyLength = _MAX_FNAME; // length of SubKey buffer

  PSID sid;

  char lpName[200];
  DWORD dwSize = 200;
  char lpDomain[200];
  SID_NAME_USE SNU;


  BeaconPrintf(CALLBACK_OUTPUT, "\n[+] Enumerating Users on: %ws\n", computer);

  while ((rc = ADVAPI32$RegEnumKeyExA(
    hKey,
    dwSubKeyIndex,
    szSubKey,
    &dwSubKeyLength,
    NULL,
    NULL,
    NULL,
    NULL)
    ) != ERROR_NO_MORE_ITEMS) {
    if (rc == ERROR_SUCCESS) {
      dwSubKeyIndex++;
      dwSubKeyLength = _MAX_FNAME;
      
  if (MSVCRT$strstr(szSubKey, "S-1-5-21-") != NULL) {

  ADVAPI32$ConvertStringSidToSidA(szSubKey, &sid);
  ADVAPI32$LookupAccountSidA(NULL, sid, lpName, &dwSize, lpDomain, &dwSize, &SNU);
  BeaconPrintf(CALLBACK_OUTPUT, "[*] User \"%s\\%s\" is Logged on - \"%ws\"", lpDomain, lpName, computer);

}
}
}
}
