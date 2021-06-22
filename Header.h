#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>

#define NT_SUCCESS(status) ((status) >= 0)
#define GLE GetLastError()

#define SeTcbPrivilege 7
#define SeDebugPrivilege 20
#define SeImpersonatePrivilege 29

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(int Privilege, bool Enable, bool ThreadPrivilege, bool* Previous);

//My setup didn't include the proper headers for LogonUserExExW so I had to resolve it dynamically
typedef BOOL(WINAPI* _LogonUserExExW)(
	_In_      LPTSTR        lpszUsername,
	_In_opt_  LPTSTR        lpszDomain,
	_In_opt_  LPTSTR        lpszPassword,
	_In_      DWORD         dwLogonType,
	_In_      DWORD         dwLogonProvider,
	_In_opt_  PTOKEN_GROUPS pTokenGroups,
	_Out_opt_ PHANDLE       phToken,
	_Out_opt_ PSID* ppLogonSid,
	_Out_opt_ PVOID* ppProfileBuffer,
	_Out_opt_ LPDWORD       pdwProfileLength,
	_Out_opt_ PQUOTA_LIMITS pQuotaLimits
);

_RtlAdjustPrivilege RtlAdjustPrivilege;
_LogonUserExExW LogonUserExExW;

void ResolveDynamicFunctions();
bool EnablePrivilege(bool impersonating, int privilege_value);
bool ImpersonateTcbToken();
HANDLE GetTrustedInstallerToken();
void TestToken(HANDLE token);
