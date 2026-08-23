#include <stdio.h>
#include <windows.h>

BOOL EnableDebugPrivilege();
BOOL TestCriticalApi();
typedef NTSTATUS(__cdecl *RTLSETPROCESSISCRITICAL)(IN BOOLEAN NewValue,OUT PBOOLEAN OldValue OPTIONAL,IN BOOLEAN NeedBreaks);

int main(void)
{
    TestCriticalApi();
    return 0;
}

BOOL EnableDebugPrivilege()
{
    HANDLE hToken = NULL;
    LUID debugPrivilegeValueLuid={0};
    TOKEN_PRIVILEGES tokenPrivilege = {0};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugPrivilegeValueLuid))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    tokenPrivilege.PrivilegeCount = 1;
    tokenPrivilege.Privileges[0].Luid = debugPrivilegeValueLuid;
    tokenPrivilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPrivilege, sizeof(tokenPrivilege), NULL, NULL))
    {
        CloseHandle(hToken);
        return FALSE;
    }

    return TRUE;
}

BOOL TestCriticalApi()
{
    if(!EnableDebugPrivilege())
        return FALSE;

    HMODULE  hNtdllMod = GetModuleHandle(TEXT("ntdll.dll"));
    if(!hNtdllMod)
        return FALSE;

    RTLSETPROCESSISCRITICAL RtlSetProcessIsCritical;
    RtlSetProcessIsCritical = (RTLSETPROCESSISCRITICAL)GetProcAddress(hNtdllMod, "RtlSetProcessIsCritical");
    if (!RtlSetProcessIsCritical)
        return FALSE;

    NTSTATUS status = RtlSetProcessIsCritical(TRUE, NULL, FALSE);
    printf("status:%x\n",status);

    getchar();

    status = RtlSetProcessIsCritical(FALSE, NULL, FALSE);
    printf("status:%x\n",status);
    getchar();

    return TRUE;
}