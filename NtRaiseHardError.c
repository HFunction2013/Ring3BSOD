#include <stdio.h>
#include <windows.h>
// 需要的Shutdown权限，至于为什么是19看上面RtlAdjustPrivilege的介绍
const ULONG SE_SHUTDOWN_PRIVILEGE = 19;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
}UNICODE_STRING, *PUNICODE_STRING;

typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

// 函数指针
typedef NTSTATUS(NTAPI *NTRAISEHARDERROR)(
    IN NTSTATUS             ErrorStatus,
    IN ULONG                NumberOfParameters,
    IN PUNICODE_STRING      UnicodeStringParameterMask OPTIONAL,
    IN PVOID                *Parameters,
    IN HARDERROR_RESPONSE_OPTION ResponseOption,
    OUT PHARDERROR_RESPONSE Response
    );

typedef BOOL(NTAPI *RTLADJUSTPRIVILEGE)(ULONG, BOOL, BOOL, PBOOLEAN);

HARDERROR_RESPONSE_OPTION ResponseOption = OptionShutdownSystem;
HARDERROR_RESPONSE Response;

NTRAISEHARDERROR NtRaiseHardError;
RTLADJUSTPRIVILEGE RtlAdjustPrivilege;

int main()
{
    // 任何进程都会自动加载ntdll，因此直接获取模块地址即可，不必再LoadLibrary
    HMODULE  NtBase = GetModuleHandle(TEXT("ntdll.dll"));
    if (!NtBase) return false;

    // 获取各函数地址
    NtRaiseHardError = (NTRAISEHARDERROR)GetProcAddress(NtBase, "NtRaiseHardError");
    RtlAdjustPrivilege = (RTLADJUSTPRIVILEGE)GetProcAddress(NtBase, "RtlAdjustPrivilege");
    // 提权
    BOOLEAN B;
    if (!RtlAdjustPrivilege(SE_SHUTDOWN_PRIVILEGE, TRUE, FALSE, &B) == 0)
    {
        printf("提权失败");
        getchar();
        return 0;
    }
    NTSTATUS status = NtRaiseHardError(0xC0000217, 0, NULL, NULL, OptionShutdownSystem, &Response);
    return 0;
}