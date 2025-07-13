#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>

typedef LONG (NTAPI* pfnNtSuspendProcess) (HANDLE);
typedef LONG (NTAPI* pfnNtResumeProcess)(HANDLE);
typedef NTSTATUS(NTAPI* pfnNtTerminateProcess)(HANDLE ProcessHandle, NTSTATUS ExitStatus);
typedef NTSTATUS(NTAPI* pfnNtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    CLIENT_ID *ClientId
);
typedef NTSTATUS(NTAPI* pfnNtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded
);

typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

class Memory_ {
public:
    Memory_(std::string arg_procName);
    ~Memory_();
    void ResetProc();
    

    bool OpenHandle(DWORD perm);

    inline bool HasPerm(const DWORD perm) {
        return m_perms & perm;
    };

    bool SuspendProc();
    bool ResumeProc();
    bool ReadProcMem(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesRead);
    bool WriteProcMem(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesWritten);

    uintptr_t PatternGetAddr(std::string pat_str);
    bool Terminate();
    bool GetPID();
    bool SetDebugPrivilege(const bool enabled);
    bool GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName);

    DWORD m_pID = 0;
    HANDLE m_handle = NULL;
    uintptr_t m_baseAddr = 0;
    DWORD m_baseSize = 0;

private:
    std::string m_procName = "";

    pfnNtSuspendProcess NtSuspendProcess = NULL;
    pfnNtSuspendProcess NtResumeProcess = NULL;
    pfnNtTerminateProcess NtTerminateProcess = NULL;
    pfnNtOpenProcess NtOpenProcess = NULL;
    pfnNtReadVirtualMemory NtReadVirtualMemory = NULL;
    pfnNtWriteVirtualMemory NtWriteVirtualMemory = NULL;

    bool m_isSuspended = false;
    DWORD m_perms = 0;

};

