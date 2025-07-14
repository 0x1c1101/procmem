#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSTATUS NTAPI NtSuspendProcess(HANDLE ProcessHandle);
extern "C" NTSTATUS NTAPI NtResumeProcess(HANDLE ProcessHandle);
extern "C" NTSTATUS NTAPI NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
extern "C" NTSTATUS NTAPI NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, CLIENT_ID* ClientId);
extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

namespace ProcMem {

class Process {
public:
    Process(std::string arg_procName);
    ~Process();

    bool OpenHandle(DWORD perm);
    void Reset();

    inline bool HasPerm(const DWORD perm) {
        return m_perms & perm;
    };

    bool Suspend();
    bool Resume();
    bool Terminate();
    bool ReadMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesRead);
    bool WriteMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesWritten);
    uintptr_t PatternGetAddr(std::string pat_str);
    bool GetPID();
    bool SetDebugPrivilege(const bool enabled);
    bool GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName);

    DWORD m_pID = 0;
    HANDLE m_handle = NULL;
    uintptr_t m_baseAddr = 0;
    DWORD m_baseSize = 0;

private:
    std::string m_procName = "";
    bool m_isSuspended = false;
    DWORD m_perms = 0;

};
}