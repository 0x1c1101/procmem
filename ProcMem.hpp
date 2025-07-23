#pragma once

#include <windows.h>
#include <winternl.h>
#include <unordered_map>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

namespace ProcMem {

    extern "C" NTSTATUS NTAPI NtSuspendProcess(HANDLE);
    extern "C" NTSTATUS NTAPI NtResumeProcess(HANDLE);
    extern "C" NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
    extern "C" NTSTATUS NTAPI NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
    extern "C" NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
    extern "C" NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);

    typedef struct _CUSTOM_MODULEINFO {
        uintptr_t m_baseAddress;
        ULONG  m_size;
        uintptr_t m_entryPoint;
    } CUSTOM_MODULEINFO;

class Process {
public:
    Process(std::string arg_procName);
    Process(DWORD arg_pID);
    ~Process();

    void OpenHandle(DWORD perm);
    void Reset();

    inline bool HasPerm(const DWORD perm) {
        return m_perms & perm;
    };

    bool Suspend();
    bool Resume();
    bool Terminate();
    bool ReadMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesRead);
    bool WriteMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T &bytesWritten);
    uintptr_t PatternGetAddr(std::string pat_str, std::string module_name = "");
    bool GetPID();
    bool SetDebugPrivilege(const bool enabled);
    bool LoadModules();
    CUSTOM_MODULEINFO* GetModuleInfo(const std::string module_name);
    DWORD m_pID = 0;
    HANDLE m_handle = NULL;

private:
    std::string m_procName = "";
    bool m_isSuspended = false;
    DWORD m_perms = 0;
    std::unordered_map<std::string, CUSTOM_MODULEINFO> m_modules;


};
}
