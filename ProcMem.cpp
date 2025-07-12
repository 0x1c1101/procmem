#include "ProcMem.hpp"
#include <vector>
#include <string>
#include <sstream>
#include <tlhelp32.h>

Memory_::Memory_(std::string arg_procName)
{
    m_procName = arg_procName;

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll)
    {
        std::cout << "[!] Failed to get ntdll.dll module.\n";
        return;
    }

    NtSuspendProcess = (pfnNtSuspendProcess)GetProcAddress(hNtDll, "NtSuspendProcess");
    if (!NtSuspendProcess)
    {
        std::cout << "[!] Failed to get NtSuspendProcess.\n";
        return;
    }

    NtResumeProcess = (pfnNtResumeProcess)GetProcAddress(hNtDll, "NtResumeProcess");
    if (!NtResumeProcess)
    {
        std::cout << "[!] Failed to get NtResumeProcess.\n";
        return;
    }

    NtTerminateProcess = (pfnNtTerminateProcess)GetProcAddress(hNtDll, "NtTerminateProcess");
    if (!NtTerminateProcess)
    {
        std::cout << "[!] Failed to get NtTerminateProcess.\n";
        return;
    }

    NtOpenProcess = (pfnNtOpenProcess)GetProcAddress(hNtDll, "NtOpenProcess");
    if (!NtOpenProcess)
    {
        std::cout << "[!] Failed to get NtOpenProcess.\n";
        return;
    }

    NtReadVirtualMemory = (pfnNtReadVirtualMemory)GetProcAddress(hNtDll, "NtReadVirtualMemory");
    if (!NtReadVirtualMemory)
    {
        std::cout << "[!] Failed to get NtReadVirtualMemory.\n";
        return;
    }

    NtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtDll, "NtWriteVirtualMemory");
    if (!NtWriteVirtualMemory)
    {
        std::cout << "[!] Failed to get NtWriteVirtualMemory.\n";
        return;
    }

    SetDebugPrivilege(true);
}

Memory_::~Memory_()
{
    if (m_isSuspended)
        ResumeProc();

    SetDebugPrivilege(false);

    ResetProc();
}

void Memory_::ResetProc()
{
    m_baseAddr = 0;
    m_baseSize = 0;
    m_pID = 0;
    m_perms = 0;

    if (m_handle)
    {
        CloseHandle(m_handle);
        m_handle = NULL;
    }

}

bool Memory_::OpenHandle(DWORD perm)
{
    if (m_pID == 0) {
        if (!GetPID())
        {
            std::cout << "[-] Couldn't get the PID\n";
            return false;
        }
    }

    if (m_handle)
    {
        CloseHandle(m_handle);
        m_handle = NULL;
    }

    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)(uintptr_t)m_pID;
    cid.UniqueThread = 0;

    OBJECT_ATTRIBUTES objAttr = { 0 };
    objAttr.Length = sizeof(objAttr);

    NtOpenProcess(&m_handle, perm, &objAttr, &cid);


    if (!m_handle) {
        std::wcout << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return false;
    }

    m_perms = perm;
    return true;
}

bool Memory_::SuspendProc()
{
    if (!m_handle || !HasPerm(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION)) {
        if (!OpenHandle(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION))
            return false;
    }

    LONG status = NtSuspendProcess(m_handle);
    if (status != 0)
    {
        std::cout << "[-] Failed to suspend process. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    std::cout << "[+] Process " << m_procName << " suspended successfully.\n";
    m_isSuspended = true;
    return true;
}

bool Memory_::ResumeProc()
{
    if (!m_handle || !HasPerm(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION)) {
        if (!OpenHandle(PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION))
            return false;

    }

    LONG status = NtResumeProcess(m_handle);
    if (status != 0)
    {
        std::cout << "[-] Failed to resume process. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    std::cout << "[+] Process " << m_procName << " resumed successfully.\n";
    m_isSuspended = false;
    return true;
}

bool Memory_::ReadProcMem(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T& bytesRead)
{
    if (!m_handle || !HasPerm(PROCESS_VM_READ)) {
        if (!OpenHandle(PROCESS_VM_READ))
            return false;
    }

    if (!m_handle)
        return false;


    // No need unless PAGE_NOACCESS
    // PROCESS_VM_OPERATION is required

    /*
    DWORD oldprotect;
    DWORD temp;
    
    if (!VirtualProtectEx(m_handle, (LPVOID)vAddr, size, PAGE_READONLY, &oldprotect)) {
        std::cout << "[-] ReadProcMem failed: VirtualProtectEx\n";
        return false;
    }
    */

    NTSTATUS status = NtReadVirtualMemory (m_handle, (LPVOID)vAddr, buffer, (ULONG)size, (PULONG)& bytesRead);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] ReadProcMem failed: NtReadVirtualMemory. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    /*
    if (!VirtualProtectEx(m_handle, (LPVOID)vAddr, size, oldprotect, &temp)) {
        std::cout << "[-] ReadProcMem failed: VirtualProtectEx (restore)\n";
        return false;
    }
    */

    return true;
}

bool Memory_::WriteProcMem(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T& bytesWritten)
{
    if (!m_handle || !HasPerm(PROCESS_VM_WRITE)) {
        if (!OpenHandle(PROCESS_VM_WRITE))
            return false;
    }

    if (!m_handle)
        return false;

    NTSTATUS status = NtWriteVirtualMemory(m_handle, (LPVOID)vAddr, buffer, (ULONG)size, (PULONG)&bytesWritten);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] WriteProcMem failed: NtWriteVirtualMemory. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}

uintptr_t Memory_::PatternGetAddr(std::string pat_str)
{
    if (!m_handle || !m_pID) {
        std::cout << "[-] Failed to get pattern. Handle or the PID is NULL.\n";
        return 0;
    }

    std::istringstream iss(pat_str);
    std::string byteStr;

    std::string mask = "";
    std::vector<BYTE> pattern;
    while (iss >> byteStr) {
        if (byteStr == "?" || byteStr == "??") {
            pattern.push_back(0x00);  // Wildcard placeholder
            mask += '?';
        }
        else {
            pattern.push_back(static_cast<BYTE>(std::stoul(byteStr, nullptr, 16)));
            mask += 'x';
        }
    }

    if (pattern.size() < 4 || pattern.size() != mask.length()) {
        std::cout << "[-] Pattern is too short.\n";
        return 0;
    }

    if (!m_baseAddr) {
        std::wstring processName(m_procName.begin(), m_procName.end());
        if (!GetModuleBaseAddress(m_pID, processName.c_str())) {
            std::cout << "[-] Could not get the Module Base Address.\n";
            return 0;
        }
    }


    const size_t pattern_size = pattern.size();
    BYTE buffer[4096];

    uintptr_t currChunk = m_baseAddr;

    while (currChunk < m_baseAddr + m_baseSize)
    {
        SIZE_T bytesRead = 0;
        if (!ReadProcMem(currChunk, &buffer, sizeof(buffer), bytesRead) || !bytesRead) {
            std::cout << "[-] Failed to read memory at address " << currChunk << ".\n";
            return 0;
        }
        
        int j = 1;
        for (int i = 0; i < bytesRead - pattern_size; i++) {

            if (buffer[i] == pattern[0]) {

                
                for (; j < pattern_size; j++) {
                    if (mask[j] == '?')
                        continue;

                    if (buffer[i + j] != pattern[j])
                        break;
                }

                if (j == pattern_size)
                {
                    uintptr_t addr = currChunk + i;

                    std::cout << "[+] Found pattern at " << std::hex << addr << std::dec << ".\n";
                    return addr;

                }

                j = 1;
            }


        }

        currChunk += bytesRead;

    }


    std::cout << "[-] Could not find the pattern.\n";
    return 0;
}

bool Memory_::Terminate()
{
    if (!m_handle || !HasPerm(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION)) {
        if (!OpenHandle(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION))
            return false;
    }
    if (!m_handle)
        return false;

    auto result = NtTerminateProcess(m_handle, 0);
    if (NT_SUCCESS(result))
    {
        std::cout << "[+] Process " << m_procName << " has been terminated successfully.\n";
        ResetProc();
    }

    return result;
}

bool Memory_::GetPID()
{
    if (m_procName.empty())
        return false;

    std::wstring processName(m_procName.begin(), m_procName.end());
    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (!_wcsicmp(processEntry.szExeFile, processName.c_str())) {
                CloseHandle(snapshot);
                m_pID = processEntry.th32ProcessID;
                return true;
            }
        } while (Process32Next(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return false; // Not found
}

bool Memory_::SetDebugPrivilege(const bool enabled)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;

    tp.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    CloseHandle(hToken);

    return result && GetLastError() == ERROR_SUCCESS;
}

bool Memory_::GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    MODULEENTRY32 modEntry = { sizeof(MODULEENTRY32) };

    if (Module32First(hSnapshot, &modEntry)) {
        do {
            if (!_wcsicmp(modEntry.szModule, moduleName)) {
                CloseHandle(hSnapshot);
                m_baseAddr = (uintptr_t)modEntry.modBaseAddr;
                m_baseSize = modEntry.modBaseSize;
                return true;
            }
        } while (Module32Next(hSnapshot, &modEntry));
    }

    CloseHandle(hSnapshot);
    return false;
}