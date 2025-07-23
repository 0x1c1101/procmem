#include "ProcMem.hpp"
#include <vector>
#include <string>
#include <sstream>

using namespace ProcMem;

Process::Process(std::string arg_procName) : m_procName(std::move(arg_procName))
{
    if (!SetDebugPrivilege(true))
        throw std::exception("[-] Could not set the debug privilege.");
}

Process::Process(DWORD arg_pID) : m_pID(arg_pID)
{
    if (!SetDebugPrivilege(true))
        throw std::exception("[-] Could not set the debug privilege.");
}

Process::~Process()
{
    if (m_isSuspended)
        Resume();

    SetDebugPrivilege(false);

    Reset();
}

void Process::Reset()
{
    m_pID = 0;
    m_perms = 0;

    if (m_handle)
    {
        CloseHandle(m_handle);
        m_handle = NULL;
    }

    m_modules.clear();
}

void Process::OpenHandle(DWORD perm)
{
    if (!m_pID && !GetPID())
        throw std::exception("OpenHandle(): Couldn't get the PID");

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


    if (!m_handle)
        throw std::exception("OpenHandle(): NtOpenProcess failed ");

    m_perms = perm;

}

bool Process::Suspend()
{
    if (!m_handle || !HasPerm(PROCESS_SUSPEND_RESUME) || !HasPerm(PROCESS_QUERY_INFORMATION))
        OpenHandle(m_perms | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION);

    auto status = NtSuspendProcess(m_handle);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] Failed to suspend process. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    std::cout << "[+] Process " << m_procName << " suspended successfully.\n";
    m_isSuspended = true;
    return true;
}

bool Process::Resume()
{
    if (!m_handle || !HasPerm(PROCESS_SUSPEND_RESUME) || !HasPerm(PROCESS_QUERY_INFORMATION))
        OpenHandle(m_perms | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION);

    auto status = NtResumeProcess(m_handle);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] Failed to resume process. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }
    
    std::cout << "[+] Process " << m_procName << " resumed successfully.\n";
    m_isSuspended = false;
    return true;
}

bool Process::ReadMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T& bytesRead)
{
    if (!m_handle || !HasPerm(PROCESS_VM_READ))
        OpenHandle(m_perms | PROCESS_VM_READ);

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

bool Process::WriteMemory(uintptr_t vAddr, LPVOID buffer, SIZE_T size, SIZE_T& bytesWritten)
{
    if (!m_handle || !HasPerm(PROCESS_VM_WRITE))
        OpenHandle(m_perms | PROCESS_VM_WRITE);

    NTSTATUS status = NtWriteVirtualMemory(m_handle, (LPVOID)vAddr, buffer, (ULONG)size, (PULONG)&bytesWritten);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] WriteProcMem failed: NtWriteVirtualMemory. NTSTATUS: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}

uintptr_t Process::PatternGetAddr(std::string pat_str, std::string module_name)
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

    auto moduleInfo = GetModuleInfo((module_name.empty() ? m_procName : module_name));
    if (!moduleInfo) {
        std::cout << "[-] Could not get the Module Information.\n";
        return 0;
    }

    uintptr_t baseAddr = moduleInfo->m_baseAddress;
    DWORD baseSize = moduleInfo->m_size;

    const size_t pattern_size = pattern.size();
    BYTE buffer[4096];
    uintptr_t currChunk = baseAddr;

    // Boyer-Moore preprocessing
    std::unordered_map<BYTE, size_t> badCharacterShift;
    for (size_t i = 0; i < pattern_size - 1; ++i) {
        badCharacterShift[pattern[i]] = pattern_size - 1 - i;
    }

    while (currChunk < baseAddr + baseSize) {
        SIZE_T bytesRead = 0;
        if (!ReadMemory(currChunk, &buffer, sizeof(buffer), bytesRead) || !bytesRead) {
            std::cout << "[-] Failed to read memory at address " << currChunk << ".\n";
            return 0;
        }

        size_t i = 0;
        while (i <= bytesRead - pattern_size) {
            size_t j = pattern_size - 1;

            while (j != SIZE_MAX && buffer[i + j] == pattern[j] || mask[j] == '?') {
                if (j == 0) {
                    uintptr_t addr = currChunk + i;
                    std::cout << "[+] Found pattern at " << std::hex << addr << std::dec << ".\n";
                    return addr;
                }
                --j;
            }

            // If mismatch happens, we use the bad character shift heuristic
            if (j != SIZE_MAX) {
                auto shift = badCharacterShift.find(buffer[i + j]);
                i += shift != badCharacterShift.end() ? shift->second : pattern_size;
            }
            else
                i += pattern_size;
        }

        currChunk += bytesRead;
    }


    std::cout << "[-] Could not find the pattern.\n";
    return 0;
}

bool Process::Terminate()
{
    if (!m_handle || !HasPerm(PROCESS_TERMINATE) || !HasPerm(PROCESS_QUERY_INFORMATION))
        OpenHandle(m_perms | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION);

    auto result = NtTerminateProcess(m_handle, 0);
    if (NT_SUCCESS(result))
    {
        std::cout << "[+] Process " << m_procName << " has been terminated successfully.\n";
        Reset();
    }
    return result;
}

bool Process::GetPID()
{
    if (m_procName.empty())
        throw std::exception("GetPID(): Process Name is empty.");

    std::wstring process_name = std::wstring(m_procName.begin(), m_procName.end());

    PVOID buffer = NULL;
    ULONG bufSize = 0;

    NTSTATUS status = -1;
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, 0, 0, &bufSize);

    //auto status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, 0, 0, &bufSize);
    if (!bufSize)
    {
        std::string error = "GetPID(): NtQuerySystemInformation error. " + std::to_string(status);
        throw std::exception(error.c_str());
    }


    if (buffer = VirtualAlloc(0, bufSize, MEM_COMMIT, PAGE_READWRITE)) {
        SYSTEM_PROCESS_INFORMATION* sysproc_info = (SYSTEM_PROCESS_INFORMATION*)buffer;
        if (NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation, buffer, bufSize, &bufSize))) {

            while (sysproc_info) {

                if (sysproc_info->ImageName.Length > 0 && sysproc_info->ImageName.Buffer != nullptr) {
                    auto imageName = std::wstring(
                        sysproc_info->ImageName.Buffer,
                        sysproc_info->ImageName.Length / sizeof(WCHAR)
                    );

                    //std::wcout << L"[" << imageName << L"]" << std::endl;

                    if (lstrcmpiW(process_name.c_str(), imageName.c_str()) == 0) {
                        m_pID = (DWORD)sysproc_info->UniqueProcessId;
                        std::cout << "[+] Found PID: " << m_pID << std::endl;
                        return true;
                    }
                }

                if (!sysproc_info->NextEntryOffset)
                    break;

                sysproc_info = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)sysproc_info + sysproc_info->NextEntryOffset);
            }

        }

        VirtualFree(buffer, 0, MEM_RELEASE);
    }

    return false; // Not found
}

bool Process::SetDebugPrivilege(const bool enabled)
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

CUSTOM_MODULEINFO* Process::GetModuleInfo(const std::string module_name) {
    if (m_modules.empty())
        LoadModules();

    if (m_modules.find(module_name) != m_modules.end())
        return &m_modules[module_name];

    return NULL;

}


bool Process::LoadModules()
{
    if (!m_handle || !HasPerm(PROCESS_QUERY_INFORMATION) || !HasPerm(PROCESS_VM_READ))
        OpenHandle(m_perms | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ);


    PROCESS_BASIC_INFORMATION pbi = {};

    NTSTATUS status = NtQueryInformationProcess(
        m_handle,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        nullptr
    );

    if (!NT_SUCCESS(status)){
        std::string error = "LoadModules(): Could not get the PBI. " + std::to_string(status);
        throw std::exception(error.c_str());
    }

    SIZE_T bytesRead = 0; 
    PEB peb = {};
    if (!ReadMemory((uintptr_t)pbi.PebBaseAddress, &peb, sizeof(peb), bytesRead) || !bytesRead)
        throw std::exception("LoadModules(): Could not get the PEB .");

    PEB_LDR_DATA ldr = {};
    if (!ReadMemory((uintptr_t)peb.Ldr, &ldr, sizeof(ldr), bytesRead) || !bytesRead)
        throw std::exception("LoadModules(): Failed to read PEB_LDR_DATA.");

    LIST_ENTRY* head = reinterpret_cast<LIST_ENTRY*>(ldr.Reserved2[1]); // InLoadOrderModuleList
    LIST_ENTRY* current = head;

    do {
        LDR_DATA_TABLE_ENTRY ldrEntry = {};
        if (!ReadMemory((uintptr_t)current, &ldrEntry, sizeof(ldrEntry), bytesRead) || !bytesRead) {
            break;
        }

        std::string baseName;
        UNICODE_STRING* baseDLLName = reinterpret_cast<UNICODE_STRING*>(&ldrEntry.Reserved4[0]);
        if (baseDLLName->Buffer && baseDLLName->Length > 0) {

            std::wstring buffer(baseDLLName->Length / sizeof(WCHAR), L'\0');
            if (ReadMemory((uintptr_t)baseDLLName->Buffer, (LPVOID)buffer.data(), baseDLLName->Length, bytesRead) && bytesRead) {
                baseName = std::string(buffer.begin(), buffer.end());
            }
        }

        if (!baseName.empty()) {
            CUSTOM_MODULEINFO modInfo = {};
            modInfo.m_baseAddress = (uintptr_t)ldrEntry.DllBase;
            modInfo.m_size = (ULONG)ldrEntry.Reserved3[1];
            modInfo.m_entryPoint = (uintptr_t)ldrEntry.Reserved3[0];
            //std::cout << baseName << std::endl;
            //std::cout << modInfo.m_baseAddress << std::endl;
            m_modules[baseName] = modInfo;
        }
        
        current = reinterpret_cast<LIST_ENTRY*>(ldrEntry.Reserved1[0]); // Points to Flink
    } while (current != head && current != nullptr);

    if (m_modules.size() > 0)
        return true;

    return false;
}
