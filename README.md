It's a simple _external process_ management library that I used in my game cheat. It utilizes API functions only from the ntdll.dll for stealth.

## Features

- Suspend/Resume Process
- Terminate Process
- Read/Write Memory
- Handle Permission Management
- Fast Pattern Scanning (Boyer-Moore)


## Example Usage

```cpp
void SetFPSLimit(const int fps) {
    try {
        using namespace ProcMem;

        Process pr = Process("test.exe");

        pr.OpenHandle(PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);

        pr.Suspend();
        auto addr = pr.PatternGetAddr("E9 ?? 00 00 00 E8 ?? ?? ?? ?? 48 8B C8 44 89 ?? 24 28 ?? ?? ?? ?? ?? ?? ?? ?? 0F 28 D7 BA 13 00 00 00 E8 ?? ?? ?? ??");
        int32_t offset = 0;
        SIZE_T bytesread = 0;
        pr.ReadMemory(addr - 4, &offset, sizeof(offset), bytesread);

        int oldfps = 0;
        pr.ReadMemory(addr + offset, &oldfps, sizeof(oldfps), bytesread);
        pr.Resume();

        if (oldfps != fps) {
            if (pr.WriteMemory(addr + offset, &fps, sizeof(fps), bytesread))
                cout << "[+] FPS limit has been removed..." << endl;
        }
    }
    catch(const std::exception& e){
        std::cout << e.what() << std::endl;
    }
}
```
