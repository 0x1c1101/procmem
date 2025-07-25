It's a simple _external process_ management library that I used in my game cheat. It utilizes API functions only from the `ntdll.dll` for stealth. You can use the `GetProcAddress()` if you want to load functions dynamically and hide them from the Import Address Table.

## Features

- Suspend/Resume Process
- Terminate Process
- Read/Write Memory
- Permission Management
- Fast Pattern Scanning (Boyer-Moore)
- Restore when out of scope


## Example Usage

```cpp
void SetFPSLimit(const int newLimit) {
    try {
        using namespace ProcMem;

	// You can directly use PID -> Process(1219)
        Process pr = Process("test.exe");

        pr.OpenHandle(PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);

        pr.Suspend();
        auto addr = pr.PatternGetAddr("E9 ?? 00 00 00 E8 ?? ?? ?? ?? 48 8B C8 44 89 ?? 24 28 ?? ?? ?? ?? ?? ?? ?? ?? 0F 28 D7 BA 13 00 00 00 E8 ?? ?? ?? ??");
        int32_t offset = 0;
        SIZE_T bytesread = 0;
        pr.ReadMemory(addr - 4, &offset, sizeof(offset), bytesread);

        int currentFPS = 0;
        pr.ReadMemory(addr + offset, &currentFPS, sizeof(currentFPS), bytesread);
        pr.Resume();

        if (currentFPS != newLimit) {
            if (pr.WriteMemory(addr + offset, &newLimit, sizeof(newLimit), bytesread))
                cout << "[+] FPS limit has been removed..." << endl;
        }
    }
    catch(const std::exception& e){
        std::cout << e.what() << std::endl;
    }
}
```
