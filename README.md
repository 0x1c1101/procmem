It's a simple _external process_ memory management module that I used in my game cheat. It gets API functions from the ntdll.dll in case the original ones are hooked.

## Features

- Suspend/Resume Process
- Read/Write Memory
- Fast Pattern Scanning
- Terminate Process

## Example Usage

```cpp
void SetFPSLimit(int fps) {
  
  Memory_ mem = Memory_("test.exe");
  
  mem.OpenHandle(PROCESS_VM_READ | PROCESS_SUSPEND_RESUME);
  
  mem.SuspendProc();
  auto addr = mem.PatternGetAddr("<insert pattern here>");
  int32_t offset = 0;
  SIZE_T bytesread = 0;
  mem.ReadProcMem(addr - 4, &offset, sizeof(offset), bytesread);
  
  int oldfps = 0;
  mem.ReadProcMem(addr + offset, &oldfps, sizeof(oldfps), bytesread);
  mem.ResumeProc();
  
  if (oldfps != fps) {
  	if (mem.WriteProcMem(addr + offset, &fps, sizeof(fps), bytesread)) {
  		cout << "[+] FPS limit has been removed..." << endl;
  	}
  }
}
```
