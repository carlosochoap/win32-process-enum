 # win32-process-enum

  Process enumerator using the Win32 Tool Help Library. Educational project for learning malware reconnaissance
  techniques.

  ## What it does

  1. **Enumerates all running processes** using `CreateToolhelp32Snapshot` + `Process32First/Next`
  2. **Displays process details**: PID, PPID (parent), thread count, executable name
  3. **Detects security tools**: antivirus, debuggers, VM tools, sandbox software
  4. **Enumerates loaded modules (DLLs)** of detected processes using `Module32First/Next`
  5. **Flags suspicious DLLs** that indicate analysis environments (Sandboxie, hooking DLLs, etc.)

  ## Techniques learned

  | Concept | Win32 API | Malware use case |
  |---|---|---|
  | Process snapshot | `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` | Reconnaissance: know what's running |
  | Process iteration | `Process32FirstW` / `Process32NextW` | Find AV to evade, or targets to inject |
  | Parent PID (PPID) | `PROCESSENTRY32W.th32ParentProcessID` | Detect suspicious parent-child chains |
  | Module enumeration | `TH32CS_SNAPMODULE` + `Module32FirstW/NextW` | Find base addresses, detect hooks |
  | Suspicious DLL detection | Compare loaded DLLs against known list | Detect sandboxes, debuggers, AV hooks |

  ## Build

  Open `win32-process-enum.sln` in Visual Studio and build (x64 Debug).

  Or with MSVC command line:
  cl main.c /Fe:process-enum.exe

  ## Notes

  - Module enumeration requires appropriate permissions. Protected processes (SYSTEM, csrss.exe) return
  `ERROR_ACCESS_DENIED (5)`. Run as Administrator to access more processes.
  - This is for **educational purposes only**. Run only on your own machine or VM.

  ## Project 3 of 10

  Part of a progressive learning series: C + malware techniques for Windows.
