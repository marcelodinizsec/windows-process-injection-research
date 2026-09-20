Demonstrates process enumeration using NtQuerySystemInformation from
ntdll.dll directly, bypassing the Win32 API layer (CreateToolhelp32Snapshot,
EnumProcesses).

Key implementation details:
- Runtime resolution of NtQuerySystemInformation via GetProcAddress
- Two-phase call pattern: probe call for buffer sizing + real query
- Walks the SYSTEM_PROCESS_INFORMATION linked list via NextEntryOffset
- Null guard on ImageName.Buffer for PID 0 (System Idle Process)

Security research context:
- Illustrates why AV/EDR hooks on Win32 APIs can be bypassed at this level
- DKOM rootkits manipulate the same kernel list this API reads from
- Divergence between this output and Win32 results indicates hidden processes