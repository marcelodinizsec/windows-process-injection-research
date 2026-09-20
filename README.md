# Windows Process Injection — Research & Study Lab

> A personal research repository documenting my study of process injection
> techniques, shellcode execution patterns and Windows internals as applied
> to malware analysis, reverse engineering and detection engineering.

---

## Purpose

This repository serves as a structured study lab for understanding how
process injection techniques work at a low level — covering the Windows
API layer, the Native API (ntdll), memory management and execution
primitives.

The goal is not to build offensive tools, but to deeply understand the
mechanics behind techniques commonly found in real-world malware, so they
can be identified, analyzed and detected more effectively.

---

## Audience

- Malware analysts and reverse engineers
- Security researchers studying Windows internals
- Detection engineers building EDR/AV signatures and behavioral rules
- Red teamers learning the fundamentals behind the tools they use

---

## Repository Structure

windows-process-injection-research/
│
├── 01-shellcode-basics/
│ ├── shellcode_injection_demo.cpp # VirtualAlloc + memcpy + exec
│ └── README.md
│
├── 02-dll-injection/
│ ├── classic_dll_injection.cpp # CreateRemoteThread + LoadLibrary
│ └── README.md
│
├── 03-process-hollowing/
│ ├── process_hollowing.cpp # ZwUnmapViewOfSection + WriteProcessMemory
│ └── README.md
│
├── 04-apc-injection/
│ ├── apc_injection.cpp # QueueUserAPC
│ └── README.md
│
├── 05-thread-hijacking/
│ ├── thread_hijacking.cpp # SuspendThread + SetThreadContext
│ └── README.md
│
├── 06-ntdll-native-api/
│ ├── process_enum_ntquery.cpp # NtQuerySystemInformation
│ └── README.md
│
├── references/
│ └── REFERENCES.md
│
└── README.md


---

## Techniques Covered

| # | Technique | Key APIs | Status |
|---|-----------|----------|--------|
| 01 | Shellcode Injection (basic) | `VirtualAlloc`, `VirtualProtect`, `memcpy` | ✅ Done |
| 02 | Classic DLL Injection | `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` | 🔄 In progress |
| 03 | Process Hollowing | `CreateProcess`, `ZwUnmapViewOfSection`, `WriteProcessMemory`, `SetThreadContext` | 📋 Planned |
| 04 | APC Injection | `OpenThread`, `QueueUserAPC`, `SleepEx` | 📋 Planned |
| 05 | Thread Hijacking | `SuspendThread`, `GetThreadContext`, `SetThreadContext` | 📋 Planned |
| 06 | Native API Process Enumeration | `NtQuerySystemInformation` | ✅ Done |

---

## Key Concepts Explored

- **Windows memory model** — virtual address space, page permissions, W^X (DEP)
- **VirtualAlloc / VirtualProtect** — RW → RX permission separation
- **Native API vs Win32 API** — bypassing high-level API monitoring via ntdll
- **Position-Independent Code (PIC)** — why shellcode must be self-contained
- **Detection perspective** — how each technique is detected by AV/EDR solutions
  (behavioral heuristics, API hooks, memory scanning, ETW events)

---

## Detection & Defense Notes

Each technique folder contains a `README.md` that discusses:

- What the technique looks like from a **defender's perspective**
- Which **Windows events / ETW providers** are triggered
- Common **YARA / Sigma rules** that detect the pattern
- How **AV/EDR hooks** intercept the relevant API calls
- **MITRE ATT&CK** mapping

Understanding how these techniques are detected is as important as
understanding how they work.

---

## MITRE ATT&CK Coverage

| Technique | ATT&CK ID |
|-----------|-----------|
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) |
| Process Hollowing | [T1055.012](https://attack.mitre.org/techniques/T1055/012/) |
| DLL Injection | [T1055.001](https://attack.mitre.org/techniques/T1055/001/) |
| Thread Execution Hijacking | [T1055.003](https://attack.mitre.org/techniques/T1055/003/) |
| Asynchronous Procedure Call | [T1055.004](https://attack.mitre.org/techniques/T1055/004/) |

---

## Build Environment

- **OS:** Windows 10 / 11 x64
- **Compiler:** MSVC (Visual Studio 2022) or MinGW-w64
- **SDK:** Windows SDK 10.0+
- **Standard:** C++17

```bash
# MSVC
cl /EHsc /std:c++17 shellcode_injection_demo.cpp

# MinGW
g++ -std=c++17 -o demo shellcode_injection_demo.cpp -lntdll
```

> ⚠️ These examples should be compiled and run only inside an isolated
> virtual machine. Never run unknown or modified code on a production system.

---

## Disclaimer

This repository is intended **strictly for educational and research purposes**.
All code is written to understand how injection techniques work internally —
with the explicit goal of improving detection, analysis and defensive
capabilities.

The author is a cybersecurity researcher specializing in malware analysis
and reverse engineering. Nothing in this repository is intended to facilitate
unauthorized access to systems or any form of malicious activity.

**Use responsibly. Test only in environments you own or have explicit
permission to test.**

---

## References

- [Windows Internals, 7th Edition — Russinovich, Ionescu, Solomon](https://learn.microsoft.com/en-us/sysinternals/)
- [MSDN — VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)
- [MSDN — NtQuerySystemInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)
- [MITRE ATT&CK — T1055 Process Injection](https://attack.mitre.org/techniques/T1055/)
- [Malware Unicorn Workshops](https://malwareunicorn.org/)
- [VX Underground — Malware Source Code Archive](https://vx-underground.org/)
- [Sektor7 — Malware Development Courses](https://institute.sektor7.net/)

---

## Author

**Marcelo Diniz**
Senior Cybersecurity Researcher | Malware Analysis | Reverse Engineering | Detection Engineering

- GitHub: [github.com/marcelodinizsec](https://github.com/marcelodinizsec)
- LinkedIn: [linkedin.com/in/marcelo-diniz-7822767](https://linkedin.com/in/marcelo-diniz-7822767)
