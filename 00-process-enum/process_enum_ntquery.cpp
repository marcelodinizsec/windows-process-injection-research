/*
 * process_enum_ntquery.cpp
 *
 * Educational example: enumerating running processes on Windows using
 * NtQuerySystemInformation from the Native API (ntdll.dll) directly,
 * bypassing the higher-level Win32 API (CreateToolhelp32Snapshot,
 * EnumProcesses, etc.).
 *
 * Why this matters in security research:
 *   - Malware and rootkits use this pattern to enumerate processes without
 *     triggering Win32-level API hooks placed by AV/EDR agents.
 *   - DKOM (Direct Kernel Object Manipulation) rootkits hide processes by
 *     unlinking entries from the kernel list that this API reads from.
 *   - Comparing results between this call and Win32 equivalents is a
 *     classic technique for detecting hidden processes during DFIR.
 *
 * Compile: cl /EHsc process_enum_ntquery.cpp ntdll.lib
 * Tested on: Windows 10 / 11 x64, MSVC
 */

#include <windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

// ---------------------------------------------------------------------------
// NtQuerySystemInformation — function pointer typedef
//
// This function is exported by ntdll.dll but is not officially documented
// as a stable Win32 API. We resolve it at runtime via GetProcAddress to
// avoid a hard import-table entry and to mirror how real-world code
// (both malware and security tools) typically calls it.
//
// Parameters:
//   SystemInformationClass — what kind of information to query
//   SystemInformation      — caller-allocated output buffer
//   SystemInformationLength — size of the buffer in bytes
//   ReturnLength           — receives the required / written size
// ---------------------------------------------------------------------------
typedef NTSTATUS (NTAPI* pNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS,   // information class selector
    PVOID,                      // output buffer
    ULONG,                      // buffer size
    PULONG                      // required size (out)
);

int main() {

    // -----------------------------------------------------------------------
    // Step 1 — Resolve NtQuerySystemInformation from ntdll.dll at runtime.
    //
    // ntdll.dll is always mapped into every Windows process, so
    // GetModuleHandleA never fails here. GetProcAddress walks the DLL's
    // export table to find the function's address.
    // -----------------------------------------------------------------------
    pNtQuerySystemInformation NtQuerySystemInformation =
        (pNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"),
            "NtQuerySystemInformation"
        );

    if (!NtQuerySystemInformation) {
        std::cerr << "[!] Failed to resolve NtQuerySystemInformation\n";
        return 1;
    }

    std::cout << "[*] NtQuerySystemInformation resolved successfully\n";

    // -----------------------------------------------------------------------
    // Step 2 — Probe call to determine the required buffer size.
    //
    // Passing a NULL buffer and size 0 causes the kernel to return
    // STATUS_INFO_LENGTH_MISMATCH, but it also writes the required byte
    // count into the last parameter. This is the standard sizing idiom
    // for this API.
    // -----------------------------------------------------------------------
    ULONG size = 0;
    NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &size);

    std::cout << "[*] Required buffer size: " << size << " byte(s)\n";

    // -----------------------------------------------------------------------
    // Step 3 — Allocate the output buffer and perform the real query.
    // -----------------------------------------------------------------------
    PVOID buffer = malloc(size);
    if (!buffer) {
        std::cerr << "[!] Memory allocation failed\n";
        return 1;
    }

    NTSTATUS status = NtQuerySystemInformation(
        SystemProcessInformation,   // query: list all processes
        buffer,                     // output buffer
        size,                       // buffer size in bytes
        &size                       // actual bytes written (out)
    );

    if (!NT_SUCCESS(status)) {
        // NT_SUCCESS checks bit 31 of the NTSTATUS value (0 = success).
        std::cerr << "[!] NtQuerySystemInformation failed — NTSTATUS: 0x"
                  << std::hex << status << "\n";
        free(buffer);
        return 1;
    }

    std::cout << "[+] Process list retrieved successfully\n\n";

    // -----------------------------------------------------------------------
    // Step 4 — Walk the linked list of SYSTEM_PROCESS_INFORMATION entries.
    //
    // The buffer returned by the kernel is a singly-linked list where each
    // entry is a SYSTEM_PROCESS_INFORMATION struct. Entries are connected
    // via NextEntryOffset — a byte offset from the current entry to the
    // next one. An offset of 0 marks the last entry.
    //
    // Memory layout:
    //   [Entry 0] --NextEntryOffset--> [Entry 1] --NextEntryOffset--> ... --> [Entry N, offset=0]
    // -----------------------------------------------------------------------
    auto* proc = (SYSTEM_PROCESS_INFORMATION*)buffer;

    while (true) {
        // ImageName is a UNICODE_STRING; Buffer can be null for the System
        // Idle process (PID 0), so we guard against a null dereference.
        const wchar_t* imageName = proc->ImageName.Buffer
                                 ? proc->ImageName.Buffer
                                 : L"(no name)";

        std::wcout << L"PID: "   << proc->UniqueProcessId
                   << L" | Name: " << imageName
                   << L"\n";

        // NextEntryOffset == 0 signals the last entry in the list.
        if (proc->NextEntryOffset == 0)
            break;

        // Advance to the next entry by adding the byte offset to the
        // current pointer. The cast to BYTE* ensures pointer arithmetic
        // works in single-byte increments.
        proc = (SYSTEM_PROCESS_INFORMATION*)((BYTE*)proc + proc->NextEntryOffset);
    }

    // -----------------------------------------------------------------------
    // Step 5 — Release resources.
    // -----------------------------------------------------------------------
    free(buffer);
    std::cout << "\n[+] Done\n";

    return 0;
}