/*
 * shellcode_injection_demo.cpp
 *
 * Educational example: demonstrating the classic shellcode injection pattern
 * using Windows VirtualAlloc / memcpy / function-pointer execution.
 *
 * The payload used here consists entirely of NOP instructions (0x90),
 * which perform no operation and exist only to illustrate the technique.
 * No real shellcode is present in this example.
 *
 * Typical use in malware analysis / red-team research:
 *   1. Allocate a RW region  → write the payload
 *   2. Change protection to RX (remove write permission)
 *   3. Cast to function pointer and call
 *
 * Compile: cl /EHsc shellcode_injection_demo.cpp
 * Tested on: Windows 10/11 x64, MSVC
 */

#include <iostream>
#include <windows.h>

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

// Placeholder payload: four NOP slides — safe, inert, executes and returns.
// In a real scenario this buffer would contain position-independent code (PIC)
// compiled with a tool such as msfvenom, donut, or a custom shellcode encoder.
static const unsigned char payload[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP NOP NOP NOP
    0xC3                      // RET  — clean return to caller
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void printLastError(const char* context) {
    std::cerr << "[!] " << context
              << " failed — GetLastError: " << GetLastError() << "\n";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main() {

    const SIZE_T payloadSize = sizeof(payload);

    std::cout << "[*] Shellcode injection demo (educational)\n";
    std::cout << "[*] Payload size: " << payloadSize << " byte(s)\n";

    // ------------------------------------------------------------------
    // Step 1 — Allocate a RW (read/write) region.
    //          We intentionally do NOT request EXECUTE permission here.
    //          Write and execute permissions should never coexist on the
    //          same page in production code (W^X / DEP principle).
    // ------------------------------------------------------------------
    void* region = VirtualAlloc(
        NULL,
        payloadSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE              // RW only — no execute yet
    );

    if (!region) {
        printLastError("VirtualAlloc(PAGE_READWRITE)");
        return 1;
    }

    std::cout << "[+] Memory allocated at: " << region << "\n";

    // ------------------------------------------------------------------
    // Step 2 — Copy the payload into the allocated region.
    // ------------------------------------------------------------------
    memcpy(region, payload, payloadSize);
    std::cout << "[+] Payload copied to allocated region\n";

    // ------------------------------------------------------------------
    // Step 3 — Change protection from RW to RX (read/execute).
    //          Removing write access before execution is the correct
    //          approach and mirrors how loaders and real-world implants
    //          behave to avoid triggering W+X heuristics in AV/EDR.
    // ------------------------------------------------------------------
    DWORD oldProtect = 0;
    if (!VirtualProtect(region, payloadSize, PAGE_EXECUTE_READ, &oldProtect)) {
        printLastError("VirtualProtect(PAGE_EXECUTE_READ)");
        VirtualFree(region, 0, MEM_RELEASE);
        return 1;
    }

    std::cout << "[+] Memory protection changed to PAGE_EXECUTE_READ\n";

    // ------------------------------------------------------------------
    // Step 4 — Cast the region pointer to a callable function and invoke.
    //          The payload (NOPs + RET) simply returns immediately.
    // ------------------------------------------------------------------
    using VoidFn = void(*)();
    auto execPayload = reinterpret_cast<VoidFn>(region);

    std::cout << "[*] Transferring execution to payload...\n";
    execPayload();
    std::cout << "[+] Payload returned successfully\n";

    // ------------------------------------------------------------------
    // Step 5 — Release the allocated memory.
    //          Always free resources; in implant research this step is
    //          often skipped (process exit cleans up), but good hygiene
    //          matters in educational code.
    // ------------------------------------------------------------------
    VirtualFree(region, 0, MEM_RELEASE);
    std::cout << "[+] Memory released — done\n";

    return 0;
}