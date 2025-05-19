#include <windows.h>
#include <cassert>

extern "C" {
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif
#include "..\beacon.h"
}

namespace bof {
    namespace mock {
        namespace syscall {
            /**
             * @brief A function to find the first occurrence of a system call instruction in memory.
             *
             * This function searches for a specific system call instruction pattern within the
             * memory block starting at the given address 'addr'. The pattern to search for
             * depends on the target architecture:
             *
             * - On x64, the assembly pattern is: 'syscall; ret;' (0x0f, 0x05, 0xc3).
             * - On x86, the assembly pattern is: 'sysenter; ret;' (0x0f, 0x34, 0xc3).
             *
             * @param addr A pointer to the starting address of the memory block.
             * @return A pointer to the first occurrence of the system call instruction pattern
             *         if found, or NULL if the pattern is not found within the first 32 bytes.
             *
             */

            PBYTE FindSyscallInstruction(PBYTE addr) {
#if _M_X64
                char syscallPattern[] = { '\x0f', '\x05', '\xc3' }; // syscall; ret;
#else
                char syscallPattern[] = { '\x0f', '\x34', '\xc3' }; // sysenter; ret;
#endif
                for (int offset = 0; offset < 32; ++offset) {
                    if (!memcmp(syscallPattern, (char*)addr + offset, sizeof(syscallPattern))) {
                        return addr + offset;
                    }
                }
                return NULL;
            }

            /**
             * @brief Find the system call number in the memory block
             *
             * This function searches for a specific pattern within the memory block starting at the
             * given address 'addr' to identify the system call number. The pattern to search for
             * depends on the target architecture:
             *
             * - On x64, the assembly pattern is: 'mov r10, rcx; mov eax, <syscall num>' (0x4c, 0x8b, 0xd1, 0xb8).
             * - On x86, the assembly pattern is: 'mov eax, <syscall num>' (0xb8).
             *
             * @param addr A pointer to the starting address of the memory block.
             * @return The system call number found in memory following the pattern, or 0 if the
             *         pattern is not found within the first 32 bytes.
             *
             */
            DWORD FindSyscallNumber(PBYTE addr) {
#if _M_X64
                char syscallPattern[] = { '\x4c', '\x8b', '\xd1', '\xb8' };
#else
                char syscallPattern[] = { '\xb8' };
#endif
                for (int offset = 0; offset < 32; ++offset) {
                    if (!memcmp(syscallPattern, (char*)addr + offset, sizeof(syscallPattern))) {
                        DWORD* numAddress = (DWORD*)(addr + offset + sizeof(syscallPattern));
                        return *numAddress;
                    }
                }
                return 0;
            }

            /**
             * A function to resolve the a system call number and function address.
             *
             * @param entry A pointer to a SYSCALL_API_ENTRY structure where resolved information will be stored.
             * @param funcHash Hash value representing the target function to resolve.
             * @return Returns TRUE if the resolution is successful; otherwise, returns FALSE.
             *
             */
            BOOL ResolveSyscallEntry(PSYSCALL_API_ENTRY entry, const char* funcName) {
                // Resolve the NT function address
                static HMODULE ntdll = LoadLibraryA("ntdll");
                PVOID fnAddr = GetProcAddress(ntdll, funcName);

                if (!fnAddr) {
                    return FALSE;
                }

                // Find the syscall number
                DWORD sysnum = FindSyscallNumber((PBYTE)fnAddr);

                // Find the address of the syscall instruction
                PVOID jmpAddr = FindSyscallInstruction((PBYTE)fnAddr);

#ifdef _M_IX86
                if (!jmpAddr) {
                    jmpAddr = (PVOID)__readfsdword(0xc0); // If WoW64, this returns wow64cpu!X86SwitchTo64BitMode
                }
#endif

                // We did not find the syscall
                if (sysnum == 0 || jmpAddr == NULL) {
                    return FALSE;
                }

                // Fill the entry
                entry->fnAddr = fnAddr;
                entry->sysnum = sysnum;
                entry->jmpAddr = jmpAddr;

                return TRUE;
            }

            /**
             * A helper macro for resolving an SYSCALL_API_ENTRY.
             *
             * @param field The field in the SYSCALL_API structure in which the resolved entry will be stored.
             * @param name The function name used to generate a compile-time hash for entry lookup.
             */
            #define RESOLVE_ENTRY(field, name) { \
                if(!ResolveSyscallEntry(&field, name)) { assert(false && "Could not resolve the syscall entry"); } \
            }

            /**
             * Resolve system call function addresses and syscall numbers.
             *
             * @param syscalls A pointer to a SYSCALL_API structure.
             * @return TRUE if all system call entries are successfully resolved, FALSE otherwise.
             *
             */
            void ResolveSyscalls(PSYSCALL_API syscalls) {
                RESOLVE_ENTRY(syscalls->ntAllocateVirtualMemory, "NtAllocateVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntAllocateVirtualMemory, "NtAllocateVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntProtectVirtualMemory, "NtProtectVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntFreeVirtualMemory, "NtFreeVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntGetContextThread, "NtGetContextThread");
                RESOLVE_ENTRY(syscalls->ntSetContextThread, "NtSetContextThread");
                RESOLVE_ENTRY(syscalls->ntResumeThread, "NtResumeThread");
                RESOLVE_ENTRY(syscalls->ntCreateThreadEx, "NtCreateThreadEx");
                RESOLVE_ENTRY(syscalls->ntOpenProcess, "NtOpenProcess");
                RESOLVE_ENTRY(syscalls->ntOpenThread, "NtOpenThread");
                RESOLVE_ENTRY(syscalls->ntClose, "NtClose");
                RESOLVE_ENTRY(syscalls->ntCreateSection, "NtCreateSection");
                RESOLVE_ENTRY(syscalls->ntMapViewOfSection, "NtMapViewOfSection");
                RESOLVE_ENTRY(syscalls->ntUnmapViewOfSection, "NtUnmapViewOfSection");
                RESOLVE_ENTRY(syscalls->ntQueryVirtualMemory, "NtQueryVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntDuplicateObject, "NtDuplicateObject");
                RESOLVE_ENTRY(syscalls->ntReadVirtualMemory, "NtReadVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntWriteVirtualMemory, "NtWriteVirtualMemory");
                RESOLVE_ENTRY(syscalls->ntReadFile, "NtReadFile");
                RESOLVE_ENTRY(syscalls->ntWriteFile, "NtWriteFile");
                RESOLVE_ENTRY(syscalls->ntCreateFile, "NtCreateFile");
            }

            /**
             * A function to resolve the RTL function address.
             *
             * @param address   A pointer to where the resolved information will be stored.
             * @param funcHash  Hash value representing the target function to resolve.
             *
             * @return Returns TRUE if the resolution is successful; otherwise, returns FALSE.
             *
             */
            BOOL ResolveNtdllFunc(PVOID* address, const char* funcName) {
                static const HMODULE ntdll = LoadLibraryA("ntdll");
                *address = GetProcAddress(ntdll, funcName);
                return *address != NULL;
            }

            /**
             * A helper macro for resolving a RTL function address.
             *
             * @param field The field in the RTL_API structure in which the resolved function address will be stored.
             * @param name The function name used to generate a compile-time hash for entry lookup.
             */
            #define RESOLVE_RTL_ENTRY(field, name) { \
                if(!ResolveNtdllFunc(&field, name)) { assert(field && "Could not resolve RTL entry"); } \
            }

            /**
             * Resolve RTL function addresses.
             *
             * @param rtls A pointer to a RTL_API structure.
             *
             */
            void ResolveRtls(PRTL_API rtls) {
                /* Resolve the RTL function addresses */
                RESOLVE_RTL_ENTRY(rtls->rtlDosPathNameToNtPathNameUWithStatusAddr, "RtlDosPathNameToNtPathName_U_WithStatus");
                RESOLVE_RTL_ENTRY(rtls->rtlFreeHeapAddr, "RtlFreeHeap");
                rtls->rtlGetProcessHeapAddr = GetProcessHeap();
                assert(rtls->rtlGetProcessHeapAddr && "Could not get the process heap address");
            }
        }
    }
}