#include <iostream>
#include <cstdio>
#include <vector>
#include <algorithm>
#include <utility>
#include <cstring>
#include <map>
#include <tuple>
#include <cassert>
#include <windows.h>

extern "C" {
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#endif
#include "..\beacon.h"
}

#include "mock.h"

namespace bof {
    namespace utils {
        template <typename T>
        T swapEndianness(T value) {
            char *ptr = reinterpret_cast<char *>(&value);
            std::reverse(ptr, ptr + sizeof(T));
            return value;
        }

        template <typename T>
        std::vector<char> toBytes(T input) {
            char *ptr = reinterpret_cast<char *>(&input);
            return std::vector<char>(ptr, ptr + sizeof(T));
        }

        const char* typeToStr(int callbackType) {
            switch (callbackType) {
                case CALLBACK_OUTPUT: return "CALLBACK_OUTPUT";
                case CALLBACK_OUTPUT_OEM: return "CALLBACK_OUTPUT_OEM";
                case CALLBACK_ERROR: return "CALLBACK_ERROR";
                case CALLBACK_OUTPUT_UTF8: return "CALLBACK_OUTPUT_UTF8";
                default: return "CALLBACK_UNKOWN";
            }
        }
    }

    namespace mock {
        static BEACON_INFO beaconInfo = { 0 };

        char *BofData::get() {
            return size() > 0 ? reinterpret_cast<char *>(&data[0]) : nullptr;
        }

        int BofData::size() {
            return data.size();
        }

        void BofData::addData(const char *buf, std::size_t len) {
            std::vector<char> bytes;
            bytes.assign(buf, buf + len);
            insert(static_cast<int>(len));
            append(bytes);
        }

        void BofData::append(const std::vector<char> &data) {
            this->data.insert(std::end(this->data), std::begin(data), std::end(data));
        }

        void BofData::insert(int v) {
            append(bof::utils::toBytes(bof::utils::swapEndianness(v)));
        }

        void BofData::insert(short v) {
            append(bof::utils::toBytes(bof::utils::swapEndianness(v)));
        }

        void BofData::insert(unsigned int v) {
            insert(static_cast<int>(v));
        }

        void BofData::insert(unsigned short v) {
            insert(static_cast<short>(v));
        }

        void BofData::insert(const char *v) {
            addData(v, std::strlen(v) + 1);
        }

        void BofData::insert(const wchar_t *v) {
            addData((const char *)v, (std::wcslen(v) + 1) * sizeof(wchar_t));
        }

        void BofData::insert(const std::vector<char>& data) {
            pack<int32_t>(data.size());
            append(data);
        }

        void setBeaconInfo(BEACON_INFO& info) {
            std::memcpy(&bof::mock::beaconInfo, &info, sizeof(BEACON_INFO));
        }

        void setSection(PALLOCATED_MEMORY_SECTION info, PVOID baseAddress, SIZE_T size, DWORD finalProtection, DWORD allocationType, ALLOCATED_MEMORY_LABEL label) {
            info->BaseAddress = baseAddress;
            info->VirtualSize = size;
            info->PreviousProtect = finalProtection;
            info->CurrentProtect = finalProtection;
            info->MaskSection = TRUE;
            info->Label = label;
        }

        ALLOCATED_MEMORY_REGION allocateBeaconMemory(const bof::profile::Stage& stage, size_t size, DWORD* initialPermission) {
            ALLOCATED_MEMORY_REGION info;
            std::memset(&info, 0, sizeof(info));

            /* Allocate the base memory for Beacon. The following .stage options affect how the memory is allocated:
            *   - .stage.allocator: Set how Beacon's Reflective Loader allocates memory for the agent. Options are: HeapAlloc, MapViewOfFile, and VirtualAlloc.
            *   - .stage.module_x64/x86: Ask the ReflectiveLoader to load the specified library and overwrite its space instead of allocating memory with the .stage.allocator.
            */
            *initialPermission = stage.useRWX == bof::profile::UseRWX::True ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            if (stage.module.empty()) {
                HANDLE hHeap = INVALID_HANDLE_VALUE;
                HANDLE hFile = INVALID_HANDLE_VALUE;

                switch (stage.allocator) {
                    case bof::profile::Allocator::HeapAlloc: {
                        // For heap allocator we don't honor the .stage.userwx flag
                        *initialPermission = PAGE_EXECUTE_READWRITE;
                        hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
                        assert(hHeap != NULL && "Could not create the heap");
                        info.AllocationBase = HeapAlloc(hHeap, 0, size);
                        info.Type = MEM_PRIVATE;
                        info.CleanupInformation.AllocationMethod = METHOD_HEAPALLOC;
                        info.CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle = hHeap;
                        info.CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.DestroyHeap = TRUE;
                        break;
                    }
                    case bof::profile::Allocator::MapViewOfFile: {
                        hFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, size, NULL);
                        assert(hFile != NULL && "Could not create file mapping");
                        info.AllocationBase = MapViewOfFile(hFile, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE, 0, 0, 0);
                        info.Type = MEM_MAPPED;
                        info.CleanupInformation.AllocationMethod = METHOD_NTMAPVIEW;
                        CloseHandle(hFile);

                        DWORD old = 0;
                        if (!VirtualProtect(info.AllocationBase, size, *initialPermission, &old)) {
                            assert(false && "Could not set the initial memory permission for the Beacon memory");
                        }
                        break;
                    }
                    case bof::profile::Allocator::VirtualAlloc: {
                        info.AllocationBase = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, *initialPermission);
                        info.Type = MEM_PRIVATE;
                        info.CleanupInformation.AllocationMethod = METHOD_VIRTUALALLOC;
                        break;
                    }
                }
            }
            else {
                // For simplicity we use module base here instead of resolving a function
                info.AllocationBase = (PVOID)LoadLibraryExA(stage.module.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
                info.Type = MEM_IMAGE;
                info.CleanupInformation.AllocationMethod = METHOD_MODULESTOMP;

                DWORD old = 0;
                if (!VirtualProtect(info.AllocationBase, size, *initialPermission, &old)) {
                    assert(false && "Could not set the initial memory permission for the Beacon memory");
                }
            }
            assert(info.AllocationBase != NULL && "Could not allocate the base memory for Beacon");

            // Set the necessary fields for the Beacon memory
            info.Purpose = PURPOSE_BEACON_MEMORY;
            info.RegionSize = size;
            info.CleanupInformation.Cleanup = TRUE;

            return info;
        }

        BEACON_INFO setupMockBeacon(const bof::profile::Stage& stage) {
            const std::vector<std::tuple<ALLOCATED_MEMORY_LABEL, std::string>> sections{
                { LABEL_PEHEADER, "PE" },
                { LABEL_TEXT, ".text" },
                { LABEL_RDATA, ".rdata" },
                { LABEL_DATA, ".data" },
#ifdef _M_X64
                { LABEL_PDATA, ".pdata" },
#endif
                { LABEL_RELOC, ".reloc" },
            };
            const size_t sectionSize = 0x1000;

            BEACON_INFO info = { 0 };
            info.version = bof::CsVersion;

            // Set the static mask key
            for (size_t i = 0; i < MASK_SIZE; ++i) {
                info.mask[i] = 0xAB;
            }

            // Allocate the memory for Beacon
            DWORD initialProtection = 0;
            ALLOCATED_MEMORY_REGION beaconMemory = allocateBeaconMemory(stage, sections.size() * sectionSize, &initialProtection);
            info.allocatedMemory.AllocatedMemoryRegions[0] = beaconMemory;
            info.beacon_ptr = stage.obfuscate == bof::profile::Obfuscate::False
                ? reinterpret_cast<char*>(beaconMemory.AllocationBase)
                : reinterpret_cast<char*>(beaconMemory.AllocationBase) - 0x1000;

            // Build the section list
            PALLOCATED_MEMORY_SECTION nextSection = info.allocatedMemory.AllocatedMemoryRegions[0].Sections;
            char* sectionBase = reinterpret_cast<char*>(beaconMemory.AllocationBase);
            for (auto [section, name] : sections) {
                // Skip the PE header if .stage.obfuscate = true
                if (stage.obfuscate == bof::profile::Obfuscate::True && section == LABEL_PEHEADER) {
                    continue;
                }

                // Fill the memory
                for (size_t i = 0; i < sectionSize; ++i) {
                    sectionBase[i] = name[i % name.length()];
                }

                DWORD finalProtection = initialProtection;

                // Fix the .code section permission if the allocator is not heap alloc and .stage.userwx is false
                if (stage.allocator != bof::profile::Allocator::HeapAlloc || !stage.module.empty()) {
                    if (section == LABEL_TEXT && stage.useRWX == bof::profile::UseRWX::False) {
                        finalProtection = PAGE_EXECUTE_READ;

                        // Fix the permissions
                        DWORD old = 0;
                        if (!VirtualProtect(sectionBase, sectionSize, finalProtection, &old)) {
                            assert(false && "Could not set the final memory protection");
                        }
                    }
                }

                // Set the section memory information
                setSection(nextSection, sectionBase, sectionSize, finalProtection, beaconMemory.Type, section);

                // Next section
                ++nextSection;
                sectionBase += sectionSize;
            }

            // Add few mock heap records
            const size_t numberOfHeapRecords = 2;
            info.heap_records = new HEAP_RECORD[numberOfHeapRecords + 1];
            assert(info.heap_records != nullptr && "Could not the allocate heap records array");
            for (size_t i = 0; i < numberOfHeapRecords; ++i) {
                info.heap_records[i].ptr = new char[512];
                info.heap_records[i].size = 512;
                assert(info.heap_records[i].ptr != nullptr && "Could not allocate a heap record");
            }
            info.heap_records[numberOfHeapRecords].ptr = NULL;
            info.heap_records[numberOfHeapRecords].size = 0;

            return info;
        }

        void resolveMockUpSleepmaskLocation(BEACON_INFO& info) {
            // Get the base address of the debug exe
            char* exeBase = (char*)GetModuleHandleA(NULL);
            // Find the start of the section headers
            PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)exeBase;
            PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(exeBase + dosHeader->e_lfanew);
            PIMAGE_SECTION_HEADER sectionHeader = (PIMAGE_SECTION_HEADER)(reinterpret_cast<char*>(&ntHeader->OptionalHeader) + ntHeader->FileHeader.SizeOfOptionalHeader);
            // Find the .text section which will be our "mock" sleepmask code
            DWORD numberOfSections = ntHeader->FileHeader.NumberOfSections;
            while (numberOfSections--) {
                if (strcmp(reinterpret_cast<char*>(sectionHeader->Name), ".text") == 0) {
                    info.sleep_mask_ptr = exeBase + sectionHeader->VirtualAddress;
                    info.sleep_mask_text_size = sectionHeader->Misc.VirtualSize;
                    // In theory, the total size would contains also the data part, but we cannot guarantee the section order.
                    info.sleep_mask_total_size = sectionHeader->Misc.VirtualSize;
                    return;
                }
                ++sectionHeader;
            }
            assert(false && "Could not find the text section of the debug image");
        }

        FUNCTION_CALL createFunctionCallStructure(PVOID targetFunction, WinApi targetFunctionName, BOOL bMask, int numOfArgs, ...) {
            int i = 0;
            FUNCTION_CALL functionCall = { 0 };
            va_list valist = NULL;

            /* Set basic info for encapsulated function call */
            functionCall.functionPtr = targetFunction;
            functionCall.function = targetFunctionName;
            functionCall.bMask = bMask;
            functionCall.numOfArgs = numOfArgs;

            /* Start parsing valist and copy over variadic arguments. */
            va_start(valist, numOfArgs);
            for (i = 0; i < numOfArgs; i++)
            {
                functionCall.args[i] = va_arg(valist, ULONG_PTR);
            }
            va_end(valist);

            return functionCall;
        }
    }

    namespace output {
        std::vector<OutputEntry> outputs;

        void addEntry(int type, const char* data, int len) {
            OutputEntry output = {
                type,
                std::string(data, data + len)
            };
            outputs.push_back(output);
        }

        const std::vector<OutputEntry>& getOutputs() {
            return outputs;
        }

        void reset() {
            outputs.clear();
        }

        void PrintTo(const OutputEntry& o, std::ostream* os) {
            *os << "{ callbackType: " << bof::utils::typeToStr(o.callbackType) << ", output: " << o.output << " }";
        }
    }

    namespace valuestore {
        std::map<std::string, void*> values;

        void reset() {
            values.clear();
        }
    }

    namespace bud {
        char custom[BEACON_USER_DATA_CUSTOM_SIZE] = { 0 };

        void reset() {
            std::memset(custom, 0, BEACON_USER_DATA_CUSTOM_SIZE);
        }

        void set(const char* data) {
            if (data) {
                std::memcpy(custom, data, BEACON_USER_DATA_CUSTOM_SIZE);
            }
        }
    }

    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, PSLEEPMASK_INFO sleepMaskInfo, PFUNCTION_CALL functionCall) {
        // Reset the global output container
        bof::output::reset();
        // Execute the entrypoint
        sleepMaskFunc(sleepMaskInfo, functionCall);
        // Return the stored outputs
        return bof::output::getOutputs();
    }

    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, const bof::profile::Stage& stage, const bof::mock::MockSleepMaskConfig& config) {
        SLEEPMASK_INFO sleepmaskInfo = {
            .version = bof::CsVersion,
            .reason = DEFAULT_SLEEP,
            .sleep_time = config.sleepTimeMs,
            .beacon_info = bof::mock::setupMockBeacon(stage),
        };
        bof::mock::resolveMockUpSleepmaskLocation(sleepmaskInfo.beacon_info);

        std::vector<bof::output::OutputEntry> output;
        do {
            output = runMockedSleepMask(sleepMaskFunc, &sleepmaskInfo, NULL);
        } while (config.runForever);

        return output;
    }

    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc, const bof::profile::Stage& stage) {
        // Set the default config for the mock sleepmask runner
        const bof::mock::MockSleepMaskConfig config = {
            .sleepTimeMs = 5000,
            .runForever = false,
        };
        return runMockedSleepMask(sleepMaskFunc, stage, config);
    }

    std::vector<bof::output::OutputEntry> runMockedSleepMask(SLEEPMASK_FUNC sleepMaskFunc) {
        return runMockedSleepMask(sleepMaskFunc, bof::profile::defaultStage);
    }

    std::vector<bof::output::OutputEntry> runMockedBeaconGate(SLEEPMASK_FUNC sleepMaskFunc, PFUNCTION_CALL functionCall, const bof::profile::Stage& stage) { 
        SLEEPMASK_INFO sleepmaskInfo = {
            .version = bof::CsVersion,
            .reason = BEACON_GATE,
            .sleep_time = 0,
            .beacon_info = bof::mock::setupMockBeacon(stage),
        };
        bof::mock::resolveMockUpSleepmaskLocation(sleepmaskInfo.beacon_info);
        return runMockedSleepMask(sleepMaskFunc, &sleepmaskInfo, functionCall);
    }

    std::vector<bof::output::OutputEntry> runMockedBeaconGate(SLEEPMASK_FUNC sleepMaskFunc, PFUNCTION_CALL functionCall) {
        return runMockedBeaconGate(sleepMaskFunc, functionCall, bof::profile::defaultStage);
    }
}

#include "mock_syscalls.cpp"

extern "C"
{
    // Print API
    void BeaconPrintf(int type, const char *fmt, ...) {
        printf("[Output Callback: %s (0x%X)]\n", bof::utils::typeToStr(type), type);
        va_list args;
        va_start(args, fmt);
        int size = vsnprintf(nullptr, 0, fmt, args);
        if (size >= 0) {
            char* buffer = new char[size + 1];
            vsnprintf(buffer, size + 1, fmt, args);
            bof::output::addEntry(type, buffer, size);
            delete[] buffer;
        }
        vprintf(fmt, args);
        printf("\n");
        va_end(args);
    }

    void BeaconOutput(int type, const char *data, int len) {
        bof::output::addEntry(type, data, len);
        printf("[Output Callback: %s (0x%X)]\n%.*s", bof::utils::typeToStr(type), type, len, data);
    }

    // Parser API
    void BeaconDataParse(datap *parser, char *buffer, int size) {
        parser->buffer = buffer;
        parser->original = buffer;
        parser->size = size;
        parser->length = size;
    }

    int BeaconDataInt(datap *parser) {
        int value = *(int *)(parser->buffer);
        parser->buffer += sizeof(int);
        parser->length -= sizeof(int);
        return bof::utils::swapEndianness(value);
    }

    short BeaconDataShort(datap *parser) {
        short value = *(short *)(parser->buffer);
        parser->buffer += sizeof(short);
        parser->length -= sizeof(short);
        return bof::utils::swapEndianness(value);
    }

    int BeaconDataLength(datap *parser) {
        return parser->length;
    }

    char *BeaconDataExtract(datap *parser, int *size) {
        int size_im = BeaconDataInt(parser);
        char *buff = parser->buffer;
        parser->buffer += size_im;
        if (size)
        {
            *size = size_im;
        }
        return buff;
    }

    // Format API
    void BeaconFormatAlloc(formatp *format, int maxsz) {
        format->original = new char[maxsz];
        format->buffer = format->original;
        format->length = maxsz;
        format->size = maxsz;
    }

    void BeaconFormatReset(formatp *format) {
        format->buffer = format->original;
        format->length = format->size;
    }

    void BeaconFormatFree(formatp *format) {
        delete[] format->original;
    }

    void BeaconFormatAppend(formatp *format, const char *text, int len) {
        memcpy(format->buffer, text, len);
        format->buffer += len;
        format->length -= len;
    }

    void BeaconFormatPrintf(formatp *format, const char *fmt, ...) {
        va_list args;
        va_start(args, fmt);
        int len = vsprintf_s(format->buffer, format->length, fmt, args);
        format->buffer += len;
        format->length -= len;
        va_end(args);
    }

    char *BeaconFormatToString(formatp *format, int *size) {
        if (size)
        {
            *size = format->size - format->length;
        }
        return format->original;
    }

    void BeaconFormatInt(formatp *format, int value) {
        value = bof::utils::swapEndianness(value);
        BeaconFormatAppend(format, (char *)&value, 4);
    }

    // Internal API
    BOOL BeaconUseToken(HANDLE token) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
        return TRUE;
    }

    void BeaconRevertToken() {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    BOOL BeaconIsAdmin() {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
        return FALSE;
    }

    void BeaconGetSpawnTo(BOOL x86, char *buffer, int length) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    void BeaconInjectProcess(HANDLE hProc, int pid, char *payload,
                             int p_len, int p_offset, char *arg,
                             int a_len)
    {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo,
                                      char *payload, int p_len,
                                      int p_offset, char *arg,
                                      int a_len)
    {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    void BeaconCleanupProcess(PROCESS_INFORMATION *pInfo) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    BOOL toWideChar(char *src, wchar_t *dst, int max) {
        std::string str = src;
        std::wstring wstr(str.begin(), str.end());

        size_t bytes = min(wstr.length() * sizeof(wchar_t), max);
        std::memcpy(dst, wstr.c_str(), bytes);
        return TRUE;
    }

    BOOL BeaconInformation(BEACON_INFO* info) {
        std::memcpy(&bof::mock::beaconInfo, info, sizeof(BEACON_INFO));
        return TRUE;
    }

    BOOL BeaconAddValue(const char* key, void* ptr) {
        auto item = bof::valuestore::values.find(std::string(key));
        if (ptr && item == bof::valuestore::values.end()) {
            bof::valuestore::values[std::string(key)] = ptr;
            return TRUE;
        }
        return FALSE;
    }

    void* BeaconGetValue(const char* key) {
        auto item = bof::valuestore::values.find(std::string(key));
        if (item != bof::valuestore::values.end()) {
            return item->second;
        }
        return NULL;
    }

    BOOL BeaconRemoveValue(const char* key) {
        auto item = bof::valuestore::values.find(std::string(key));
        if (item != bof::valuestore::values.end()) {
            bof::valuestore::values.erase(item);
            return TRUE;
        }
        return FALSE;
    }

    PDATA_STORE_OBJECT BeaconDataStoreGetItem(size_t index) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
        return NULL;
    }

    void BeaconDataStoreProtectItem(size_t index) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    void BeaconDataStoreUnprotectItem(size_t index) {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
    }

    size_t BeaconDataStoreMaxEntries() {
        std::cerr << "Not implemented: " << __FUNCTION__ << std::endl;
        return 0;
    }

    char* BeaconGetCustomUserData() {
        return bof::bud::custom;
    }

    BOOL BeaconGetSyscallInformation(PBEACON_SYSCALLS info, BOOL resolveIfNotInitialized) {
        if (info) {
            bof::mock::syscall::ResolveSyscalls(info->syscalls);
            bof::mock::syscall::ResolveRtls(info->rtls);
            return TRUE;
        }
        return FALSE;
    }

    // Beacon System Call API
    LPVOID BeaconVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        return VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    LPVOID BeaconVirtualAllocEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
        return VirtualAllocEx(processHandle, lpAddress, dwSize, flAllocationType, flProtect);
    }

    BOOL BeaconVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        return VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }

    BOOL BeaconVirtualProtectEx(HANDLE processHandle, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {
        return VirtualProtectEx(processHandle, lpAddress, dwSize, flNewProtect, lpflOldProtect);
    }

    BOOL BeaconVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
        return VirtualFree(lpAddress, dwSize, dwFreeType);
    }

    BOOL BeaconGetThreadContext(HANDLE threadHandle, PCONTEXT threadContext) {
        return GetThreadContext(threadHandle, threadContext);
    }

    BOOL BeaconSetThreadContext(HANDLE threadHandle, PCONTEXT threadContext) {
        return SetThreadContext(threadHandle, threadContext);
    }

    DWORD BeaconResumeThread(HANDLE threadHandle) {
        return ResumeThread(threadHandle);
    }

    HANDLE BeaconOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId) {
        return OpenProcess(desiredAccess, inheritHandle, processId);
    }

    HANDLE BeaconOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId) {
        return OpenThread(desiredAccess, inheritHandle, threadId);
    }

    BOOL BeaconCloseHandle(HANDLE object) {
        return CloseHandle(object);
    }

    BOOL BeaconUnmapViewOfFile(LPCVOID baseAddress) {
        return UnmapViewOfFile(baseAddress);
    }

    SIZE_T BeaconVirtualQuery(LPCVOID address, PMEMORY_BASIC_INFORMATION buffer, SIZE_T length) {
        return VirtualQuery(address, buffer, length);
    }

    BOOL BeaconDuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions) {
        return DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
    }

    BOOL BeaconReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
        return ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    BOOL BeaconWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
        return WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }


}
