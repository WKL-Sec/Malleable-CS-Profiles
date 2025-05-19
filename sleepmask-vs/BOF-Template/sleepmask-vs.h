#pragma once
#include "sleepmask.h"

typedef struct _CUSTOM_USER_DATA {
    char data[32];
} CUSTOM_USER_DATA, * PCUSTOM_USER_DATA;

typedef struct _EXTC2_SYNC_INFO {
    HANDLE ExtC2Init;
    HANDLE ExtC2StopEvent;
    HANDLE ExtC2SleepEvent;
    HANDLE ExtC2ContinueEvent;
} EXTC2_SYNC_INFO, * PEXTC2_SYNC_INFO;

ALLOCATED_MEMORY_PURPOSE ExternalC2 = (ALLOCATED_MEMORY_PURPOSE)2000;

typedef enum {
    EXTC2_DLL_NOT_LOADED = -1,
    EXTC2_DLL_EMPTY,
    EXTC2_DLL_LOADED,
    EXTC2_DLL_INITIALIZED,
    EXTC2_DLL_NOT_INITIALIZED,
} EXTC2_DLL_STATE;

/**
* Declare functions.
* 
* Note: This isn't explicitly required due to the #includes
* in sleepmask.cpp. However, it improves the UX as it improves
* intellisense.
*/

// debug.cpp
void PrintSleepMaskInfo(PSLEEPMASK_INFO info);
void PrintAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION memoryRegion);

// extc2.cpp
EXTC2_DLL_STATE GetExternalC2DllState(PSLEEPMASK_INFO info, PCUSTOM_USER_DATA customUserData);
void ExternalC2Sleep(PSLEEPMASK_INFO info, PCUSTOM_USER_DATA customUserData);

// gate.cpp
void BeaconGateWrapper(PSLEEPMASK_INFO info, PFUNCTION_CALL functionCall);
void BeaconGate(PFUNCTION_CALL gateFunction);

// masking.cpp
BOOL XORData(char* buffer, size_t size, char* key, size_t keyLength);
void XORSections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask);
void XORHeapRecords(BEACON_INFO* beaconInfo);
void XORBeacon(BEACON_INFO* beaconInfo, BOOL mask);
void MaskBeacon(BEACON_INFO* beaconInfo);
void UnMaskBeacon(BEACON_INFO* beaconInfo);

// pivot.cpp
void PivotSleep(PSLEEPMASK_INFO info, PCUSTOM_USER_DATA customUserData);

// sleep.cpp
void SleepMaskWrapper(PSLEEPMASK_INFO info);

// stdlib.cpp 
BOOL _memcpy(void* dest, void* src, size_t size);
void* _memset(void* ptr, int byte, size_t size);
int _memcmp(const void* ptr1, const void* ptr2, size_t size);

// utils.cpp
PALLOCATED_MEMORY_REGION FindRegionByPurpose(PALLOCATED_MEMORY allocatedMemory, ALLOCATED_MEMORY_PURPOSE purpose);
