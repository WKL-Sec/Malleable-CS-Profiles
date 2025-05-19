#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"

/**
* A helper function to display the contents of the SLEEPMASK_INFO structure
* 
* @param info A pointer to a SLEEPMASK_INFO structure
*/
void PrintSleepMaskInfo(PSLEEPMASK_INFO info) {
    DLOGF("SLEEPMASK: Version: %X\n", info->beacon_info.version);
    DLOGF("SLEEPMASK: Sleepmask: %p\n", info->beacon_info.sleep_mask_ptr);
    DLOGF("SLEEPMASK: Sleepmask Text Size: %x\n", info->beacon_info.sleep_mask_text_size);
    DLOGF("SLEEPMASK: Sleepmask Total Size: %x\n", info->beacon_info.sleep_mask_total_size);
    DLOGF("SLEEPMASK: Beacon: %p\n", info->beacon_info.beacon_ptr);
    DLOGF("SLEEPMASK: Heap Records: %p\n", info->beacon_info.heap_records);
    DLOGF("SLEEPMASK: Mask Key: %p\n", &info->beacon_info.mask[0]);
    DLOGF("SLEEPMASK: Allocated Memory: %p\n", &info->beacon_info.allocatedMemory);

    return;
}

/**
* A helper function to display the contents of a ALLOCATED_MEMORY_REGION structure
*
* @param memoryRegion A pointer to a ALLOCATED_MEMORY_REGION structure
*/
void PrintAllocatedMemoryRegion(PALLOCATED_MEMORY_REGION memoryRegion) {
    DLOGF("SLEEPMASK: Allocated Memory Region\n");
    DLOGF("SLEEPMASK: \tBaseAddress: %p\n", memoryRegion->AllocationBase);
    DLOGF("SLEEPMASK: \tRegionSize: %lu\n", memoryRegion->RegionSize);
    DLOGF("SLEEPMASK: \tType: %x\n", memoryRegion->Type);
    DLOGF("SLEEPMASK: \tPurpose: %x\n", memoryRegion->Purpose);

    for (int i = 0; i < sizeof(memoryRegion->Sections) / sizeof(ALLOCATED_MEMORY_SECTION); ++i) {
        if (memoryRegion->Sections[i].Label == LABEL_EMPTY || memoryRegion->Sections[i].BaseAddress == NULL) {
            continue;
        }
        DLOGF("SLEEPMASK: \tSection[%d]\n", i);
        DLOGF("SLEEPMASK: \t\tLabel: %lu\n", memoryRegion->Sections[i].Label);
        DLOGF("SLEEPMASK: \t\tBaseAddress: %p\n", memoryRegion->Sections[i].BaseAddress);
        DLOGF("SLEEPMASK: \t\tVirtualSize: %lu\n", memoryRegion->Sections[i].VirtualSize);
        DLOGF("SLEEPMASK: \t\tCurrenProtection: %x\n", memoryRegion->Sections[i].CurrentProtect);
        DLOGF("SLEEPMASK: \t\tPreviousProtect: %x\n", memoryRegion->Sections[i].PreviousProtect);
        DLOGF("SLEEPMASK: \t\tMaskSection: %s\n", memoryRegion->Sections[i].MaskSection ? "TRUE" : "FALSE");
    }

    DLOGF("SLEEPMASK: \tCleanup Information:\n");
    DLOGF("SLEEPMASK: \t\tCleanup: %s\n", memoryRegion->CleanupInformation.Cleanup ? "TRUE" : "FALSE");
    if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_HEAPALLOC) {
        DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_HEAPALLOC\n");
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: HeapHandle: %p\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.HeapAllocInfo.HeapHandle);
    }
    else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_MODULESTOMP) {
        DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_MODULESTOMP\n");
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: ModuleHandle: %p\n", memoryRegion->CleanupInformation.AdditionalCleanupInformation.ModuleStompInfo.ModuleHandle);
    }
    else {
        if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_VIRTUALALLOC) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_VIRTUALALLOC\n");
        }
        else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_NTMAPVIEW) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_NTMAPVIEW\n");
        }
        else if (memoryRegion->CleanupInformation.AllocationMethod == METHOD_UNKNOWN) {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_UNKNOWN\n");
        }
        else {
            DLOGF("SLEEPMASK: \t\tAllocationMethod: METHOD_USER_DEFINED (%d)\n", memoryRegion->CleanupInformation.AllocationMethod);
        }
        DLOGF("SLEEPMASK: \t\tAdditionalCleanupInformation: NONE\n");
    }

    return;
}
