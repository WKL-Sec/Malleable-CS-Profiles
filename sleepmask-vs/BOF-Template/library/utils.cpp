#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"
#include "../sleepmask-vs.h"

/**
* Find a specific region within the ALLOCATED_MEMORY structure
* 
* @param allocatedMemory A pointer to a ALLOCATED_MEMORY structure
* @param purpose An enum to indicate the desired memory region
* @return A pointer to the desired ALLOCATED_MEMORY_REGION structure
*/
PALLOCATED_MEMORY_REGION FindRegionByPurpose(PALLOCATED_MEMORY allocatedMemory, ALLOCATED_MEMORY_PURPOSE purpose) {
    for (int i = 0; i < sizeof(allocatedMemory->AllocatedMemoryRegions) / sizeof(ALLOCATED_MEMORY_REGION); i++) {
        if (allocatedMemory->AllocatedMemoryRegions[i].Purpose == purpose) {
            return &allocatedMemory->AllocatedMemoryRegions[i];
        }
    }
    return NULL;
}
