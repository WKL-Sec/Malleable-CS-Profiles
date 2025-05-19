#include <windows.h>

#include "base\helpers.h"
#include "sleepmask.h"
/**
 * For the debug build we want:
 *   a) Include the mock-up layer
 *   b) Undefine DECLSPEC_IMPORT since the mocked Beacon API
 *      is linked against the the debug build.
 */
#ifdef _DEBUG
#undef DECLSPEC_IMPORT
#define DECLSPEC_IMPORT
#include "base\mock.h"
#endif

extern "C" {
#include "beacon.h"
#include "beacon_gate.h"

#include "sleepmask-vs.h"
#include "library\debug.cpp"
#include "library\extc2.cpp"
#include "library\utils.cpp"
#include "library\stdlib.cpp"
#include "library\sleep.cpp"
#include "library\masking.cpp"
#include "library\pivot.cpp"
#include "library\gate.cpp"

    /**
    * Sleepmask-VS entry point
    *
    * Note: To enable logging for Release builds set ENABLE_LOGGING to
    * 1 in debug.h.   
    */
    void sleep_mask(PSLEEPMASK_INFO info, PFUNCTION_CALL funcCall) {
        if (info->reason == DEFAULT_SLEEP || info->reason == PIVOT_SLEEP) {
            DLOGF("SLEEPMASK: Sleeping\n");
            SleepMaskWrapper(info);
        }
        else if (info->reason == BEACON_GATE) {
            DLOGF("SLEEPMASK: Calling %d via BeaconGate\n", funcCall->function);
            BeaconGateWrapper(info, funcCall);
        }

        return;
    }
}

// Define a main function for the debug build
#if defined(_DEBUG) && !defined(_GTEST)
int main(int argc, char* argv[]) {
    /**
    * Sleepmask Example
    */
    bof::runMockedSleepMask(sleep_mask,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::False,
            .module = "",
        },
        {
            .sleepTimeMs = 5000,
            .runForever = true,
        }
    );

    /**
    * Beacon Gate Example
    * 
    * Note: The GateArg() Macro ensures arguments are the correct size for the architecture
    */  
    /*
    FUNCTION_CALL functionCall = bof::mock::createFunctionCallStructure(
        VirtualAlloc, // Function Pointer
        WinApi::VIRTUALALLOC, // Human Readable WinApi Enum
        TRUE, // Mask Beacon
        4, // Number of Arguments
        GateArg(NULL),  // VirtualAlloc Arg1
        GateArg(0x1000), // VirtualAlloc Arg2 
        GateArg(MEM_RESERVE | MEM_COMMIT), // VirtualAlloc Arg3
        GateArg(PAGE_EXECUTE_READWRITE) // VirtualAlloc Arg4
    );

    // Run BeaconGate
    bof::runMockedBeaconGate(sleep_mask, &functionCall,
        {
            .allocator = bof::profile::Allocator::VirtualAlloc,
            .obfuscate = bof::profile::Obfuscate::False,
            .useRWX = bof::profile::UseRWX::False,
            .module = "",
        });

    // Free the memory allocated by BeaconGate
    VirtualFree((LPVOID)functionCall.retValue, 0, MEM_RELEASE);
    */
    return 0;
}

// Define unit tests
#elif defined(_GTEST)
#include <gtest\gtest.h>

TEST(BofTest, Test1) {}
#endif
