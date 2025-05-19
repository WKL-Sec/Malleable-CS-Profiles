# Sleepmask-VS

This repository contains Sleepmask-VS, a simple Sleepmask example that can be used as a template to develop custom Sleepmask BOFs.
Sleepmask-VS was built using the Beacon Object File Visual Studio template ([BOF-VS](https://github.com/Cobalt-Strike/bof-vs)).
This repository will grow over time to provide additional Sleepmask/BeaconGate examples.

## Quick Start Guide

### Prerequisites:

* An x64 Windows 10/11 development machine (without a security solution)
* Visual Studio Community/Pro/Enterprise 2022 (Desktop Development with C++ installed)

### Debug

The `Debug` target builds Sleepmask-VS as an executable, which 
allows you to benefit from the convenience of debugging it within
Visual Studio. This will enable you to work at the source
code level without running the Sleepmask BOF through a Beacon.

BOF-VS provides a mocking framework to simplify Sleepmask/BeaconGate development. 
As part of calling the `runMockedSleepMask()`/`runMockedBeaconGate()` functions it 
is possible to replicate malleable C2 settings. This can be seen in the example below:

```
int main(int argc, char* argv[]) {
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

    return 0;
}
```

To simplify the development of custom gates, Sleepmask-VS also provides the functionality to mock
Beacon's WINAPI calls. `createFunctionCallStructure()` is a helper function that makes it easy to
create `FUNCTION_CALL` structures. `runMockedBeaconGate()` can then be used to call the Sleepmask
entry point and pass it a pointer to the generated `FUNCTION_CALL` to replicate Beacon's behaviour.
The following example demonstrates how to proxy a call to `VirtualAlloc` through BeaconGate: 

```
FUNCTION_CALL functionCall = bof::mock::createFunctionCallStructure(
    VirtualAlloc, // Function Pointer
    WinApi::VIRTUALALLOC, // Human readable WinApi enum
    TRUE, // Mask Beacon
    4, // Number of Arguments (for VirtualAlloc)
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
```

Note: In this example we also free the memory created by BeaconGate.

### Release

The `Release` target compiles an object file for use
with Cobalt Strike. 

To use Sleepmask-VS:
1. Enable the Sleepmask (`stage.sleep_mask "true";`)
2. Enable required BeaconGate functions (`stage.beacon_gate { ... }`)
3. Compile Sleepmask-VS
4. Load `sleepmask.cna` in the Script Manager
5. Export a Beacon