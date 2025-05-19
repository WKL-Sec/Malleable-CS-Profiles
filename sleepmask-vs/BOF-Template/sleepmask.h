#ifndef _SLEEPMASK_H_
#define _SLEEPMASK_H_

#include <windows.h>
#include "beacon.h"
#include "beacon_gate.h"

/* Define the supported action types for the pivot beacons */
typedef enum _PIVOT_ACTION {
	ACTION_UNKNOWN,
	ACTION_TCP_RECV,
	ACTION_TCP_ACCEPT,
	ACTION_PIPE_WAIT,
	ACTION_PIPE_PEEK
} PIVOT_ACTION;

/*
 *  action       - defines which ACTION_ type to use in the pivot_sleep
 *  in           - defines the in socket for the ACTION_TCP_ types
 *  out          - defines the out socket for the ACTION_TCP_ types
 *  pipe         - defines the pipe for the ACTION_PIPE_ types
 */
typedef struct _PIVOT_ARGS {
	PIVOT_ACTION action;
	SOCKET in;
	SOCKET out;
	HANDLE pipe;
} PIVOT_ARGS, * PPIVOT_ARGS;

typedef enum _REASON_FOR_CALL {
	DEFAULT_SLEEP,
	PIVOT_SLEEP,
	BEACON_GATE
} REASON_FOR_CALL;

/*
 *  version        - version of the structure. format: 0xMMmmPP, where MM = Major, mm = Minor, and PP = Patch
 *  reason         - reason for the call (default sleep, pivot sleep, beacon gate)
 *  sleep_time     - the time to sleep in milliseconds
 *  beacon_info    - the BEACON_INFO structure
 *  pivot_args     - the PIVOT_ARGS structure
 */
typedef struct _SLEEPMASK_INFO {
	unsigned int version;
	REASON_FOR_CALL reason;
	DWORD sleep_time;
	BEACON_INFO beacon_info;
	PIVOT_ARGS pivot_args;
} SLEEPMASK_INFO, * PSLEEPMASK_INFO;

typedef void(* SLEEPMASK_FUNC)(PSLEEPMASK_INFO, PFUNCTION_CALL);
#endif // _SLEEPMASK_H_
