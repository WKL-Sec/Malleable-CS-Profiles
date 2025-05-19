#include <stdio.h>
#include <Windows.h>
#include <stdarg.h>
#include "base/helpers.h"

typedef struct _STACK_CONFIG {

	PVOID pRopGadget;
	PVOID pTarget;
	DWORD dwNumberOfArgs;
	PVOID pEbx;
	PVOID pArgs;

}STACK_CONFIG, * PSTACK_CONFIG;

//extern 
PVOID Spoof(PSTACK_CONFIG pConfig);

UINT64 FindGadget() {
	DFR_LOCAL(KERNEL32, GetModuleHandleA);

	PBYTE hModule = (PBYTE)GetModuleHandleA("kernel32");
	DWORD dwSize = ((PIMAGE_NT_HEADERS64)(hModule + ((PIMAGE_DOS_HEADER)hModule)->e_lfanew))->OptionalHeader.SizeOfImage;
	UINT64 pGadget = NULL;

	// Searching for the Bytes 0xFF 0x23, which corresponds to the instruction "jmp QWORD PTR [rbx]"
	for (int i = 0; i < dwSize - 1; i++) {

		if (hModule[i] == 0xff && hModule[i + 1] == 0x23) {
			pGadget = (UINT64)(hModule + i);
			break;
		}

	}

	return pGadget;
}

// Function To Initialize the STACK_CONFIG Structure
BOOL SetupConfig(PVOID pGadget, PSTACK_CONFIG pConfig, PVOID pTarget, DWORD dwArgCount, ...) {



	va_list arg_list;



	// Initializing the Struct values

	// To Keep The Stack Aligned, The Number Of Arguments Are Modified 
	pConfig->dwNumberOfArgs = (dwArgCount > 4) ? dwArgCount : 4;
	pConfig->dwNumberOfArgs += (dwArgCount % 2 != 0) ? 1 : 0;
	pConfig->pTarget = pTarget;
	pConfig->pRopGadget = pGadget;
	pConfig->pArgs = malloc(8 * pConfig->dwNumberOfArgs);


	if (!pConfig->pArgs) {
		printf("[-] Unable To Allocate Memory For Arguments\n");
		return FALSE;
	}
	memset(pConfig->pArgs, 0x00, 8 * pConfig->dwNumberOfArgs);

	// Storing the Argument Values
	va_start(arg_list, dwArgCount);
	for (int i = 0; i < dwArgCount; i++) {

		((PUINT64)(pConfig->pArgs))[i] = va_arg(arg_list, UINT64);

	}

	return TRUE;
}