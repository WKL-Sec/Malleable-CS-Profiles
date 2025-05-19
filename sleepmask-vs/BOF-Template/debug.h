#pragma once

// Controls logging for the release build
#define ENABLE_LOGGING 0

#if ENABLE_LOGGING || _DEBUG
#ifndef _DEBUG
/**
* We do not use the DFR macros here because of vsprintf_s.
* It's a variadic function which makes it difficult for the macro
* to find the right function declaration.
*/
WINBASEAPI VOID WINAPI KERNEL32$OutputDebugStringA(LPCSTR lpOutputString);
WINBASEAPI int       __cdecl MSVCRT$vsprintf_s(char* _DstBuf, size_t _DstSize, const char* _Format, ...);

#define OutputDebugStringA        KERNEL32$OutputDebugStringA
#define vsprintf_s                MSVCRT$vsprintf_s
#endif

#define DLOG(fmt) OutputDebugStringA(fmt)
#define DLOGF(fmt, ...) dlog(fmt, __VA_ARGS__)

void dlog(const char* fmt, ...) {
    char buff[512];
    va_list va;
    va_start(va, fmt);
    vsprintf_s(buff, 512, fmt, va);
    va_end(va);
    OutputDebugStringA(buff);
}

#else
#define DLOG(fmt);
#define DLOGF(fmt, ...);
#endif
