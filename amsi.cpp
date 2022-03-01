#include "pch.h"
#include "iostream"
 
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPCWSTR appName = NULL;
        typedef struct HAMSICONTEXT {
            DWORD       Signature;            // "AMSI" or 0x49534D41
            PWCHAR      AppName;           // set by AmsiInitialize
            DWORD       Antimalware;       // set by AmsiInitialize
            DWORD       SessionCount;      // increased by AmsiOpenSession
        } HAMSICONTEXT;
        typedef enum AMSI_RESULT {
            AMSI_RESULT_CLEAN,
            AMSI_RESULT_NOT_DETECTED,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END,
            AMSI_RESULT_DETECTED
        } AMSI_RESULT;
 
        typedef struct HAMSISESSION {
            DWORD test;
        } HAMSISESSION;
 
        typedef struct r {
            DWORD r;
        };
 
        void AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext);
        void AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION * amsiSession);
        void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
        void AmsiResultIsMalware(r);
        void AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiUninitialize(HAMSICONTEXT amsiContext);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
