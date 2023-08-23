// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "vovk.h"
#include <DbgEng.h>
#include <ntverp.h>

//
// globals
//
EXT_API_VERSION         ApiVersion = { 1, 0, EXT_API_VERSION_NUMBER64, 0 };
WINDBG_EXTENSION_APIS   ExtensionApis;
ULONG SavedMajorVersion;
ULONG SavedMinorVersion;

int DllInit(
	HANDLE hModule,
	DWORD  dwReason,
	DWORD  dwReserved
)
{
	switch (dwReason) {
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;

	case DLL_PROCESS_ATTACH:
		break;
	}

	return TRUE;
}


VOID
WinDbgExtensionDllInit(
	PWINDBG_EXTENSION_APIS lpExtensionApis,
	USHORT MajorVersion,
	USHORT MinorVersion
)
{
	ExtensionApis = *lpExtensionApis;

	SavedMajorVersion = MajorVersion;
	SavedMinorVersion = MinorVersion;

	return;
}

LPEXT_API_VERSION
ExtensionApiVersion(
	VOID
)
{
	//
	// ExtensionApiVersion should return EXT_API_VERSION_NUMBER64 in order for APIs
	// to recognize 64 bit addresses.  KDEXT_64BIT also has to be defined before including
	// wdbgexts.h to get 64 bit headers for WINDBG_EXTENSION_APIS
	//
	return &ApiVersion;
}

//
// Routine called by debugger after load
//
VOID
CheckVersion(
	VOID
)
{
	return;
}


extern "C"
HRESULT
CALLBACK
DebugExtensionInitialize(
	PULONG Version,
	PULONG Flags
) {

	// 
	// We're version 1.0 of our extension DLL
	// 
	*Version = DEBUG_EXTENSION_VERSION(1, 0);

	// 
	// Flags must be zero
	// 
	*Flags = 0;

	// 
	// Done!
	// 
	return S_OK;
}