// dllmain.cpp : Defines the entry point for the DLL application.
// vovk yara rule generator - creates yara rules based on dynamic execution in the debugger
// Vishal Thakur 2023. 
// Github: https://github.com/malienist/vovk 
#include "pch.h"
#include "vovk.h"
#include <DbgEng.h>
#include <ntverp.h>

HRESULT
CALLBACK
// break at every new module load
c(
	PDEBUG_CLIENT4 Client,
	PCSTR args
) {
	PDEBUG_CONTROL        debugControl;
	HRESULT               ld;

	// 
   // Our debug control instance will allow us to output, execute
   // commands, evaluate symbols, etc.
   // 
	ld = Client->QueryInterface(__uuidof(IDebugControl),
		(VOID**)&debugControl);

	if (ld != S_OK) {
		return ld;
	}

	// break on every new module load
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		"sxe ld; g",
		DEBUG_EXECUTE_NOT_LOGGED);

	// start the dump file
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		".logopen c:\\vovk-mem.dmp",
		DEBUG_EXECUTE_NOT_LOGGED);
	
	// print BYTE values to the screen - we will use these to create our yara rules
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		"db; db; db; db; db; db; db; db; db; db",
		DEBUG_EXECUTE_NOT_LOGGED);

	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		"g; db; db; db; db; db; db; db; db; db; db",
		DEBUG_EXECUTE_NOT_LOGGED);
}

HRESULT
CALLBACK
// break at specified modules
d(
	PDEBUG_CLIENT4 Client,
	PCSTR args
) {
	PDEBUG_CONTROL        debugControl;
	HRESULT               ld;

	// 
   // Our debug control instance will allow us to output, execute
   // commands, evaluate symbols, etc.
   // 
	ld = Client->QueryInterface(__uuidof(IDebugControl),
		(VOID**)&debugControl);

	if (ld != S_OK) {
		return ld;
	}

	// break on every new module load - change this for the bp you want
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		"bp wininet!InternetConnectW; g",
		DEBUG_EXECUTE_NOT_LOGGED);

	// start the dump file
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		".logopen c:\\vovk-mem.dmp",
		DEBUG_EXECUTE_NOT_LOGGED);

	// print BYTE values to the screen - we will use these to create our yara rules
	ld = debugControl->Execute(DEBUG_OUTCTL_ALL_CLIENTS,
		"db; g",
		DEBUG_EXECUTE_NOT_LOGGED);

	// manually break the loop
}