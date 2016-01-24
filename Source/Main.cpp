
// ****************************************************************************
// File: Main.cpp
// Desc: IDA Pro plug in that does an extra pass to fix unresolved code.
//       Plug-in interface
//
// ****************************************************************************
#include "stdafx.h"

// Run IDA in plug in debug mode with -z20

// === Function Prototypes ===
int idaapi IDAP_init();
void idaapi IDAP_term();
void idaapi IDAP_run(int arg);
extern void CORE_Init();
extern void CORE_Process(int iArg);
extern void CORE_Exit();


// === Data ===
const char PLUGIN_NAME[] = "ExtraPass";

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	PLUGIN_UNL,				// Plug-in flags
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
    PLUGIN_NAME,	        // Comment - unused
    PLUGIN_NAME,	        // As above - unused
    PLUGIN_NAME,	        // Plug-in name shown in Edit->Plugins menu
	NULL                    // Hot key to run the plug-in
};

// Init
int idaapi IDAP_init()
{
    // Only x86 supported
    if (ph.id != PLFM_386)
        return(PLUGIN_SKIP);

    CORE_Init();
    return(PLUGIN_OK);
}

// Un-init
void idaapi IDAP_term()
{
    CORE_Exit();
}

// Run
void idaapi IDAP_run(int iArg)
{
    CORE_Process(iArg);
}



