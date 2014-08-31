
// ****************************************************************************
// File: Main.cpp
// Desc: IDA Pro plug in that does an extra pass to fix unresolved code. 
//       Plug-in interface
//
// ****************************************************************************
#include "stdafx.h"

// Run IDA in plug in debug mode with -z20

// === Function Prototypes ===
int IDAP_init();
void IDAP_term();
void IDAP_run(int arg);
extern void CORE_Init();
extern void CORE_Process(int iArg);
extern void CORE_Exit();


// === Data ===
char IDAP_comment[] = "ExtraPass: Does an extra pass on Win32 code sections to fix unresolved code.";
char IDAP_help[] 	= "ExtraPass: Point to the top of the \".text\" code segment\nThen press the hot key to activate.";
char IDAP_name[] 	= "ExtraPass";
char IDAP_hotkey[] 	= "Alt-4"; // Preferred/default

// Plug-in description block
extern "C" ALIGN(32) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,	// IDA version plug-in is written for
	PLUGIN_UNL,				// Plug-in flags
	IDAP_init,	            // Initialization function
	IDAP_term,	            // Clean-up function
	IDAP_run,	            // Main plug-in body
	IDAP_comment,	        // Comment - unused
	IDAP_help,	            // As above - unused
	IDAP_name,	            // Plug-in name shown in Edit->Plugins menu
	IDAP_hotkey	            // Hot key to run the plug-in
};

// Init
int IDAP_init()
{
    CORE_Init();
    return(PLUGIN_OK);   
}

// Un-init
void IDAP_term()
{
    CORE_Exit();
}

// Run 
void IDAP_run(int iArg)
{	
    CORE_Process(iArg);   
}



