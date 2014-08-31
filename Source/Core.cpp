
// ****************************************************************************
// File: Core.cpp
// Desc: Core of the 
//
// ****************************************************************************
#include "stdafx.h"
#include "ContainersInl.h"


//#define LOG_FILE

#define MIN_ALIGN_BYTES 2 // Minimal run of alignment bytes to consider

/*
    1st pass. Look for " dd " without "offset". Finds missing code
    For each found:
        1. Find the extents of the block and undefine it
        2. Analise it for code

    2nd pass. Look for " dw " without "offset". Finds missing code
    Same as above.

    3nd pass. Look for " db " without "offset". Finds missing code
    Same as above.

    4th pass. Look at gaps between functions. Finds missing functions
    If code is found try to make a function of it.

*/


// Process states
enum eSTATES
{
    eSTATE_INIT,   // Initialize

    eSTATE_PASS_1, // DWORD find
    eSTATE_PASS_2, // WORD find
    eSTATE_PASS_3, // BYTE find
    eSTATE_PASS_4, // Find missing "align" blocks
	eSTATE_PASS_5, // Find lost code
	eSTATE_PASS_6, // Find missing functions

    eSTATE_FINISH, // Done
    
    eSTATE_EXIT,
};


// Function info container
struct tFUNCNODE : public Container::NodeEx<Container::ListHT, tFUNCNODE>
{	
	ea_t uAddress;
	UINT uSize;

	// Use IDA allocs
	static PVOID operator new(size_t size){	return(qalloc(size)); };
	static void operator delete(PVOID _Ptr){ return(qfree(_Ptr)); }
};



// === Function Prototypes ===
static void ShowEndStats();
static BOOL CheckBreak();
static void NextState();
static LPCTSTR GetDisasmText(ea_t ea);
static LPCTSTR TimeString(TIMESTAMP Time);
static BOOL BuildFuncionList();
static void FlushFunctionList();
static void ProcessFuncGap(ea_t startEA, UINT uSize);
static void SafeJumpTo(ea_t ea);


// === Data ===
static TIMESTAMP  s_StartTime = 0;
static TIMESTAMP   s_StepTime = 0;
static segment_t  *s_pThisSeg = NULL;
static ea_t s_uStartAddress   = NULL;
static ea_t s_uCurrentAddress = NULL;
static ea_t s_uLastAddress    = NULL;
#ifdef LOG_FILE
static FILE *s_hLogFile       = NULL;
#endif
static BOOL s_bStepStop       = TRUE;
static eSTATES s_eState       = eSTATE_INIT;
static int  s_iStartFuncCount = 0;
static UINT s_uStrayDWORD     = 0;
static UINT s_uStrayWORD      = 0;
static UINT s_uStrayBYTE      = 0;
static UINT s_uAligns         = 0;
static WORD s_wDoDataToBytes  = 1;
static WORD s_wDoAlignBlocks  = 1;
static WORD s_wDoMissingCode  = 1;
static WORD s_wDoMissingFunc  = 1;
static ALIGN(32) Container::ListEx<Container::ListHT, tFUNCNODE> s_FuncList;

// Options dialog
static const char szOptionDialog[] =
{	
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'
	
	// Help block
	"HELP\n"
	"\"ExtraPass PlugIn\"" 
	"An IDA Pro 5.xx Win32 executable clean up plug-in.\n"
	"By Sirmabus\n\n"
	
	"This plug-in does an extra pass on the first code section\n"
	"in attempts to fix several anomalies found with some\n"
	"Win32 native executables. In particular ones with lots script\n"
	"stubs, etc.\n\n"

	"It does essentially four passes:\n"
	"1. Convert all stray data to \"unknown\" (for the following passes).\n\n"

	"2. Fixes \"align xx\" blocks.\n"
	"These are internally runs of CCh (int 3), or 90h ('nop') bytes.\n\n"

	"3. Scans for missing code. Basically tells IDA to convert stray data bytes to code.\n"
	"Finds new blocks of codes, or reverts back to data (unfortunately such as in return'less\n"
	"exception blocks, or unfortunately some times messes up data/index tables.\n\n"

	"4. Finds missing/undefined functions. It does this by finding gaps from the end of one\n"
	"function to the next.\n\n"

	"For best results, run the plug-in at least two times.\n"
	"See \"ExtraPass.txt\" for more help.\n"
	"ENDHELP\n"	

	// Title
	"<ExtraPass Plug-in>\n"

	// Message text
	"-Version: %A, %A, by Sirmabus-\n\n" 		
	"WARNING: Save your DB before running this plug-in!\nIt might cause adverse effects or even lock up in some cases!  \n\n"

	"Choose processing passes:\n"	

	// checkbox -> s_wDoDataToBytes 
	"<#Scan the entire code section converting all DD,DW,DB data declarations back to\n"		// hint
	"unknown bytes, to be reexamined as possible code, functions, and alignment blocks\n"	
	"in the next passes.#"
	"1 Byte scan                 :C>>\n"																// label

	// checkbox -> s_wDoAlignBlocks 
	"<#Find missing \"align xx\" blocks.#"
	"2 Find align blocks       :C>>\n"																		    

	// checkbox -> s_wDoMissingCode 
	"<#Find lost code bytes.#"
	"3 Find missing code      :C>>\n"																		    

	// checkbox -> s_wDoMissingFunc 
	"<#Find missing/undeclared functions.#"
	"4 Find missing functions:C>>\n\n\n"
};


// Initialize
void CORE_Init()
{        
    s_eState = eSTATE_INIT;
}


// Un-initialize
void CORE_Exit()
{
	#ifdef LOG_FILE
    if(s_hLogFile) 
    {
        qfclose(s_hLogFile);
        s_hLogFile = NULL;
    } 
	#endif

	FlushFunctionList();
    set_user_defined_prefix(0, NULL);
}
    

// Plug-in process
void CORE_Process(int iArg)
{   
    while(TRUE)
    {
        switch(s_eState)
        {
            // Initialize
            case eSTATE_INIT:
            {            
				msg("\n== ExtraPass plug-in: v: %s - %s, By Sirmabus ==\n", MY_VERSION, __DATE__); 
				
				// Do UI for process pass selection
				s_wDoDataToBytes = s_wDoAlignBlocks = s_wDoMissingCode = s_wDoMissingFunc = 1;
				int iUIResult = AskUsingForm_c(szOptionDialog, MY_VERSION, __DATE__, &s_wDoDataToBytes, &s_wDoAlignBlocks, &s_wDoMissingCode, &s_wDoMissingFunc);
				if(!iUIResult || ((s_wDoDataToBytes + s_wDoAlignBlocks + s_wDoMissingCode + s_wDoMissingFunc) == 0))
				{		
					// User canceled, or no options selected, bail out
					msg(" - Canceled -\n\n");
					s_eState = eSTATE_EXIT;
					break;
				}

                // IDA must be IDLE 
                if(autoIsOk())
                {                    
                    // Ask for the log file name once
                    #ifdef LOG_FILE
                    if(!s_hLogFile)
                    {
                        if(char *szFileName = askfile_c(1, "*.txt", "Select a log file name:"))
                        {     
                            // Open it for appending
                            s_hLogFile = qfopen(szFileName, "ab");       
                        }
                    }
                    if(!s_hLogFile)
                    {
                        msg("** Log file open failed! Aborted. **\n");
                        return;
                    }    
                    #endif
                         
                    s_pThisSeg = NULL;
                    s_uCurrentAddress = 0;                    
                    s_uStrayDWORD = 0, s_uStrayWORD = 0, s_uStrayBYTE = 0;
					s_iStartFuncCount = get_func_qty();
                    
                    if(s_iStartFuncCount > 0)
                    {    
                        //msg("Starting function count: %d\n", s_iStartFuncCount);
                        
                        /*
                        msg("\n=========== Segments ===========\n");
                        int iSegCount = get_segm_qty();              
                        for(int i = 0; i < iSegCount; i++)
                        {                            
                            if(segment_t *pSegInfo = getnseg(i))
                            {
                                char szName[128] = {0};
                                get_segm_name(pSegInfo, szName, (sizeof(szName) - 1));
                                char szClass[16] = {0};
                                get_segm_class(pSegInfo, szClass, (sizeof(szClass) - 1));
                                msg("[%d] \"%s\", \"%s\".\n", i, szName, szClass);                                
                            }
                        }
                        */

                        // For now just pick the first code segment
                        // TODO: Make a UI to select which segment, and, or just do all code segments
                        int iSegCount = get_segm_qty();              
                        int iIndex = 0;
                        for(; iIndex < iSegCount; iIndex++)
                        {                            
                            if(s_pThisSeg = getnseg(iIndex))
                            {
                                char szClass[16] = {0};
                                get_segm_class(s_pThisSeg, szClass, (sizeof(szClass) - 1));
                                if(strcmp(szClass, "CODE") == 0)
                                    break;
                            }
                        }

                        // Found one?
                        if(s_pThisSeg && (iIndex < iSegCount))
                        {
							// TODO: Add UI handler for "cancel"
							show_wait_box("  Take a smoke, drink some coffee, this could be a while..   \n<Press Pause/Break key to abort>"); 

                            char szName[128] = {0};
                            get_segm_name(s_pThisSeg, szName, (sizeof(szName) - 1));
                            if(szName[0] == '_') szName[0] = ',';
                            char szClass[16] = {0};
                            get_segm_class(s_pThisSeg, szClass, (sizeof(szClass) - 1));
                            msg("Processing segment: \"%s\", \"%s\".\n\n", szName, szClass);                            

							// Save start position
							s_uStartAddress = get_screen_ea();                            
                           
							// Move to first process state
							s_StartTime = GetTimeStamp();
							NextState();
							break;							
                        }
                        else
                            msg("** No code segment found to process! **\n*** Aborted ***\n\n");
                    }
                    else
                        msg("** No functions in DB?! **\n*** Aborted ***\n\n");
                }
                else
                     msg("** Wait for IDA to finish processing before starting plug-in! **\n*** Aborted ***\n\n");

				// Canceled or error'ed, bail out
                s_eState = eSTATE_EXIT;
            }
            break;
        

            // Process DWORDs
            case eSTATE_PASS_1:
            {
                // Still inside segment?
                if(s_uCurrentAddress < s_pThisSeg->endEA)
                {
                    // Look for next DWORD
                    ea_t uAddress = find_text(s_uCurrentAddress, 0,0, " dd ", (SEARCH_DOWN | SEARCH_CASE));
                    if(uAddress < s_pThisSeg->endEA)
                    {
                        s_uCurrentAddress = uAddress;                        
                                                                  
                        // If it's not an offset, then try to make code of it
                        LPCTSTR pszLine = GetDisasmText(s_uCurrentAddress);
                        if(!strstr(pszLine, "dd offset "))
                        {
                            s_uStrayDWORD++;
                            
                            //msg("Line: %08X \"%s\".\n", s_uCurrentAddress, pszLine);                                                        
                            SafeJumpTo(s_uCurrentAddress);
                            ea_t uEnd = next_head(s_uCurrentAddress, s_pThisSeg->endEA); 
                          
                            // Make it unknown bytes
                            autoWait();
                            do_unknown(s_uCurrentAddress, FALSE);							
                            auto_mark_range(s_uCurrentAddress, uEnd, AU_UNK);
							autoWait();
                            s_uCurrentAddress = uEnd;
                            break;                               
                        }

                        s_uCurrentAddress = next_head(s_uCurrentAddress, s_pThisSeg->endEA);
                        break;
                    }                   
                }
               
                // To word pass	
				NextState();				
            }
            break;

            
            // Process WORDs
            case eSTATE_PASS_2:
            {             
                // Still inside segment?
                if(s_uCurrentAddress < s_pThisSeg->endEA)
                {
                    // Look for next WORD
                    ea_t uAddress = find_text(s_uCurrentAddress, 0,0, " dw ", (SEARCH_DOWN | SEARCH_CASE));
                    if(uAddress < s_pThisSeg->endEA)
                    {
                        s_uCurrentAddress = uAddress;
                        s_uStrayWORD++;                        
                        SafeJumpTo(s_uCurrentAddress);
                        ea_t uEnd = next_head(s_uCurrentAddress, s_pThisSeg->endEA);   

                        // Fix bug w/find_text() where it finds on start of seg
                        if(s_uCurrentAddress == s_pThisSeg->startEA)
                        {
                            // There could really be a dw here
                            LPCTSTR pszLine = GetDisasmText(s_uCurrentAddress);
                            if(!strstr(pszLine, " dw "))
                            {
                                s_uCurrentAddress = uEnd;
                                break;                       
                            }
                        }

						// Make it unknown bytes
                        autoWait();
                        do_unknown(s_uCurrentAddress, FALSE);				
                        auto_mark_range(s_uCurrentAddress, uEnd, AU_UNK);
						autoWait();
                        s_uCurrentAddress = uEnd;
                        break;
                    }                   
                }      

				// To byte pass			
				NextState();				            
            }
            break;


            // Process BYTEs       
            case eSTATE_PASS_3:
            {
                // Still inside segment?
                if(s_uCurrentAddress < s_pThisSeg->endEA)
                {
                    // Look for next BYTE
                    ea_t uAddress = find_text(s_uCurrentAddress, 0,0, " db ", (SEARCH_DOWN | SEARCH_CASE));
                    if(uAddress < s_pThisSeg->endEA)
                    {
                        s_uCurrentAddress = uAddress;
                        s_uStrayBYTE++;                                                                                   
                        ea_t uEnd = next_head(s_uCurrentAddress, s_pThisSeg->endEA);                        

                        // Catch when we get caught up in an array, etc.
                        if(s_uCurrentAddress <= s_uLastAddress)
                        {                         
                            // Move to next header and try again..
                            s_uCurrentAddress = uEnd;
                            s_uLastAddress = s_uCurrentAddress;
                            break;
                        }         
                        
                        // Only move screen from one section to the next
                        if(s_uCurrentAddress > (s_uLastAddress + 1))
                            SafeJumpTo(s_uCurrentAddress);
                        s_uLastAddress = s_uCurrentAddress;

                        // Fix bug w/find_text() where it finds on start of seg
                        if(s_uCurrentAddress == s_pThisSeg->startEA)
                        {
                            // There could really be a byte here
                            LPCTSTR pszLine = GetDisasmText(s_uCurrentAddress);
                            if(!strstr(pszLine, " db "))
                            {
                                s_uCurrentAddress = uEnd;
                                break;                       
                            }
                        }
              
                        autoWait();
                        do_unknown(s_uCurrentAddress, FALSE);				
                        auto_mark_range(s_uCurrentAddress, uEnd, AU_UNK);
						autoWait();
						s_uCurrentAddress = uEnd;

                        // Move to next byte to step through stray align bytes, etc.                       
                        //s_uCurrentAddress = nextaddr(s_uCurrentAddress);
                        break;
                    }                   
                }                             
               
				// Next state
				NextState();                
            }
            break;


            // Find missing align blocks
            case eSTATE_PASS_4:
            {								
				// Still inside segment?
				if(s_uCurrentAddress < s_pThisSeg->endEA)
                {					
                    // Look for next BYTE
                    ea_t uStartAddress = s_uCurrentAddress = find_text(s_uCurrentAddress, 0,0, " db ", (SEARCH_DOWN | SEARCH_CASE));
                    if(uStartAddress < s_pThisSeg->endEA)
                    {
						// Fix bug w/find_text() where it finds on start of seg
						if(s_uCurrentAddress == s_pThisSeg->startEA)
						{
							// There could really be a byte here
							LPCTSTR pszLine = GetDisasmText(s_uCurrentAddress);
							if(!strstr(pszLine, " db "))
							{
								s_uCurrentAddress = next_head(s_uCurrentAddress, s_pThisSeg->endEA);
								break;
							}
						}						
                              
                        // Catch when we get caught up in an array, etc.
                        if(s_uCurrentAddress <= s_uLastAddress)
                        {
                            // Move to next header and try again..
                            s_uCurrentAddress = next_head(s_uCurrentAddress, s_pThisSeg->endEA);
                            s_uLastAddress = s_uCurrentAddress;
                            break;
                        }                                                                                 

						// Only move cursor/screen from one section to the next
						if(s_uCurrentAddress > (s_uLastAddress + 1))
							SafeJumpTo(s_uCurrentAddress);
						s_uLastAddress = s_uCurrentAddress;				

						// Is the byte a possible alignment byte?
						// 0x000001?? = unknown byte w/o xref
						UINT uFirstByte = (UINT) getFlags(uStartAddress);
						if((uFirstByte == 0x000001CC) || (uFirstByte == 0x00000190))
						{							
							//msg("%08X Start.\n", uStartAddress); 
							//msg("%08X F: %08X.\n", uStartAddress, getFlags(uStartAddress));

							// Look for a run of them
							UINT uACount = 1;
							while(TRUE)
							{
								// Next byte
								s_uCurrentAddress = nextaddr(s_uCurrentAddress);								
                                //msg("%08X Next.\n", s_uCurrentAddress);                                
								//msg("%08X F: %08X.\n", s_uCurrentAddress, getFlags(s_uCurrentAddress));
								
								if(s_uCurrentAddress < s_pThisSeg->endEA)
								{									
									// Catch when we get caught up in an array, etc.
									if(s_uCurrentAddress <= s_uLastAddress)
									{
										// Move to next header and try again..
										s_uCurrentAddress = next_head(s_uCurrentAddress, s_pThisSeg->endEA);
										s_uLastAddress = s_uCurrentAddress;
										break;
									}   								
									s_uLastAddress = s_uCurrentAddress;									  									
															
									// Count if it' still the same byte
									if(getFlags(s_uCurrentAddress) == uFirstByte)																					
										uACount++;										
									else
										break;																						
								}
								else
									break;
							};

							// Minimal byte count?
							if(uACount >= MIN_ALIGN_BYTES)
							{
								// Does minimal bytes bring align?
								if(uACount == MIN_ALIGN_BYTES)
								{
									if((uStartAddress + uACount) & (16 - 1))
										break;
								}

								// Attempt to make it an align block
								//msg("%08X %d ALIGN.\n", uStartAddress, uACount); 
								s_uAligns += (UINT) doAlign(uStartAddress, uACount, 0);															
							}								
						}

						// Move to next	item before next search					
						s_uCurrentAddress = s_uLastAddress = next_head(s_uCurrentAddress, s_pThisSeg->endEA);
                    }    					
                }
				else				
					NextState();				
            }
            break;


			// Find missing code      
			case eSTATE_PASS_5:
			{
				// Still inside segment?
				if(s_uCurrentAddress < s_pThisSeg->endEA)
				{
					// Look for next BYTE
					ea_t uAddress = find_text(s_uCurrentAddress, 0,0, " db ", (SEARCH_DOWN | SEARCH_CASE));
					if(uAddress < s_pThisSeg->endEA)
					{
						s_uCurrentAddress = uAddress;
						s_uStrayBYTE++;                                                                                   
						ea_t uEnd = next_head(s_uCurrentAddress, s_pThisSeg->endEA);                        

						// Catch when we get caught up in an array, etc.
						if(s_uCurrentAddress <= s_uLastAddress)
						{                         
							// Move to next header and try again..
							s_uCurrentAddress = uEnd;
							s_uLastAddress = s_uCurrentAddress;
							break;
						}         

						// Only move screen from one section to the next
						if(s_uCurrentAddress > (s_uLastAddress + 1))
							SafeJumpTo(s_uCurrentAddress);
						s_uLastAddress = s_uCurrentAddress;

						// Fix bug w/find_text() where it finds on start of seg
						if(s_uCurrentAddress == s_pThisSeg->startEA)
						{
							// There could really be a byte here
							LPCTSTR pszLine = GetDisasmText(s_uCurrentAddress);
							if(!strstr(pszLine, " db "))
							{
								s_uCurrentAddress = uEnd;
								break;                       
							}
						}

						// Try to make code of it
						autoWait();
						ua_code(s_uCurrentAddress);  
						s_uCurrentAddress = uEnd;                                                                         
						
						// Move to next byte to step through stray align bytes, etc.                       
						//s_uCurrentAddress = nextaddr(s_uCurrentAddress);
						break;
					}                   
				}

				// Next state
				NextState();				
			}
			break;

            
            // Discover missing functions			
            case eSTATE_PASS_6:
            {    
				// Process function list top down
				if(tFUNCNODE *pHeadNode = s_FuncList.GetHead())
				{
					// Process it
					ProcessFuncGap(pHeadNode->uAddress, pHeadNode->uSize);
					
					// Remove it
					s_FuncList.RemoveHead();
					delete pHeadNode;
				}
				else				
					NextState();				
            }
            break;


            // Finished processing
            case eSTATE_FINISH:            			
			NextState();            
            break;
            
            // Done processing
            case eSTATE_EXIT:
            {
				NextState();
                goto BailOut; 
            }
            break;
        };

		// Check & bail out on 'break' press
		if(CheckBreak())
			goto BailOut;
    
        //Sleep(1); // Breathing room
    };

    BailOut:;
	hide_wait_box();
}


// Decide next state to take
static void NextState()
{
	// Rewind
	if(s_eState < eSTATE_FINISH)
	{
		// Top of code seg
		s_uCurrentAddress = s_uLastAddress = s_pThisSeg->startEA; 
		SafeJumpTo(s_uCurrentAddress);
		autoWait(); 		
	}

	// Logic
	switch(s_eState)
	{ 
		// Start
		case eSTATE_INIT:
		{
			if(s_wDoDataToBytes)
			{
				msg("===== Finding DWORDs =====\n");                            
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_1;
			}
			else
			if(s_wDoAlignBlocks)
			{
				msg("===== Missing align blocks =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_wDoMissingCode)
			{
				msg("===== Missing code =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_5;
			}
			else
			if(s_wDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
					
				if(BuildFuncionList())				
					s_eState = eSTATE_PASS_6;				
				else
					s_eState = eSTATE_FINISH;				
			}
			else
				s_eState = eSTATE_FINISH;
		}
		break;

		// DWORD to WORDs
		case eSTATE_PASS_1:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 
			msg("===== Finding WORDs =====\n");
			msg("<Press Break/Pause key to abort>\n");
			s_StepTime = GetTimeStamp();
			s_eState = eSTATE_PASS_2;
		}
		break;

		// WORDs to BYTEs
		case eSTATE_PASS_2:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 
			msg("===== Finding BYTES =====\n");
			msg("<Press Break/Pause key to abort>\n");		
			s_StepTime = GetTimeStamp();
			s_eState = eSTATE_PASS_3;          
		}
		break;
		
		// BYTEs to ??
		case eSTATE_PASS_3:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 

			if(s_wDoAlignBlocks)
			{				
				msg("===== Missing align blocks =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_wDoMissingCode)
			{				
				msg("===== Missing code =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_5;
			}
			else
			if(s_wDoMissingFunc)
			{				
				msg("===== Missing functions =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				
				if(BuildFuncionList())				
					s_eState = eSTATE_PASS_6;				
				else
					s_eState = eSTATE_FINISH;				
			}
			else
				s_eState = eSTATE_FINISH;
		}
		break;


		// From missing align block pass
		case eSTATE_PASS_4:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 
		
			if(s_wDoMissingCode)
			{				
				msg("===== Missing code =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_5;
			}
			else
			if(s_wDoMissingFunc)
			{				
				msg("===== Missing functions =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();

				if(BuildFuncionList())				
					s_eState = eSTATE_PASS_6;				
				else
					s_eState = eSTATE_FINISH;				
			}
			else
				s_eState = eSTATE_FINISH;
		}
		break;

		// From missing code pass
		case eSTATE_PASS_5:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 
			
			if(s_wDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
				msg("<Press Break/Pause key to abort>\n");
				s_StepTime = GetTimeStamp();

				if(BuildFuncionList())				
					s_eState = eSTATE_PASS_6;				
				else
					s_eState = eSTATE_FINISH;				
			}
			else
				s_eState = eSTATE_FINISH;
		}
		break;

		// From missing function pass
		case eSTATE_PASS_6:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime)); 
			s_eState = eSTATE_FINISH;
		}
		break;


		// From final pass, we're done
		case eSTATE_FINISH:	
		{			
			autoWait();				
			msg("\n===== Done =====\n");

			// Restore starting point
			SafeJumpTo(s_uStartAddress);

			// Show final stats
			ShowEndStats();                            
			s_eState = eSTATE_EXIT;
		}
		break;
	
		// Exit plug-in run back to IDA control
		case eSTATE_EXIT:	
		{
			// In case we aborted some place and list still exists..
			FlushFunctionList();
			s_eState = eSTATE_INIT;	
		}
		break;
	};
}


// Print out end stats
static void ShowEndStats()
{		
	msg("Total time: %s.\n", TimeString(GetTimeStamp() - s_StartTime));                	
	msg("Alignments: %d\n", s_uAligns);
	msg(" Functions: %d\n", ((int) get_func_qty() - s_iStartFuncCount));

	//msg("DDs: %d\n", s_uStrayDWORD);
	//msg("DWs: %d\n", s_uStrayWORD);
	//msg("DBs: %d\n", s_uStrayBYTE);

	msg(" \n");
}


// Checks and handles if break key pressed; returns TRUE on break.
ALIGN(32) static BOOL CheckBreak()
{
	if(GetAsyncKeyState(VK_PAUSE) & 0x8000)
	{		
		if((s_pThisSeg->startEA != BADADDR) && (s_pThisSeg->endEA != BADADDR))
		{
			msg("\n*** Aborted @ %08X ***\n\n", s_uCurrentAddress);
			if((s_uCurrentAddress >= s_pThisSeg->startEA) && (s_uCurrentAddress <= s_pThisSeg->endEA))
				SafeJumpTo(s_uCurrentAddress);
		}
		else
			msg("\n*** Aborted ***\n\n");

		// Show stats then directly to exit
		autoWait();
		ShowEndStats();
		s_eState = eSTATE_EXIT;
		return(TRUE);
	}

	return(FALSE);
}


// Safe "jumpto()" that dosn't cash on out of bounds input address
ALIGN(32) static void SafeJumpTo(ea_t ea)
{
	if(s_pThisSeg)
	{	
		try
		{			
			if(ea < s_pThisSeg->startEA)
				ea = s_pThisSeg->startEA;
			else
			if(ea > s_pThisSeg->endEA)
				s_pThisSeg->endEA;

			jumpto(ea, 0);
		}
		catch(PVOID)
		{
		}	
	}
}


// Build local list of function gaps
// There is a problem with IDA enumerating using get_next_func() after there is a change in between.
// So we build a local list first then process it for missing functions.							
static BOOL BuildFuncionList()
{
	int iCount = 0;
	FlushFunctionList();

	//Log(s_hLogFile, "\n====== Function gaps ======\n");

	if(func_t *pLastFunc = get_next_func(s_pThisSeg->startEA))
	{
		while(func_t *pNextFunc = get_next_func(pLastFunc->startEA))
		{					
			// A gap between the last function?                    						
			int iGap = ((int) pNextFunc->startEA - (int) pLastFunc->endEA);
			if(iGap > 0)
			{				
				//Log(s_hLogFile, "%08X GAP[%06d] %d.\n", pLastFunc->endEA, iCount++, iGap);				

				// Add it to the list				
				if(tFUNCNODE *pNode = new tFUNCNODE())
				{	
					pNode->uAddress = pLastFunc->endEA;
					pNode->uSize    = (UINT) iGap;

					if(s_FuncList.IsEmpty())
						s_FuncList.InsertHead(*pNode);					
					else
						s_FuncList.InsertTail(*pNode);
				}
			}

			pLastFunc = pNextFunc;
		};		
	}

	//Log(s_hLogFile, "\n\n");

	return(!s_FuncList.IsEmpty());
}

// Free function list
static void FlushFunctionList()
{
	while(tFUNCNODE *pHeadNode = s_FuncList.GetHead())
	{		
		s_FuncList.RemoveHead();
		delete pHeadNode;
	};
}




// Get a nice line of disassembled code text sans color tags
ALIGN(32) static LPCTSTR GetDisasmText(ea_t ea)
{
    static char szBuff[MAXSTR];
    szBuff[0] = szBuff[MAXSTR - 1] = 0;
    generate_disasm_line(ea, szBuff, (sizeof(szBuff) - 1));
    tag_remove(szBuff, szBuff, (sizeof(szBuff) - 1));
    return(szBuff);
}


// Get a pretty delta time string for output
static LPCTSTR TimeString(TIMESTAMP Time)
{
    static char szBuff[64];
    ZeroMemory(szBuff, sizeof(szBuff));

    if(Time >= HOUR)  
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f hours", (Time / (TIMESTAMP) HOUR));    
    else
    if(Time >= MINUTE)    
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f minutes", (Time / (TIMESTAMP) MINUTE));    
    else
        _snprintf(szBuff, (sizeof(szBuff) - 1), "%.2f seconds", Time);    

    return(szBuff);
}



// Try adding a function at specified address
ALIGN(32) static BOOL TryFunction(ea_t &curEA, ea_t &CodeStartEA, BOOL &bIsCodeWhole)  
{
	BOOL bResult = FALSE;

    if(bIsCodeWhole && (CodeStartEA != BADADDR))
    {
		//Log(s_hLogFile, "    %08X Trying function.\n", CodeStartEA);		
				
        // Try to make last code start address
		autoWait();
        if(add_func(CodeStartEA, BADADDR))
        {                      			                   
			// Wait till IDA is done creating the function, then get it's info
			autoWait();		
			if(func_t *pFunc = get_func(CodeStartEA))
			{
				// Look at function tail opcode
				ea_t tailEA = prev_head(pFunc->endEA, CodeStartEA);
				if(tailEA != BADADDR)
				{	
					//Log(s_hLogFile, "    End: %08X, %s.\n", tailEA, GetDisasmText(tailEA));	

					// If there is not a return or jump here then revert it back to unknown
					// This is usually either from incorrectly making code form data,
					// or part of some bad split up function code.	
					LPCSTR pszEndCode = GetDisasmText(tailEA);
					if((strncmp(pszEndCode, "retn", SIZESTR("retn")) != 0) && (strncmp(pszEndCode, "jmp", SIZESTR("jmp")) != 0))
					{						
						//Log(s_hLogFile, "    Weird end, reverting bytes.\n");
						msg("%08X Function problem <click me>\n", CodeStartEA);
						auto_mark_range(CodeStartEA, pFunc->endEA, AU_UNK);
						autoWait();
					}
					else
					{
						// Update current look position to the end of this function						
						//Log(s_hLogFile, "    %08X Fixed function.\n", CodeStartEA);  
						curEA = pFunc->endEA;
						//Log(s_hLogFile, "    New pos: %08X, %s.\n", curEA, GetDisasmText(curEA)); 
						bResult = TRUE;
					}
				}				
			}

			CodeStartEA = BADADDR;     
        }       		
    }    

    bIsCodeWhole = FALSE;
	return(bResult);
}

// prob: 004094B5

// Process the gap from the end of one function to the start of the next
// looking for missing functions in between.
ALIGN(32) static void ProcessFuncGap(ea_t startEA, UINT uSize)
{ 
	ea_t curEA = startEA;
	ea_t endEA = (startEA + uSize);

	// Move too it
	autoWait();
	SafeJumpTo(curEA);
	//Log(s_hLogFile, "\nS: %08X, E: %08X ==== PFG START ====\n", startEA, endEA);

    // Traverse gap
	ea_t CodeStartEA = BADADDR;
	BOOL bIsCodeWhole  = FALSE;

    while(curEA < endEA)
    {      		
		//Log(s_hLogFile, "  C: %08X, F: %08X, \"%s\".\n", curEA, getFlags(curEA), GetDisasmText(curEA));
	
        // Skip over "align" blocks.
        // #1 we will typically see more of these then anything else
        flags_t uFlags = getFlags(curEA);
        if(isAlign(uFlags))                    
        {      
            // Function between?
            if(TryFunction(curEA, CodeStartEA, bIsCodeWhole))
				continue;
        }
        else
        {
            // #2 case, we'll typically see data
            if(isData(uFlags))
            {
                // Function between?
				if(TryFunction(curEA, CodeStartEA, bIsCodeWhole))
					continue;

                bIsCodeWhole = FALSE;
            }		
            else
            // Hit some code?
            if(isCode(uFlags))
            {        			
                // Yay!, mark the start of a possible code block
                if(CodeStartEA == BADADDR)
                {					
                    CodeStartEA  = curEA;
					bIsCodeWhole = TRUE;

					// Code + empty byte is usually the start of a function
					if(!(uFlags & 0xFFFF0000))
					{
						//Log(s_hLogFile, "  *** START ***\n");
						if(TryFunction(curEA, CodeStartEA, bIsCodeWhole))
							continue;
					}
                }				
            }                     
            else
            // Undefined?
            // Usually 0xCC align bytes
            if(isUnknown(uFlags))
            {            
				//Log(s_hLogFile, "  C: %08X, Unknown type.\n", curEA);
				bIsCodeWhole = FALSE; 
            }
            else
            {                
                //Log(s_hLogFile, "  %08X ** unknown data type! **\n", curEA);
                bIsCodeWhole = FALSE; 
            }      
        }
            
		// Next item
		ea_t nextEA = next_head(curEA, endEA);
        if(nextEA != BADADDR)
			curEA = nextEA;
		else
		{
			//Log(s_hLogFile, "  Gap end: %08X.\n", curEA);
            break;
		}
        
    }; // while(curEA < startEA)
}

