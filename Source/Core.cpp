
// ****************************************************************************
// File: Core.cpp
// Desc: Core of the
//
// ****************************************************************************
#include "stdafx.h"
#include <WaitBoxEx.h>
#include <SegSelect.h>
#include <IdaOgg.h>
#include <unordered_set>
#include <vector>

#include "complete_ogg.h"

//#define VBDEV
//#define LOG_FILE

// Count of eSTATE_PASS_1 unknown byte gather passes
#define UNKNOWN_PASSES 8

// x86 hack for speed in alignment value searching
// Defs from IDA headers, not supposed to be exported but need to because some cases not covered
// by SDK accessors.
//#define MS_VAL  0x000000FFL		// Mask for byte value
//#define FF_UNK  0x00000000L		// Unknown ?
#define FF_IVL  0x00000100L		// Byte has value ?
//#define FF_DATA 0x00000400L		// Data ?
//#define FF_TAIL 0x00000200L     // Tail ?
#define FF_REF  0x00001000L     // has references
#define FF_0OFF 0x00500000L		// Offset?
//#define FF_ASCI 0x50000000L     // ASCII ?

const flags_t ALIGN_VALUE1 = (FF_IVL | 0xCC); // 0xCC (single byte "int 3") byte type
const flags_t ALIGN_VALUE2 = (FF_IVL | 0x90); // NOP byte type

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

	5th pass. Look for bad function blocks. These are blocks that are incorrectly placed as function headers, etc.
	If found, try to add them to their proper owner functions.
*/


// Process states
enum eSTATES
{
    eSTATE_INIT,	// Initialize
	eSTATE_START,	// Start processing up

    eSTATE_PASS_1,	// Find unknown data in code space
    eSTATE_PASS_2,	// Find missing "align" blocks
	eSTATE_PASS_3,	// Find lost code instructions
	eSTATE_PASS_4,  // Find missing functions part 1
	eSTATE_PASS_5,  // Find bad function blocks

    eSTATE_FINISH, // Done

    eSTATE_EXIT,
};

static const char SITE_URL[] = { "http://www.macromonkey.com/bb/" };

// UI options bit flags
// *** Must be same sequence as check box options
static SBITFLAG BitF;
const static WORD OPT_DATATOBYTES = BitF.Next();
const static WORD OPT_ALIGNBLOCKS = BitF.Next();
const static WORD OPT_MISSINGCODE = BitF.Next();
const static WORD OPT_MISSINGFUNC = BitF.Next();
const static WORD OPT_BADBLOCKS   = BitF.Next();

// Function info container
struct FUNCNODE
{
	ea_t address;
	UINT size;
};

typedef std::unordered_set<ea_t> ADDRSET;
typedef std::vector<FUNCNODE> FUNCLIST;

// === Function Prototypes ===
static void showEndStats();
static void nextState();
static LPCTSTR getDisasmText(ea_t ea);
static LPCTSTR timeString(TIMESTAMP Time);
static void buildFuncionList();
static void processFuncGap(ea_t start, UINT size);
static bool idaapi isAlignByte(flags_t flags, void *ud);
static bool idaapi isData(flags_t flags, void *ud);
static BOOL inCode(ea_t address);
static BOOL hasBadFuncStart(func_t *f);
static int  fixFuncBlock(ea_t blockAddress);

// === Data ===
static TIMESTAMP s_startTime = 0, s_stepTime = 0;
static segment_t *s_thisSeg  = NULL;
static ea_t s_segStart       = NULL;
static ea_t s_segEnd         = NULL;
static ea_t s_currentAddress = NULL;
static ea_t s_lastAddress    = NULL;
static BOOL s_isBreak        = FALSE;
#ifdef LOG_FILE
static FILE *s_logFile       = NULL;
#endif
static eSTATES s_state       = eSTATE_INIT;
static int  s_startFuncCount = 0;
static int  s_pass1Loops     = 0;
static UINT s_funcCount      = 0;
static UINT s_funcIndex      = 0;
//
static UINT s_unknownDataCount = 0;
static UINT s_alignFixes       = 0;
static UINT s_blocksFixed      = 0;
static UINT s_codeFixes        = 0;
//
static BOOL s_doDataToBytes  = TRUE;
static BOOL s_doAlignBlocks  = TRUE;
static BOOL s_doMissingCode  = TRUE;
static BOOL s_doMissingFunc  = TRUE;
static BOOL s_doBadBlocks    = TRUE;
static WORD s_audioAlertWhenDone = 1;
static SegSelect::segments *chosen = NULL;
static ALIGN(16) FUNCLIST s_funcList;


// Options dialog
static const char optionDialog[] =
{
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'

	// Help body
	"HELP\n"
	"\"ExtraPass PlugIn\""
	"An IDA Pro Win32 x86 executable clean up plugin, by Sirmabus\n\n"

	"This plugin does an \"extra pass\" to help fix and cleanup the IDB.\n"
	"It can find tens of thousands missing functions and alignment blocks making\n"
	"your IDB more complete and easier to reverse.\n\n"

	"It actually does essentially five processing steps:\n"
	"1. Convert stray code section values to \"unknown\".\n"
	"2. Fix missing \"align\" blocks.\n"
	"3. Fix missing code bytes.\n"
	"4. Locate and fix missing/undefined functions.\n"
	"5. Locate and fix bad function blocks.\n\n"

	"It's intended for, and only tested on typical MSVC and Intel complied Windows\n"
	"32bit binary executables but it might still be helpful on Delphi/Borland and\n"
	"other complied targets.\n"
	"For best results, run the plugin at least two times.\n"
	"Will not work well with Borland(r) and other targets that has data mixed with code in the same space.\n"
	"See \"ExtraPass.txt\" for more help.\n\n"
	"Forum: http://www.macromonkey.com/bb/\n"
	"ENDHELP\n"

	// Title
	"ExtraPass Plugin\n"

	// Message text
	"Version %Aby Sirmabus\n"
    "<#Click to open site.#www.macromonkey.com:k:2:1::>\n\n"

	"Choose processing steps:\n"

	// checkbox -> s_wDoDataToBytes
	"<#Scan the entire code section converting all unknown DD,DW,DB data declarations to\n"
	"unknown bytes, to be reexamined as possible code, functions, and alignment blocks\n"
	"in the following passes.#1 Convert unknown data.                                     :C>\n"

	// checkbox -> s_wDoAlignBlocks
	"<#Fix missing \"align xx\" blocks.#2 Fix align blocks.:C>\n"

	// checkbox -> s_wDoMissingCode
	"<#Fix lost code instructions.#3 Fix missing code.:C>\n"

	// checkbox -> s_wDoMissingFunc
	"<#Fix missing/undeclared functions.#4 Fix missing functions.:C>\n"

	// checkbox -> s_bDoBadBlocks
	"<#Fix bad/unconnected function blocks. Bad blocks incorrectly placed as a function head block\n"
	"when in actuality is a tail block, etc.#5 Fix bad function blocks.:C>>\n"

	// checkbox -> s_wAudioAlertWhenDone
	"<#Play sound on completion.#Play sound on completion.                                     :C>>\n"
	"<#Choose the code segment(s) to process.\nElse will use the first CODE segment by default.\n#Choose Code Segments:B:1:8::>\n"
    "                      "
};

// Checks and handles if break key pressed; returns TRUE on break.
static BOOL checkBreak()
{
    if (!s_isBreak)
    {
        if (WaitBox::isUpdateTime())
        {
            if (WaitBox::updateAndCancelCheck())
            {
                msg("\n*** Aborted ***\n\n");

                // Show stats then directly to exit               
                showEndStats();
                s_state = eSTATE_EXIT;
                s_isBreak = TRUE;
                return(TRUE);
            }
        }
    }
    return(s_isBreak);
}

// Make and address range "unknown" so it can be set with something else
static void makeUnknown(ea_t start, ea_t end)
{
    autoWait();
    //auto_mark_range(s_currentAddress, end, AU_UNK);
    //do_unknown(start, (DOUNK_SIMPLE | DOUNK_NOTRUNC));

    do_unknown_range(start, (end - start), (DOUNK_SIMPLE | DOUNK_NOTRUNC));
    autoWait();
}

// Initialize
void CORE_Init()
{   
    s_state = eSTATE_INIT;
}

// Un-initialize
void CORE_Exit()
{
    try
    {
        #ifdef LOG_FILE
        if(s_logFile)
        {
            qfclose(s_logFile);
            s_logFile = NULL;
        }
        #endif

        if (chosen)
        {
            SegSelect::free(chosen);
            chosen = NULL;
        }       

        s_funcList.clear();
        OggPlay::endPlay();
        set_user_defined_prefix(0, NULL);
    }
    CATCH()  
}

// Handler for choose code and data segment buttons
static void idaapi chooseBtnHandler(TView *fields[], int code)
{
    if (chosen = SegSelect::select(SegSelect::CODE_HINT, "Choose code segments"))
    {
        msg("Chosen: ");
        for (SegSelect::segments::iterator it = chosen->begin(); it != chosen->end(); ++it)
        {
            char buffer[64];
            if (get_true_segm_name(*it, buffer, SIZESTR(buffer)) <= 0)
                strcpy(buffer, "????");

            SegSelect::segments::iterator it2 = it; ++it2;
            if (it2 != chosen->end())
                msg("\"%s\", ", buffer);
            else
                msg("\"%s\"", buffer);
        }
        msg("\n");
        WaitBox::processIdaEvents();
    }
}

static void idaapi doHyperlink(TView *fields[], int code) { open_url(SITE_URL); }


// Plug-in process
void CORE_Process(int iArg)
{    
    try
    {   
        while (TRUE)
        {
            switch (s_state)
            {
                // Initialize
                case eSTATE_INIT:
                {
					char version[16];
					sprintf(version, "%u.%u", HIBYTE(MY_VERSION), LOBYTE(MY_VERSION));
					msg("\n>> ExtraPass: v: %s, BD: %s, By Sirmabus ==\n", version, __DATE__);
					refreshUI();                   
                    WaitBox::processIdaEvents();
                    s_isBreak = FALSE;

                    // Do UI for process pass selection
                    s_doDataToBytes = s_doAlignBlocks = s_doMissingCode = s_doMissingFunc = s_doBadBlocks = TRUE;
                    s_audioAlertWhenDone = TRUE;

                    WORD optionFlags = 0;
                    if (s_doDataToBytes) optionFlags |= OPT_DATATOBYTES;
                    if (s_doAlignBlocks) optionFlags |= OPT_ALIGNBLOCKS;
                    if (s_doMissingCode) optionFlags |= OPT_MISSINGCODE;
                    if (s_doMissingFunc) optionFlags |= OPT_MISSINGFUNC;
                    if (s_doBadBlocks)   optionFlags |= OPT_BADBLOCKS;

                    {
                        // To add forum URL to help box                   
                        int result = AskUsingForm_c(optionDialog, version, doHyperlink, &optionFlags, &s_audioAlertWhenDone, chooseBtnHandler);
                        if (!result || (optionFlags == 0))
                        {
                            // User canceled, or no options selected, bail out
                            msg(" - Canceled -\n\n");
                            WaitBox::processIdaEvents();
                            s_state = eSTATE_EXIT;
                            break;
                        }

                        s_doDataToBytes = ((optionFlags & OPT_DATATOBYTES) != 0);
                        s_doAlignBlocks = ((optionFlags & OPT_ALIGNBLOCKS) != 0);
                        s_doMissingCode = ((optionFlags & OPT_MISSINGCODE) != 0);
                        s_doMissingFunc = ((optionFlags & OPT_MISSINGFUNC) != 0);
                        s_doBadBlocks = ((optionFlags & OPT_BADBLOCKS) != 0);
                    }

                    // IDA must be IDLE
                    if (autoIsOk())
                    {
                        // Ask for the log file name once
                        #ifdef LOG_FILE
                        if(!s_logFile)
                        {
                            if(char *szFileName = askfile_c(1, "*.txt", "Select a log file name:"))
                            {
                                // Open it for appending
                                s_logFile = qfopen(szFileName, "ab");
                            }
                        }
                        if(!s_logFile)
                        {
                            msg("** Log file open failed! Aborted. **\n");
                            return;
                        }
                        #endif

                        s_thisSeg = NULL;
                        s_unknownDataCount = 0; 
                        s_alignFixes = s_blocksFixed = s_codeFixes = 0;
                        s_pass1Loops = 0; s_funcIndex = 0;
                        s_startFuncCount = get_func_qty();
                        s_funcList.reserve(s_startFuncCount);

                        if (s_startFuncCount > 0)
                        {
                            char buffer[32];
                            msg("Starting function count: %s\n", prettyNumberString(s_startFuncCount, buffer));
                            WaitBox::processIdaEvents();

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

                            // First chosen seg
                            if (chosen && !chosen->empty())
                            {
                                s_thisSeg = chosen->back();
                                chosen->pop_back();
                            }
                            else
                            // Use the first CODE seg
                            {
                                int iSegCount = get_segm_qty();
                                int iIndex = 0;
                                for (; iIndex < iSegCount; iIndex++)
                                {
                                    if (s_thisSeg = getnseg(iIndex))
                                    {
                                        char sclass[32];
                                        if (get_segm_class(s_thisSeg, sclass, SIZESTR(sclass)) <= 0)
                                            break;
                                        else
                                        if (strcmp(sclass, "CODE") == 0)
                                            break;
                                    }
                                }

                                if (iIndex >= iSegCount)
                                    s_thisSeg = NULL;
                            }

                            if (s_thisSeg)
                            {
                                WaitBox::show();
                                WaitBox::updateAndCancelCheck(-1);
                                s_segStart = s_thisSeg->startEA;
                                s_segEnd   = s_thisSeg->endEA;
                                nextState();
                                break;
                            }
                            else
                                msg("** No code segment found to process! **\n*** Aborted ***\n\n");
                        }
                        else
                            msg("** No functions in DB?! **\n*** Aborted ***\n\n");
                    }
                    else
                        msg("** Wait for IDA to finish processing before starting plugin! **\n*** Aborted ***\n\n");

                    // Canceled or error'ed, bail out
                    s_state = eSTATE_EXIT;
                }
                break;

                // Start up process
                case eSTATE_START:
                {                         
                    s_currentAddress = 0;           

                    char name[64];
                    if (get_true_segm_name(s_thisSeg, name, SIZESTR(name)) <= 0)
                        strcpy(name, "????");
                    char sclass[32];
                    if(get_segm_class(s_thisSeg, sclass, SIZESTR(sclass)) <= 0)
                        strcpy(sclass, "????");
                    msg("\nProcessing segment: \"%s\", type: %s, address: %08X-%08X, size: %08X\n\n", name, sclass, s_thisSeg->startEA, s_thisSeg->endEA, s_thisSeg->size());

                    // Move to first process state
                    s_startTime = getTimeStamp();
                    nextState();
                }
                break;


                // Find unknown data values in code
                //#define PASS1_DEBUG
                case eSTATE_PASS_1:
                {
                    // nextthat next_head next_not_tail next_visea nextaddr
                    if (s_currentAddress < s_segEnd)
                    {
                        // Value at this location data?
                        autoWait();
                        flags_t flags = get_flags_novalue(s_currentAddress);
                        if (isData(flags) && !isAlign(flags))
                        {
                            #ifdef PASS1_DEBUG
                            msg(EAFORMAT",  F: %08X data\n", s_currentAddress, flags);
                            #endif
                            ea_t end = next_head(s_currentAddress, s_segEnd);

                            // Handle an occasional over run case
                            if (end == BADADDR)
                            {
                                #ifdef PASS1_DEBUG
                                msg(EAFORMAT" **** abort end\n", s_currentAddress);
                                #endif
                                s_currentAddress = (s_segEnd - 1);
                                break;
                            }

                            // Skip if it has offset reference (most common occurrence)
                            BOOL bSkip = FALSE;
                            if (flags & FF_0OFF)
                            {
                                #ifdef PASS1_DEBUG
                                msg("  skip offset.\n");
                                #endif
                                bSkip = TRUE;
                            }
                            else
                                // Has a reference?
                                if (flags & FF_REF)
                                {
                                    ea_t eaDRef = get_first_dref_to(s_currentAddress);
                                    if (eaDRef != BADADDR)
                                    {
                                        // Ref part an offset?
                                        flags_t flags2 = get_flags_novalue(eaDRef);
                                        if (isCode(flags2) && isOff1(flags2))
                                        {
                                            // Decide instruction to global "cmd" struct
                                            BOOL bIsByteAccess = FALSE;
                                            if (decode_insn(eaDRef))
                                            {
                                                switch (cmd.itype)
                                                {
                                                    // movxx style move a byte?
                                                    case NN_movzx:
                                                    case NN_movsx:
                                                    {
                                                        #ifdef PASS1_DEBUG
                                                        msg(EAFORMAT" movzx\n", s_currentAddress);
                                                        #endif
                                                        bIsByteAccess = TRUE;
                                                    }
                                                    break;

                                                    case NN_mov:
                                                    {
                                                        if ((cmd.Operands[0].type == o_reg) && (cmd.Operands[1].dtyp == dt_byte))
                                                        {
                                                            #ifdef PASS1_DEBUG
                                                            msg(EAFORMAT" mov\n", s_currentAddress);
                                                            #endif
                                                            /*
                                                            msg(" [0] T: %d, D: %d, \n", cmd.Operands[0].type, cmd.Operands[0].dtyp);
                                                            msg(" [1] T: %d, D: %d, \n", cmd.Operands[1].type, cmd.Operands[1].dtyp);
                                                            msg(" [2] T: %d, D: %d, \n", cmd.Operands[2].type, cmd.Operands[2].dtyp);
                                                            msg(" [3] T: %d, D: %d, \n", cmd.Operands[3].type, cmd.Operands[3].dtyp);
                                                            */
                                                            bIsByteAccess = TRUE;
                                                        }
                                                    }
                                                    break;
                                                };
                                            }

                                            // If it's byte access, assume it's a byte switch table
                                            if (bIsByteAccess)
                                            {
                                                #ifdef PASS1_DEBUG
                                                msg(EAFORMAT" not byte\n", s_currentAddress);
                                                #endif                                               
                                                makeUnknown(s_currentAddress, end);                                                                                                
                                                // Step through making the array, and any bad size a byte
                                                //for(ea_t i = s_eaCurrentAddress; i < eaEnd; i++){ doByte(i, 1); }
                                                doByte(s_currentAddress, (end - s_currentAddress));
                                                autoWait();
                                                bSkip = TRUE;
                                            }
                                        }
                                    }
                                }

                            // Make it unknown bytes
                            if (!bSkip)
                            {
                                #ifdef PASS1_DEBUG
                                msg(EAFORMAT" "EAFORMAT" %02X unknown\n", s_currentAddress, end, get_flags_novalue(s_currentAddress));
                                #endif
                                makeUnknown(s_currentAddress, end);                              
                                s_unknownDataCount++;                               

                                // Note: Might have triggered auto-analysis and a alignment or function could be here now
                            }

                            // Advance to next data value, or the end which ever comes first
                            s_currentAddress = end;
                            if (s_currentAddress < s_segEnd)
                            {
                                s_currentAddress = nextthat(s_currentAddress, s_segEnd, isData, NULL);
                                break;
                            }
                        }
                        else
                        {
                            // Advance to next data value, or the end which ever comes first
                            s_currentAddress = nextthat(s_currentAddress, s_segEnd, isData, NULL);
                            break;
                        }
                    }

                    if (++s_pass1Loops < UNKNOWN_PASSES)
                    {
                        #ifdef PASS1_DEBUG
                        msg("** Pass %d Unknowns: %u\n", s_pass1Loops, s_unknownDataCount);
                        #endif
                        s_currentAddress = s_lastAddress = s_segStart;
                    }
                    else
                    {
                        #ifdef PASS1_DEBUG
                        msg("** Pass %d Unknowns: %u\n", s_pass1Loops, s_unknownDataCount);
                        #endif
                        nextState();
                    }
                }
                break;  // Find unknown data values in code


                // Find missing align blocks
                //#define PASS2_DEBUG
                case eSTATE_PASS_2:
                {
                    #define NEXT(_Here, _Limit) nextthat(_Here, _Limit, isAlignByte, NULL)

                    // Still inside this code segment?
                    ea_t end = s_segEnd;
                    if (s_currentAddress < end)
                    {
                        // Look for next unknown alignment type byte
                        // Will return BADADDR if none found which will catch in the endEA test                        
                        flags_t flags = get_flags_novalue(s_currentAddress);
                        if (!isAlignByte(flags, NULL))
                            s_currentAddress = NEXT(s_currentAddress, s_segEnd);
                        if (s_currentAddress < end)
                        {
                            // Catch when we get caught up in an array, etc.
                            ea_t startAddress = s_currentAddress;
                            if (s_currentAddress <= s_lastAddress)
                            {
                                // Move to next header and try again..
                                #ifdef PASS2_DEBUG
                                //msg(EAFORMAT", F: 0x%X *** Align test in array #1 ***\n", s_currentAddress, flags);
                                #endif
                                s_currentAddress = s_lastAddress = nextaddr(s_currentAddress);
                                break;
                            }

                            #ifdef PASS2_DEBUG
                            //msg(EAFORMAT" Start.\n", startAddress);
                            //msg(EAFORMAT", F: %08X.\n", startAddress, get_flags_novalue(startAddress));
                            #endif
                            s_lastAddress = s_currentAddress;

                            // Get run count of this align byte
                            UINT alignByteCount = 1;
                            BYTE startAlignValue = get_byte(startAddress);

                            while (TRUE)
                            {
                                // Next byte
                                s_currentAddress = nextaddr(s_currentAddress);
                                #ifdef PASS2_DEBUG
                                //msg(EAFORMAT" Next.\n", s_currentAddress);
                                //msg(EAFORMAT", F: %08X.\n", s_currentAddress, get_flags_novalue(s_currentAddress));
                                #endif

                                if (s_currentAddress < end)
                                {
                                    // Catch when we get caught up in an array, etc.
                                    if (s_currentAddress <= s_lastAddress)
                                    {
                                        #ifdef PASS2_DEBUG
                                        //msg(EAFORMAT", F: %08X *** Align test in array #2 ***\n", startAddress, get_flags_novalue(s_currentAddress));
                                        #endif
                                        s_currentAddress = s_lastAddress = nextaddr(s_currentAddress);
                                        break;
                                    }
                                    s_lastAddress = s_currentAddress;

                                    // Count if it' still the same byte
                                    if (get_byte(s_currentAddress) == startAlignValue)
                                        alignByteCount++;
                                    else
                                        break;
                                }
                                else
                                    break;
                            };

                            // Do these bytes bring about at least a 16 (could be 32) align?
                            // TODO: Must we consider other alignments such as 4 and 8?
                            //       Probably a compiler option that is not normally used anymore.
                            if (((startAddress + alignByteCount) & (16 - 1)) == 0)
                            {
                                // If short count, only try alignment if the line above or a below us has n xref
                                // We don't want to try to align odd code and switch table bytes, etc.
                                if (alignByteCount <= 2)
                                {
                                    BOOL hasRef = FALSE;

                                    // Before us
                                    ea_t endAddress = (startAddress + alignByteCount);
                                    ea_t ref = get_first_cref_from(endAddress);
                                    if (ref != BADADDR)
                                    {
                                        //msg("%08X cref from end.\n", endAddress);
                                        hasRef = TRUE;
                                    }
                                    else
                                    {
                                        ref = get_first_cref_to(endAddress);
                                        if (ref != BADADDR)
                                        {
                                            //msg("%08X cref to end.\n", endAddress);
                                            hasRef = TRUE;
                                        }
                                    }

                                    // After us
                                    if (ref == BADADDR)
                                    {
                                        ea_t foreAddress = (startAddress - 1);
                                        ref = get_first_cref_from(foreAddress);
                                        if (ref != BADADDR)
                                        {
                                            //msg("%08X cref from start.\n", eaForeAddress);
                                            hasRef = TRUE;
                                        }
                                        else
                                        {
                                            ref = get_first_cref_to(foreAddress);
                                            if (ref != BADADDR)
                                            {
                                                //msg("%08X cref to start.\n", eaForeAddress);
                                                hasRef = TRUE;
                                            }
                                        }
                                    }

                                    // No code ref, now look for a broken code ref
                                    if (ref == BADADDR)
                                    {
                                        // This is still not complete as it could still be code, but pointing to a vftable
                                        // entry in data.
                                        // But should be fixed on more passes.
                                        ea_t endAddress = (startAddress + alignByteCount);
                                        ref = get_first_dref_from(endAddress);
                                        if (ref != BADADDR)
                                        {
                                            // If it the ref points to code assume code is just broken here
                                            if (isCode(get_flags_novalue(ref)))
                                            {
                                                //msg("%08X dref from end %08X.\n", eaRef, eaEndAddress);
                                                hasRef = TRUE;
                                            }
                                        }
                                        else
                                        {
                                            ref = get_first_dref_to(endAddress);
                                            if (ref != BADADDR)
                                            {
                                                if (isCode(get_flags_novalue(ref)))
                                                {
                                                    //msg("%08X dref to end %08X.\n", eaRef, eaEndAddress);
                                                    hasRef = TRUE;
                                                }
                                            }
                                        }

                                        if (ref == BADADDR)
                                        {
                                            //msg("%08X NO REF.\n", eaStartAddress);
                                        }
                                    }

                                    // Assume it's not an alignment byte(s) and bail out
                                    if (!hasRef) break;
                                }

                                // Attempt to make it an align block                               
                                makeUnknown(startAddress, ((startAddress + alignByteCount) - 1));                                
                                BOOL result = doAlign(startAddress, alignByteCount, 0);
                                autoWait();
                                #ifdef PASS2_DEBUG
                                msg(EAFORMAT" %d %d DO ALIGN.\n", startAddress, alignByteCount, result);
                                #endif
                                if (result)
                                {
                                    #ifdef PASS2_DEBUG
                                    //msg(EAFORMAT" %d ALIGN.\n", startAddress, alignByteCount);
                                    #endif
                                    s_alignFixes++;
                                }
                                else
                                {
                                    // There are several times will IDA will fail even when the alignment block is obvious.
                                    // Usually when it's an ALIGN(32) and there is a run of 16 align bytes
                                    // Could at least do a code analyze on it. Then IDA will at least make a mini array of it
                                    #ifdef PASS2_DEBUG
                                    msg(EAFORMAT" %d ALIGN FAIL ***\n", startAddress, alignByteCount);
                                    //s_alignFails++;
                                    #endif
                                }
                            }
                        }

                        break;
                    }

                    s_currentAddress = s_segEnd;                              
                    nextState();
                    #undef NEXT
                }
                break; // Find missing align blocks


                // Find missing code
                //#define PASS3_DEBUG
                case eSTATE_PASS_3:
                {                    
                    // Still inside segment?
                    if (s_currentAddress < s_segEnd)
                    {
                        // Look for next unknown value                       
                        ea_t startAddress = next_unknown(s_currentAddress, s_segEnd);
                        if (startAddress < s_segEnd)
                        {
                            s_currentAddress = startAddress;
                            //s_uStrayBYTE++;
                            //msg("%08X unknown.\n");

                            // Catch when we get caught up in an array, etc.
                            if (s_currentAddress <= s_lastAddress)
                            {
                                // Move to next header and try again..                               
                                s_currentAddress = next_unknown(s_currentAddress, s_segEnd);
                                s_lastAddress = s_currentAddress;
                                break;
                            }
                            s_lastAddress = s_currentAddress;

                            // Try to make code of it                           
                            autoWait();
                            int result = create_insn(s_currentAddress);
                            autoWait();
                            #ifdef PASS3_DEBUG
                            msg(EAFORMAT" DO CODE %d\n", s_currentAddress, result);
                            #endif
                            if(result > 0)                            
                                s_codeFixes++;                            
                            else
                            {
                                #ifdef PASS3_DEBUG
                                msg(EAFORMAT" fix fail.\n", s_currentAddress);                               
                                #endif
                            }                            

                            // Start from possible next byte
                            s_currentAddress++;
                            break;
                        }
                    }

                    // Next state
                    s_currentAddress = s_segEnd;                   
                    nextState();
                }
                break; // Find missing code

                
                // Discover missing functions part 1
                case eSTATE_PASS_4:
                {                    
                    if (s_funcIndex < s_funcCount)
                    {
                        // Get function gap from the bottom of the function to the start of the next
                        func_t *f1 = getn_func(s_funcIndex + 0);
                        func_t *f2 = getn_func(s_funcIndex + 1);

                        UINT gapSize = (f2->startEA - f1->endEA);
                        if (gapSize > 0)                                                    
                            processFuncGap(f1->endEA, gapSize);                        

                        s_funcIndex++;
                    }                 
                    else                   
                    {
                        s_currentAddress = s_segEnd;                       
                        nextState();
                    }
                }
                break;
                
                // Discover missing functions part 2
                case eSTATE_PASS_5:
                {
                    // TODO: This is broke, hasBadFuncStart() needs work
                    #if 0
                    // Examine next function
                    if (s_funcIndex < s_funcCount)
                    {
                        if (func_t *f = getn_func(s_funcIndex))
                        {
                            if (hasBadFuncStart(f))
                            {
                                msg(EAFORMAT" bad func start.\n", f->startEA);
                                s_blocksFixed += (UINT) (fixFuncBlock(f->startEA) > 0);
                            }
                        }

                        s_funcIndex++;
                    }
                    else
                    #endif
                    {
                        s_currentAddress = s_segEnd;                        
                        nextState();
                    }
                }
                break;


                // Finished processing
                case eSTATE_FINISH:
                {
                    nextState();
                }
                break;

                // Done processing
                case eSTATE_EXIT:
                {
                    nextState();
                    goto BailOut;
                }
                break;
            };

            // Check & bail out on 'break' press
            if (checkBreak())
                goto BailOut;
        };

        BailOut:;
        s_funcList.clear();
        WaitBox::hide();
    }
    CATCH()
}


// Do next state logic
static void nextState()
{
	// Rewind
	if(s_state < eSTATE_FINISH)
	{
		// Top of code seg
		s_currentAddress = s_lastAddress = s_segStart;
		//SafeJumpTo(s_uCurrentAddress);
		autoWait();
	}

	// Logic
	switch(s_state)
	{
		// Init
		case eSTATE_INIT:
		{
			s_state = eSTATE_START;
		}
		break;

		// Start
		case eSTATE_START:
		{
			if(s_doDataToBytes)
			{
				msg("===== Fixing bad code bytes =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_1;
			}
			else
			if(s_doAlignBlocks)
			{
				msg("===== Missing align blocks =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_2;
			}
			else
			if(s_doMissingCode)
			{
				msg("===== Missing code =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_stepTime = getTimeStamp();
                s_funcIndex = 0;
                s_funcCount = (get_func_qty() - 1);
				s_state = eSTATE_PASS_4;
			}
			else
			if(s_doBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_stepTime = getTimeStamp();
				s_funcIndex = 0;
                s_funcCount = get_func_qty();
				s_state = eSTATE_PASS_5;
			}
			else
				s_state = eSTATE_FINISH;

            WaitBox::processIdaEvents();			
		}
		break;

		// Find unknown data in code space
		case eSTATE_PASS_1:
		{
			msg("Time: %s.\n\n", timeString(getTimeStamp() - s_stepTime));

			if(s_doAlignBlocks)
			{
				msg("===== Missing align blocks =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_2;
			}
			else
			if(s_doMissingCode)
			{
				msg("===== Missing code =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_stepTime = getTimeStamp();
                s_funcIndex = 0;
                s_funcCount = (get_func_qty() - 1);
				s_state = eSTATE_PASS_4;
			}
			else
			if(s_doBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_stepTime = getTimeStamp();
				s_funcIndex = 0;
                s_funcCount = get_func_qty();
				s_state = eSTATE_PASS_5;
			}
			else
				s_state = eSTATE_FINISH;

            WaitBox::processIdaEvents();
		}
		break;


		// From missing align block pass
		case eSTATE_PASS_2:
		{
			msg("Time: %s.\n\n", timeString(getTimeStamp() - s_stepTime));

			if(s_doMissingCode)
			{
				msg("===== Missing code =====\n");
				s_stepTime = getTimeStamp();
				s_state = eSTATE_PASS_3;
			}
			else
			if(s_doMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_stepTime = getTimeStamp();
                s_funcIndex = 0;
                s_funcCount = (get_func_qty() - 1);
				s_state = eSTATE_PASS_4;
			}
			else
			if(s_doBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_stepTime = getTimeStamp();
				s_funcIndex = 0;
                s_funcCount = get_func_qty();
				s_state = eSTATE_PASS_5;
			}
			else
				s_state = eSTATE_FINISH;

            WaitBox::processIdaEvents();
		}
		break;

		// From missing code pass
		case eSTATE_PASS_3:
		{
			msg("Time: %s.\n\n", timeString(getTimeStamp() - s_stepTime));

			if(s_doMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_stepTime = getTimeStamp();
                s_funcIndex = 0;
                s_funcCount = (get_func_qty() - 1);
				s_state = eSTATE_PASS_4;
			}
			else
			if(s_doBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_stepTime = getTimeStamp();
				s_funcIndex = 0;
                s_funcCount = get_func_qty();
				s_state = eSTATE_PASS_5;
			}
			else
				s_state = eSTATE_FINISH;

            WaitBox::processIdaEvents();
		}
		break;

		// From missing function pass part 1
		case eSTATE_PASS_4:
		{
			msg("Time: %s.\n\n", timeString(getTimeStamp() - s_stepTime));

			if(s_doBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_stepTime = getTimeStamp();
				s_funcIndex = 0;
                s_funcCount = get_func_qty();
				s_state = eSTATE_PASS_5;
			}
			else
				s_state = eSTATE_FINISH;

            WaitBox::processIdaEvents();
		}
		break;

		// From missing function pass part 2
		case eSTATE_PASS_5:
		{
			msg("Time: %s.\n", timeString(getTimeStamp() - s_stepTime));
            WaitBox::processIdaEvents();
			s_state = eSTATE_FINISH;
		}
		break;


		// From final pass, we're done
		case eSTATE_FINISH:
		{
			// If there are more code segments to process, do next
			autoWait();
            if (chosen && !chosen->empty())
			{
				s_thisSeg = chosen->back();
                chosen->pop_back();
				s_segStart = s_thisSeg->startEA;
				s_segEnd   = s_thisSeg->endEA;
				s_state = eSTATE_START;
			}
			else
			{
				msg("\n===== Done =====\n");
				showEndStats();
                refresh_idaview_anyway();
                WaitBox::processIdaEvents();

				// Optionally play completion sound
				if(s_audioAlertWhenDone)
				{
                    // Only if processing took at least a few seconds
                    if ((getTimeStamp() - s_startTime) > 2.2)
                    {
                        
                        WaitBox::processIdaEvents();
                        OggPlay::playFromMemory((const PVOID)complete_ogg, complete_ogg_len);
                        OggPlay::endPlay();
                    }
				}

				s_state = eSTATE_EXIT;
			}
		}
		break;

		// Exit plugin run back to IDA control
		case eSTATE_EXIT:
		{
			// In case we aborted some place and list still exists..			
            if (chosen)
            {
                SegSelect::free(chosen);
                chosen = NULL;
            }
			s_state = eSTATE_INIT;
		}
		break;
	};
}


// Print out end stats
static void showEndStats()
{
    char buffer[32];
	msg("  Total time: %s\n", timeString(getTimeStamp() - s_startTime));
    msg("  Alignments: %s\n", prettyNumberString(s_alignFixes, buffer));
    msg("Blocks fixed: %s\n", prettyNumberString(s_blocksFixed, buffer));
    int functionsDelta = ((int) get_func_qty() - s_startFuncCount);
	if (functionsDelta != 0)
		msg("   Functions: %c%s\n", ((functionsDelta >= 0) ? '+' : '-'), prettyNumberString(labs(functionsDelta), buffer)); // Can be negative
	else
		msg("   Functions: 0\n");

	//msg("Code fixes: %u\n", s_uCodeFixes);
	//msg("Code fails: %u\n", s_uCodeFixFails);
	//msg("Align fails: %d\n", s_uAlignFails);
	//msg("  Unknowns: %u\n", s_uUnknowns);

	msg(" \n");
}

// Returns TRUE if flag byte is possibly a typical alignment byte
static bool idaapi isAlignByte(flags_t flags, void *ud)
{
	if((flags == ALIGN_VALUE1) || (flags == ALIGN_VALUE2))
		return(TRUE);
	else
		return(FALSE);
}

// Return if flag is data type we want to convert to unknown bytes
static bool idaapi isData(flags_t flags, void *ud)
{
	return(!isAlign(flags) && isData(flags));
}



/*
static BOOL InCode(ea_t eaAddress)
{
	// Check current code seg first
	if((eaAddress >= s_eaSegStart) && (eaAddress <= s_eaSegEnd))
		return(TRUE);
	else
	// Else check if source seg is "CODE" class
	// TODO: This is not ideal. We should save the user input segment list and use it to test the address
	if(segment_t *pSrcSeg = getseg(eaAddress))
	{
		char szClass[16] = {0};
		get_segm_class(pSrcSeg, szClass, (sizeof(szClass) - 1));
		if(strcmp(szClass, "CODE") == 0)
			return(TRUE);
	}

	return(FALSE);
}
*/

// Get a nice line of disassembled code text sans color tags
static LPCTSTR getDisasmText(ea_t ea)
{
    static char szBuff[MAXSTR]; szBuff[0] = szBuff[MAXSTR - 1] = 0;
    generate_disasm_line(ea, szBuff, (sizeof(szBuff) - 1));
    tag_remove(szBuff, szBuff, (sizeof(szBuff) - 1));
    return(szBuff);
}


// Get a pretty delta time string for output
static LPCTSTR timeString(TIMESTAMP Time)
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
static BOOL tryFunction(ea_t codeStart, ea_t codeEnd, ea_t &current)
{
	BOOL result = FALSE;

	autoWait();
	#ifdef LOG_FILE
	Log(s_logFile, "%08X %08X Trying function.\n", codeStart, current);
	#endif
	//msg("%08X %08X Trying function.\n", CodeStartEA, rCurEA);

	/// *** Don't use "get_func()" it has a bug, use "get_fchunk()" instead ***

	// Could belong as a chunk to an existing function already or already a function here recovered already between steps.
	if(func_t *f = get_fchunk(codeStart))
	{
  		#ifdef LOG_FILE
        Log(s_logFile, "  %08X %08X %08X F: %08X already function.\n", f->endEA, f->startEA, codeStart, get_flags_novalue(codeStart));
		#endif
		//msg("  %08X %08X %08X F: %08X already function.\n", pFunc->endEA, pFunc->startEA, CodeStartEA, getFlags(CodeStartEA));
		current = prev_head(f->endEA, codeStart); // Advance to end of the function -1 location (for a follow up "next_head()")
		result = TRUE;
	}
	else
	{
		// Try function here
		if(add_func(codeStart, BADADDR))
		{
			// Wait till IDA is done possibly creating the function, then get it's info
			autoWait();
			if(func_t *f = get_fchunk(codeStart)) // get_func
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %08X function success.\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  %08X function success.\n", codeStart);
				#endif

				// Look at function tail instruction
				autoWait();
				BOOL isExpected = FALSE;
				ea_t tailEa = prev_head(f->endEA, codeStart);
				if(tailEa != BADADDR)
				{
					if(decode_insn(tailEa))
					{
						switch(cmd.itype)
						{
							// A return?
							case NN_retn: case NN_retf: case NN_iretw: case NN_iret: case NN_iretd:
							case NN_iretq: case NN_syscall:
							case NN_sysret:
							{
								isExpected = TRUE;
							}
							break;

							// A jump? (chain to another function, etc.)
							case NN_jmp: case NN_jmpfi:	case NN_jmpni: case NN_jmpshort:
							// Can be a conditional branch to another incongruent chunk
							case NN_ja:  case NN_jae: case NN_jb:  case NN_jbe:  case NN_jc:   case NN_je:   case NN_jg:
							case NN_jge: case NN_jl:  case NN_jle: case NN_jna:  case NN_jnae: case NN_jnb:  case NN_jnbe:
							case NN_jnc: case NN_jne: case NN_jng: case NN_jnge: case NN_jnl:  case NN_jnle: case NN_jno:
							case NN_jnp: case NN_jns: case NN_jnz: case NN_jo:   case NN_jp:  case NN_jpe:   case NN_jpo:
							case NN_js:  case NN_jz:
							{
								isExpected = TRUE;
							}
							break;

							// A single align byte that was mistakenly made a function?
							case NN_int3:
							case NN_nop:
							if(f->size() == 1)
							{
								// Try to make it an align								
                                makeUnknown(tailEa, (tailEa + 1));
								if(!doAlign(tailEa, 1, 0))
								{
									// If it fails, make it an instruction at least
									//msg("%08X ALIGN fail.\n", tailEA);
									create_insn(tailEa);									
								}
                                autoWait();
								//msg("%08X ALIGN\n", tailEA);
								isExpected = TRUE;
							}
							break;

							// Return-less exception or exit handler?
							case NN_call:
							{
								ea_t eaCRef = get_first_cref_from(tailEa);
								if(eaCRef != BADADDR)
								{
                                    qstring str;
                                    if (get_true_name(&str, eaCRef) > 0)
                                    {
                                        char name[MAXNAMELEN + 1];
                                        strncpy(name, str.c_str(), SIZESTR(name));
                                        _strlwr(name);

										static const char * const exitNames[] =
										{
											"exception",
											"handler",
											"exitprocess",
											"fatalappexit",
											"_abort",
											"_exit",
										};
										
										for(int i = 0; i < (sizeof(exitNames) / sizeof(const char *)); i++)
										{
											if(strstr(name, exitNames[i]))
											{
												//msg("%08X Exception\n", CodeStartEA);
												isExpected = TRUE;
												break;
											}
										}
									}
								}
							}
							// Drop through to default for "call"

							// Allow if function has attribute "noreturn"
							default:
							{
								if(f->flags & FUNC_NORET)
								{
									//msg("%08X NORETURN\n", tailEA);
									isExpected = TRUE;
								}
							}
							break;
						};
					}

					if(!isExpected)
					{	
                        char name[MAXNAMELEN + 1];
                        qstring str;
                        if (get_true_name(&str, f->startEA) > 0)
                            strncpy(name, str.c_str(), SIZESTR(name));
                        else
                            memcpy(name, "unknown", sizeof("unknown"));
						msg("%08X \"%s\" problem? <click me>\n", tailEa, name);
						//msg("  T: %d\n", cmd.itype);

						#ifdef LOG_FILE
						Log(s_logFile, "%08X \"%s\" problem? <click me>\n", tailEa, name);
						//Log(s_hLogFile, "  T: %d\n", cmd.itype);
						#endif
					}
				}

				// Update current look position to the end of this function
				current = tailEa; // Advance to end of the function -1 location (for a follow up "next_head()")
				result = TRUE;
			}
		}
	}

	return(result);
}


// Process the gap from the end of one function to the start of the next
// looking for missing functions in between.
static void processFuncGap(ea_t start, UINT size)
{
    s_currentAddress = start;
	ea_t ea  = start;
	ea_t end = (start + size);
	ea_t codeStart  = BADADDR;    

	#ifdef LOG_FILE
	Log(s_logFile, "\nS: %08X, E: %08X ==== PFG START ====\n", start, end);
	#endif
	#ifdef VBDEV
	msg("\n%08X %08X ==== Gap ====\n", start, end);
	#endif

    // Traverse gap
	autoWait();
    while(ea < end)
    {
		// Info flags for this address
        flags_t flags = get_flags_novalue(ea);
		#ifdef LOG_FILE
		Log(s_logFile, "  C: %08X, F: %08X, \"%s\".\n", ea, flags, getDisasmText(ea));
		#endif
		#ifdef VBDEV
		msg(" C: %08X, F: %08X, \"%s\".\n", ea, flags, getDisasmText(ea));
		#endif

		if(ea < start)
		{
			#ifdef LOG_FILE
			Log(s_logFile, "**** Out of start range! %08X %08X %08X ****\n", ea, start, end);
			#endif
			return;
		}
        else
		if(ea > end)
		{
			#ifdef LOG_FILE
			Log(s_logFile, "**** Out of end range! %08X %08X %08X ****\n", ea, start, end);
			#endif
			return;
		}

		// Skip over "align" blocks.
		// #1 we will typically see more of these then anything else
		if(isAlign(flags))
		{
			// Function between code start?
			if(codeStart != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %08X Trying function #1\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #1\n", codeStart);
				#endif
				tryFunction(codeStart, end, ea);
			}

			codeStart = BADADDR;
		}
		else
		// #2 case, we'll typically see data
		if(isData(flags))
		{
			// Function between code start?
			if(codeStart != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %08X Trying function #2\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #2\n", codeStart);
				#endif
				tryFunction(codeStart, end, ea);
			}

			codeStart = BADADDR;
		}
		else
		// Hit some code?
		if(isCode(flags))
		{
			// Yes, mark the start of a possible code block
			if(codeStart == BADADDR)
			{
				codeStart  = ea;

				#ifdef LOG_FILE
				Log(s_logFile, "  %08X Trying function #3, assumed func start\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #3, assumed func start\n", codeStart);
				#endif
				if(tryFunction(codeStart, end, ea))
					codeStart = BADADDR;
			}
		}
		else
		// Undefined?
		// Usually 0xCC align bytes
		if(isUnknown(flags))
		{
			#ifdef LOG_FILE
			Log(s_logFile, "  C: %08X, Unknown type.\n", ea);
			#endif
			#ifdef VBDEV
			msg("  C: %08X, Unknown type.\n", ea);
			#endif
			codeStart = BADADDR;
		}
		else
		{
			#ifdef LOG_FILE
			Log(s_logFile, "  %08X ** unknown data type! **\n", ea);
			#endif
			#ifdef VBDEV
			msg("  %08X ** unknown data type! **\n", ea);
			#endif
			codeStart = BADADDR;
		}

		// Next item
		autoWait();
		ea_t nextEa = BADADDR;
		if(ea != BADADDR)
		{
			nextEa = next_head(ea, end);
			if(nextEa != BADADDR)
				ea = nextEa;
		}

		if((nextEa == BADADDR) || (ea == BADADDR))
		{
			// If have code and at the end, try a function from the start
			if(codeStart != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_logFile, "  %08X Trying function #4\n", codeStart);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #4\n", codeStart);
				#endif
				tryFunction(codeStart, end, ea);
				autoWait();
			}

			#ifdef LOG_FILE
			Log(s_logFile, " Gap end: %08X.\n", ea);
			#endif
			#ifdef VBDEV
			msg(" Gap end: %08X.\n", ea);
			#endif

            break;
		}

    }; // while(rCurEA < startEA)
}



// =======================================================================================================
// Return TRUE if function black has a bad start reference
// Not inclusive, only valid check if function has at least one cref
// =========================================================================================================
static BOOL hasBadFuncStart(func_t *f)
{
	// Walk crefs "to"
	ea_t address = f->startEA;
	ea_t ref = get_first_fcref_to(address);

	while(ref != BADADDR)
	{
		// Fill "cmd" struct
		if(decode_insn(ref))
		{
			// Expected code opcode ref for a function entry point?
			switch(cmd.itype)
			{
				case NN_call:
				case NN_callfi:
				case NN_callni:
				break;

				case NN_jmp:
				case NN_jmpfi:
				case NN_jmpni:
				break;

				// TODO: Other valid block entry refs?

				default:
				return(TRUE);
				break;
			};

			ref = get_next_fcref_to(address, ref);
		}
		else
			return(FALSE);
	};

	return(FALSE);
}


// =======================================================================================================
// Attempt to locate block end
// =========================================================================================================
static ea_t findBlockEnd(ea_t address)
{
	while(TRUE)
	{
		// Look for end of block
		if(decode_insn(address))
		{
			if
				(
				// int3 (probably end of non-returning exception handler), any interrupt, and any jump
				((cmd.itype >= NN_int3) && (cmd.itype <= NN_jmpshort)) ||
				// Any return
				((cmd.itype == NN_retn) || (cmd.itype == NN_retf))
				)
			{
				//msg("   %08X Got end inst: %d.\n", eaAddress, cmd.itype);
				address += get_item_size(address);
				break;
			}
		}
		else
			// Not an instruction here anymore
			break;

		// Next instruction
		ea_t next = next_head(address, (ea_t) 0x7FFFFFFF);
		if(next != BADADDR)
			address = next;
		else
			// End of segment
			break;

		// Next shouldn't have a ref to it
		if(get_first_fcref_to(address) != BADADDR)
		{
			//msg("   %08X Got unexpected cref.\n", eaAddress);
			break;
		}
	};

	return(address);
}


// =======================================================================================================
// Attempt to fix broken function chunks
// =========================================================================================================
static int fixFuncBlock(ea_t eaBlock)
{
	int	fixCount = 0;

	ea_t blockEnd = findBlockEnd(eaBlock);
	//msg("%08X %08X Fixblock.\n", eaBlock, eaBlockEnd);

	// Remove possible function assumption for the block
	autoWait();
	if(del_func(eaBlock))
		autoWait();

	// Remove possible function to let IDA auto-name as it a branch label
    set_name(eaBlock, "", SN_AUTO);

	// Locate the owner function(s) to the block
	// Almost always one ref, typically only small percent will have more then one ref
	// Note: Often the first ref is seen as the previous address, which is just item/instruction relative
	// it should be part of related function anyhow.
	ADDRSET knownSet;
	int owners = 0;
	ea_t blockRef = get_first_cref_to(eaBlock);
	while(blockRef != BADADDR)
	{
		if(func_t *ownerFunc = get_func(blockRef))
		{
			owners++;

			// Ignore if we've seen handled this function already
			ea_t ownerEa = ownerFunc->startEA;
			if(knownSet.find(ownerEa) == knownSet.end())
			{
				knownSet.insert(ownerEa);
				if(append_func_tail(ownerFunc, eaBlock, blockEnd))
				{
					//msg("%08X Owner append.\n", eaOwner);
					fixCount++;
					autoWait();
				}
				else
				{
					// Fails simply because the block is probably already connected to the function
					//msg("  ** Failed to append tail block %08X to function %08X! **\n", eaBlock, eaOwner);
				}
			}
		}

		blockRef = get_next_cref_to(eaBlock, blockRef);
	};

	if(!owners)
		msg(EAFORMAT" No owner found <click me>\n", eaBlock);

	return(fixCount);
}
