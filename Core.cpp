
// ****************************************************************************
// File: Core.cpp
// Desc: Core of the
//
// ****************************************************************************
#include "stdafx.h"
#include "ContainersInl.h"
#include <WaitBoxEx.h>
#include <SegSelect.h>
#include <IdaOgg.h>

#include "complete_ogg.h"

#include <hash_set>
typedef stdext::hash_set<ea_t> ADDRSET;

// Preprocessor line backup
// WIN32;NDEBUG;_WINDOWS;_USRDLL;_WINDLL;__NT__;__IDP__;__VC__;NO_OBSOLETE_FUNCS;BUILD_QWINDOW=1;QT_DLL;QT_GUI_LIB;QT_XML_LIB;QT_CORE_LIB;QT_NAMESPACE=QT;QT_THREAD_SUPPORT;_CRT_SECURE_NO_WARNINGS;%(PreprocessorDefinitions)

//#define VBDEV
//#define LOG_FILE

// Count of eSTATE_PASS_1 unknown byte gather passes
#define UNKNOWN_PASSES 8

// x86 hack for speed in alignment value searching
// Defs from IDA headers, not supposed to be exported but need to because some cases not covered
// by SDK accessors, etc.
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
static bool idaapi IsAlignByte(flags_t flags, void *ud);
static bool idaapi IsData(flags_t flags, void *ud);
static BOOL InCode(ea_t eaAddress);
static BOOL IsBadFuncStart(func_t *pFunc);
static int  FixFuncBlock(ea_t eaBlock);

// === Data ===
static TIMESTAMP  s_StartTime = 0, s_StepTime = 0;
static segment_t  *s_thisSeg  = NULL;
static ea_t s_eaSegStart       = NULL;
static ea_t s_eaSegEnd         = NULL;
static ea_t s_eaCurrentAddress = NULL;
static ea_t s_eaLastAddress    = NULL;
#ifdef LOG_FILE
static FILE *s_hLogFile       = NULL;
#endif
static BOOL s_bStepStop       = TRUE;
static eSTATES s_eState       = eSTATE_INIT;
static int  s_iStartFuncCount = 0;
static int  s_iProgressSteps  = 0;
static int  s_iProgressStep   = 0;
static int  s_iPass1Loops     = 0;
static UINT s_uStep5Func      = 0;
//
static UINT s_uUnknowns       = 0;
static UINT s_uAligns         = 0;
static UINT s_uBlocksFixed    = 0;
//static UINT s_uAlignFails     = 0;
//static UINT s_uCodeFixes      = 0;
//static UINT s_uCodeFixFails   = 0;
//
static BOOL s_bDoDataToBytes  = TRUE;
static BOOL s_bDoAlignBlocks  = TRUE;
static BOOL s_bDoMissingCode  = TRUE;
static BOOL s_bDoMissingFunc  = TRUE;
static BOOL s_bDoBadBlocks    = TRUE;
static WORD s_wAudioAlertWhenDone = 1;
static SegSelect::segments *chosen = NULL;
static ALIGN(16) Container::ListEx<Container::ListHT, tFUNCNODE> s_FuncList;


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
	"-Version: %A build: %A by Sirmabus-\n"
    "<#Click to open my site.#www.macromonkey.com:k : 2 : 1::>\n\n"

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

// Initialize
void CORE_Init()
{
    s_eState = eSTATE_INIT;
}

// Un-initialize
void CORE_Exit()
{
    try
    {
        #ifdef LOG_FILE
        if(s_hLogFile)
        {
            qfclose(s_hLogFile);
            s_hLogFile = NULL;
        }
        #endif

        if (chosen)
        {
            SegSelect::free(chosen);
            chosen = NULL;
        }
        FlushFunctionList();
        OggPlay::endPlay();
        set_user_defined_prefix(0, NULL);
    }
    CATCH()
}

// Handler for choose code and data segment buttons
static void idaapi ChooseBtnHandler(TView *fields[], int code)
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

static void idaapi DoHyperlink(TView *fields[], int code) { open_url(SITE_URL); }


// Plug-in process
void CORE_Process(int iArg)
{
    try
    {
        while (TRUE)
        {
            switch (s_eState)
            {
            // Initialize
            case eSTATE_INIT:
            {
                msg("\n== ExtraPass plugin: v: %s, BD: %s, By Sirmabus ==\n", MY_VERSION, __DATE__);
                WaitBox::processIdaEvents();

                // Do UI for process pass selection
                s_bDoDataToBytes = s_bDoAlignBlocks = s_bDoMissingCode = s_bDoMissingFunc = s_bDoBadBlocks = TRUE;
                s_wAudioAlertWhenDone = TRUE;

                WORD wOptionFlags = 0;
                if (s_bDoDataToBytes) wOptionFlags |= OPT_DATATOBYTES;
                if (s_bDoAlignBlocks) wOptionFlags |= OPT_ALIGNBLOCKS;
                if (s_bDoMissingCode) wOptionFlags |= OPT_MISSINGCODE;
                if (s_bDoMissingFunc) wOptionFlags |= OPT_MISSINGFUNC;
                if (s_bDoBadBlocks)   wOptionFlags |= OPT_BADBLOCKS;

                {
                    // To add forum URL to help box
                    int iUIResult = AskUsingForm_c(optionDialog, MY_VERSION, __DATE__, DoHyperlink, &wOptionFlags, &s_wAudioAlertWhenDone, ChooseBtnHandler);
                    if (!iUIResult || (wOptionFlags == 0))
                    {
                        // User canceled, or no options selected, bail out
                        msg(" - Canceled -\n\n");
                        WaitBox::processIdaEvents();
                        s_eState = eSTATE_EXIT;
                        break;
                    }

                    s_bDoDataToBytes = ((wOptionFlags & OPT_DATATOBYTES) != 0);
                    s_bDoAlignBlocks = ((wOptionFlags & OPT_ALIGNBLOCKS) != 0);
                    s_bDoMissingCode = ((wOptionFlags & OPT_MISSINGCODE) != 0);
                    s_bDoMissingFunc = ((wOptionFlags & OPT_MISSINGFUNC) != 0);
                    s_bDoBadBlocks = ((wOptionFlags & OPT_BADBLOCKS) != 0);
                }

                // IDA must be IDLE
                if (autoIsOk())
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

                    s_thisSeg = NULL;
                    s_uUnknowns = 0;
                    s_iProgressStep = 0;
                    s_iPass1Loops = 0;
                    s_iStartFuncCount = get_func_qty();

                    if (s_iStartFuncCount > 0)
                    {
                        msg("Starting function count: %d\n", s_iStartFuncCount);
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
                            s_eaSegStart = s_thisSeg->startEA;
                            s_eaSegEnd   = s_thisSeg->endEA;
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
                    msg("** Wait for IDA to finish processing before starting plugin! **\n*** Aborted ***\n\n");

                // Canceled or error'ed, bail out
                s_eState = eSTATE_EXIT;
            }
            break;

            // Start up process
            case eSTATE_START:
            {
                // Cheating on the fact: BOOL == (int) 1
                s_iProgressSteps = ((s_bDoDataToBytes ? UNKNOWN_PASSES : 0) + (s_bDoAlignBlocks + s_bDoMissingCode + s_bDoMissingFunc + s_bDoBadBlocks));
                s_eaCurrentAddress = 0;
                s_iProgressStep = 0;

                char name[64];
                if (get_true_segm_name(s_thisSeg, name, SIZESTR(name)) <= 0)
                    strcpy(name, "????");
                char sclass[32];
                if(get_segm_class(s_thisSeg, sclass, SIZESTR(sclass)) <= 0)
                    strcpy(sclass, "????");
                msg("\nProcessing segment: \"%s\", type: %s, address: %08X-%08X, size: %08X\n\n", name, sclass, s_thisSeg->startEA, s_thisSeg->endEA, s_thisSeg->size());

                // Move to first process state
                s_StartTime = GetTimeStamp();
                NextState();
            }
            break;

            // Find unknown data values in code
            case eSTATE_PASS_1:
            {
                // nextthat next_head next_not_tail next_visea nextaddr
                if (s_eaCurrentAddress < s_eaSegEnd)
                {
                    // Value at this location data?
                    autoWait();
                    flags_t Flags = getFlags(s_eaCurrentAddress);
                    if (isData(Flags) && !isAlign(Flags))
                    {
                        //msg("%08X %08X data\n", s_eaCurrentAddress, Flags);
                        ea_t eaEnd = next_head(s_eaCurrentAddress, s_eaSegEnd);

                        // Handle an occasional over run case
                        if (eaEnd == BADADDR)
                        {
                            //msg("%08X **** abort end\n", s_eaCurrentAddress);
                            s_eaCurrentAddress = (s_eaSegEnd - 1);
                            break;
                        }

                        // Skip if it has offset reference (most common occurance)
                        BOOL bSkip = FALSE;
                        if (Flags & FF_0OFF)
                        {
                            //msg("  skip offset.\n");
                            bSkip = TRUE;
                        }
                        else
                            // Has a reference?
                            if (Flags & FF_REF)
                            {
                                ea_t eaDRef = get_first_dref_to(s_eaCurrentAddress);
                                if (eaDRef != BADADDR)
                                {
                                    // Ref part an offset?
                                    flags_t ValueRef = getFlags(eaDRef);
                                    if (isCode(ValueRef) && isOff1(ValueRef))
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
                                                //msg("%08X movzx\n", s_eaCurrentAddress);
                                                bIsByteAccess = TRUE;
                                            }
                                            break;

                                            case NN_mov:
                                            {
                                                if ((cmd.Operands[0].type == o_reg) && (cmd.Operands[1].dtyp == dt_byte))
                                                {
                                                    //msg("%08X mov\n", s_eaCurrentAddress);
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
                                            //msg("%08X not byte\n", s_eaCurrentAddress);
                                            autoWait();
                                            do_unknown(s_eaCurrentAddress, DOUNK_SIMPLE);
                                            auto_mark_range(s_eaCurrentAddress, eaEnd, AU_UNK);
                                            autoWait();
                                            // Step through making the array, and any bad size a byte
                                            //for(ea_t i = s_eaCurrentAddress; i < eaEnd; i++){ doByte(i, 1); }
                                            doByte(s_eaCurrentAddress, (eaEnd - s_eaCurrentAddress));
                                            autoWait();
                                            bSkip = TRUE;
                                        }
                                    }
                                }
                            }

                        // Make it unknown bytes
                        if (!bSkip)
                        {
                            //msg("%08X %08X %02X unknown\n", s_eaCurrentAddress, eaEnd, getFlags(s_eaCurrentAddress));
                            autoWait();
                            do_unknown(s_eaCurrentAddress, DOUNK_SIMPLE);
                            for (ea_t i = (s_eaCurrentAddress + 1); i < eaEnd; i++){ do_unknown(i, DOUNK_SIMPLE); }
                            autoWait();
                            auto_mark_range(s_eaCurrentAddress, eaEnd, AU_UNK);
                            s_uUnknowns++;
                            autoWait();

                            // Note: Might have triggered auto-analysis and a alignment or function could be here now
                        }

                        // Advance to next data value, or the end which ever comes first
                        s_eaCurrentAddress = eaEnd;
                        if (s_eaCurrentAddress < s_eaSegEnd)
                        {
                            s_eaCurrentAddress = nextthat(s_eaCurrentAddress, s_eaSegEnd, IsData, NULL);
                            break;
                        }
                    }
                    else
                    {
                        // Advance to next data value, or the end which ever comes first
                        s_eaCurrentAddress = nextthat(s_eaCurrentAddress, s_eaSegEnd, IsData, NULL);
                        break;
                    }
                }

                if (++s_iPass1Loops < UNKNOWN_PASSES)
                {
                    //msg("** Pass %d Unknowns: %u\n", s_iPass1Loops, s_uUnknowns);
                    s_eaCurrentAddress = s_eaLastAddress = s_eaSegStart;
                }
                else
                {
                    //msg("** Pass %d Unknowns: %u\n", s_iPass1Loops, s_uUnknowns);
                    NextState();
                }
            }
            break;

            // Find missing align blocks
            case eSTATE_PASS_2:
            {
                #define NEXT(_Here, _Limit) nextthat(_Here, _Limit, IsAlignByte, NULL)

                // Still inside this code segment?
                ea_t endEA = s_eaSegEnd;
                if (s_eaCurrentAddress < endEA)
                {
                    // Look for next unknown alignment type byte
                    // Will return BADADDR if none found which will catch in the endEA test
                    autoWait();
                    flags_t StartValue = getFlags(s_eaCurrentAddress);
                    if (!IsAlignByte(StartValue, NULL))
                        s_eaCurrentAddress = NEXT(s_eaCurrentAddress, s_eaSegEnd);
                    if (s_eaCurrentAddress < endEA)
                    {
                        // Catch when we get caught up in an array, etc.
                        ea_t eaStartAddress = s_eaCurrentAddress;
                        if (s_eaCurrentAddress <= s_eaLastAddress)
                        {
                            // Move to next header and try again..
                            msg("%08X F: %08X *** Align test in array #1 ***\n", s_eaCurrentAddress);
                            s_eaCurrentAddress = s_eaLastAddress = nextaddr(s_eaCurrentAddress);
                            break;
                        }

                        //msg("%08X Start.\n", eaStartAddress);
                        //msg("%08X F: %08X.\n", eaStartAddress, getFlags(eaStartAddress));
                        s_eaLastAddress = s_eaCurrentAddress;

                        // Get run count of this align byte
                        UINT uAlignByteCount = 1;
                        flags_t StartAlignValue = getFlags(eaStartAddress);

                        while (TRUE)
                        {
                            // Next byte
                            s_eaCurrentAddress = nextaddr(s_eaCurrentAddress);
                            //msg("%08X  Next.\n", s_eaCurrentAddress);
                            //msg("%08X  F: %08X.\n", s_eaCurrentAddress, getFlags(s_eaCurrentAddress));

                            if (s_eaCurrentAddress < endEA)
                            {
                                // Catch when we get caught up in an array, etc.
                                if (s_eaCurrentAddress <= s_eaLastAddress)
                                {
                                    msg("%08X F: %08X *** Align test in array #2 ***\n", eaStartAddress);
                                    s_eaCurrentAddress = s_eaLastAddress = nextaddr(s_eaCurrentAddress);
                                    break;
                                }
                                s_eaLastAddress = s_eaCurrentAddress;

                                // Count if it' still the same byte
                                if (getFlags(s_eaCurrentAddress) == StartAlignValue)
                                    uAlignByteCount++;
                                else
                                    break;
                            }
                            else
                                break;
                        };

                        // Do these bytes bring about at least a 16 (could be 32) align?
                        // TODO: Must we consider other alignments such as 4 and 8?
                        //       Probably a compiler option that is not normally used anymore.
                        if (((eaStartAddress + uAlignByteCount) & (16 - 1)) == 0)
                        {
                            // If short count, only try alignment if the line above or a below us has n xref
                            // We don't want to try to align odd code and switch table bytes, etc.
                            if (uAlignByteCount <= 2)
                            {
                                BOOL bHasRef = FALSE;

                                // Before us
                                ea_t eaEndAddress = (eaStartAddress + uAlignByteCount);
                                ea_t eaRef = get_first_cref_from(eaEndAddress);
                                if (eaRef != BADADDR)
                                {
                                    //msg("%08X cref from end.\n", eaEndAddress);
                                    bHasRef = TRUE;
                                }
                                else
                                {
                                    eaRef = get_first_cref_to(eaEndAddress);
                                    if (eaRef != BADADDR)
                                    {
                                        //msg("%08X cref to end.\n", eaEndAddress);
                                        bHasRef = TRUE;
                                    }
                                }

                                // After us
                                if (eaRef == BADADDR)
                                {
                                    ea_t eaForeAddress = (eaStartAddress - 1);
                                    eaRef = get_first_cref_from(eaForeAddress);
                                    if (eaRef != BADADDR)
                                    {
                                        //msg("%08X cref from start.\n", eaForeAddress);
                                        bHasRef = TRUE;
                                    }
                                    else
                                    {
                                        eaRef = get_first_cref_to(eaForeAddress);
                                        if (eaRef != BADADDR)
                                        {
                                            //msg("%08X cref to start.\n", eaForeAddress);
                                            bHasRef = TRUE;
                                        }
                                    }
                                }

                                // No code ref, now look for a broken code ref
                                if (eaRef == BADADDR)
                                {
                                    // This is still not complete as it could still be code, but pointing to a vftable
                                    // entry in data.
                                    // But should be fixed on more passes.
                                    ea_t eaEndAddress = (eaStartAddress + uAlignByteCount);
                                    eaRef = get_first_dref_from(eaEndAddress);
                                    if (eaRef != BADADDR)
                                    {
                                        // If it the ref points to code assume code is just broken here
                                        if (isCode(getFlags(eaRef)))
                                        {
                                            //msg("%08X dref from end %08X.\n", eaRef, eaEndAddress);
                                            bHasRef = TRUE;
                                        }
                                    }
                                    else
                                    {
                                        eaRef = get_first_dref_to(eaEndAddress);
                                        if (eaRef != BADADDR)
                                        {
                                            if (isCode(getFlags(eaRef)))
                                            {
                                                //msg("%08X dref to end %08X.\n", eaRef, eaEndAddress);
                                                bHasRef = TRUE;
                                            }
                                        }
                                    }

                                    if (eaRef == BADADDR)
                                    {
                                        //msg("%08X NO REF.\n", eaStartAddress);
                                    }
                                }

                                // Assume it's not an alignment byte(s) and bail out
                                if (!bHasRef) break;
                            }

                            // Attempt to make it an align block
                            bool bResult = doAlign(eaStartAddress, uAlignByteCount, 0);
                            // IDA will some times fail on 32 aligns for some reason, give it another try
                            if (!bResult)
                            {
                                // Try again with explicit limits
                                bResult = doAlign(eaStartAddress, uAlignByteCount, 32);
                                if (!bResult)
                                    bResult = doAlign(eaStartAddress, uAlignByteCount, 16);
                            }

                            if (bResult)
                            {
                                //msg("%08X %d ALIGN.\n", eaStartAddress, uAlignByteCount);
                                s_uAligns++;
                            }
                            else
                            {
                                // There are several times will IDA will fail even when the alignment block is obvious.
                                // Usually when it's an ALIGN(32) and there is a run of 16 align bytes
                                // Could at least do a code analize on it. Then IDA will at least make a mini array of it
                                //msg("%08X %d ** align fail **\n", eaStartAddress, uAlignByteCount);
                                //s_uAlignFails++;
                            }
                        }
                    }

                    break;
                }

                s_eaCurrentAddress = s_eaSegEnd;
                CheckBreak();
                NextState();
                #undef NEXT
            }
            break;

            // Find missing code
            case eSTATE_PASS_3:
            {
                // Still inside segment?
                if (s_eaCurrentAddress < s_eaSegEnd)
                {
                    // Look for next unknown value
                    autoWait();
                    ea_t eaStartAddress = next_unknown(s_eaCurrentAddress, s_eaSegEnd);
                    if (eaStartAddress < s_eaSegEnd)
                    {
                        s_eaCurrentAddress = eaStartAddress;
                        //s_uStrayBYTE++;
                        //msg("%08X Code.\n");

                        // Catch when we get caught up in an array, etc.
                        if (s_eaCurrentAddress <= s_eaLastAddress)
                        {
                            // Move to next header and try again..
                            msg("%08X F: %08X *** Align Pass 5 array catch ***\n", s_eaCurrentAddress);
                            s_eaCurrentAddress = next_unknown(s_eaCurrentAddress, s_eaSegEnd);
                            s_eaLastAddress = s_eaCurrentAddress;
                            break;
                        }
                        s_eaLastAddress = s_eaCurrentAddress;

                        // Try to make code of it
                        #if 0
                        int iResult = ua_code(s_eaCurrentAddress);
                        //msg("  Result: %08X.\n", iResult);
                        if(iResult > 0)
                        {
                            //s_uCodeFixes++;
                        }
                        else
                        {
                            //msg("%08X fix fail.\n", s_eaCurrentAddress);
                            //s_uCodeFixFails++;
                        }
                        #endif

                        // Start from possible next byte
                        s_eaCurrentAddress++;
                        break;
                    }
                }

                // Next state
                s_eaCurrentAddress = s_eaSegEnd;
                CheckBreak();
                NextState();
            }
            break;

            // Discover missing functions part 1
            case eSTATE_PASS_4:
            {
                // Process function list top down
                if (tFUNCNODE *pHeadNode = s_FuncList.GetHead())
                {
                    // Process it
                    ProcessFuncGap((s_eaCurrentAddress = pHeadNode->uAddress), pHeadNode->uSize);

                    // Remove function entry
                    s_FuncList.RemoveHead();
                    delete pHeadNode;
                }
                else
                {
                    s_eaCurrentAddress = s_eaSegEnd;
                    CheckBreak();
                    NextState();
                }
            }
            break;

            // Discover missing functions part 2
            case eSTATE_PASS_5:
            {
                // Examine next function
                if (s_uStep5Func < get_func_qty())
                {
                    if (func_t *pFunc = getn_func(s_uStep5Func))
                    {
                        if (IsBadFuncStart(pFunc))
                        {
                            s_uBlocksFixed += (UINT)(FixFuncBlock(pFunc->startEA) > 0);
                        }
                    }

                    s_uStep5Func++;
                }
                else
                {
                    s_eaCurrentAddress = s_eaSegEnd;
                    CheckBreak();
                    NextState();
                }
            }
            break;


            // Finished processing
            case eSTATE_FINISH:
            {
                NextState();
            }
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
            if (CheckBreak())
                goto BailOut;

            //Sleep(1); // Breathing room
        };

        BailOut:;
        WaitBox::hide();
    }
    CATCH()
}


// Decide next state to take
static void NextState()
{
	// Rewind
	if(s_eState < eSTATE_FINISH)
	{
		// Top of code seg
		s_eaCurrentAddress = s_eaLastAddress = s_eaSegStart;
		//SafeJumpTo(s_uCurrentAddress);
		autoWait();
	}

	// Logic
	switch(s_eState)
	{
		// Init
		case eSTATE_INIT:
		{
			s_eState = eSTATE_START;
		}
		break;

		// Start
		case eSTATE_START:
		{
			if(s_bDoDataToBytes)
			{
				msg("===== Fixing bad code bytes =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_1;
			}
			else
			if(s_bDoAlignBlocks)
			{
				msg("===== Missing align blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_2;
			}
			else
			if(s_bDoMissingCode)
			{
				msg("===== Missing code =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_3;
			}
			else
			if(s_bDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_StepTime = GetTimeStamp();

				// Function list problem in IDA 6.x still?
				BuildFuncionList();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_bDoBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_uStep5Func = 0;
				s_eState = eSTATE_PASS_5;
			}
			else
				s_eState = eSTATE_FINISH;

            WaitBox::processIdaEvents();
			s_iProgressStep = 1;
		}
		break;

		// Find unknown data in code space
		case eSTATE_PASS_1:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime));

			if(s_bDoAlignBlocks)
			{
				msg("===== Missing align blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_2;
			}
			else
			if(s_bDoMissingCode)
			{
				msg("===== Missing code =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_3;
			}
			else
			if(s_bDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_StepTime = GetTimeStamp();
				BuildFuncionList();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_bDoBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_uStep5Func = 0;
				s_eState = eSTATE_PASS_5;
			}
			else
				s_eState = eSTATE_FINISH;

            WaitBox::processIdaEvents();
			s_iProgressStep++;
		}
		break;


		// From missing align block pass
		case eSTATE_PASS_2:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime));

			if(s_bDoMissingCode)
			{
				msg("===== Missing code =====\n");
				s_StepTime = GetTimeStamp();
				s_eState = eSTATE_PASS_3;
			}
			else
			if(s_bDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_StepTime = GetTimeStamp();
				BuildFuncionList();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_bDoBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_uStep5Func = 0;
				s_eState = eSTATE_PASS_5;
			}
			else
				s_eState = eSTATE_FINISH;

            WaitBox::processIdaEvents();
			s_iProgressStep++;
		}
		break;

		// From missing code pass
		case eSTATE_PASS_3:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime));

			if(s_bDoMissingFunc)
			{
				msg("===== Missing functions =====\n");
                WaitBox::processIdaEvents();
				s_StepTime = GetTimeStamp();
				BuildFuncionList();
				s_eState = eSTATE_PASS_4;
			}
			else
			if(s_bDoBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_uStep5Func = 0;
				s_eState = eSTATE_PASS_5;
			}
			else
				s_eState = eSTATE_FINISH;

            WaitBox::processIdaEvents();
			s_iProgressStep++;
		}
		break;

		// From missing function pass part 1
		case eSTATE_PASS_4:
		{
			msg("Time: %s.\n\n", TimeString(GetTimeStamp() - s_StepTime));

			if(s_bDoBadBlocks)
			{
				msg("===== Bad function blocks =====\n");
				s_StepTime = GetTimeStamp();
				s_uStep5Func = 0;
				s_eState = eSTATE_PASS_5;
			}
			else
				s_eState = eSTATE_FINISH;

            WaitBox::processIdaEvents();
			s_iProgressStep++;
		}
		break;

		// From missing function pass part 2
		case eSTATE_PASS_5:
		{
			msg("Time: %s.\n", TimeString(GetTimeStamp() - s_StepTime));
            WaitBox::processIdaEvents();
			s_eState = eSTATE_FINISH;
			s_iProgressStep++;
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
				s_eaSegStart = s_thisSeg->startEA;
				s_eaSegEnd   = s_thisSeg->endEA;
				s_eState = eSTATE_START;
			}
			else
			{
				msg("\n===== Done =====\n");
				ShowEndStats();
                refresh_idaview_anyway();
                WaitBox::processIdaEvents();

				// Optionally play completion sound
				if(s_wAudioAlertWhenDone)
				{
                    // Only if processing took at least a few seconds
                    if ((GetTimeStamp() - s_StartTime) > 2.2)
                    {
                        WaitBox::updateAndCancelCheck(100);
                        WaitBox::processIdaEvents();
                        OggPlay::playFromMemory((const PVOID)complete_ogg, complete_ogg_len);
                        OggPlay::endPlay();
                    }
				}

				s_eState = eSTATE_EXIT;
				s_iProgressStep++;
			}
		}
		break;

		// Exit plugin run back to IDA control
		case eSTATE_EXIT:
		{
			// In case we aborted some place and list still exists..
			FlushFunctionList();
            if (chosen)
            {
                SegSelect::free(chosen);
                chosen = NULL;
            }
			s_eState = eSTATE_INIT;
		}
		break;
	};
}


// Print out end stats
static void ShowEndStats()
{
	msg("  Total time: %s.\n", TimeString(GetTimeStamp() - s_StartTime));
	msg("  Alignments: %u\n", s_uAligns);
	msg("Blocks fixed: %u\n", s_uBlocksFixed);
	msg("   Functions: %d\n", ((int) get_func_qty() - s_iStartFuncCount)); // Can be negative

	//msg("Code fixes: %u\n", s_uCodeFixes);
	//msg("Code fails: %u\n", s_uCodeFixFails);
	//msg("Align fails: %d\n", s_uAlignFails);
	//msg("  Unknowns: %u\n", s_uUnknowns);

	msg(" \n");
}


// Checks and handles if break key pressed; returns TRUE on break.
static BOOL CheckBreak()
{
	// Calc approx progress

	// s_eaSegStart
	// s_eaSegEnd
	// s_eaCurrentAddress

    if (WaitBox::isUpdateTime())
    {
        int iProgressPercent;
        if (s_iProgressStep == 0)
            iProgressPercent = 0;
        else
        if (s_iProgressStep > s_iProgressSteps)
            iProgressPercent = 100;
        else
        {
            double fPerStep = (1.0 / (double) s_iProgressSteps);
            double fAcum    = (fPerStep * (double)(s_iProgressStep - 1));

            ea_t eaCurrent = s_eaCurrentAddress;
            if (eaCurrent < s_eaSegStart)
                eaCurrent = s_eaSegStart;
            else
            if (eaCurrent > s_eaSegEnd)
                eaCurrent = s_eaSegEnd;

            double fMyPos    = (((double)(eaCurrent - s_eaSegStart) / (double)(s_eaSegEnd - s_eaSegStart)) * fPerStep);
            iProgressPercent = (int)((fAcum + fMyPos) * 100.0);
        }

        if (WaitBox::updateAndCancelCheck(iProgressPercent))
        {
            msg("\n*** Aborted ***\n\n");

            // Show stats then directly to exit
            autoWait();
            ShowEndStats();
            s_eState = eSTATE_EXIT;
            return(TRUE);
        }
    }

	return(FALSE);
}


// Build local list of function gaps
// There is a problem with IDA enumerating using get_next_func() after there is a change in between.
// So we build a local list first then process it for missing functions.
static BOOL BuildFuncionList()
{
	int iCount = 0;
	FlushFunctionList();

	#ifdef LOG_FILE
	Log(s_hLogFile, "\n====== Function gaps ======\n");
	#endif
	//msg("\n====== Function gaps ======\n");

	if(func_t *pLastFunc = get_next_func(s_eaSegStart))
	{
		iCount++;

		while(func_t *pNextFunc = get_next_func(pLastFunc->startEA))
		{
			iCount++;

			// A gap between the last function?
			int iGap = ((int) pNextFunc->startEA - (int) pLastFunc->endEA);
			if(iGap > 0)
			{
				#ifdef LOG_FILE
				Log(s_hLogFile, "%08X GAP[%06d] %d.\n", pLastFunc->endEA, iCount++, iGap);
				#endif
				//msg("%08X GAP[%06d] %d.\n", pLastFunc->endEA, iCount++, iGap);

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
	//msg("Func count: %d %d.\n", iCount, get_func_qty());

	#ifdef LOG_FILE
	Log(s_hLogFile, "\n\n");
	#endif

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

// Returns TRUE if flag byte is possibly a typical alignment byte
static bool idaapi IsAlignByte(flags_t flags, void *ud)
{
	if((flags == ALIGN_VALUE1) || (flags == ALIGN_VALUE2))
		return(TRUE);
	else
		return(FALSE);
}

// Return if flag is data type we want to convert to unknown bytes
static bool idaapi IsData(flags_t flags, void *ud)
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
static LPCTSTR GetDisasmText(ea_t ea)
{
    static char szBuff[MAXSTR]; szBuff[0] = szBuff[MAXSTR - 1] = 0;
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
static BOOL TryFunction(ea_t CodeStartEA, ea_t CodeEndEA, ea_t &rCurEA)
{
	BOOL bResult = FALSE;

	autoWait();
	#ifdef LOG_FILE
	Log(s_hLogFile, "%08X %08X Trying function.\n", CodeStartEA, rCurEA);
	#endif
	//msg("%08X %08X Trying function.\n", CodeStartEA, rCurEA);

	/// *** Don't use "get_func()" it has a bug, use "get_fchunk()" instead ***

	// Could belong as a chunk to an existing function already or already a function here recovered already between steps.
	if(func_t *pFunc = get_fchunk(CodeStartEA))
	{
  		#ifdef LOG_FILE
		Log(s_hLogFile, "  %08X %08X %08X F: %08X already function.\n", pFunc->endEA, pFunc->startEA, CodeStartEA, getFlags(CodeStartEA));
		#endif
		//msg("  %08X %08X %08X F: %08X already function.\n", pFunc->endEA, pFunc->startEA, CodeStartEA, getFlags(CodeStartEA));
		rCurEA = prev_head(pFunc->endEA, CodeStartEA); // Advance to end of the function -1 location (for a follow up "next_head()")
		bResult = TRUE;
	}
	else
	{
		// Try function here
		if(add_func(CodeStartEA, BADADDR))
		{
			// Wait till IDA is done possibly creating the function, then get it's info
			autoWait();
			if(func_t *pFunc = get_fchunk(CodeStartEA)) // get_func
			{
				#ifdef LOG_FILE
				Log(s_hLogFile, "  %08X function success.\n", CodeStartEA);
				#endif
				#ifdef VBDEV
				msg("  %08X function success.\n", CodeStartEA);
				#endif

				// Look at function tail instruction
				autoWait();
				BOOL bExpected = FALSE;
				ea_t tailEA = prev_head(pFunc->endEA, CodeStartEA);
				if(tailEA != BADADDR)
				{
					if(decode_insn(tailEA))
					{
						switch(cmd.itype)
						{
							// A return?
							case NN_retn: case NN_retf: case NN_iretw: case NN_iret: case NN_iretd:
							case NN_iretq: case NN_syscall:
							case NN_sysret:
							{
								bExpected = TRUE;
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
								bExpected = TRUE;
							}
							break;

							// A single align byte that was mistakenly made a function?
							case NN_int3:
							case NN_nop:
							if(pFunc->size() == 1)
							{
								// Try to make it an align
								autoWait();
								do_unknown(tailEA, DOUNK_SIMPLE);
								autoWait();
								if(!doAlign(tailEA, 1, 0))
								{
									// If it fails, make it an instruction at least
									//msg("%08X ALIGN fail.\n", tailEA);
									create_insn(tailEA);
									autoWait();
								}
								//msg("%08X ALIGN\n", tailEA);
								bExpected = TRUE;
							}
							break;

							// Return-less exception or exit handler?
							case NN_call:
							{
								ea_t eaCRef = get_first_cref_from(tailEA);
								if(eaCRef != BADADDR)
								{
									char szName[MAXNAMELEN + 1];
									if(get_true_name(BADADDR, eaCRef, szName, SIZESTR(szName)))
									{
										const char * const aszExitNames[] =
										{
											"exception",
											"handler",
											"exitprocess",
											"fatalappexit",
											"_abort",
											"_exit",
										};

										_strlwr(szName);
										for(int i = 0; i < (sizeof(aszExitNames) / sizeof(const char *)); i++)
										{
											if(strstr(szName, aszExitNames[i]))
											{
												//msg("%08X Exception\n", CodeStartEA);
												bExpected = TRUE;
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
								if(pFunc->flags & FUNC_NORET)
								{
									//msg("%08X NORETURN\n", tailEA);
									bExpected = TRUE;
								}
							}
							break;
						};
					}

					if(!bExpected)
					{
						char szName[MAXNAMELEN + 1];
						if(!get_true_name(BADADDR, pFunc->startEA, szName, SIZESTR(szName)))
							memcpy(szName, "unknown", sizeof("unknown"));
						msg("%08X \"%s\" problem? <click me>\n", tailEA, szName);
						//msg("  T: %d\n", cmd.itype);

						#ifdef LOG_FILE
						Log(s_hLogFile, "%08X \"%s\" problem? <click me>\n", tailEA, szName);
						//Log(s_hLogFile, "  T: %d\n", cmd.itype);
						#endif
					}
				}

				// Update current look position to the end of this function
				rCurEA = tailEA; // Advance to end of the function -1 location (for a follow up "next_head()")
				bResult = TRUE;
			}
		}
	}

	return(bResult);
}


// Process the gap from the end of one function to the start of the next
// looking for missing functions in between.
static void ProcessFuncGap(ea_t startEA, UINT uSize)
{
	ea_t curEA = startEA;
	ea_t endEA = (startEA + uSize);
	ea_t CodeStartEA  = BADADDR;

	#ifdef LOG_FILE
	Log(s_hLogFile, "\nS: %08X, E: %08X ==== PFG START ====\n", startEA, endEA);
	#endif
	#ifdef VBDEV
	msg("\n%08X %08X ==== Gap ====\n", startEA, endEA);
	#endif

    // Traverse gap
	autoWait();
    while(curEA < endEA)
    {
		// Info flags for this address
		flags_t uFlags = getFlags(curEA);
		#ifdef LOG_FILE
		Log(s_hLogFile, "  C: %08X, F: %08X, \"%s\".\n", curEA, uFlags, GetDisasmText(curEA));
		#endif
		#ifdef VBDEV
		msg(" C: %08X, F: %08X, \"%s\".\n", curEA, uFlags, GetDisasmText(curEA));
		#endif

		if(curEA < startEA)
		{
			#ifdef LOG_FILE
			Log(s_hLogFile, "**** Out of start range! %08X %08X %08X ****\n", curEA, startEA, endEA);
			#endif
			return;
		}
		if(curEA > endEA)
		{
			#ifdef LOG_FILE
			Log(s_hLogFile, "**** Out of end range! %08X %08X %08X ****\n", curEA, startEA, endEA);
			#endif
			return;
		}

		// Skip over "align" blocks.
		// #1 we will typically see more of these then anything else
		if(isAlign(uFlags))
		{
			// Function between code start?
			if(CodeStartEA != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_hLogFile, "  %08X Trying function #1\n", CodeStartEA);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #1\n", CodeStartEA);
				#endif
				TryFunction(CodeStartEA, endEA, curEA);
			}

			CodeStartEA = BADADDR;
		}
		else
		// #2 case, we'll typically see data
		if(isData(uFlags))
		{
			// Function between code start?
			if(CodeStartEA != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_hLogFile, "  %08X Trying function #2\n", CodeStartEA);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #2\n", CodeStartEA);
				#endif
				TryFunction(CodeStartEA, endEA, curEA);
			}

			CodeStartEA = BADADDR;
		}
		else
		// Hit some code?
		if(isCode(uFlags))
		{
			// Yes, mark the start of a possible code block
			if(CodeStartEA == BADADDR)
			{
				CodeStartEA  = curEA;

				#ifdef LOG_FILE
				Log(s_hLogFile, "  %08X Trying function #3, assumed func start\n", CodeStartEA);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #3, assumed func start\n", CodeStartEA);
				#endif
				if(TryFunction(CodeStartEA, endEA, curEA))
					CodeStartEA = BADADDR;
			}
		}
		else
		// Undefined?
		// Usually 0xCC align bytes
		if(isUnknown(uFlags))
		{
			#ifdef LOG_FILE
			Log(s_hLogFile, "  C: %08X, Unknown type.\n", curEA);
			#endif
			#ifdef VBDEV
			msg("  C: %08X, Unknown type.\n", curEA);
			#endif
			CodeStartEA = BADADDR;
		}
		else
		{
			#ifdef LOG_FILE
			Log(s_hLogFile, "  %08X ** unknown data type! **\n", curEA);
			#endif
			#ifdef VBDEV
			msg("  %08X ** unknown data type! **\n", curEA);
			#endif
			CodeStartEA = BADADDR;
		}

		// Next item
		autoWait();
		ea_t nextEA = BADADDR;
		if(curEA != BADADDR)
		{
			nextEA = next_head(curEA, endEA);
			if(nextEA != BADADDR)
				curEA = nextEA;
		}

		if((nextEA == BADADDR) || (curEA == BADADDR))
		{
			// If have code and at the end, try a function from the start
			if(CodeStartEA != BADADDR)
			{
				#ifdef LOG_FILE
				Log(s_hLogFile, "  %08X Trying function #4\n", CodeStartEA);
				#endif
				#ifdef VBDEV
				msg("  %08X Trying function #4\n", CodeStartEA);
				#endif
				TryFunction(CodeStartEA, endEA, curEA);
				autoWait();
			}

			#ifdef LOG_FILE
			Log(s_hLogFile, " Gap end: %08X.\n", curEA);
			#endif
			#ifdef VBDEV
			msg(" Gap end: %08X.\n", curEA);
			#endif

            break;
		}

    }; // while(rCurEA < startEA)
}



// =======================================================================================================
// Return TRUE if function black has a bad start reference
// Not inclusive, only valid check if function has at least one cref
// =========================================================================================================
static BOOL IsBadFuncStart(func_t *pFunc)
{
	// Walk crefs "to"
	ea_t eaAddress = pFunc->startEA;
	ea_t eaCref    = get_first_fcref_to(eaAddress);

	while(eaCref != BADADDR)
	{
		// Fill "cmd" struct
		if(decode_insn(eaCref))
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

			eaCref = get_next_fcref_to(eaAddress, eaCref);
		}
		else
			return(FALSE);
	};

	return(FALSE);
}


// =======================================================================================================
// Attempt to locate block end
// =========================================================================================================
static ea_t FindBlockEnd(ea_t eaAddress)
{
	while(TRUE)
	{
		// Look for end of block
		if(decode_insn(eaAddress))
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
				eaAddress += get_item_size(eaAddress);
				break;
			}
		}
		else
			// Not an instruction here anymore
			break;

		// Next instruction
		ea_t eaNext = next_head(eaAddress, (ea_t) 0x7FFFFFFF);
		if(eaNext != BADADDR)
			eaAddress = eaNext;
		else
			// End of segment
			break;

		// Next shouldn't have a ref to it
		if(get_first_fcref_to(eaAddress) != BADADDR)
		{
			//msg("   %08X Got unexpected cref.\n", eaAddress);
			break;
		}
	};

	return(eaAddress);
}


// =======================================================================================================
// Attempt to fix broken function chunks
// =========================================================================================================
static int FixFuncBlock(ea_t eaBlock)
{
	int	iFixCount = 0;

	ea_t eaBlockEnd = FindBlockEnd(eaBlock);
	//msg("%08X %08X Fixblock.\n", eaBlock, eaBlockEnd);

	// Remove possible function assumption for the block
	autoWait();
	if(del_func(eaBlock))
		autoWait();

	// Remove possible function to let IDA auto-name as it a branch label
	if(set_name(eaBlock, "", SN_AUTO))
		autoWait();

	// Locate the owner function(s) to the block
	// Almost always one ref, typically only small percent will have more then one ref
	// Note: Often the first ref is seen as the previous address, which is just item/instruction relative
	// it should be part of related function anyhow.
	ADDRSET KnownSet;
	int iOwners = 0;
	ea_t eaBlockRef = get_first_cref_to(eaBlock);
	while(eaBlockRef != BADADDR)
	{
		if(func_t *pOwnerFunc = get_func(eaBlockRef))
		{
			iOwners++;

			// Ignore if we've seen handled this function already
			ea_t eaOwner = pOwnerFunc->startEA;
			if(KnownSet.find(eaOwner) == KnownSet.end())
			{
				KnownSet.insert(eaOwner);
				if(append_func_tail(pOwnerFunc, eaBlock, eaBlockEnd))
				{
					//msg("%08X Owner append.\n", eaOwner);
					iFixCount++;
					autoWait();
				}
				else
				{
					// Fails simply because the block is probably already connected to the function
					//msg("  ** Failed to append tail block %08X to function %08X! **\n", eaBlock, eaOwner);
				}
			}
		}

		eaBlockRef = get_next_cref_to(eaBlock, eaBlockRef);
	};

	if(!iOwners)
		msg("%08X No owner found <click me>\n", eaBlock);

	return(iFixCount);
}
