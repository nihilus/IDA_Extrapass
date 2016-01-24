
// ****************************************************************************
// File: Utility.h
// Desc: Utility functions
//
// ****************************************************************************
#pragma once

// Size of string with out terminator
#define SIZESTR(x) (sizeof(x) - 1)

// Data and function alignment (w/processor pack)
#define ALIGN(_x_) __declspec(align(_x_))

// Time
typedef double TIMESTAMP;  // Time in floating seconds
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)
#define DAY    (HOUR * 24)

TIMESTAMP GetTimeStamp();
TIMESTAMP GetTimeStampLow();
void Trace(LPCTSTR pszFormat, ...);
void Log(FILE *pLogFile, const char *format, ...);


// Sequential 32 bit flag serializer
struct SBITFLAG
{
	inline SBITFLAG() : Index(0) {}
	inline UINT First(){ Index = 0; return(1 << Index++); }
	inline UINT Next(){ return(1 << Index++); }
	UINT Index;
};

#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC__ __FILE__ "("__STR1__(__LINE__)") : Warning MSG: "
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "

// Now you can use the #pragma message to add the location of the message:
//
// #pragma message(__LOC__ "important part to be changed")
// #pragma message(__LOC2__ "error C9901: wish that error would exist")

//#undef MYCATCH
#define CATCH() catch (...) { msg("** Exception in %s()! ***\n", __FUNCTION__); }