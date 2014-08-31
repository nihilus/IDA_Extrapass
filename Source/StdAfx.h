// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
#define AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_

/* 
	Problem when going from VC6 to VC2005 and, or  a problem using IDA SDK libs (w/VC2005) 
	so no longer using pre-compiled header.  Effects next to nothing anyhow..
*/

#pragma once
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0502 // WinXP++    
#define _WIN32_WINNT 0x0502

#include <windows.h>
#include <time.h>

// IDA libs
//#define __NOT_ONLY_PRO_FUNCS__
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <kernwin.hpp>

#include "Utility.h"

#define MY_VERSION "2.1"

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
