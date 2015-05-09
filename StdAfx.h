
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER       _WIN32_WINNT_WINXP
#define _WIN32_WINNT _WIN32_WINNT_WINXP
#define _WIN32_IE_   _WIN32_WINNT_WINXP
#include <windows.h>
#include <time.h>
#include <mmsystem.h>
#include <math.h>
#include <Shellapi.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#pragma warning(disable : 4244) // "conversion from 'int64' to 'size_t', possible loss of data"
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
#include <name.hpp>
#include <allins.hpp>

#include "Utility.h"

#define MY_VERSION "3.4"
