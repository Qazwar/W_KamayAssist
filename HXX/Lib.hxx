// Include all headers

#ifndef LIB_MAIN
#define LIB_MAIN
#pragma once

#include "Includes.hxx"
#include "Utils.hxx"
#include "Console.hxx"
#include "VirtualMemory.hxx"
#include "FileSystem.hxx"
#include "Process.hxx"
#include "SigScanning.hxx"

#ifndef ISLIBPROJECT
#ifdef _UNICODE
#ifdef _M_IX86
#ifdef _DEBUG
#pragma comment(lib,"../Debug/Lib_wchar.lib")
#else
#pragma comment(lib,"../Release/Lib_wchar.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib,"../x64/Debug/Lib_wchar.lib")
#else
#pragma comment(lib,"../x64/Release/Lib_wchar.lib")
#endif
#endif
#else
#ifdef _M_IX86
#ifdef _DEBUG
#pragma comment(lib,"../Debug/Lib_char.lib")
#else
#pragma comment(lib,"../Release/Lib_char.lib")
#endif
#else
#ifdef _DEBUG
#pragma comment(lib,"../x64/Debug/Lib_char.lib")
#else
#pragma comment(lib,"../x64/Release/Lib_char.lib")
#endif
#endif
#endif
#endif

#endif