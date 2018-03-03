#ifndef LIB_UTILS
#define LIB_UTILS
#pragma once

#define DO_ONCE_SCOPE(Code) \
{\
static bool bCodeRun = false; \
if(!bCodeRun) \
{ \
  Code; \
  bCodeRun = true; \
} \
} \

#define DO_ONCE(Code) \
static bool bCodeRun = false; \
if(!bCodeRun) \
{ \
  Code; \
  bCodeRun = true; \
} \

#define EXTERN extern

#define BUFSIZE 512

/* Defines */
#define FOREGROUND_CYAN FOREGROUND_GREEN | FOREGROUND_BLUE
#define FOREGROUND_ROSE FOREGROUND_RED | FOREGROUND_BLUE
#define FOREGROUND_YELLOW FOREGROUND_RED | FOREGROUND_GREEN
#define BACKGROUND_CYAN BACKGROUND_GREEN | BACKGROUND_BLUE
#define BACKGROUND_ROSE BACKGROUND_RED | BACKGROUND_BLUE
#define BACKGROUND_YELLOW BACKGROUND_RED | BACKGROUND_GREEN
#define CONSOLE_UNDERLINED COMMOLVB_UNDERSCORE
#define CONSOLE_BOX COMMOLVB_GRID_HORIZONTAL | COMMOLVB_GRID_RVERTICAL | COMMOLVB_REVERSE_VIDEO
#define CONSOLE_REVERSE COMMOLVB_REVERSE_VIDEO
#define MINSIZEVIRTUALMEMORY  0x1000
#define UNINITIALIZED 0xFFFFFFFF

//https://people.freebsd.org/~wpaul/pe/pe_var.h
#define IMR_RELTYPE(x)				((x >> 12) & 0xF)
#define IMR_RELOFFSET(x)			(x & 0xFFF)

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#define _FunctionOffset(offset) (*(HEX*)(*(HEX*)this + offset))
#define _FunctionManualthisOffset(offset,thiss) (*(HEX*)(*(HEX*)thiss + offset))
#define _Offset(offset,type) (*(type*)((HEX)this + offset))
#define _POffset(offset,type) ((type*)((HEX)this + offset))
#define _OffsetManualthis(offset,type,thiss) (*(type*)((HEX)thiss + offset))
#define _POffsetManualthis(offset,type,thiss) ((type*)((HEX)thiss + offset))

/* Typedefs */

typedef void* Pointer;
typedef void** pPointer;

#ifdef ENVIRONMENT32
typedef unsigned long uHEX;
typedef signed long HEX;
#else
typedef unsigned long long uHEX;
typedef signed long long HEX;
#endif
typedef uHEX *puHEX;
typedef HEX *pHEX;

typedef unsigned char Byte;
typedef Byte* pByte;
typedef pByte Bytes;

typedef unsigned long uHEX32;
typedef signed long HEX32;
typedef uHEX32 *puHEX32;
typedef HEX32 *pHEX32;
typedef unsigned long long uHEX64;
typedef signed long long HEX64;
typedef uHEX64 *puHEX64;
typedef HEX64 *pHEX64;

// Our string converter
EXTERN std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> StringConverter;

// Auto convert was meant to be portable on projects settings for acsii and unicode
#ifdef _UNICODE
typedef wchar_t String;
typedef std::wstring stdString;
#define AutoConvertS(s) StringConverter.from_bytes(s).c_str()
#define AutoConvertW(s) s
#define AutoConvertC(s) StringConverter.to_bytes(s).c_str()
#else
typedef char String;
typedef std::string stdString;
#define AutoConvertS(s) s
#define AutoConvertW(s) StringConverter.to_bytes(s).c_str()
#define AutoConvertC(s) s
#endif

// Copy a string into another string.
void CopyString( String*dest , HEX destsize , const String* src );

// Open a file
void Open_S( FILE** _Stream , String const* _FileName , String const* _Mode );

// Get length of a string
HEX StrLen( String const*Str );

// Add a string into another string
void StrCat_S( String *Str , HEX MaxSize , String* const cStr );

HEX StringPos( String* sBuf , String* sBuf2 , HEX Size );

// Put variables into a buffer.
void SPrintf_S( String*buf , HEX Size , const String* str , va_list list );

void SPrintf_S( String*buf , HEX Size , const String* str , ... );

void ToLower( String*str , HEX Size );

bool StrHasOnlyDigits( const stdString &str );

void SetClipBoard( const stdString &s );

// Allocating memory (not forcely virtual)
template<typename T = Pointer> __forceinline T Alloc( HEX Size )
{
    return ::operator new( Size );
}

// Freeing memory (not forcely virtual)
template<typename T = Pointer> __forceinline void FreeAlloc( T pBuf )
{
    ::operator delete( pBuf );
}

// Relative Virtual Address (Rva-> offset located temporary on the cache of the disk) _ (RawData -> offset on the disk)
// Sections have VirtualAddress as name for addresses, but it should be called Rva since it's just an offset.

uHEX32 RvaToRawOffset( PIMAGE_NT_HEADERS NtHeaders , uHEX32 Rva , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr );

// Works the same as above, we just invert the roles between VirtualAddress to PointerToRawData (the firsts addresses of the section) and VirtualSize and SizeOfRawData.
uHEX32 RawToRvaOffset( PIMAGE_NT_HEADERS NtHeaders , uHEX32 Raw , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr );

uHEX32 RvaToRawOffset32( PIMAGE_NT_HEADERS32 NtHeaders , uHEX32 Rva , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr );

uHEX32 RawToRvaOffset32( PIMAGE_NT_HEADERS32 NtHeaders , uHEX32 Raw , PIMAGE_SECTION_HEADER SectionHeaderF = nullptr );

// Each memory bytes have a protection flag set on it for every processes, we can modify it with VirtualProtectEx.
// This is the case too with sections when it's written into memory.
// It has protection flags, and we set it accordignly to the characteristipc of the sections , so it looks "legit".
uHEX32 GetProtectionOfSection( PIMAGE_SECTION_HEADER Section );

template<typename T = HEX> __forceinline T _GetModule( const String* sModuleName , HEX HexAddressToAdd = 0 )
{
    return ( T ) ( ( HEX ) GetModuleHandle( sModuleName ) + HexAddressToAdd );
}

template<typename T = pPointer> __forceinline T _VTable( Pointer pAddress )
{
    return *( T* ) ( pAddress );
}

template<typename T = Pointer> __forceinline T _VirtualFunction( Pointer pAddress , int iIndex )
{
    return ( T ) ( _VTable( pAddress )[ iIndex ] );
}

template< typename RetType = void , typename P = Pointer , typename ... vArgs > __forceinline RetType _CallVirtualFunction( P pAddress , int iIndex , vArgs ... pArgs )
{
    return ( ( RetType( __thiscall* )( P , vArgs ... ) ) _VTable( pAddress )[ iIndex ] ) ( pAddress , pArgs ... );
}

template<typename T = Pointer> __forceinline T _Function( Pointer pAddress )
{
    return ( T ) ( pAddress );
}

enum E_CallingConvention
{
    e_thiscall ,
    e_fastcall ,
    e_stdcall ,
    e_nothing
};

template< typename RetType = void , typename ... vArgs > __forceinline RetType _CallFunction( E_CallingConvention CallingConvention , Pointer pAddress , vArgs ... pArgs )
{
    if ( CallingConvention == e_thiscall )
    {
        return ( ( RetType( __thiscall* )( vArgs ... ) ) pAddress ) ( pArgs ... );
    }
    else if ( CallingConvention == e_fastcall )
    {
        return ( ( RetType( __fastcall* )( vArgs ... ) ) pAddress ) ( pArgs ... );
    }
    else if ( CallingConvention == e_stdcall )
    {
        return ( ( RetType( __stdcall* )( vArgs ... ) ) pAddress ) ( pArgs ... );
    }
    else
        return ( ( RetType( *)( vArgs ... ) ) pAddress ) ( pArgs ... );
}

template<typename T = Pointer> __forceinline T _Cast( Pointer pTemp )
{
    return ( T ) ( pTemp );
}

// Just a class to call our entrypoint later in manual mapping.
// So we can pass it as the argument when we create a thread remotly to call the entrypoint with that.

class DllMain64
{
public:

    DllMain64( Pointer _EntryPoint , uHEX64 _Module , uHEX64 _Reason , uHEX64 _Reserved );

    Pointer EntryPoint;
    uHEX64 Module , Reason , Reserved;
};

class DllMain
{
public:

    DllMain( Pointer _EntryPoint , Pointer _Module , Pointer _Reason , Pointer _Reserved );

    Pointer EntryPoint , Module , Reason , Reserved;
};

class DllMain32
{
public:

    DllMain32( Pointer _EntryPoint , uHEX32 _Module , uHEX32 _Reason , uHEX32 _Reserved );

    Pointer EntryPoint;
    uHEX32 Module , Reason , Reserved;
};

stdString sTime();

class CTimer
{
public:

    CTimer();

    void Clear();

    void Start();

    void End();

    LARGE_INTEGER lgFrequency;
    LARGE_INTEGER lgt1 , lgt2;
    double dElapsedTime;
};

//https://www.codeproject.com/Tips/139349/Getting-the-address-of-a-function-in-a-DLL-loaded

//-----------------------------------------------------------------------------

/* PE Library */

/*#include "../libs/pe_lib/pe_bliss.h"
#ifndef _DEBUG
#ifdef ENVIRONMENT64
#pragma comment(lib,"..\\x64\\Release\\pe_bliss.lib")
#else
#pragma comment(lib,"..\\Release\\pe_bliss.lib")
#endif
#else
#ifdef ENVIRONMENT64
#pragma comment(lib,"..\\x64\\Debug\\pe_bliss.lib")
#else
#pragma comment(lib,"..\\Debug\\pe_bliss.lib")
#endif
#endif*/

#endif 