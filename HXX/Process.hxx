#ifndef LIB_PROCESS
#define LIB_PROCESS
#pragma once

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // ?
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004
#define THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR 0x00000010 // ?
#define THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET 0x00000020 // ?
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

typedef _CLIENT_ID CLIENT_ID;
typedef _CLIENT_ID* PCLIENT_ID;

typedef struct _PS_ATTRIBUTE
{
    ULONG Attribute;
    SIZE_T Size;
    union
    {
        ULONG Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE , *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[ 1 ];
} PS_ATTRIBUTE_LIST , *PPS_ATTRIBUTE_LIST;

namespace N_Process
{
    // Create our variable to count relocs (in case if there is multiple injections).
    EXTERN int iCountReloc;

    // Fix Relocations by type of blocks, here we fix the addresses to the new process
    // So it can calls correctly the IAT Functions, strings and others ressources
    bool FixBaseRelocation( HEX HexDelta , PWORD pwRelocationAddress , Bytes pbRelocationBlock );

    class Process
    {
    public:

        // Constructors of the class process;
        // Here we initialize proc id, the handle of the process, and the process path (exe's path).
        // We can get it by PID or Path in directory, or just the handle of it.
        // GetModuleBaseName stands getting for the exe's name in task manager for example.
        Process( Pointer _pProcess = GetCurrentProcess() );

        Process( HEX _HexProcessID );

        Process( stdString _swProcessName );

        // Deconstructor, free our memory allocated, etc...
        ~Process();

        // Get the process handle.
        Pointer Get();

        // Find a module by name.
        Pointer FindModule( stdString DLLName , bool bForce = false );

        // Find the module path from the module address , GetModuleFileNameEx can do it
        stdString FindModulePath( Pointer pModuleAddress );

        void PrintAllModules();

        void RefreshGetModules();

        void GetInformations();

        stdString &GetName();

        HEX &GetID();

        void Free();

        bool SetAllAccess();

        Pointer CreateRemotlyThread( Pointer pRoutine , Pointer pArguments , pHEX pHexRetRoutine = nullptr , unsigned long *pULRetThread = nullptr );

        // Force an image (dll) to load into the process with LoadLibrary.
        Pointer ForceLoadLibrary( stdString PathToDLL , pPointer pModuleAddress = nullptr , bool bCloseAfter = true );

        // Same as force load library but vice-versa.
        Pointer ForceFreeLibrary( Pointer pModuleAddress );

        Pointer ForceFreeLibrary( stdString DLLName );

        void FreeAllForcedLoadedLibraries();

        // Get remotly the exported function of a process.
        uHEX GetFunction( const PCHAR pcFunctionName , const stdString & sModuleName );

        HEX _ManualMapModule( Pointer pAddressImage , pPointer pReturnModuleBase = nullptr , std::vector<Byte> pbReserved = { 0x24 , 0x07 }
                              , bool bWriteHeaders = false
                              , bool bProtect = true );

        HEX ManualMapModule( stdString pFilePath , pPointer pReturnModuleBase = nullptr
                             , bool bWriteHeaders = false
                             , std::vector<Byte> pbReserved = { 0x24 , 0x07 }
        , bool bProtect = true );

        // Name of the process
        stdString sName;
        stdString sProcessPath;

        // Number of modules of the process
        std::map <stdString , HEX> mshModules;

        // The handle of the process, and its address in memory.
        Pointer pProcess , pAddress;

        // Process ID.
        HEX HexProcessID;

        // The number of modules that were forced by LoadLibrary and manual mapping.
        std::map <Pointer , stdString> psForcedModules;
    };
};

#endif