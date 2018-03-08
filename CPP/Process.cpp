#include "Lib.hxx"

// Fix Relocations by type of blocks, here we fix the addresses to the new process
// So it can calls correctly the IAT Functions, strings and others ressources
bool N_Process::FixBaseRelocation( HEX HexDelta , PWORD pwRelocationAddress , Bytes pbRelocationBlock )
{
    bool bReturn = true;

    switch ( IMR_RELTYPE( *pwRelocationAddress ) )
    {
        case IMAGE_REL_BASED_ABSOLUTE:
        {
            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "IMAGE_REL_BASED_ABSOLUTE [%i]\n" ) , iCountReloc );
            break;
        }
        case IMAGE_REL_BASED_HIGHLOW:
        {
            PDWORD32 dwRaw = ( PDWORD32 ) ( pbRelocationBlock + IMR_RELOFFSET( *pwRelocationAddress ) );
            DWORD32 dwBackup = *dwRaw;

            *dwRaw += ( DWORD32 ) HexDelta;
            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "IMAGE_REL_BASED_HIGHLOW (0x%p) -> (0x%p) [%i]\n" ) ,
                                                    dwBackup , *dwRaw , iCountReloc );

            break;
        }
        case IMAGE_REL_BASED_DIR64:
        {
            PDWORD64 dwRaw = ( PDWORD64 ) ( pbRelocationBlock + IMR_RELOFFSET( *pwRelocationAddress ) );
            DWORD64 dwBackup = *dwRaw;

            *dwRaw += ( DWORD64 ) HexDelta;

            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "IMAGE_REL_BASED_DIR64 (0x%p) -> (0x%p) [%i]\n" ) ,
                                                    dwBackup , *dwRaw , iCountReloc );
        }
        // This should be fixed also, but it doesn't seem to appear anyway
        case IMAGE_REL_BASED_HIGHADJ:
        {
            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "IMAGE_REL_BASED_HIGHADJ  [%i]\n" ) , iCountReloc );
            break;
        }
        default:
        {
            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "UNKNOWN RELOCATION (0x%p) [%i]\n" ) , IMR_RELTYPE( *pwRelocationAddress ) , iCountReloc );
            bReturn = false;
        }
    }

    iCountReloc++;

    return bReturn;
}

N_Process::Process::Process( Pointer _pProcess )
{
    pProcess = _pProcess;
    HexProcessID = ( HEX ) GetProcessId( pProcess );

    String wBuf[ UNICODE_STRING_MAX_CHARS ];
    GetModuleBaseName( pProcess , 0 , wBuf , sizeof( wBuf ) );

    sName = stdString( wBuf );

    GetInformations();

    String sProcessPathTmp[ MAX_PATH ];
    if ( GetModuleFileNameEx( pProcess , nullptr , sProcessPathTmp , MAX_PATH ) )
    {
        sProcessPath = stdString( sProcessPathTmp );
    }

    N_Console::PrintDebug<FOREGROUND_GREEN>( TEXT( "[%s->Initialized]\n" ) , sName.c_str() );
}

N_Process::Process::Process( HEX _HexProcessID )
{
    //Open the process to get the handle of it, with maximum rights.

    pProcess = OpenProcess( MAXIMUM_ALLOWED , false , ( DWORD ) _HexProcessID );

    HexProcessID = _HexProcessID;

    String wBuf[ UNICODE_STRING_MAX_CHARS ];
    GetModuleBaseName( pProcess , 0 , wBuf , sizeof( wBuf ) );

    sName = stdString( wBuf );

    GetInformations();

    String sProcessPathTmp[ MAX_PATH ];
    if ( GetModuleFileNameEx( pProcess , nullptr , sProcessPathTmp , MAX_PATH ) )
    {
        sProcessPath = stdString( sProcessPathTmp );
    }

    N_Console::PrintDebug<FOREGROUND_GREEN>( TEXT( "[%s->Initialized]\n" ) , sName.c_str() );
}

N_Process::Process::Process( stdString _swProcessName )
{
    pAddress = nullptr;
    sName = _swProcessName;

    //Snapshots, are what they are, they take "screenshots" of every processes

    PROCESSENTRY32 ProcessEntry;
    ProcessEntry.dwSize = sizeof( PROCESSENTRY32 );

    // Create our snapshop to capture processes
    Pointer SnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS , 0 );

    // We must check if a process is encountered first before getting the others , so we don't make useless loops.

    if ( Process32First( SnapShot , &ProcessEntry ) )
    {
        // Capture the rest of the processes.

        while ( Process32Next( SnapShot , &ProcessEntry ) )
        {
            // Compare if our string contains the name of the exe we captured from the struct PROCESSENTRY32

            if ( StrCmp( ProcessEntry.szExeFile , _swProcessName.c_str() ) == 0 )
            {
                // Open the process to get the handle of it, with maximum rights.

                pProcess = OpenProcess( MAXIMUM_ALLOWED , false , ProcessEntry.th32ProcessID );

                HexProcessID = ProcessEntry.th32ProcessID;
            }
        }
    }

    CloseHandle( SnapShot );

    GetInformations();

    String sProcessPathTmp[ MAX_PATH ];
    if ( GetModuleFileNameEx( pProcess , nullptr , sProcessPathTmp , MAX_PATH ) )
    {
        sProcessPath = stdString( sProcessPathTmp );
    }

    N_Console::PrintDebug<FOREGROUND_GREEN>( TEXT( "[%s->Initialized]\n" ) , sName.c_str() );
}

// Deconstructor, free our memory allocated, etc...
N_Process::Process::~Process()
{
    Free();
}

// Get the process handle.
Pointer N_Process::Process::Get()
{
    return pProcess;
}

// Find a module by name.
Pointer N_Process::Process::FindModule( stdString DLLName , bool bForce )
{
    // First let's refresh the list of the modules loaded into the prcess before comparing them.
    RefreshGetModules();

    // Loop until we find.
    Pointer pModuleAddress = nullptr;
    for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
    {
        if ( StrCmpI( ( String* ) it->first.data() , DLLName.c_str() ) == false )
        {
            pModuleAddress = ( Pointer ) it->second;
        }
    }

    // If we force, we need to inject the dll into the process
    // We could use manualmap instead for injection, so it complety hides all the modules
    // Because it might be detected for some anti cheats.

    if ( bForce && ( pModuleAddress == nullptr ) )
    {
        // Force first by the name simply.
        ForceLoadLibrary( DLLName , &pModuleAddress , true );

        // If it doesn't work, it means that LoadLibrary function couldn't find the path of the dll itself.
        // So we manually write it, the needed dll are in system32, and others dlls that aren't in System32 are already loaded into the processes.
        // So we don't need to care about other paths.

        RefreshGetModules();

        for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
        {
            if ( StrCmpI( ( String* ) it->first.data() , DLLName.c_str() ) == false )
            {
                pModuleAddress = ( Pointer ) it->second;
            }
        }

        if ( pModuleAddress == nullptr )
        {
            String sWindowsPath[ MAX_PATH ];
            GetWindowsDirectory( sWindowsPath , sizeof( sWindowsPath ) );
            stdString sDLLPath = stdString( sWindowsPath );
            sDLLPath += TEXT( "\\System32\\" );
            sDLLPath += DLLName;

            // Let's force it again with the path of the dll.
            ForceLoadLibrary( sDLLPath , &pModuleAddress , true );

            RefreshGetModules();

            // If it's still unloaded let's refresh and iterate all modules to be sure it didn't got loaded in late or some bogus.
            if ( pModuleAddress == nullptr )
            {
                for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
                {
                    if ( StrCmpI( ( String* ) it->first.data() , DLLName.c_str() ) == 0 )
                    {
                        pModuleAddress = ( Pointer ) it->second;
                    }
                }
            }
            else
            {
                for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
                {
                    uHEX32 pModuleAddress32 = ( uHEX32 ) ( uHEX ) pModuleAddress;

                    if ( ( uHEX32 ) it->second == pModuleAddress32 )
                    {
                        pModuleAddress = ( Pointer ) it->second;
                    }
                }
            }
        }
        else
        {
            //on 64 bit GetExitCodeThread gives a wrong addresss about the module because it's a dword not a dword64 so this is how we check if it has been really loaded.
            for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
            {
                uHEX32 pModuleAddress32 = ( uHEX32 ) ( uHEX ) pModuleAddress;

                if ( ( uHEX32 ) it->second == pModuleAddress32 )
                {
                    pModuleAddress = ( Pointer ) it->second;
                }
            }
        }

        // Others dlls..
        if ( pModuleAddress == nullptr )
        {
            String sWindowsPath[ MAX_PATH ];
            GetWindowsDirectory( sWindowsPath , sizeof( sWindowsPath ) );
            stdString sDLLPath = stdString( sWindowsPath );
            sDLLPath += TEXT( "\\syswow64\\" );
            sDLLPath += DLLName;

            // Let's force it again with the path of the dll.
            ForceLoadLibrary( sDLLPath , &pModuleAddress , true );

            RefreshGetModules();

            // If it's still unloaded let's refresh and iterate all modules to be sure it didn't got loaded in late or some bogus.
            if ( pModuleAddress == nullptr )
            {
                for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
                {
                    if ( StrCmpI( ( String* ) it->first.data() , DLLName.c_str() ) == 0 )
                    {
                        pModuleAddress = ( Pointer ) it->second;
                    }
                }
            }
            else
            {
                for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
                {
                    uHEX32 pModuleAddress32 = ( uHEX32 ) ( uHEX ) pModuleAddress;

                    if ( ( uHEX32 ) it->second == pModuleAddress32 )
                    {
                        pModuleAddress = ( Pointer ) it->second;
                    }
                }
            }
        }
        else
        {
            //on 64 bit GetExitCodeThread gives a wrong addresss about the module because it's a dword not a dword64 so this is how we check if it has been really loaded.
            for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
            {
                uHEX32 pModuleAddress32 = ( uHEX32 ) ( uHEX ) pModuleAddress;

                if ( ( uHEX32 ) it->second == pModuleAddress32 )
                {
                    pModuleAddress = ( Pointer ) it->second;
                }
            }
        }
    }

    return pModuleAddress;
}

// Find the module path from the module address , GetModuleFileNameEx can do it
stdString N_Process::Process::FindModulePath( Pointer pModuleAddress )
{
    String PathToDLL[ UNICODE_STRING_MAX_CHARS ];
    GetModuleFileNameEx( pProcess , ( HMODULE ) pModuleAddress , PathToDLL , sizeof( PathToDLL ) );

    return stdString( PathToDLL );
}

void N_Process::Process::PrintAllModules()
{
    RefreshGetModules();

    for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
    {
        N_Console::Print<FOREGROUND_GREEN>( TEXT( "[%s->PrintAllModules] Module: %s - 0x%p\n" ) , it->first.c_str() , it->second );
    }
}

void N_Process::Process::RefreshGetModules()
{
    // Let's clear all our previous
    mshModules.clear();

    // Temp buffer to get modules addresses.
    std::vector<Pointer> vswMods( 0xFFF );

    // Let's enumerate all modules.

    // Just a random stuff that windows needs (didn't look at it yet what it truely means).
    DWORD dwNeeded;

    if ( EnumProcessModulesEx( pProcess , ( HMODULE* ) vswMods.data() , ( DWORD ) vswMods.size() , &dwNeeded , LIST_MODULES_ALL ) )
    {
        // Buffer of module name
        TCHAR szModName[ MAX_PATH ];

        for ( DWORD i = 0; i < ( dwNeeded / sizeof( HMODULE ) ); i++ )
        {
            if ( GetModuleBaseName( pProcess , ( HMODULE ) vswMods[ i ] , szModName , MAX_PATH ) )
            {
                // Emplace for each module name its address.
                // Same as mshModules[ szModName ] = ( HEX ) vswMods[ i ];
                mshModules.emplace( szModName , ( HEX ) vswMods[ i ] );
            }
        }
    }

    vswMods.clear();
}

void N_Process::Process::GetInformations()
{
    RefreshGetModules();

    for ( auto it = mshModules.begin(); it != mshModules.end(); it++ )
    {
        String *StrFound = StrStrI( ( String* ) it->first.data() , sName.c_str() );

        if ( StrFound != nullptr )  //If we found the process, print it cyan otherwhise just green.
        {
            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->GetInformations] Found: %s -> 0x%p\n" ) , sName.c_str() , it->first.c_str() , it->second );
            pAddress = ( Pointer ) it->second;
            sName = it->first;
        }
        else
            N_Console::PrintDebug<FOREGROUND_GREEN>( TEXT( "[%s->GetInformations] Module: %s -> 0x%p\n" ) , sName.c_str() , it->first.c_str() , it->second );
    }

    if ( pAddress == nullptr ) //We couldn't find the process something that should never happen?
        N_Console::PrintDebug( TEXT( "[%s->GetInformations] Failed to find the base address of the process\n" ) , sName.c_str() );
}

stdString &N_Process::Process::GetName()
{
    return sName;
}

HEX &N_Process::Process::GetID()
{
    return HexProcessID;
}

void N_Process::Process::Free()
{
    N_Console::PrintDebug<FOREGROUND_GREEN>( TEXT( "[%s->Uninitialized]\n" ) , sName.c_str() );

    if ( pProcess != nullptr )
        CloseHandle( pProcess );

    HexProcessID = 0;
    sName.clear();
    mshModules.clear();
}

bool N_Process::Process::SetAllAccess()
{
    // Get a token for our process to adjust privileges to all access.

    Pointer pToken;
    if ( !OpenProcessToken( pProcess , TOKEN_ALL_ACCESS , &pToken ) )
    {
        return false;
    }

    // Set the token privileges to debug.

    TOKEN_PRIVILEGES tp;
    tp.Privileges[ 0 ].Attributes = SE_PRIVILEGE_ENABLED;
    tp.PrivilegeCount = 1;
    LUID luid;

    if ( !LookupPrivilegeValue( 0 , SE_DEBUG_NAME , &luid ) )
    {
        CloseHandle( pToken );
        return false;
    }

    tp.Privileges[ 0 ].Luid = luid;

    //Adjust the token privileges for setting the process to all access.

    if ( !AdjustTokenPrivileges( pToken , false , &tp , sizeof( TOKEN_PRIVILEGES ) , nullptr , nullptr ) )
    {
        CloseHandle( pToken );
        return false;
    }

    // Close token handle.

    CloseHandle( pToken );

    if ( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        return false;
    }

    return true;
}

Pointer N_Process::Process::CreateRemotlyThread( Pointer pRoutine , Pointer pArguments , pHEX pHexRetRoutine , unsigned long *pULRetThread )
{
    // Open with ida pro and search for RtlCreateUserThread

    // Same as CreateRemoteThread, just undocumented version.

    // It creates a thread remotly to the process, so we can call LoadLibrary or other api functions or routines.

    // Calls -> RtlpCreateUserThreadEx -> NtCreateThreadEx

    /*typedef NTSYSCALLAPI
        NTSTATUS
        ( NTAPI * tNtCreateThreadEx )(
        _Out_ PHANDLE ThreadHandle ,
        _In_ ACCESS_MASK DesiredAccess ,
        _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes ,
        _In_ HANDLE ProcessHandle ,
        _In_ PVOID StartRoutine , // PUSER_THREAD_START_ROUTINE
        _In_opt_ PVOID Argument ,
        _In_ ULONG CreateFlags , // THREAD_CREATE_FLAGS_*
        _In_ SIZE_T ZeroBits ,
        _In_ SIZE_T StackSize ,
        _In_ SIZE_T MaximumStackSize ,
        _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
        );

    tNtCreateThreadEx NtCreateThreadEx = ( tNtCreateThreadEx ) GetProcAddress( LoadLibrary( TEXT( "ntdll.dll" ) ) , "NtCreateThreadEx" );

    if ( NtCreateThreadEx != nullptr )
    {
        HANDLE hRemotedThread;
        OBJECT_ATTRIBUTES ObjAttributes;
        InitializeObjectAttributes( &ObjAttributes ,
                                    nullptr ,
                                    OBJ_KERNEL_HANDLE ,
                                    nullptr ,
                                    nullptr );

        NTSTATUS NtStatus = NtCreateThreadEx( &hRemotedThread , THREAD_ALL_ACCESS , &ObjAttributes
                          , NtCurrentProcess
                          , ( LPTHREAD_START_ROUTINE ) pRoutine
                          , pArguments
                          , THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER
                          | THREAD_CREATE_FLAGS_HAS_SECURITY_DESCRIPTOR
                          | THREAD_CREATE_FLAGS_ACCESS_CHECK_IN_TARGET
                          , 0 , 0 , 0 , 0 );

        if ( pULRetThread != nullptr )
        {
            *pULRetThread = NtStatus;
        }

        // Wait for the thread finishing.

        WaitForSingleObject( hRemotedThread , INFINITE );

        // Get the return code from the api function or the routine.
        // It can be null depending on the routine or api function.

        if ( pHexRetRoutine != nullptr )
        {
            GetExitCodeThread( hRemotedThread , ( LPDWORD ) pHexRetRoutine );
        }

        return hRemotedThread;
    }*/

    typedef NTSTATUS
    ( NTAPI * tRtlCreateUserThread )(
        IN HANDLE               ProcessHandle ,
        IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL ,
        IN BOOLEAN              CreateSuspended ,
        IN ULONG                StackZeroBits ,
        IN OUT PULONG           StackReserved ,
        IN OUT PULONG           StackCommit ,
        IN PVOID                StartAddress ,
        IN PVOID                StartParameter OPTIONAL ,
        OUT PHANDLE             ThreadHandle ,
        OUT PCLIENT_ID          ClientID );

    tRtlCreateUserThread RtlCreateUserThread = ( tRtlCreateUserThread ) ( Pointer ) GetProcAddress( LoadLibrary( TEXT( "ntdll.dll" ) ) , "RtlCreateUserThread" );

    if ( RtlCreateUserThread != nullptr )
    {
        Pointer pRemotedThread = nullptr;

        SECURITY_DESCRIPTOR Security;
        InitializeSecurityDescriptor( &Security , SECURITY_DESCRIPTOR_REVISION );

        /*ACL acl;
        acl.AclRevision = ACL_REVISION_DS;
        acl.AclSize = sizeof( acl );
        acl.Sbz1 = 0x24;
        acl.Sbz2 = 0x37;
        PSID sid;
        SID_IDENTIFIER_AUTHORITY SIDIA;
        Byte bSecAuth[] = SECURITY_NT_AUTHORITY;
        memcpy( &SIDIA.Value , bSecAuth , sizeof( bSecAuth ) );
        AllocateAndInitializeSid( &SIDIA , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , 0 , &sid );
        SetSecurityDescriptorDacl( &Security , true , &acl , true );
        SetSecurityDescriptorGroup( &Security , sid , true );
        SetSecurityDescriptorOwner( &Security , sid , true );
        SetSecurityDescriptorRMControl( &Security , nullptr );
        SetSecurityDescriptorSacl( &Security , true , &acl , true );*/

        CLIENT_ID CID;
        NTSTATUS ULRetCode = RtlCreateUserThread( pProcess , &Security , false , 0 , nullptr , nullptr , pRoutine , pArguments , &pRemotedThread , &CID );

        if ( pULRetThread != nullptr )
        {
            *pULRetThread = ULRetCode;
        }

        // Wait for the thread finishing.

        WaitForSingleObject( pRemotedThread , INFINITE );

        // Get the return code from the api function or the routine.
        // It can be null depending on the routine or api function.

        if ( pHexRetRoutine != nullptr )
        {
            GetExitCodeThread( pRemotedThread , ( LPDWORD ) pHexRetRoutine );
        }

        return pRemotedThread;
    }

    return nullptr;
}

// Force an image (dll) to load into the process with LoadLibrary.
Pointer N_Process::Process::ForceLoadLibrary( stdString PathToDLL , pPointer pModuleAddress , bool bCloseAfter )
{
    // Allocate virtual memory for our dll path.
    N_VirtualMemory::VirtualBuffer* pVRemotedPathToDll = new N_VirtualMemory::VirtualBuffer( PathToDLL.size() * sizeof( String )
                                                                                             , PAGE_READWRITE
                                                                                             , nullptr
                                                                                             , pProcess , PathToDLL , ( Pointer ) PathToDLL.data() );

    HEX HexModuleAddress = 0;

    Pointer pRet = CreateRemotlyThread( LoadLibrary , pVRemotedPathToDll->pAddress , &HexModuleAddress );

    //if we didn't get the address of the forced library, let's be sure that it's not loaded.

    if ( HexModuleAddress == 0 )
        HexModuleAddress = ( HEX ) FindModule( PathToDLL );

    // Let's emplace it.
    psForcedModules.emplace( ( Pointer ) HexModuleAddress , PathToDLL );

    // We can choose to close our handle or not (dependinng on the project, see SimpleInjector.cpp)
    if ( bCloseAfter )
    {
        CloseHandle( pRet );
    }

    // If the address isn't null, we set the address of the module in it.
    if ( pModuleAddress != nullptr )
        *pModuleAddress = ( Pointer ) HexModuleAddress;

    delete pVRemotedPathToDll;

    return ( Pointer ) HexModuleAddress;
}

// Same as force load library but vice-versa.
Pointer N_Process::Process::ForceFreeLibrary( Pointer pModuleAddress )
{
    return CreateRemotlyThread( FreeLibrary , pModuleAddress );
}

Pointer N_Process::Process::ForceFreeLibrary( stdString DLLName )
{
    Pointer pModuleAddress = FindModule( DLLName );

    if ( pModuleAddress != nullptr )
        return ForceFreeLibrary( pModuleAddress );

    return nullptr;
}

void N_Process::Process::FreeAllForcedLoadedLibraries()
{
    for ( auto it = psForcedModules.begin(); it != psForcedModules.end(); it++ )
    {
        Pointer pThread = ForceFreeLibrary( it->first );

        if ( pThread == nullptr )
        {
            N_Console::PrintDebug( TEXT( "[%s->ForceFreeAllForcedLoadedLibraries] failed to create a thread for module %s\n" ) , sName.c_str() , it->second.c_str() );
        }

        if ( FindModule( it->second ) != nullptr )
        {
            N_Console::PrintDebug( TEXT( "[%s->ForceFreeAllForcedLoadedLibraries] failed to free for module %s\n" ) , sName.c_str() , it->second.c_str() );
        }
    }
}

// Get remotly the exported function of a process.
// I guess we could do this better by manual mapping the dll if it's not found and find the exported function from there.
// But it requires a bit more of work, so I'm going to let it like this way first.

uHEX N_Process::Process::GetFunction( const PCHAR pcFunctionName , const stdString & sModuleName )
{
    //First we load simply the module in our current process with the name of it. (can be kernel32.dll).

    uHEX HexModule = ( uHEX ) LoadLibrary( sModuleName.c_str() );

    // Something went wrong there, seems like LoadLibrary couldn't find its path, let's do it.
    if ( HexModule == 0 )
    {
        // The module should be loaded in every cases into the other process, so we find the address of it.
        Pointer pRemotedModuleAddress = FindModule( sModuleName.c_str() );

        // Gotcha.
        if ( pRemotedModuleAddress != nullptr )
        {
            // Now we have the module address of the remoted process, we can get its full path in the disk.

            stdString sPathToDLL = FindModulePath( pRemotedModuleAddress );

            // Now we can load it for getting the offset of the function!
            HexModule = ( uHEX ) LoadLibrary( sPathToDLL.c_str() );

            // Module in disk got deleted instantly just before LoadLibrary was called? No it should really never happen. But who knows.
            if ( HexModule != 0 )
            {
                N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->GetFunction] resolved path for module %s (%s)\n" ) , sName.c_str() , sModuleName.c_str()
                                                        , sPathToDLL.c_str() );
            }
            else
            {
                N_Console::PrintDebug( TEXT( "[%s->GetFunction] couldn't resolve path for module %s\n" ) , sName.c_str() , sModuleName.c_str() );
                return 0;
            }
        }
        else
        {
            N_Console::PrintDebug( TEXT( "[%s->GetFunction] couldn't find module %s from process\n" ) , sName.c_str() , sModuleName.c_str() );
            return 0;
        }
    }

    // Now we loaded the module into our current process,
    // We can get the exported function from the module (dll)
    // First by name, or by ordinal.

    uHEX HexFunction = ( uHEX ) GetProcAddress( ( HMODULE ) HexModule , pcFunctionName );

    // Ouch, we can't do more until reading the module file for retrieving the function offset manually.
    // But. Should never really happen anyway.

    if ( HexFunction == 0 )
    {
        N_Console::PrintDebug( TEXT( "[%s->GetFunction] couldn't get function offset for module %s\n" ) , sName.c_str() , sModuleName.c_str() );
        return 0;
    }

    // Get the offset of the function by substracting our module base address, and it's address

    uHEX HexOffset = HexFunction - HexModule;

    // Get the module address of the remoted process, and force it to load, in case it wasn't loaded yet.
    // It should be always a dll in System32 , but who knows maybe not always~.
    // Still it's good enough.

    Pointer pRemotedModule = FindModule( sModuleName , true );

    if ( pRemotedModule == nullptr )
    {
        N_Console::PrintDebug( TEXT( "[%s->GetFunction] couldn't get address for module %s\n" ) , sName.c_str() , sModuleName.c_str() );
        return 0;
    }

    return ( ( uHEX ) pRemotedModule + HexOffset );
}
/*

Manual mapping, means manually injecting into a process an image (.dll for example) , instead of using the functions that the windows api give to load an image.
For example LoadLibrary function that loads DLLs. The + on doing that is you can manipulate how the image will be loaded, so to hide it from modules list,
or hacking an executable (a game), wich is usually good for anti cheats.

I don't know what do LoadLibrary exactly, and it could be reversed, but for the moment, since there is a lot of documentations about it.
And a friend of mine helped me to do mine,
I've just read (https://people.freebsd.org/~wpaul/pe/subr_pe.c , http://www.rohitab.com/discuss/topic/40761-manual-dll-injection/) and made my own.

What you need, in priority to manual map is to do these 3 steps, you can do it in different ways, but it works mostly all the same.
There is actually more steps, but you don't need it when you have no use for it.

1) Copy sections to process. (sections contains everything that is about executable code, ressources, icons, strings, etc... in a file)
2) Resolve the import table, wich contains all the informations about the functions needed to import exported functions that are in DLLs.
3) Resolve the base relocation table wich is used for resolve all the addresses that are used into the code section. (such as strings location, functions imported etc..)

Keep remember that there is a lot of ways of resolving a manual inject, some others are better, some less.
This one works alright, but more is need to do, like TlsCallBacks, Exception support, Debug stuffs... But for the moment I don't need them so I just ignore them,
but I'll do it once I'll be stuck.

*/

HEX N_Process::Process::_ManualMapModule( Pointer pAddressImage , pPointer pReturnModuleBase , std::vector<Byte> pbReserved
                                          , bool bWriteHeaders
                                          , bool bProtect )
{
    //Declare our routine before to remove error C2362.

    std::vector<Byte> bDLL_Main_Start;

    // The first header is the dos header, it contains mostly the information we need to check if it has the dos signature
    // It checks if the file can be executed.  +/-

    PIMAGE_DOS_HEADER pDosHeader = ( PIMAGE_DOS_HEADER ) pAddressImage;

    //Then the second header the nt headers, wich contains every informations to execute the image etc...

    PIMAGE_NT_HEADERS pNtHeaders = ( PIMAGE_NT_HEADERS ) ( ( HEX ) pDosHeader + ( HEX ) pDosHeader->e_lfanew );

    if ( pDosHeader->e_magic != IMAGE_DOS_SIGNATURE )
    {
        return 0;
    }

    // Let's allocate memory virtually on the process for our new image base, SizeOfImage will be the max size in memory.
    // So we don't need to know the exact size of the file, because on how it's managed in memory.
    // We must set a PAGE_EXECUTE_READWRITE flag because the executable might need some others ressources into the allocated image, like unitialized data.
    // We also try to allocate the new image base at the default image base, so we don't have to resolve the relocations. (Very useful)

    N_VirtualMemory::VirtualBuffer *pVNewImage = new N_VirtualMemory::VirtualBuffer( ( HEX ) pNtHeaders->OptionalHeader.SizeOfImage
                                                                                     , PAGE_EXECUTE_READWRITE
                                                                                     , ( Pointer ) 0
                                                                                     , pProcess , TEXT( "pVNewImage" ) );

    // Write headers (dos + nt headers) to the new image
    // It might be needed to unpack some shitty dll

    if ( bWriteHeaders )
    {
        if ( !pVNewImage->WriteToProcessFromCurrent( pAddressImage , pNtHeaders->OptionalHeader.SizeOfHeaders ) )
        {
            N_Console::PrintDebug( TEXT( "[%s->ManualMapModule] failed to write headers\n" ) , sName.c_str() );
            goto FreeNewImage;
        }
    }

    N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] importing functions to the new image\n" ) , sName.c_str() );

    /*
    Get the import descriptor (that will be used to get functions exported from others modules, that will be imported here).

    The import descriptor contains all the informations to import our functions correctly to the process (so set the right addresses to each imported functions).

    All DataDirectory virtual addresses is relative (offset) to the image,
    so you could just do pAddressImage + pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress

    And we only need it for virtual addresses. No need to resolve imports from file  just how it will be in virtual memory.

    */

    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = ( PIMAGE_IMPORT_DESCRIPTOR )
        ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders , ( uHEX32 ) pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ].VirtualAddress ) );

    // Should be never null but in case.

    if ( pImportDescriptor != nullptr )
    {
        // Iterate all functions for each modules.

        while ( pImportDescriptor->Name != 0 )
        {
            // Get the module name.

            stdString wpsModuleName = stdString( AutoConvertS( ( PCHAR ) ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders , ( uHEX32 ) pImportDescriptor->Name ) ) ) );

            // No modules.

            if ( wpsModuleName.empty() )
            {
                N_Console::PrintDebug( TEXT( "[%s->ManualMapModule] failed to get module name\n" )
                                       , sName.c_str() , wpsModuleName.c_str() );
                goto FreeNewImage;
            }

            // The difference between  OriginalFirstThunk & FirstThunk
            // is that one that maintains offsets to the names of the imported functions ( OriginalFirstThunk )
            // and another that now has the actual addresses of the functions ( FirstThunk )
            // So we can only resolve first thunk and increment first thunk, so FT overrides OFT.

            if ( pImportDescriptor->FirstThunk != 0 )
            {
                PIMAGE_THUNK_DATA pThunkData = ( PIMAGE_THUNK_DATA ) ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders
                                                                       , ( uHEX32 ) pImportDescriptor->FirstThunk ) );

                while ( pThunkData != nullptr && pThunkData->u1.AddressOfData != 0 )
                {
                    if ( IMAGE_SNAP_BY_ORDINAL( pThunkData->u1.Ordinal ) )
                    {
                        PCHAR pcFunctionOrdinalName = ( ( PCHAR ) IMAGE_ORDINAL( pThunkData->u1.Ordinal ) );

                        if ( pcFunctionOrdinalName == nullptr )
                        {
                            continue;
                        }

                        pThunkData->u1.Function = GetFunction( pcFunctionOrdinalName , wpsModuleName );

                        if ( pThunkData->u1.Function == -1 )
                        {
                            goto FreeNewImage;
                        }
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME ImportByName = ( PIMAGE_IMPORT_BY_NAME ) ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders
                                                                                         , ( uHEX32 ) pThunkData->u1.AddressOfData ) );

                        PCHAR pcFunctionName = ( PCHAR ) ImportByName->Name;

                        if ( pcFunctionName == nullptr )
                        {
                            continue;
                        }

                        pThunkData->u1.Function = GetFunction( pcFunctionName , wpsModuleName );

                        if ( pThunkData->u1.Function == -1 )
                        {
                            goto FreeNewImage;
                        }
                    }

                    pThunkData++;
                }
            }

            pImportDescriptor++;
        }
    }

    iCountReloc = 0;

    N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] fixing base relocations to the new image\n" ) , sName.c_str() );

    // The base relocation directory contains informations to move addresses on the new image base to make it compatible with the process (if you don't want a crash).
    // So the executable code doesn't read at an address that points to nothing.
    // It moves all the addresses from the default image base to the new image base (our DLL that is in the process),
    // so every calls that the .text (code) section is calling for example.
    // Can be reference to an api windows function to call the function from IAT, or strings, or again some addresses that is used in code section...

    // If relocs are stripped we can't do anything about it...

    // Get the delta between our new image and the default image base, so we can move all the addresses to the new image
    // First we need to see if need really to resolve anything. If the new image base was allocated on the address of the default image base previously
    // We just ignore it because they are already resolved by default.

    HEX HexDelta = ( HEX ) pVNewImage->pAddress - ( HEX ) pNtHeaders->OptionalHeader.ImageBase;

    if ( !( pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED ) && ( HexDelta != 0 ) )
    {
        // Same as the import table, we just transform the relative virtual address to a virtual address with our readed file.

        PIMAGE_BASE_RELOCATION pImageBaseRelocation = ( PIMAGE_BASE_RELOCATION )
            ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders , ( uHEX32 ) pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].VirtualAddress ) );

        // The size of base relocations tables.

        uHEX32 HexSizeOfRelocation = pNtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ].Size;

        if ( HexSizeOfRelocation > 0 && pImageBaseRelocation != nullptr )
        {
            // Get the end address of the base relocations.

            HEX HexEndOfRelocation = ( HEX ) pImageBaseRelocation + ( HEX ) HexSizeOfRelocation;

            // Resolve addresses from the default image base to the new image base until there is no more addresses to resolve.
            // When we are at the end of the base relocation.

            while ( ( HEX ) pImageBaseRelocation < ( HEX ) HexEndOfRelocation )
            {
                // Each base relocations entries contains a block,
                // each blocks contains all the virtual addresses to solve to the new virtual addresses ( our new base image. )

                // Get the number of addresses to resolve.
                DWORD dwNumberOfRelocations = ( pImageBaseRelocation->SizeOfBlock - ( DWORD ) sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( WORD );

                // Get the first address of the block to resolve.
                PWORD pwRelocationAddress = ( PWORD ) ( pImageBaseRelocation + 1 );

                // Get the virtual address of the current block.
                Bytes bRelocationBlock = ( Bytes ) ( ( uHEX ) pAddressImage + ( uHEX ) RvaToRawOffset( pNtHeaders , ( uHEX32 ) pImageBaseRelocation->VirtualAddress ) );

                for ( DWORD i = 0; i < dwNumberOfRelocations; i++ )
                {
                    if ( !FixBaseRelocation( HexDelta , pwRelocationAddress , bRelocationBlock ) )
                    {
                        N_Console::PrintDebug( TEXT( "[%s->ManualMapModule] failed to fix base relocations\n" )
                                               , sName.c_str() );
                        goto FreeNewImage;
                    }

                    //Get on the next block of relocation once we resolved all virtual addresses on that block.
                    ++pwRelocationAddress;
                }

                // Set our last relocation address to our current base relocation,
                // so it doesn't do an infinite loop and tells to the code that we finished to resolve addresses
                // from this block.

                pImageBaseRelocation = ( PIMAGE_BASE_RELOCATION ) pwRelocationAddress;
            }
        }
    }

    // Now once we resolved the import table and moved correctly the references from base relocation table,
    // We can copy sections to the process and execute the entrypoint routine to the process to load our image!

    // Get the first section of our image. It means basically getting the all the sections pointer.

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION( pNtHeaders );

    // Iterate until we get all sections.
    for ( WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++ )
    {
        //stdString sSectionName = AutoConvertS( ( PCHAR ) Section[ i ].Name );

        // We can ignore useless sections such as .reloc section wich contained the informations to move the addresses, (it has IMAGE_SCN_MEM_DISCARDABLE as characteristic)
        // because we already resolved it.
        // Sometimes there might be no data in file, but it could still have a size in virtual memory, because of unitialized data that is used
        // When the image is executed.

        if ( Section[ i ].SizeOfRawData != 0 && ( ( Section[ i ].Characteristics & IMAGE_SCN_MEM_DISCARDABLE ) == 0 ) )
        {
            Pointer pRaw = ( Pointer ) ( ( HEX ) pAddressImage + ( HEX ) Section[ i ].PointerToRawData );

            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] copying section to process\n" )
                                                    , sName.c_str() );

            if ( !pVNewImage->ReplaceLocal( pRaw , ( HEX ) Section[ i ].VirtualAddress , Section[ i ].SizeOfRawData ) )
            {
                N_Console::PrintDebug( TEXT( "[%s->ManualMapModule] failed to copy section to process\n" ) , sName.c_str() );
                goto FreeNewImage;
            }
        }

        // Set the protection flags to our sections seperatly from its characteristics.

        if ( bProtect )
        {
            uHEX32 HexProtectionFlag = GetProtectionOfSection( &Section[ i ] );

            N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] modifying section protection flags to process (Flags %i)\n" ) , sName.c_str()
                                                    , HexProtectionFlag );

            HEX HexSize = Section[ i ].Misc.VirtualSize;
            Pointer pAddressToProtect = ( Pointer ) ( ( HEX ) pVNewImage->pAddress + ( HEX ) Section[ i ].VirtualAddress );
            pVNewImage->Flags.push_back( N_VirtualMemory::VirtualMemoryFlag( pAddressToProtect , HexSize , HexProtectionFlag ) );

            if ( !pVNewImage->RefreshFlags() )
            {
                N_Console::PrintDebug( TEXT( "[%s->ManualMapModule] failed to modify section protection flags to process\n" ) , sName.c_str() );
                goto FreeNewImage;
            }
        }
    }

    // Write the entrypoint routine to the process to call the original entry point,
    // we can't directly call then entrypoint routine here because the current allocation is not for our current process!
    // This is can be used for TlsCallBacks too.

#ifdef ENVIRONMENT32
    bDLL_Main_Start = { 0x8B , 0x44 , 0x24 , 0x04 , 0xFF , 0x70 , 0x0C , 0xFF , 0x70 , 0x08 , 0xFF , 0x70 , 0x04 , 0x8B , 0x00 , 0xFF , 0xD0 , 0xC2 , 0x04 , 0x00 };
#else
    bDLL_Main_Start = { 0x4C , 0x8B , 0x41 , 0x18 , 0x48 , 0x8B , 0xC1 , 0x48 , 0x8B , 0x51 , 0x10 , 0x48 , 0x8B , 0x49 , 0x08 , 0x48 , 0xFF , 0x20 };
#endif

    /*

    Microsoft:
    The .tls (thread local storage) section provides direct PE and COFF support for static thread local storage (TLS).
    TLS is a special storage class that Windows supports in which a data object is not an automatic (stack) variable,
    yet is local to each individual thread that runs the code.
    Thus, each thread can maintain a different value for a variable declared by using TLS.

    TODO: Support Tls.

    This code under works only for current process, because when injected into another process,
    *pHexTlsCallBacks is trying to read from another process, wich results as an exception.

    */

    // Write our argument to our process for our thread, so the entrypoint routine/thread can call the original entry point from the process with the informations given
    // Into the class given.
    // We need to do that because another process can't read directly into another.

    N_VirtualMemory::VirtualBuffer *pVRemotedReserved = new N_VirtualMemory::VirtualBuffer( pbReserved.size()
                                                                                            , PAGE_READONLY
                                                                                            , nullptr , pProcess , TEXT( "pVRemotedReserved" ) , pbReserved.data() );

    pVRemotedReserved->PrintBytes();

    DllMain *DllArgs = new DllMain( ( Pointer ) ( ( HEX ) pVNewImage->pAddress + ( HEX ) pNtHeaders->OptionalHeader.AddressOfEntryPoint )
                                    , pVNewImage->pAddress , ( Pointer ) DLL_PROCESS_ATTACH , pVRemotedReserved->pAddress );

    N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] EntryPoint routine: 0x%p\n" ) , sName.c_str() , DllArgs->EntryPoint );

    N_VirtualMemory::VirtualBuffer *pVRemotedArguments = new N_VirtualMemory::VirtualBuffer( sizeof( DllMain ) , PAGE_READONLY
                                                                                             , nullptr , pProcess , TEXT( "pVRemotedArguments" ) , ( Pointer ) DllArgs );

    pVRemotedArguments->PrintBytes();

    //If you want to understand the opcodes just above go on DLL_Main_Routines project!

    N_VirtualMemory::VirtualBuffer *pVRoutine = new N_VirtualMemory::VirtualBuffer( bDLL_Main_Start.size() , PAGE_EXECUTE
                                                                                    , nullptr , pProcess , TEXT( "pVRoutine" ) , ( Pointer ) bDLL_Main_Start.data() );

    pVRoutine->PrintBytes();

    N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] calling the entry point created from the process to execute the new image (0x%p)\n" )
                                            , sName.c_str()
                                            , DllArgs->EntryPoint );

    // Get the module address base in the process.

    if ( pReturnModuleBase != nullptr )
        *pReturnModuleBase = pVNewImage->pAddress;

    static Byte iCountModules = 0;
    iCountModules++;

    String sTmpCount[ 0xFF ];
    SPrintf_S( sTmpCount , 0xFF , TEXT( "%i" ) , iCountModules );

    psForcedModules.emplace( ( Pointer ) pVNewImage->pAddress , stdString( TEXT( "ManualMapped Module: " ) ) + stdString( sTmpCount ) );

    // Create the thread to the process to call our entrypoint routine, so it can calls the original entrypoint.

    HEX HexExitCode = 0;
    Pointer pThread = CreateRemotlyThread( pVRoutine->pAddress , pVRemotedArguments->pAddress , &HexExitCode );

    // Injected!

    N_Console::PrintDebug<FOREGROUND_CYAN>( TEXT( "[%s->ManualMapModule] exit code: 0x%p \n" ) , sName.c_str() , HexExitCode );

    CloseHandle( pThread );

    // Delete our routine so the guy can't see where is the original entry point, and others informations about the manual mapper.
    delete pVRoutine;
    delete pVRemotedArguments;
    delete pVRemotedReserved;
    delete pVNewImage;

    return 1;

FreeNewImage:

    delete pVNewImage;

    return 0;
}

HEX N_Process::Process::ManualMapModule( stdString pFilePath , pPointer pReturnModuleBase
                                         , bool bWriteHeaders
                                         , std::vector<Byte> pbReserved
                                         , bool bProtect )
{
    HEX HexSize;
    Pointer pFile = N_FileSystem::ReadFile( pFilePath , &HexSize );

    if ( pFile != nullptr )
    {
        return _ManualMapModule( pFile , pReturnModuleBase , pbReserved , bWriteHeaders , bProtect );
    }
    else
    {
        return 0;
    }
}