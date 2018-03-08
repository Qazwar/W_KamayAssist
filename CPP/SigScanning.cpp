#include "Lib.hxx"

SigScanningFile::SigScanningFile( stdString _sProcessName , stdString _sName )
{
    sName = _sName;
    pProcess = new N_Process::Process( _sProcessName );
    pFirstOffset = nullptr;
}

SigScanningFile::SigScanningFile( HEX _HexProcID , stdString _sName )
{
    sName = _sName;
    pProcess = new N_Process::Process( _HexProcID );
    pFirstOffset = nullptr;
}

SigScanningFile::SigScanningFile( Pointer _pProcess , stdString _sName )
{
    sName = _sName;
    pProcess = new N_Process::Process( _pProcess );
    pFirstOffset = nullptr;
}

SigScanningFile::SigScanningFile( Pointer _pProcess , std::vector<Byte> bytes , stdString Module , stdString _sName )
{
    sName = _sName;
    pProcess = new N_Process::Process( _pProcess );
    pFirstOffset = nullptr;
    Scan( bytes , Module );
}

SigScanningFile::~SigScanningFile()
{
    OffsetsFound.clear();
    sName.clear();
    pFirstOffset = nullptr;
}

void SigScanningFile::FindOffsets( stdString sModuleName , Pointer pAddress , Pointer pTemp , HEX Size , std::vector<Byte> bytes , bool *pbFoundAOnce )
{
    // Set to false by first so we can tell we didn't find anything.

    if ( pbFoundAOnce != nullptr )
    {
        *pbFoundAOnce = false;
    }

    PIMAGE_DOS_HEADER pImageDosHeader = ( PIMAGE_DOS_HEADER ) pTemp;

    if ( pImageDosHeader == nullptr )
    {
        return;
    }

    PIMAGE_NT_HEADERS pImageNtHeaders = ( PIMAGE_NT_HEADERS ) ( ( HEX ) pImageDosHeader + pImageDosHeader->e_lfanew );

    if ( pImageNtHeaders == nullptr )
    {
        return;
    }

    // Size of module.

    HEX iDest = 0;

    // The signature.
    Bytes pbData = bytes.data();

    // The size of the signature.
    const HEX DataSize = bytes.size();

    // All the offsets found.

    std::vector<Pointer> pOffsetsFound;

    HEX StartAddress = pImageNtHeaders->OptionalHeader.ImageBase + IMAGE_FIRST_SECTION( pImageNtHeaders )[ 0 ].VirtualAddress;
    HEX EndAddress = pImageNtHeaders->OptionalHeader.ImageBase + pImageNtHeaders->OptionalHeader.SizeOfImage;

    HEX HexData = 0;
    HEX iData = 0;

    bool bFoundSignature = true;

    do
    {
        // Iterate byte by byte until we find the signature into our module.

        bFoundSignature = true;

        for ( iData = 0; iData < DataSize; iData++ )
        {
            HexData = *( pHEX ) &pbData[ iData ];

            if ( HexData >= StartAddress
                 && HexData < EndAddress
                 && ( DataSize - iData ) >= sizeof( HEX ) )
            {
                iData += sizeof( HEX ) - 1;
            }
            else
            {
                if ( ( ( Bytes ) ( ( HEX ) pTemp + iDest ) )[ iData ] != pbData[ iData ] )
                {
                    bFoundSignature = false;
                    break;
                }
            }
        }

        if ( bFoundSignature )
        {
            // If we found it, we get the address from the file, and convert it into a virtual address
            // So we can get the address while it's still in memory.

            HEX RvaAddress = RawToRvaOffset( ImageNtHeader( pTemp ) , ( uHEX32 ) iDest );

            // Check if somehow it wasn't into the sections.. (Shouldn't happen)

            if ( RvaAddress != 0 )
            {
                // Add the address found.

                if ( pFirstOffset == nullptr )
                    pFirstOffset = ( Pointer ) ( ( HEX ) pAddress + RvaAddress );

                pOffsetsFound.push_back( ( Pointer ) ( ( HEX ) pAddress + RvaAddress ) );
            }
        }

        // Increment the size by a byte so we can go on the next address of the module.

        iDest++;
    } while ( iDest < Size );

    // Emplace all addresses found into its module name.

    sOffsetsFound TmpOffsetsFound;
    TmpOffsetsFound.sModuleName = sModuleName;
    TmpOffsetsFound.pOffsets = pOffsetsFound;
    TmpOffsetsFound.pModuleAddress = pAddress;
    OffsetsFound.push_back( TmpOffsetsFound );

    // We found atleast one address, so it's good.

    if ( ( pbFoundAOnce != nullptr ) && OffsetsFound.size() > 0 )
    {
        *pbFoundAOnce = true;
    }
}

void SigScanningFile::Scan( std::vector<Byte> bytes , stdString Module )
{
    pFirstOffset = nullptr;

    // Refresh every modules from the process to be sure we didn't miss anything.

    pProcess->RefreshGetModules();

    if ( Module != TEXT( "NoModules" ) )
    {
        // If the name of the module is given, search the signature.

        Pointer pModuleAddress = pProcess->FindModule( Module );

        if ( pModuleAddress != nullptr )
        {
            // Get the module path from its address.

            stdString sPathModule = pProcess->FindModulePath( ( Pointer ) pModuleAddress );

            // Read the file from the module path.

            HEX Size = 0;
            Pointer pTempModule = N_FileSystem::ReadFile( sPathModule , &Size );

            // Count how much time it took to get the address of the given signature. (benchmark)

            CTimer *Timer = new CTimer();

            FindOffsets( sPathModule , pModuleAddress , pTempModule , Size , bytes );

            Timer->End();

            FreeAlloc( pTempModule );

            N_Console::PrintDebug<FOREGROUND_ROSE>( TEXT( "%s -> Found offsets in: %f ms (Path: %s, Size: %i)\n" ) , sName.c_str() , Timer->dElapsedTime , sPathModule.c_str() , Size );
        }
    }
    else
    {
        // Otherwhise iterates all modules and search the given signature.

        for ( auto it = pProcess->mshModules.begin(); it != pProcess->mshModules.end(); it++ )
        {
            // Get the module path from its address.

            stdString sPathModule = pProcess->FindModulePath( ( Pointer ) it->second );

            // Read the file from the module path.

            HEX Size = 0;
            Pointer pTempModule = N_FileSystem::ReadFile( sPathModule , &Size );

            // Count how much time it took to get the address of the given signature. (benchmark)

            CTimer *Timer = new CTimer();

            FindOffsets( sPathModule , ( Pointer ) it->second , pTempModule , Size , bytes );

            Timer->End();

            FreeAlloc( pTempModule );

            N_Console::PrintDebug<FOREGROUND_ROSE>( TEXT( "%s -> Found offsets in: %f ms (Path: %s, Size: %i)\n" ) , sName.c_str() , Timer->dElapsedTime , sPathModule.c_str() , Size );
        }
    }
}

void SigScanningFile::PrintAllOffsets()
{
    for ( auto it = OffsetsFound.begin(); it != OffsetsFound.end(); it++ )
    {
        for ( uHEX i = 0; i < it->pOffsets.size(); i++ )
        {
            N_Console::Print<FOREGROUND_CYAN>( TEXT( "Module: %s (%p) Offset: %p\n" ) , it->sModuleName.c_str() , it->pModuleAddress , it->pOffsets[ i ] );
        }
    }
}

void SigScanningFile::Scan( Pointer pData , HEX Size , stdString Module )
{
    std::vector<Byte> bytes( Size );
    memcpy( bytes.data() , pData , Size );
    Scan( bytes , Module );
}

void SigScanningFile::Scan( std::string sBytes , stdString Module )
{
}