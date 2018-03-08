#ifndef LIB_SIGSCANNING
#define LIB_SIGSCANNING

#pragma once

struct sOffsetsFound
{
    std::vector<Pointer> pOffsets;
    Pointer pModuleAddress;
    stdString sModuleName;
};

class SigScanningFile
{
public:

    SigScanningFile( stdString _sProcessName , stdString _sName = TEXT( "TmpScan" ) );

    SigScanningFile( HEX _HexProcID , stdString _sName = TEXT( "TmpScan" ) );

    SigScanningFile( Pointer _pProcess , stdString _sName = TEXT( "TmpScan" ) );

    SigScanningFile( Pointer _pProcess , std::vector<Byte> bytes , stdString Module = TEXT( "NoModules" ) , stdString _sName = TEXT( "TmpScan" ) );

    ~SigScanningFile();

    void FindOffsets( stdString sModuleName , Pointer pAddress , Pointer pTemp , HEX Size , std::vector<Byte> bytes , bool *pbFoundAOnce = nullptr );

    void Scan( std::vector<Byte> bytes , stdString Module = TEXT( "NoModules" ) );

    void Scan( std::string sBytes , stdString Module = TEXT( "NoModules" ) );

    void PrintAllOffsets();

    void Scan( Pointer pData , HEX Size , stdString Module = TEXT( "NoModules" ) );

    // The process to scan
    N_Process::Process *pProcess;

    // All the offsets found through the module(s)
    std::vector<sOffsetsFound> OffsetsFound;

    // The name of the signature scan.
    stdString sName;

    Pointer pFirstOffset;
};

#endif