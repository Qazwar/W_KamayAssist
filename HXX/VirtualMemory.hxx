#ifndef LIB_VIRTUALMEMORY
#define LIB_VIRTUALMEMORY
#pragma once

// Protection flags

namespace N_VirtualMemory
{
    class VirtualMemoryFlag
    {
    public:

        VirtualMemoryFlag( Pointer _pAddress , HEX _HexSize , uHEX32 _Flag , uHEX32 _HexOldFlag = 0 , uHEX32 _HexOldFlagAPI = 0 )
        {
            pAddress = _pAddress;
            HexSize = _HexSize;
            HexFlag = _Flag;
            HexOldFlag = _HexOldFlag;
            HexOldFlagAPI = _HexOldFlagAPI;
        }

        Pointer pAddress;
        uHEX32 HexFlag;
        HEX HexSize;
        uHEX32 HexOldFlagAPI , HexOldFlag;
    };

    std::vector<VirtualMemoryFlag> &FillVirtualMemoryFlags( Pointer pAddress , HEX HexSize , uHEX32 HexFlag );

    // Modify protection flags
    bool VirtualModifyProtectionFlags( Pointer pProcess = ( Pointer ) GetCurrentProcess()
                                       , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE ) );

    bool VirtualModifyProtectionFlags( Pointer pAddress
                                       , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                                       , HEX HexSize = MINSIZEVIRTUALMEMORY
                                       , uHEX32 HexProtectionFlags = PAGE_EXECUTE_READWRITE
                                       , puHEX32 pHexOldProtectionFlags = nullptr );

// Allocate virtual memory.
    Pointer VirtualAllocation( HEX HexSize = MINSIZEVIRTUALMEMORY
                               , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                               , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                               , Pointer pAllocationAddress = nullptr );

    Pointer VirtualAllocation( HEX HexSize = MINSIZEVIRTUALMEMORY
                               , uHEX32 HexFlag = PAGE_EXECUTE_READWRITE
                               , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                               , Pointer pAllocationAddress = nullptr );

    // Free virtual memory.
    bool FreeVirtualAllocation( Pointer pAddress , Pointer pProcess = ( Pointer ) GetCurrentProcess() , bool bLastCall = false );

    // Read virtual memory.
    bool VirtualReadMemory( Pointer pAddress , Pointer pRead , HEX HexSize = MINSIZEVIRTUALMEMORY
                            , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                            , Pointer pProcess = ( Pointer ) GetCurrentProcess() , pHEX pHexNbOfReadBytes = nullptr , bool bLastCall = false );

    // Write virtual memory.
    bool VirtualWriteMemory( Pointer pAddress , Pointer pWrite , HEX HexSize = MINSIZEVIRTUALMEMORY
                             , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                             , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                             , pHEX pHexNbOfReadBytes = nullptr , bool bLastCall = false );

    // Get virtual memory information.

    void VirtualQueryMBI( Pointer pAddress
                          , HEX HexSize = MINSIZEVIRTUALMEMORY
                          , PMEMORY_BASIC_INFORMATION pMBI = nullptr
                          , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                          , HEX *_HexNbBuffer = nullptr );

    HEX VirtualQueryProtectionFlags( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    HEX VirtualQuerySize( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    HEX VirtualQueryState( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    HEX VirtualQueryType( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    Pointer VirtualQueryBaseAddress( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    HEX VirtualQueryAllocationProtect( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    Pointer VirtualQueryAllocationBase( Pointer pAddress , HEX HexSize = MINSIZEVIRTUALMEMORY , Pointer pProcess = ( Pointer ) GetCurrentProcess() );

    // Write virtual memory from the current process
    bool WriteVirtualMemoryFromCurrentProcess_S( Pointer pAddressDestination , Pointer pAddressSource
                                                 , HEX &HexSizeOfDestination , HEX HexSizeOfSource
                                                 , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                                 , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess()
                                                 , Pointer pRebaseAddressDestination = nullptr );

    // Copy virtual memory from a process, to another process.
    bool CopyVirtualMemory_S( Pointer pAddressDestination , HEX &HexSizeOfDestination
                              , Pointer pAddressSource , HEX HexSizeOfSource
                              , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess() , Pointer pProcessSource = ( Pointer ) GetCurrentProcess()
                              , std::vector<VirtualMemoryFlag>& DestinationFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                              , std::vector<VirtualMemoryFlag>& SourceFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                              , Pointer pRebaseAddressDestination = nullptr );

    // Compare how much the data is not corresponding.

    HEX CompareVirtualMemory_S( Pointer pAddressDestination , HEX HexSizeOfDestination , Pointer pAddressSource , HEX HexSizeOfSource
                                , std::vector<VirtualMemoryFlag>& DestinationFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                , std::vector<VirtualMemoryFlag>& SourceFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess() , Pointer pProcessSource = ( Pointer ) GetCurrentProcess() , bool *bFailed = false );

    // Find the offset in the virtual memory, from a process, to another.
    // We could use aternativly memcmp though.
    // Same code as in SigScanning.h +/-

    HEX FindOffsetVirtualMemory_s( Pointer pAddressDestination , HEX HexSizeOfDestination
                                   , Pointer pAddressSource , HEX HexSizeOfSource
                                   , std::vector<VirtualMemoryFlag>& DestinationFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                   , std::vector<VirtualMemoryFlag>& SourceFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                   , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess() , Pointer pProcessSource = ( Pointer ) GetCurrentProcess()
                                   , bool *bFailed = nullptr );

    bool RemoveVirtualMemory_S( Pointer pAddress , HEX &HexSize , HEX pFromAddress , HEX HexSizeToRemove
                                , std::vector<VirtualMemoryFlag>& Flags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                                , Pointer pRebaseAddressDestination = nullptr );

    bool ReplaceVirtualMemory_S( Pointer pFromAddress , Pointer pAddressDestination , Pointer pAddressSource
                                 , HEX &HexSizeOfDestination , HEX HexSizeOfSource
                                 , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess()
                                 , Pointer pProcessSource = ( Pointer ) GetCurrentProcess()
                                 , std::vector<VirtualMemoryFlag>& DestinationFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                 , std::vector<VirtualMemoryFlag>& SourceFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                                 , Pointer pRebaseAddressDestination = nullptr );

    // First we just add virtual memory in where we want to and move the saved bytes from where it has been written.
    bool AddVirtualMemory_S( Pointer pFromAddress , Pointer pAddressDestination , Pointer pAddressSource
                             , HEX &HexSizeOfDestination , HEX HexSizeOfSource
                             , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess()
                             , Pointer pProcessSource = ( Pointer ) GetCurrentProcess()
                             , std::vector<VirtualMemoryFlag>& DestinationFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                             , std::vector<VirtualMemoryFlag>& SourceFlags = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                             , Pointer pRebaseAddressDestination = nullptr );

    class VirtualBuffer
    {
    public:

        // Constructor allocate virtual memory for our buffer, and set the protection flags correctly to that allocated virtual memory.
        VirtualBuffer( HEX HexSize = MINSIZEVIRTUALMEMORY
                       , uHEX32 HexFlag = PAGE_EXECUTE_READWRITE
                       , Pointer pAllocationAddress = nullptr
                       , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                       , const stdString& sName = TEXT( "TempVirtualBuffer" )
                       , Pointer pAddressToCopy = nullptr );

        VirtualBuffer( Pointer pAddress
                       , HEX HexSize
                       , Pointer pProcess = ( Pointer ) GetCurrentProcess()
                       , const stdString& sName = TEXT( "TempVirtualBuffer" ) );

        // In case we want to copy another buffer.
        VirtualBuffer( VirtualBuffer *pVBuf );

        // Free the buffer.
        ~VirtualBuffer();

        // If our buffer is valid.
        bool IsValid();

        void PrintBytes();

        bool RefreshFlags();

        // In case we want to read the virtual memory and allocate somewhere to the current process to modify like we want more easily.
        Pointer GetLocal();

        // Copy buffer to another.
        bool Copy( VirtualBuffer* pVBuf );

        // Replace virtual memory from a process to another process.
        bool Replace( Pointer pAddressDestination , HEX SizeOfDestination , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess()
                      , std::vector<VirtualMemoryFlag>& FlagsDestination = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                      , Pointer pFromAddress = nullptr );

        // Same as above, but with a buffer.
        bool Replace( VirtualBuffer* pVBuf , Pointer pFromAddress = nullptr );

        // Add virtual memory from a process to another process.
        bool Add( Pointer pAddressDestination , HEX SizeOfDestination , Pointer pProcessDestination = ( Pointer ) GetCurrentProcess()
                  , std::vector<VirtualMemoryFlag> &FlagsDestination = FillVirtualMemoryFlags( nullptr , MINSIZEVIRTUALMEMORY , PAGE_EXECUTE_READWRITE )
                  , Pointer pFromAddress = nullptr );

        // Same as above, but with a buffer.
        bool Add( VirtualBuffer* pVBuf , Pointer pFromAddress = nullptr );

        // Remove virtual memory from a buffer.
        bool Remove( VirtualBuffer* pVBuf );

        // Add bytes from a current process to the buffer.
        bool AddLocal( Pointer pAddressAdd , HEX pFromAddress , HEX HexSizeToAdd );

        // Replaces bytes from a current process to the buffer.
        bool ReplaceLocal( Pointer pAddressAdd , HEX pFromAddress , HEX HexSizeToAdd );

        // Remove bytes from a current process to the buffer.
        bool RemoveLocal( HEX pFromAddress , HEX HexSizeToRemove );

        // Write bytes from a current process to the buffer.
        bool WriteToProcessFromCurrent( Pointer pAddressLocalData , HEX HexSizeOfSource );

        // Transfer buffer to another process.
        bool TransferToProcess( Pointer pChangedProcess = ( Pointer ) GetCurrentProcess() );

        // Compare size to another buffer.
        HEX Compare( VirtualBuffer* pVBuf );

        // Find the offset into the buffer.
        HEX Find( VirtualBuffer*pVBuf );

        // Find the offset with bytes or local data (current process).
        HEX FindLocal( Pointer pAddressSource , HEX HexSizeOfSource );

        void Free();

        bool operator>( VirtualBuffer *pVBuf );

        bool operator<( VirtualBuffer *pVBuf );

        bool operator==( VirtualBuffer *pVBuf );

        bool operator>=( VirtualBuffer *pVBuf );

        bool operator<=( VirtualBuffer *pVBuf );

        bool operator!=( VirtualBuffer *pVBuf );

        bool operator>( HEX _HexSize );

        bool operator<( HEX _HexSize );

        bool operator==( HEX _HexSize );

        HEX operator==( std::vector<Byte> Value );

        HEX operator==( stdString Value );

        bool operator<=( HEX _HexSize );

        bool operator>=( HEX _HexSize );

        bool operator!=( HEX _HexSize );

        bool operator=( VirtualBuffer *pVBuf );

        bool operator+=( VirtualBuffer *pVBuf );

        bool operator-=( VirtualBuffer *pVBuf );

        bool operator+=( std::vector<Byte> Value );

        bool operator+=( stdString Value );

        bool operator-=( std::vector<Byte> Value );

        bool operator-=( stdString Value );

        bool operator-=( HEX _HexSize );

        bool operator=( std::vector<Byte> Value );

        bool operator=( Byte Value );

        bool operator=( stdString Value );

        bool UnProtect();

        VirtualBuffer &operator[]( HEX HexValue );

        Pointer operator[]( HEX HexValue ) const;

    public:

        // pAllocationAddress is where we want to allocate virtual memory.
        // pProcess is wich process the virtual memory is allocated for.
        // pAddress is the address of the buffer.
        Pointer pAddress , pProcess , pAllocationAddress;

        // Size of buffer
        HEX HexSize;

        HEX HexSlot = -1;

        // Name of buffer
        stdString sName;

        //Initialized buffer
        bool bInitialized = false;

        //Table of protection flags.
        std::vector<VirtualMemoryFlag> Flags;
    };
};

#endif