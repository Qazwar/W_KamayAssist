#ifndef LIB_FILESYSTEM
#define LIB_FILESYSTEM
#pragma once

namespace N_FileSystem
{
    EXTERN bool bOnceWrite;

    // To understand what means "rb" etc : https://msdn.microsoft.com/fr-fr/library/z5hh6ee9.aspx
    Pointer ReadFile( stdString path , HEX *psize );

    void WriteFile( stdString path , std::vector<Byte> bytes );

    void WriteFile( stdString path , stdString sString );

    void WriteFile( stdString path , Pointer pAddress , HEX HexSize );

    void ClearFile( stdString path );

    bool CreateFolder( stdString path );
};

#endif