#include "Lib.hxx"

// To understand what means "rb" etc : https://msdn.microsoft.com/fr-fr/library/z5hh6ee9.aspx

Pointer N_FileSystem::ReadFile( stdString path , HEX *psize )
{
    // Open the file
    FILE* File;
    Open_S( &File , path.c_str() , TEXT( "rb" ) );

    if ( File == nullptr )
        return nullptr;

    // Get size of the file
    fseek( File , 0 , SEEK_END );
    HEX size = ( HEX ) ftell( File );
    rewind( File );

    // Allocate temp memory for our file
    Pointer pTemp = Alloc( size );

    fread_s( pTemp , size , 1 , size , File );
    fclose( File );

    if ( psize != nullptr )
    {
        *psize = size;
    }

    return pTemp;
}

void N_FileSystem::WriteFile( stdString path , std::vector<Byte> bytes )
{
    FILE* File;
    Open_S( &File , path.c_str() , TEXT( "ab+" ) );

    if ( File == nullptr )
        return;

    fwrite( bytes.data() , sizeof( Byte ) , bytes.size() , File );

    fclose( File );
}

void N_FileSystem::WriteFile( stdString path , stdString sString )
{
    FILE* File;
    Open_S( &File , path.c_str() , TEXT( "ab+" ) );

    if ( File == nullptr )
        return;

    fwrite( sString.data() , sizeof( String ) , sString.size() , File );

    fclose( File );
}

void N_FileSystem::WriteFile( stdString path , Pointer pAddress , HEX HexSize )
{
    FILE* File;
    Open_S( &File , path.c_str() , TEXT( "ab+" ) );

    if ( File == nullptr )
        return;

    fwrite( pAddress , sizeof( Byte ) , HexSize , File );

    fclose( File );
}

void N_FileSystem::ClearFile( stdString path )
{
    FILE* File;
    Open_S( &File , path.c_str() , TEXT( "w" ) );

    if ( File == nullptr )
        return;

    fclose( File );
}

void CreateDirectories( stdString path , bool &bCreated )
{
    bCreated = CreateDirectory( path.c_str() , nullptr );

    if ( GetLastError() == ERROR_ALREADY_EXISTS )
    {
        bCreated = true;
        return;
    }
    else if ( GetLastError() == ERROR_PATH_NOT_FOUND )
    {
        std::vector<stdString> svParents;
        stdString sParentPath = path;
        svParents.push_back( sParentPath );

        size_t nPosIgnore = sParentPath.rfind( TEXT( ":" ) );

        bool bBreak = false;

        while ( !bBreak )
        {
            size_t nPos = sParentPath.rfind( TEXT( "\\" ) );

            if ( nPos != stdString::npos
                 && ( nPos - nPosIgnore ) != 1 )
            {
                sParentPath.erase( sParentPath.begin() + nPos , sParentPath.end() );
                svParents.push_back( sParentPath );
            }
            else
            {
                bBreak = true;
            }
        }

        if ( !svParents.empty() )
        {
            bCreated = true;

            for ( int it = ( int ) svParents.size() - 1; it >= 0; it-- )
            {
                if ( !CreateDirectory( svParents[ it ].c_str() , nullptr ) )
                {
                    if ( GetLastError() != ERROR_ALREADY_EXISTS )
                        bCreated = false;
                }
            }
        }
    }
}

bool N_FileSystem::CreateFolder( stdString path )
{
    bool bCreated = false;

    CreateDirectories( path , bCreated );

    return bCreated;
}