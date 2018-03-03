#include "Lib.hxx"

// Let's put all strings into a vector (buffer)
stdString N_Console::sAllStrings;

// If console is openned
bool N_Console::bOpenned;
bool N_Console::bClearedLogs;

bool N_FileSystem::bOnceWrite;

// Create our variable to count relopc (in case if there is multiple injections).
int N_Process::iCountReloc;

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> StringConverter;