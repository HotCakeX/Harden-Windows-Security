#pragma once
#include <string>
#include <mutex>
#include <sstream>
#include <iostream>
#include <utility>
#include "StringUtilities.h"

// Global variable and mutex for storing the last error message.
extern std::wstring g_lastErrorMsg;
extern std::mutex g_errorMutex;

// Global flag to indicate if the code is running as a library (DLL mode).
// When set to true, COM initialization and security are skipped because they are assumed to be already initialized.
// In packaged WinUI3 apps, Com and Com Security are already initialized so we cannot reinitialize them otherwise we'd get errors.
extern bool g_skipCOMInit;

void SetLastErrorMsg(const std::wstring& msg);
void ClearLastErrorMsg();

// All strings that need to be written to streams must be through these methods only.
// No wide string must be written directly to cout or cerr. No direct usage of wcerr or wcout must exist anywhere in the code.

// logging for stdout.
template<typename... Args>
inline void LogOut(Args&&... args)
{
	wostringstream woss;
	// Fold expression to stream all arguments into one wide buffer
	((woss << forward<Args>(args)), ...);
	wstring wideLine = woss.str();
	string utf8 = WideToUtf8(wideLine.c_str());
	cout << utf8 << '\n';
}

// logging for stderr.
template<typename... Args>
inline void LogErr(Args&&... args)
{
	wostringstream woss;
	((woss << forward<Args>(args)), ...);
	wstring wideLine = woss.str();
	string utf8 = WideToUtf8(wideLine.c_str());
	cerr << utf8 << '\n';
}
