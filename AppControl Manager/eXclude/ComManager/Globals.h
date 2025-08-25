#pragma once
#include <string>
#include <mutex>

// Global variable and mutex for storing the last error message.
extern std::wstring g_lastErrorMsg;
extern std::mutex g_errorMutex;

// Global flag to indicate if the code is running as a library (DLL mode).
// When set to true, COM initialization and security are skipped because they are assumed to be already initialized.
// In packaged WinUI3 apps, Com and Com Security are already initialized so we cannot reinitialize them otherwise we'd get errors.
extern bool g_skipCOMInit;

void SetLastErrorMsg(const std::wstring& msg);
void ClearLastErrorMsg();
