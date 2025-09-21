#include "Globals.h"

using namespace std;

wstring g_lastErrorMsg;      // Default-initialized empty
mutex g_errorMutex;          // Default-initialized
constinit bool g_skipCOMInit = false; // Remains false unless SetDllMode(true) is called

// Set the global error message (thread-safe)
void SetLastErrorMsg(const wstring& msg)
{
	lock_guard<mutex> lock(g_errorMutex);
	g_lastErrorMsg = msg;
}

// Clear the global error message.
void ClearLastErrorMsg()
{
	lock_guard<mutex> lock(g_errorMutex);
	g_lastErrorMsg.clear();
}
