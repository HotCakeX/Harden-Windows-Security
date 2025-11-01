#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <cwctype>
#include <chrono>
#include <ctime>
#include "../Globals.h"

using namespace std;

namespace ScheduledTasks {

	// Location of the tasks: C:\Windows\System32\Tasks\

	// Macros and helpers for error checking
#ifndef CHECK_HR
#define CHECK_HR(hr, msg) \
    if (FAILED(hr)) { \
        _com_error err(hr); \
        LogErr(L"[Error] ", msg, L": 0x", hex, hr, L" - ", err.ErrorMessage()); \
        return 1; \
    }
#endif

#ifndef CHECK_HR_VOID
#define CHECK_HR_VOID(hr, msg) \
    if (FAILED(hr)) { \
        _com_error err(hr); \
        LogErr(L"[Error] ", msg, L": 0x", hex, hr, L" - ", err.ErrorMessage()); \
        return; \
    }
#endif

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "comsuppw.lib")

#ifndef TASK_SUNDAY
#define TASK_SUNDAY    0x1
#define TASK_MONDAY    0x2
#define TASK_TUESDAY   0x4
#define TASK_WEDNESDAY 0x8
#define TASK_THURSDAY  0x10
#define TASK_FRIDAY    0x20
#define TASK_SATURDAY  0x40
#endif

	int RunScheduledTasksCommand(int argc, wchar_t* argv[]);

	struct TriggerParam
	{
		wstring type;
		map<wstring, wstring> kv;
	};

	static vector<wstring> split(const wstring& s, wchar_t delim)
	{
		vector<wstring> res;
		size_t start = 0, end = 0;
		while ((end = s.find(delim, start)) != wstring::npos) {
			res.push_back(s.substr(start, end - start));
			start = end + 1;
		}
		res.push_back(s.substr(start));
		return res;
	}

	static wstring trim(const wstring& s)
	{
		auto b = s.find_first_not_of(L" \t\r\n");
		if (b == wstring::npos) return L"";
		auto e = s.find_last_not_of(L" \t\r\n");
		return s.substr(b, e - b + 1);
	}

	static TriggerParam ParseTriggerString(const wstring& triggerStr)
	{
		TriggerParam t;
		auto pairs = split(triggerStr, L';');
		for (auto& p : pairs)
		{
			auto eq = p.find(L'=');
			if (eq != wstring::npos)
			{
				wstring key = trim(p.substr(0, eq));
				wstring val = trim(p.substr(eq + 1));
				if (key == L"type") t.type = val;
				else t.kv[key] = val;
			}
		}
		return t;
	}

	static WORD ParseDaysOfWeek(const wstring& days)
	{
		WORD val = 0;
		auto daysvec = split(days, L',');
		for (auto& d : daysvec)
		{
			wstring s = d;
			for (auto& c : s) c = static_cast<wchar_t>(tolower(c));
			if (s == L"sun") val |= TASK_SUNDAY;
			else if (s == L"mon") val |= TASK_MONDAY;
			else if (s == L"tue") val |= TASK_TUESDAY;
			else if (s == L"wed") val |= TASK_WEDNESDAY;
			else if (s == L"thu") val |= TASK_THURSDAY;
			else if (s == L"fri") val |= TASK_FRIDAY;
			else if (s == L"sat") val |= TASK_SATURDAY;
		}
		return val;
	}

	static LONG ParseMonths(const wstring& months)
	{
		LONG val = 0;
		auto mvec = split(months, L',');
		for (auto& m : mvec)
		{
			wstring s = m;
			for (auto& c : s) c = static_cast<wchar_t>(tolower(c));
			if (s == L"jan") val |= (1 << 0);
			else if (s == L"feb") val |= (1 << 1);
			else if (s == L"mar") val |= (1 << 2);
			else if (s == L"apr") val |= (1 << 3);
			else if (s == L"may") val |= (1 << 4);
			else if (s == L"jun") val |= (1 << 5);
			else if (s == L"jul") val |= (1 << 6);
			else if (s == L"aug") val |= (1 << 7);
			else if (s == L"sep") val |= (1 << 8);
			else if (s == L"oct") val |= (1 << 9);
			else if (s == L"nov") val |= (1 << 10);
			else if (s == L"dec") val |= (1 << 11);
		}
		return val;
	}

	static vector<int> ParseDaysOfMonth(const wstring& days)
	{
		vector<int> res;
		auto v = split(days, L',');
		for (auto& d : v)
		{
			try { res.push_back(stoi(d)); }
			catch (...) {}
		}
		return res;
	}

	// Format SYSTEMTIME to YYYY-MM-DDTHH:MM:SS
	static wstring FormatSystemTime(const SYSTEMTIME& st)
	{
		wchar_t buf[32] = {};
		swprintf_s(buf, 32, L"%04d-%02d-%02dT%02d:%02d:%02d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
		return buf;
	}

	// Parse YYYY-MM-DDTHH:MM:SS to SYSTEMTIME
	static bool ParseISO8601(const wstring& s, SYSTEMTIME& st)
	{
		// Accepts YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD HH:MM:SS
		int y, m, d, h = 0, mi = 0, sec = 0;
		if (swscanf_s(s.c_str(), L"%d-%d-%dT%d:%d:%d", &y, &m, &d, &h, &mi, &sec) == 6 ||
			swscanf_s(s.c_str(), L"%d-%d-%d %d:%d:%d", &y, &m, &d, &h, &mi, &sec) == 6)
		{
			st.wYear = static_cast<WORD>(y);
			st.wMonth = static_cast<WORD>(m);
			st.wDay = static_cast<WORD>(d);
			st.wHour = static_cast<WORD>(h);
			st.wMinute = static_cast<WORD>(mi);
			st.wSecond = static_cast<WORD>(sec);
			st.wMilliseconds = 0;
			return true;
		}
		return false;
	}

	// Function to create or get a folder hierarchy in Task Scheduler
	static HRESULT CreateFolderHierarchy(ITaskService* pService, const wstring& folderPath, ITaskFolder** ppFolder)
	{
		*ppFolder = nullptr;

		// If the path is just the root folder, return it
		if (folderPath == L"\\")
		{
			HRESULT hr = pService->GetFolder(_bstr_t(L"\\"), ppFolder);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] GetFolder(root) failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			}
			return hr;
		}

		// Split the path into components (e.g., "\folder1\folder2" -> {"folder1", "folder2"})
		vector<wstring> components;
		size_t start = 1; // Skip the initial '\'
		while (start < folderPath.length())
		{
			size_t end = folderPath.find(L'\\', start);
			if (end == wstring::npos)
				end = folderPath.length();
			components.push_back(folderPath.substr(start, end - start));
			start = end + 1;
		}

		// Start with the root folder
		ITaskFolder* pCurrentFolder = nullptr;
		HRESULT hr = pService->GetFolder(_bstr_t(L"\\"), &pCurrentFolder);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] GetFolder(root) failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			return hr;
		}

		// Iterate through components to get or create each subfolder
		for (const auto& component : components)
		{
			ITaskFolder* pSubFolder = nullptr;
			hr = pCurrentFolder->GetFolder(_bstr_t(component.c_str()), &pSubFolder);
			if (FAILED(hr))
			{
				// Folder doesn't exist, create it
				hr = pCurrentFolder->CreateFolder(_bstr_t(component.c_str()), _variant_t(), &pSubFolder);
				if (FAILED(hr))
				{
					_com_error err(hr);
					LogErr(L"[Error] CreateFolder failed for: ", component, L" HRESULT=0x", hex, hr, L" - ", err.ErrorMessage());
					pCurrentFolder->Release();
					return hr;
				}
			}
			pCurrentFolder->Release();
			pCurrentFolder = pSubFolder;
		}
		*ppFolder = pCurrentFolder; // Transfer ownership to caller
		return S_OK;
	}

	// Add a trigger to a trigger collection
	static HRESULT AddTriggerToCollection(ITriggerCollection* pTriggers, const TriggerParam& trig)
	{
		if (trig.type.empty())
			return E_INVALIDARG;

		// Map trigger type string to TASK_TRIGGER_TYPE2
		map<wstring, TASK_TRIGGER_TYPE2> triggerTypeMap = {
			{L"boot", TASK_TRIGGER_BOOT},
			{L"logon", TASK_TRIGGER_LOGON},
			{L"onetime", TASK_TRIGGER_TIME},
			{L"daily", TASK_TRIGGER_DAILY},
			{L"weekly", TASK_TRIGGER_WEEKLY},
			{L"monthly", TASK_TRIGGER_MONTHLY},
			{L"idle", TASK_TRIGGER_IDLE}
		};

		auto it = triggerTypeMap.find(trig.type);
		if (it == triggerTypeMap.end())
			return E_INVALIDARG;
		TASK_TRIGGER_TYPE2 ttype = it->second;

		ITrigger* pBaseTrig = nullptr;
		HRESULT hr = pTriggers->Create(ttype, &pBaseTrig);
		if (FAILED(hr) || !pBaseTrig) {
			_com_error err(hr);
			LogErr(L"[Error] Trigger Create failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			return hr;
		}

		// Set start boundary (if provided)
		if (trig.kv.count(L"start"))
		{
			// Check and parse date
			SYSTEMTIME st = {};
			if (ParseISO8601(trig.kv.at(L"start"), st))
			{
				wstring s = FormatSystemTime(st);
				hr = pBaseTrig->put_StartBoundary(_bstr_t(s.c_str()));
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_StartBoundary failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pBaseTrig->Release();
					return hr;
				}
			}
			else
			{
				// If not parseable, pass as is (user might give full ISO string)
				hr = pBaseTrig->put_StartBoundary(_bstr_t(trig.kv.at(L"start").c_str()));
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_StartBoundary failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pBaseTrig->Release();
					return hr;
				}
			}
		}
		else if (ttype == TASK_TRIGGER_TIME || ttype == TASK_TRIGGER_DAILY || ttype == TASK_TRIGGER_WEEKLY || ttype == TASK_TRIGGER_MONTHLY)
		{
			// For time-based triggers, start is required
			pBaseTrig->Release();
			LogErr(L"[Error] start is required for this trigger type.");
			return E_INVALIDARG;
		}

		// Set repetition if present (supported by all triggers)
		IRepetitionPattern* pRep = nullptr;
		if (SUCCEEDED(pBaseTrig->get_Repetition(&pRep)) && pRep)
		{
			if (trig.kv.count(L"repeat_interval")) {
				hr = pRep->put_Interval(_bstr_t(trig.kv.at(L"repeat_interval").c_str()));
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_Interval failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pRep->Release();
					pBaseTrig->Release();
					return hr;
				}
			}

			// If we don't specify repeat_duration then it will mean repeat the task indefinitely.
			// This option appears as "for a duration of" in the Task Scheduler GUI.
			if (trig.kv.count(L"repeat_duration")) {
				hr = pRep->put_Duration(_bstr_t(trig.kv.at(L"repeat_duration").c_str()));
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_Duration failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pRep->Release();
					pBaseTrig->Release();
					return hr;
				}
			}

			// Set StopAtDurationEnd if provided in trigger
			if (trig.kv.count(L"stop_at_duration_end"))
			{
				wstring s = trig.kv.at(L"stop_at_duration_end");
				VARIANT_BOOL val = (s == L"true" || s == L"1" || s == L"yes") ? VARIANT_TRUE : VARIANT_FALSE;
				hr = pRep->put_StopAtDurationEnd(val);
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_StopAtDurationEnd failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pRep->Release();
					pBaseTrig->Release();
					return hr;
				}
			}
			pRep->Release();
		}

		// Set ExecutionTimeLimit if provided in trigger
		if (trig.kv.count(L"execution_time_limit"))
		{
			hr = pBaseTrig->put_ExecutionTimeLimit(_bstr_t(trig.kv.at(L"execution_time_limit").c_str()));
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_ExecutionTimeLimit failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pBaseTrig->Release();
				return hr;
			}
		}

		switch (ttype)
		{
		case TASK_TRIGGER_DAILY:
		{
			IDailyTrigger* pDaily = nullptr;
			if (SUCCEEDED(pBaseTrig->QueryInterface(IID_IDailyTrigger, (void**)&pDaily)) && pDaily)
			{
				if (trig.kv.count(L"interval")) {
					hr = pDaily->put_DaysInterval(static_cast<short>(_wtoi(trig.kv.at(L"interval").c_str())));
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] put_DaysInterval failed: 0x", hex, hr, L" - ", err.ErrorMessage());
						pDaily->Release();
						pBaseTrig->Release();
						return hr;
					}
				}
				pDaily->Release();
			}
			break;
		}
		case TASK_TRIGGER_WEEKLY:
		{
			IWeeklyTrigger* pWeekly = nullptr;
			if (SUCCEEDED(pBaseTrig->QueryInterface(IID_IWeeklyTrigger, (void**)&pWeekly)) && pWeekly)
			{
				if (trig.kv.count(L"interval")) {
					hr = pWeekly->put_WeeksInterval(static_cast<short>(_wtoi(trig.kv.at(L"interval").c_str())));
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] put_WeeksInterval failed: 0x", hex, hr, L" - ", err.ErrorMessage());
						pWeekly->Release();
						pBaseTrig->Release();
						return hr;
					}
				}
				if (trig.kv.count(L"days_of_week")) {
					hr = pWeekly->put_DaysOfWeek(ParseDaysOfWeek(trig.kv.at(L"days_of_week")));
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] put_DaysOfWeek failed: 0x", hex, hr, L" - ", err.ErrorMessage());
						pWeekly->Release();
						pBaseTrig->Release();
						return hr;
					}
				}
				pWeekly->Release();
			}
			break;
		}
		case TASK_TRIGGER_MONTHLY:
		{
			IMonthlyTrigger* pMonthly = nullptr;
			if (SUCCEEDED(pBaseTrig->QueryInterface(IID_IMonthlyTrigger, (void**)&pMonthly)) && pMonthly)
			{
				if (trig.kv.count(L"months")) {
					LONG monthsValue = ParseMonths(trig.kv.at(L"months"));
					hr = pMonthly->put_MonthsOfYear(static_cast<short>(monthsValue));
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] put_MonthsOfYear failed: 0x", hex, hr, L" - ", err.ErrorMessage());
						pMonthly->Release();
						pBaseTrig->Release();
						return hr;
					}
				}
				if (trig.kv.count(L"days_of_month"))
				{
					auto dom = ParseDaysOfMonth(trig.kv.at(L"days_of_month"));
					long mask = 0;
					for (auto day : dom) {
						if (day >= 1 && day <= 31)
							mask |= (1L << (day - 1));
					}
					hr = pMonthly->put_DaysOfMonth(mask);
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] put_DaysOfMonth failed: 0x", hex, hr, L" - ", err.ErrorMessage());
						pMonthly->Release();
						pBaseTrig->Release();
						return hr;
					}
				}
				pMonthly->Release();
			}
			break;
		}
		}

		pBaseTrig->Release();
		return S_OK;
	}

	// Recursive delete helpers

	// Recursively find and delete tasks by name in a folder and all subfolders
	static void DeleteTasksByName(ITaskFolder* pFolder, const wstring& name, int& deletedCount)
	{
		// 1. Delete tasks with the specified name in this folder
		IRegisteredTaskCollection* pTasks = nullptr;

		// Get the tasks (including hidden)
		HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTasks);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] GetTasks failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			return;
		}
		if (pTasks)
		{
			LONG count = 0;
			hr = pTasks->get_Count(&count);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] get_Count failed on tasks: 0x", hex, hr, L" - ", err.ErrorMessage());
				pTasks->Release();
				return;
			}
			for (LONG i = 1; i <= count; ++i) // 1-based index
			{
				IRegisteredTask* pTask = nullptr;
				hr = pTasks->get_Item(_variant_t(i), &pTask);
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] get_Item failed on tasks: 0x", hex, hr, L" - ", err.ErrorMessage());
					continue;
				}
				if (pTask)
				{
					BSTR bstrTaskName = nullptr;
					hr = pTask->get_Name(&bstrTaskName);
					if (FAILED(hr)) {
						_com_error err(hr);
						LogErr(L"[Error] get_Name failed on task: 0x", hex, hr, L" - ", err.ErrorMessage());
					}
					else if (bstrTaskName)
					{
						// if name is empty, delete all tasks; else delete only matching name
						if (name.empty() || _wcsicmp(bstrTaskName, name.c_str()) == 0)
						{
							// Delete task
							HRESULT delHr = pFolder->DeleteTask(_bstr_t(bstrTaskName), 0);
							if (SUCCEEDED(delHr))
							{
								LogOut(L"[Deleted] ", bstrTaskName, L" in folder");
								++deletedCount;
							}
							else
							{
								_com_error err(delHr);
								LogErr(L"[Error] Failed to delete task: ", bstrTaskName, L" HRESULT=0x", hex, delHr, L" - ", err.ErrorMessage());
							}
						}
						SysFreeString(bstrTaskName);
					}
					pTask->Release();
				}
			}
			pTasks->Release();
		}

		// 2. Recurse into subfolders using ITaskFolderCollection
		ITaskFolderCollection* pFolders = nullptr;
		hr = pFolder->GetFolders(0, &pFolders);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] GetFolders failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			return;
		}
		if (pFolders)
		{
			LONG count = 0;
			hr = pFolders->get_Count(&count);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] get_Count failed on folders: 0x", hex, hr, L" - ", err.ErrorMessage());
				pFolders->Release();
				return;
			}
			for (LONG i = 1; i <= count; ++i) // 1-based index
			{
				ITaskFolder* pSubFolder = nullptr;
				hr = pFolders->get_Item(_variant_t(i), &pSubFolder);
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] get_Item failed on folders: 0x", hex, hr, L" - ", err.ErrorMessage());
					continue;
				}
				if (pSubFolder)
				{
					DeleteTasksByName(pSubFolder, name, deletedCount);
					pSubFolder->Release();
				}
			}
			pFolders->Release();
		}
	}

	// Recursively search for folders by path, return matching ITaskFolder* (caller must Release), or nullptr if not found
	static ITaskFolder* FindFolderByPath(ITaskFolder* pRoot, const wstring& path)
	{
		if (path.empty() || path == L"\\" || path == L"/")
			return pRoot;

		vector<wstring> components;
		size_t start = 0;
		wstring normPath = path;
		if (normPath[0] == L'\\' || normPath[0] == L'/') normPath = normPath.substr(1);
		while (start < normPath.length())
		{
			size_t end = normPath.find(L'\\', start);
			if (end == wstring::npos)
				end = normPath.length();
			components.push_back(normPath.substr(start, end - start));
			start = end + 1;
		}
		ITaskFolder* pCurr = pRoot;
		for (const auto& comp : components)
		{
			ITaskFolder* pNext = nullptr;
			HRESULT hr = pCurr->GetFolder(_bstr_t(comp.c_str()), &pNext);
			if (FAILED(hr))
			{
				if (pCurr != pRoot) pCurr->Release();
				_com_error err(hr);
				LogErr(L"[Error] GetFolder failed for: ", comp, L" HRESULT=0x", hex, hr, L" - ", err.ErrorMessage());
				return nullptr;
			}
			if (pCurr != pRoot) pCurr->Release();
			pCurr = pNext;
		}
		return pCurr;
	}

	int RunScheduledTasksCommand(int argc, wchar_t* argv[])
	{
		// 1) Parse CLI args
		bool deleteMode = false;                    // delete tasks mode
		bool deleteFolderMode = false;              // delete folder mode
		wstring taskName, exePath, exeArgs, taskFolder, taskAuthor, taskDescription, sid, password;
		int logonType = TASK_LOGON_SERVICE_ACCOUNT; // Default: 5
		int runLevel = TASK_RUNLEVEL_HIGHEST;       // Default: 1
		bool hidden = false;
		bool allowStartIfOnBatteries = false;
		bool dontStopIfGoingOnBatteries = false;
		bool startWhenAvailable = false;
		int restartCount = -1;
		wstring restartInterval;
		int priority = -1;
		bool runOnlyIfNetworkAvailable = false;
		wstring taskExecutionTimeLimit;		// execution time limit for the whole task
		bool wakeToRun = false;              // WakeToRun flag for the whole task
		bool wakeToRunSet = false;           // To track if user set the param
		int multipleInstancesPolicy = -1;    // MultipleInstancesPolicy param for the task, -1 means unset
		bool allowHardTerminate = false;     // AllowHardTerminate for the task
		bool allowHardTerminateSet = false;  // To track if user set AllowHardTerminate
		bool allowDemandStart = false;       // AllowDemandStart for the task
		bool allowDemandStartSet = false;    // To track if user set AllowDemandStart
		vector<wstring> triggerArgs;
		int useUnifiedSchedulingEngine = -1; // variable for UseUnifiedSchedulingEngine CLI parameter (default: -1, means unset)

		for (int i = 1; i < argc; ++i)
		{
			wstring a = argv[i];
			if (a == L"--delete")
				deleteMode = true;
			else if (a == L"--deletefolder")
				deleteFolderMode = true;
			else if (a == L"--name" && i + 1 < argc)
				taskName = argv[++i];
			else if (a == L"--exe" && i + 1 < argc)
				exePath = argv[++i];
			else if (a == L"--arg" && i + 1 < argc)
				exeArgs = argv[++i];
			else if (a == L"--hidden")
				hidden = true;
			else if (a == L"--allowstartifonbatteries")
				allowStartIfOnBatteries = true;
			else if (a == L"--dontstopifgoingonbatteries")
				dontStopIfGoingOnBatteries = true;
			else if (a == L"--startwhenavailable")
				startWhenAvailable = true;
			else if (a == L"--restartcount" && i + 1 < argc)
				restartCount = _wtoi(argv[++i]);
			else if (a == L"--restartinterval" && i + 1 < argc)
				restartInterval = argv[++i];
			else if (a == L"--priority" && i + 1 < argc)
				priority = _wtoi(argv[++i]);
			else if (a == L"--runonlyifnetworkavailable")
				runOnlyIfNetworkAvailable = true;
			else if (a == L"--folder" && i + 1 < argc)
				taskFolder = argv[++i];
			else if (a == L"--author" && i + 1 < argc)
				taskAuthor = argv[++i];
			else if (a == L"--description" && i + 1 < argc)
				taskDescription = argv[++i];
			else if (a == L"--sid" && i + 1 < argc)
				sid = argv[++i];
			else if (a == L"--logon" && i + 1 < argc)
				logonType = _wtoi(argv[++i]);
			else if (a == L"--runlevel" && i + 1 < argc)
				runLevel = _wtoi(argv[++i]);
			else if (a == L"--password" && i + 1 < argc)
				password = argv[++i];
			else if (a == L"--useunifiedschedulingengine" && i + 1 < argc)
			{
				wstring value = argv[++i];
				if (value == L"true" || value == L"1" || value == L"yes")
					useUnifiedSchedulingEngine = 1;
				else if (value == L"false" || value == L"0" || value == L"no")
					useUnifiedSchedulingEngine = 0;
				else
				{
					LogErr(L"[Error] Invalid value for --useunifiedschedulingengine: ", value);
					return 2;
				}
			}

			// parse execution time limit for the whole task
			else if (a == L"--executiontimelimit" && i + 1 < argc)
				taskExecutionTimeLimit = argv[++i];

			// parse WakeToRun parameter for the whole task
			else if (a == L"--waketorun" && i + 1 < argc)
			{
				wstring value = argv[++i];
				if (value == L"true" || value == L"1" || value == L"yes")
				{
					wakeToRun = true; wakeToRunSet = true;
				}
				else if (value == L"false" || value == L"0" || value == L"no")
				{
					wakeToRun = false; wakeToRunSet = true;
				}
				else
				{
					LogErr(L"[Error] Invalid value for --waketorun: ", value);
					return 2;
				}
			}

			// parse MultipleInstancesPolicy param
			else if (a == L"--multipleinstancespolicy" && i + 1 < argc)
			{
				multipleInstancesPolicy = _wtoi(argv[++i]);
				if (multipleInstancesPolicy < 0 || multipleInstancesPolicy > 3)
				{
					LogErr(L"[Error] Invalid value for --multipleinstancespolicy: ", multipleInstancesPolicy, L" (valid: 0=Parallel, 1=Queue, 2=IgnoreNew, 3=StopExisting)");
					return 2;
				}
			}

			// parse AllowHardTerminate param
			else if (a == L"--allowhardterminate" && i + 1 < argc)
			{
				wstring value = argv[++i];
				if (value == L"true" || value == L"1" || value == L"yes")
				{
					allowHardTerminate = true; allowHardTerminateSet = true;
				}
				else if (value == L"false" || value == L"0" || value == L"no")
				{
					allowHardTerminate = false; allowHardTerminateSet = true;
				}
				else
				{
					LogErr(L"[Error] Invalid value for --allowhardterminate: ", value);
					return 2;
				}
			}

			// parse AllowDemandStart param
			else if (a == L"--allowdemandstart" && i + 1 < argc)
			{
				wstring value = argv[++i];
				if (value == L"true" || value == L"1" || value == L"yes")
				{
					allowDemandStart = true; allowDemandStartSet = true;
				}
				else if (value == L"false" || value == L"0" || value == L"no")
				{
					allowDemandStart = false; allowDemandStartSet = true;
				}
				else
				{
					LogErr(L"[Error] Invalid value for --allowdemandstart: ", value);
					return 2;
				}
			}
			else if (a == L"--trigger" && i + 1 < argc)
				triggerArgs.push_back(argv[++i]);
			else
			{
				LogErr(L"[Error] Unknown option: ", a);
				return 2;
			}
		}

		// DELETE FOLDER MODE
		if (deleteFolderMode)
		{
			if (taskFolder.empty())
			{
				LogErr(L"[Error] --folder is required for --deletefolder");
				return 2;
			}
			// Initialize COM
			HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
			CHECK_HR(hr, L"CoInitializeEx failed");

			// Connect to Task Service
			ITaskService* pService = nullptr;
			hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
				CLSCTX_INPROC_SERVER,
				IID_ITaskService,
				reinterpret_cast<void**>(&pService));
			CHECK_HR(hr, L"CoCreateInstance(ITaskService) failed");
			hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
			CHECK_HR(hr, L"ITaskService::Connect failed");

			// Get root folder
			ITaskFolder* pRootFolder = nullptr;
			hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
			if (FAILED(hr) || !pRootFolder)
			{
				_com_error err(hr);
				LogErr(L"[Error] Cannot get root folder: 0x", hex, hr, L" - ", err.ErrorMessage());
				pService->Release();
				CoUninitialize();
				return 1;
			}

			// Normalize folder path
			wstring fullPath = taskFolder;
			if (fullPath.empty()) fullPath = L"\\";
			if (fullPath[0] != L'\\') fullPath = L"\\" + fullPath;

			// Extract parent path and child folder name
			size_t pos = fullPath.find_last_of(L'\\');
			wstring parentPath, childName;
			if (pos == 0)
			{
				parentPath = L"\\";
				childName = fullPath.substr(1);
			}
			else
			{
				parentPath = fullPath.substr(0, pos);
				childName = fullPath.substr(pos + 1);
			}

			// Find the target child folder so we can delete its tasks
			ITaskFolder* pChildFolder = FindFolderByPath(pRootFolder, fullPath);
			if (pChildFolder)
			{
				int deletedCount = 0;

				// delete every task in that folder and its subfolders
				DeleteTasksByName(pChildFolder, L"", deletedCount);
				pChildFolder->Release();
			}
			else
			{
				LogErr(L"[Error] Cannot find folder to delete: ", fullPath);
				pRootFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}

			// Now delete the (now-empty) folder itself
			ITaskFolder* pParent = FindFolderByPath(pRootFolder, parentPath);
			if (!pParent)
			{
				LogErr(L"[Error] Cannot find parent folder: ", parentPath);
				pRootFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
			HRESULT delHr = pParent->DeleteFolder(_bstr_t(childName.c_str()), 0);
			if (SUCCEEDED(delHr))
			{
				LogOut(L"[Success] Folder \"", fullPath, L"\" and all its tasks deleted.");
			}
			else
			{
				_com_error err(delHr);
				LogErr(L"[Error] Failed to delete folder: ", fullPath, L" HRESULT=0x", hex, delHr, L" - ", err.ErrorMessage());
			}
			pParent->Release();
			pRootFolder->Release();
			pService->Release();
			CoUninitialize();
			return SUCCEEDED(delHr) ? 0 : 1;
		}

		// DELETE TASKS MODE
		if (deleteMode)
		{
			if (taskName.empty())
			{
				LogErr(L"[Error] --name is required for --delete");
				return 2;
			}

			// Initialize COM
			HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
			CHECK_HR(hr, L"CoInitializeEx failed");

			// Connect to Task Service
			ITaskService* pService = nullptr;
			hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
				CLSCTX_INPROC_SERVER,
				IID_ITaskService,
				reinterpret_cast<void**>(&pService));
			CHECK_HR(hr, L"CoCreateInstance(ITaskService) failed");
			hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
			CHECK_HR(hr, L"ITaskService::Connect failed");

			// Get root folder
			ITaskFolder* pRootFolder = nullptr;
			hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
			if (FAILED(hr) || !pRootFolder)
			{
				_com_error err(hr);
				LogErr(L"[Error] Cannot get root folder: 0x", hex, hr, L" - ", err.ErrorMessage());
				if (pService) pService->Release();
				CoUninitialize();
				return 1;
			}

			int deletedCount = 0;
			if (!taskFolder.empty())
			{
				ITaskFolder* pTarget = FindFolderByPath(pRootFolder, taskFolder);
				if (!pTarget)
				{
					LogErr(L"[Error] Cannot find folder: ", taskFolder);
					pRootFolder->Release();
					if (pService) pService->Release();
					CoUninitialize();
					return 1;
				}
				DeleteTasksByName(pTarget, taskName, deletedCount);
				if (pTarget != pRootFolder) pTarget->Release();
			}
			else
			{
				// Recursively search all folders
				DeleteTasksByName(pRootFolder, taskName, deletedCount);
			}

			LogOut(L"Deleted ", deletedCount, L" tasks with name \"", taskName, L"\".");
			pRootFolder->Release();
			if (pService) pService->Release();
			CoUninitialize();
			return 0;
		}

		// CREATION MODE: Validate required
		if (taskName.empty() || exePath.empty())
		{
			LogErr(L"[Error] --name and --exe are required for creation.");
			return 2;
		}

		// Default to SYSTEM SID if not provided
		if (sid.empty())
			sid = L"S-1-5-18"; // SYSTEM SID

		// 2) Initialize COM
		HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
		CHECK_HR(hr, L"CoInitializeEx failed");

		// 3) Connect to Task Service
		ITaskService* pService = nullptr;
		hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
			CLSCTX_INPROC_SERVER,
			IID_ITaskService,
			reinterpret_cast<void**>(&pService));
		CHECK_HR(hr, L"CoCreateInstance(ITaskService) failed");
		hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
		CHECK_HR(hr, L"ITaskService::Connect failed");

		// 4) Determine target folder
		wstring targetPath = taskFolder.empty() ? L"\\" : taskFolder;
		if (!targetPath.empty() && targetPath[0] != L'\\')
			targetPath = L"\\" + targetPath; // Normalize path to start with '\'

		ITaskFolder* pTargetFolder = nullptr;
		hr = CreateFolderHierarchy(pService, targetPath, &pTargetFolder);
		CHECK_HR(hr, L"Cannot get or create target folder");

		// 5) Create TaskDefinition
		ITaskDefinition* pTaskDef = nullptr;
		hr = pService->NewTask(0, &pTaskDef);
		if (FAILED(hr))
		{
			_com_error err(hr);
			LogErr(L"[Error] NewTask failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// 6) RegistrationInfo
		IRegistrationInfo* pReg = nullptr;
		hr = pTaskDef->get_RegistrationInfo(&pReg);
		if (FAILED(hr) || !pReg) {
			_com_error err(hr);
			LogErr(L"[Error] get_RegistrationInfo failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		// Use provided author or default
		wstring author = taskAuthor.empty() ? L"ScheduledTaskManager" : taskAuthor;
		hr = pReg->put_Author(_bstr_t(author.c_str()));
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_Author failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pReg->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		// Use provided description or default
		wstring description = taskDescription.empty() ? L"User-defined scheduled task" : taskDescription;
		hr = pReg->put_Description(_bstr_t(description.c_str()));
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_Description failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pReg->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		pReg->Release();

		// 7) Settings: Hidden + Compatibility + battery + restart + priority + network + new features
		// https://learn.microsoft.com/windows/win32/api/taskschd/nn-taskschd-itasksettings
		ITaskSettings* pSettings = nullptr;
		hr = pTaskDef->get_Settings(&pSettings);
		if (FAILED(hr) || !pSettings) {
			_com_error err(hr);
			LogErr(L"[Error] get_Settings failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		hr = pSettings->put_Compatibility(TASK_COMPATIBILITY_V2_4); // Windows 11
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_Compatibility failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		hr = pSettings->put_Hidden(hidden ? VARIANT_TRUE : VARIANT_FALSE);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_Hidden failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// AllowStartIfOnBatteries: mapped to put_DisallowStartIfOnBatteries(FALSE) if allowed, TRUE if disallowed
		hr = pSettings->put_DisallowStartIfOnBatteries(allowStartIfOnBatteries ? VARIANT_FALSE : VARIANT_TRUE);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_DisallowStartIfOnBatteries failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// DontStopIfGoingOnBatteries: mapped to put_StopIfGoingOnBatteries(FALSE) if don't stop, TRUE if do stop
		hr = pSettings->put_StopIfGoingOnBatteries(dontStopIfGoingOnBatteries ? VARIANT_FALSE : VARIANT_TRUE);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_StopIfGoingOnBatteries failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		hr = pSettings->put_StartWhenAvailable(startWhenAvailable ? VARIANT_TRUE : VARIANT_FALSE);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_StartWhenAvailable failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// RestartCount
		if (restartCount >= 0) {
			hr = pSettings->put_RestartCount(restartCount);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_RestartCount failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// RestartInterval (ISO8601 duration, e.g., PT5M for 5 minutes)
		if (!restartInterval.empty()) {
			hr = pSettings->put_RestartInterval(_bstr_t(restartInterval.c_str()));
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_RestartInterval failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// Priority (0 = highest, 10 = lowest, default is 7)
		// https://learn.microsoft.com/windows/win32/api/taskschd/nf-taskschd-itasksettings-get_priority
		if (priority >= 0 && priority <= 10) {
			hr = pSettings->put_Priority(priority);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_Priority failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// RunOnlyIfNetworkAvailable
		hr = pSettings->put_RunOnlyIfNetworkAvailable(runOnlyIfNetworkAvailable ? VARIANT_TRUE : VARIANT_FALSE);
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_RunOnlyIfNetworkAvailable failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pSettings->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// UseUnifiedSchedulingEngine support
		// This parameter, if set by CLI, will set the UseUnifiedSchedulingEngine property via ITaskSettings2
		if (useUnifiedSchedulingEngine != -1)
		{
			ITaskSettings2* pSettings2 = nullptr;
			hr = pSettings->QueryInterface(__uuidof(ITaskSettings2), (void**)&pSettings2);
			if (SUCCEEDED(hr) && pSettings2)
			{
				hr = pSettings2->put_UseUnifiedSchedulingEngine(useUnifiedSchedulingEngine ? VARIANT_TRUE : VARIANT_FALSE);
				if (FAILED(hr)) {
					_com_error err(hr);
					LogErr(L"[Error] put_UseUnifiedSchedulingEngine failed: 0x", hex, hr, L" - ", err.ErrorMessage());
					pSettings2->Release();
					pSettings->Release();
					pTaskDef->Release();
					pTargetFolder->Release();
					pService->Release();
					CoUninitialize();
					return 1;
				}
				pSettings2->Release();
			}
		}

		// Task-level execution time limit support
		// Set ExecutionTimeLimit for the entire task if provided in CLI
		if (!taskExecutionTimeLimit.empty()) {
			hr = pSettings->put_ExecutionTimeLimit(_bstr_t(taskExecutionTimeLimit.c_str()));
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_ExecutionTimeLimit failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// WakeToRun support
		// Set WakeToRun if provided in CLI
		if (wakeToRunSet) {
			hr = pSettings->put_WakeToRun(wakeToRun ? VARIANT_TRUE : VARIANT_FALSE);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_WakeToRun failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// MultipleInstancesPolicy support
		// Set MultipleInstancesPolicy if provided in CLI
		if (multipleInstancesPolicy >= 0 && multipleInstancesPolicy <= 3) {
			hr = pSettings->put_MultipleInstances(static_cast<TASK_INSTANCES_POLICY>(multipleInstancesPolicy));
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_MultipleInstances failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// AllowHardTerminate support
		if (allowHardTerminateSet) {
			hr = pSettings->put_AllowHardTerminate(allowHardTerminate ? VARIANT_TRUE : VARIANT_FALSE);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_AllowHardTerminate failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		// AllowDemandStart support
		if (allowDemandStartSet) {
			hr = pSettings->put_AllowDemandStart(allowDemandStart ? VARIANT_TRUE : VARIANT_FALSE);
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_AllowDemandStart failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pSettings->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}

		pSettings->Release();

		// 8) Triggers
		ITriggerCollection* pTriggers = nullptr;
		hr = pTaskDef->get_Triggers(&pTriggers);
		if (FAILED(hr) || !pTriggers) {
			_com_error err(hr);
			LogErr(L"[Error] get_Triggers failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		if (!triggerArgs.empty())
		{
			for (const auto& tstr : triggerArgs)
			{
				TriggerParam tp = ParseTriggerString(tstr);
				HRESULT thr = AddTriggerToCollection(pTriggers, tp);
				if (FAILED(thr))
					LogErr(L"[Error] Failed to add trigger: ", tstr, L" HRESULT=0x", hex, thr);
			}
		}
		else
		{
			// Default: Add a BOOT trigger if no trigger specified
			TriggerParam tp;
			tp.type = L"boot";
			HRESULT thr = AddTriggerToCollection(pTriggers, tp);
			if (FAILED(thr)) {
				LogErr(L"[Error] Failed to add default BOOT trigger: HRESULT=0x", hex, thr);
				pTriggers->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}
		pTriggers->Release();

		// 9) Exec Action
		IActionCollection* pActions = nullptr;
		hr = pTaskDef->get_Actions(&pActions);
		if (FAILED(hr) || !pActions) {
			_com_error err(hr);
			LogErr(L"[Error] get_Actions failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		IExecAction* pExec = nullptr;
		hr = pActions->Create(TASK_ACTION_EXEC, reinterpret_cast<IAction**>(&pExec));
		if (FAILED(hr) || !pExec) {
			_com_error err(hr);
			LogErr(L"[Error] Actions::Create(TASK_ACTION_EXEC) failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pActions->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		hr = pExec->put_Path(_bstr_t(exePath.c_str()));
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_Path failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pExec->Release();
			pActions->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		if (!exeArgs.empty()) {
			hr = pExec->put_Arguments(_bstr_t(exeArgs.c_str()));
			if (FAILED(hr)) {
				_com_error err(hr);
				LogErr(L"[Error] put_Arguments failed: 0x", hex, hr, L" - ", err.ErrorMessage());
				pExec->Release();
				pActions->Release();
				pTaskDef->Release();
				pTargetFolder->Release();
				pService->Release();
				CoUninitialize();
				return 1;
			}
		}
		pExec->Release();
		pActions->Release();

		// 10) Principal: Set Run Level
		IPrincipal* pPrincipal = nullptr;
		hr = pTaskDef->get_Principal(&pPrincipal);
		if (FAILED(hr) || !pPrincipal) {
			_com_error err(hr);
			LogErr(L"[Error] get_Principal failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		hr = pPrincipal->put_RunLevel(static_cast<TASK_RUNLEVEL_TYPE>(runLevel));
		if (FAILED(hr)) {
			_com_error err(hr);
			LogErr(L"[Error] put_RunLevel failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pPrincipal->Release();
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}
		pPrincipal->Release();

		// 11) Register Task
		IRegisteredTask* pRegistered = nullptr;
		_variant_t varPassword = password.empty() ? _variant_t() : _variant_t(password.c_str());
		hr = pTargetFolder->RegisterTaskDefinition(
			_bstr_t(taskName.c_str()),
			pTaskDef,
			TASK_CREATE_OR_UPDATE,
			_variant_t(sid.c_str()),                 // User-specified or default SID
			varPassword,                             // Password if provided
			static_cast<TASK_LOGON_TYPE>(logonType), // User-specified or default logon type
			_variant_t(L""),                         // No custom SDDL
			&pRegistered);

		if (SUCCEEDED(hr))
		{
			LogOut(L"[Success] Task \"", taskName, L"\" registered successfully.");
			if (pRegistered)
				pRegistered->Release();
		}
		else
		{
			_com_error err(hr);
			LogErr(L"[Error] RegisterTaskDefinition failed: 0x", hex, hr, L" - ", err.ErrorMessage());
			pTaskDef->Release();
			pTargetFolder->Release();
			pService->Release();
			CoUninitialize();
			return 1;
		}

		// 12) Cleanup
		if (pTaskDef) pTaskDef->Release();
		if (pTargetFolder) pTargetFolder->Release();
		if (pService) pService->Release();
		CoUninitialize();

		return 0;
	}
}
