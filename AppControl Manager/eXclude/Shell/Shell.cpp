#include <windows.h>
#include <shobjidl.h>
#include <shobjidl_core.h>
#include <shlwapi.h>
#include <new>
#include <cwchar>
#include <string_view>
#include <array>
#include <span>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")

// Defining the Package Family Name (PFN)
// It's set to a placeholder value here, replaced during compilation
static constexpr LPCWSTR APP_CONTROL_MANAGER_PFN = L"PFN!App";

static const int ICON_RESOURCE_INDEX = 0;
static const int ICON_POLICY_EDITOR = 1;
static const int ICON_FILE_SIGNATURE = 2;
static const int ICON_FILE_HASHES = 3;

// {af39e5cf-0fda-4333-bd25-b87d43a71cca}
inline constexpr GUID CLSID_AppControlManagerCommand =
{ 0xaf39e5cf, 0x0fda, 0x4333, { 0xbd, 0x25, 0xb8, 0x7d, 0x43, 0xa7, 0x1c, 0xca } };

// GUIDs for sub commands
// {bcf84055-fcb6-4585-bfb9-fffbe105af56}
inline constexpr GUID CLSID_SubCommand1 =
{ 0xbcf84055, 0xfcb6, 0x4585, { 0xbf, 0xb9, 0xff, 0xfb, 0xe1, 0x05, 0xaf, 0x56 } };
// {7b864272-39e5-4580-8015-ef182f730b57}
inline constexpr GUID CLSID_SubCommand2 =
{ 0x7b864272, 0x39e5, 0x4580, { 0x80, 0x15, 0xef, 0x18, 0x2f, 0x73, 0x0b, 0x57 } };
// {46d08941-b04b-4596-b71a-437fc1f9043a}
inline constexpr GUID CLSID_SubCommand3 =
{ 0x46d08941, 0xb04b, 0x4596, { 0xb7, 0x1a, 0x43, 0x7f, 0xc1, 0xf9, 0x04, 0x3a } };

// Dll-wide instance count and module handle
constinit long   g_cDllRef = 0;
static    HMODULE g_hModule = nullptr;

// Cached icon location strings
static wchar_t g_cachedMainIconLocation[MAX_PATH + 16] = {};
static wchar_t g_cachedPolicyEditorIconLocation[MAX_PATH + 16] = {};
static wchar_t g_cachedFileSignatureIconLocation[MAX_PATH + 16] = {};
static wchar_t g_cachedFileHashesIconLocation[MAX_PATH + 16] = {};
static bool g_iconLocationsCached = false;

// Cached COM Application Activation Manager
static IApplicationActivationManager* g_cachedAppActivationManager = nullptr;
static bool g_appActivationManagerCached = false;

static constexpr LPCWSTR g_commandTitles[] = {
	L"Open in Policy Editor",
	L"View File Signature",
	L"Get File Hashes"
};

static constexpr GUID g_commandGuids[] = {
	CLSID_SubCommand1,
	CLSID_SubCommand2,
	CLSID_SubCommand3
};

static constexpr LPCWSTR g_commandActions[] = {
	L"--action=PolicyEditor --file=\"%s\"",
	L"--action=FileSignature --file=\"%s\"",
	L"--action=FileHashes --file=\"%s\""
};

// Direct array access lookup table for icon locations
static LPCWSTR* g_iconLocationLookupTable[] = {
	reinterpret_cast<LPCWSTR*>(&g_cachedPolicyEditorIconLocation),
	reinterpret_cast<LPCWSTR*>(&g_cachedFileSignatureIconLocation),
	reinterpret_cast<LPCWSTR*>(&g_cachedFileHashesIconLocation)
};

// Pre-formatted parameter templates
static constexpr std::wstring_view g_parameterPrefixes[] = {
	L"--action=PolicyEditor --file=\"",
	L"--action=FileSignature --file=\"",
	L"--action=FileHashes --file=\""
};

static constexpr std::wstring_view g_parameterSuffix = L"\"";

// String building function for parameter construction
inline void BuildOptimizedParameterString(wchar_t* dest, size_t destSize, ULONG commandIndex, LPCWSTR filePath) noexcept
{
	if (!dest || !filePath || commandIndex >= 3) return;

	// Get the pre-formatted prefix for this command
	auto prefix = g_parameterPrefixes[commandIndex];
	auto suffix = g_parameterSuffix;

	// Calculate required lengths
	size_t prefixLen = prefix.length();
	size_t filePathLen = wcslen(filePath);
	size_t suffixLen = suffix.length();
	size_t totalLen = prefixLen + filePathLen + suffixLen + 1; // +1 for null terminator

	// Ensure we don't overflow the destination buffer
	if (totalLen > destSize) return;

	wchar_t* currentPos = dest;

	// Copy prefix
	wmemcpy(currentPos, prefix.data(), prefixLen);
	currentPos += prefixLen;

	// Copy file path
	wmemcpy(currentPos, filePath, filePathLen);
	currentPos += filePathLen;

	// Copy suffix
	wmemcpy(currentPos, suffix.data(), suffixLen);
	currentPos += suffixLen;

	// Null terminate
	*currentPos = L'\0';
}

// File extension comparison function
inline bool IsValidPolicyFile(LPCWSTR filePath)
{
	if (!filePath) return false;
	LPCWSTR ext = PathFindExtensionW(filePath);
	if (ext && *ext == L'.')
	{
		ext++; // skip the dot
		return (_wcsicmp(ext, L"xml") == 0 || _wcsicmp(ext, L"cip") == 0);
	}
	return false;
}

class CSubCommand : public IExplorerCommand
{
public:
	CSubCommand(ULONG commandIndex) : _cRef(1), _commandIndex(commandIndex)
	{
		InterlockedIncrement(&g_cDllRef);
	}

	~CSubCommand()
	{
		InterlockedDecrement(&g_cDllRef);
	}

	// IUnknown - Optimized QueryInterface using IsEqualIID
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv)
	{
		if (!ppv) return E_POINTER;
		*ppv = nullptr;

		if (IsEqualIID(riid, IID_IUnknown) ||
			IsEqualIID(riid, IID_IInitializeCommand) ||
			IsEqualIID(riid, IID_IExplorerCommand))
		{
			*ppv = static_cast<IExplorerCommand*>(this);
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef()
	{
		return InterlockedIncrement(&_cRef);
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		ULONG c = InterlockedDecrement(&_cRef);
		if (c == 0) delete this;
		return c;
	}

	// IInitializeCommand
	HRESULT STDMETHODCALLTYPE Initialize(PCWSTR /*pszCommandName*/, IPropertyBag* /*ppb*/)
	{
		return S_OK;
	}

	// IExplorerCommand
	HRESULT STDMETHODCALLTYPE GetTitle(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszName)
	{
		return SHStrDupW(g_commandTitles[_commandIndex], ppszName);
	}

	// GetIcon with direct array access
	HRESULT STDMETHODCALLTYPE GetIcon(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszIcon)
	{
		if (!ppszIcon) return E_POINTER;
		*ppszIcon = nullptr;

		if (g_iconLocationsCached)
		{
			LPCWSTR iconLocation = reinterpret_cast<LPCWSTR>(g_iconLocationLookupTable[_commandIndex]);
			return SHStrDupW(iconLocation, ppszIcon);
		}
		return E_FAIL;
	}

	HRESULT STDMETHODCALLTYPE GetToolTip(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszInfotip)
	{
		if (!ppszInfotip) return E_POINTER;
		*ppszInfotip = nullptr;

		static constexpr std::wstring_view Tooltips[] = {
			L"Open the App Control policy in the Policy Editor to inspect and modify all of its details.",
			L"View all of the signers and signatures of the file (if any).",
			L"Get multiple different types of hashes of the file."
		};
		auto sv = Tooltips[_commandIndex];
		return SHStrDupW(sv.data(), ppszInfotip);
	}

	HRESULT STDMETHODCALLTYPE GetCanonicalName(GUID* pguidCommandName)
	{
		*pguidCommandName = g_commandGuids[_commandIndex];
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE GetState(
		IShellItemArray* psiItemArray,
		BOOL /*fOkToBeSlow*/,
		EXPCMDSTATE* pCmdState)
	{
		// Only show the Policy Editor option if the file is .xml or .cip
		if (_commandIndex == 0)
		{
			// Default to hidden
			*pCmdState = ECS_HIDDEN;

			if (psiItemArray)
			{
				DWORD count = 0;
				if (SUCCEEDED(psiItemArray->GetCount(&count)) && count > 0)
				{
					IShellItem* psi = nullptr;
					if (SUCCEEDED(psiItemArray->GetItemAt(0, &psi)) && psi)
					{
						LPWSTR pszPath = nullptr;
						if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath)) && pszPath)
						{
							if (IsValidPolicyFile(pszPath))
							{
								*pCmdState = ECS_ENABLED;
							}
							CoTaskMemFree(pszPath);
						}
						psi->Release();
					}
				}
			}
			return S_OK;
		}

		// Other subcommands always enabled
		*pCmdState = ECS_ENABLED;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Invoke(
		IShellItemArray* psiItemArray,
		IBindCtx*       /*pBindCtx*/)
	{
		if (!psiItemArray)
			return S_OK;

		DWORD count = 0;
		if (FAILED(psiItemArray->GetCount(&count)) || count == 0)
			return S_OK;

		IShellItem* psi = nullptr;
		if (FAILED(psiItemArray->GetItemAt(0, &psi)) || !psi)
			return S_OK;

		LPWSTR pszPath = nullptr;
		if (SUCCEEDED(psi->GetDisplayName(SIGDN_FILESYSPATH, &pszPath)) && pszPath)
		{
			std::array<wchar_t, MAX_PATH * 2 + 64> parameters{};
			std::span<wchar_t> paramSpan(parameters);

			BuildOptimizedParameterString(paramSpan.data(), paramSpan.size(), _commandIndex, pszPath);

			// Use cached Application Activation Manager if available
			if (g_appActivationManagerCached && g_cachedAppActivationManager)
			{
				DWORD processId = 0;
				g_cachedAppActivationManager->ActivateApplication(
					APP_CONTROL_MANAGER_PFN,
					paramSpan.data(),
					AO_NONE,
					&processId);
			}
			else
			{
				// Fallback to creating new instance if cache failed
				IApplicationActivationManager* pActMgr = nullptr;
				if (SUCCEEDED(CoCreateInstance(
					CLSID_ApplicationActivationManager,
					nullptr,
					CLSCTX_LOCAL_SERVER,
					IID_IApplicationActivationManager,
					reinterpret_cast<void**>(&pActMgr))))
				{
					DWORD processId = 0;
					pActMgr->ActivateApplication(
						APP_CONTROL_MANAGER_PFN,
						paramSpan.data(),
						AO_NONE,
						&processId);
					pActMgr->Release();
				}
			}

			CoTaskMemFree(pszPath);
		}
		psi->Release();
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE GetFlags(EXPCMDFLAGS* pFlags)
	{
		*pFlags = ECF_DEFAULT;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE EnumSubCommands(IEnumExplorerCommand** /*ppEnum*/)
	{
		return E_NOTIMPL;
	}

private:
	long  _cRef;
	ULONG _commandIndex;
};

class CSubCommandEnumerator : public IEnumExplorerCommand
{
public:
	CSubCommandEnumerator() : _cRef(1), _currentIndex(0)
	{
		InterlockedIncrement(&g_cDllRef);
	}
	~CSubCommandEnumerator()
	{
		InterlockedDecrement(&g_cDllRef);
	}

	// IUnknown - Optimized QueryInterface using IsEqualIID
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv)
	{
		if (!ppv) return E_POINTER;
		*ppv = nullptr;

		if (IsEqualIID(riid, IID_IUnknown) ||
			IsEqualIID(riid, IID_IEnumExplorerCommand))
		{
			*ppv = static_cast<IEnumExplorerCommand*>(this);
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef()
	{
		return InterlockedIncrement(&_cRef);
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		ULONG c = InterlockedDecrement(&_cRef);
		if (c == 0) delete this;
		return c;
	}

	// IEnumExplorerCommand
	HRESULT STDMETHODCALLTYPE Next(ULONG celt, IExplorerCommand** ppUICommand, ULONG* pceltFetched)
	{
		if (!ppUICommand) return E_POINTER;
		ULONG fetched = 0;
		for (ULONG i = 0; i < celt && _currentIndex < 3; i++, _currentIndex++)
		{
			CSubCommand* pSubCmd = new (std::nothrow) CSubCommand(_currentIndex);
			if (!pSubCmd) return E_OUTOFMEMORY;
			ppUICommand[i] = static_cast<IExplorerCommand*>(pSubCmd);
			fetched++;
		}
		if (pceltFetched) *pceltFetched = fetched;
		return (fetched == celt) ? S_OK : S_FALSE;
	}

	HRESULT STDMETHODCALLTYPE Skip(ULONG celt)
	{
		if (_currentIndex + celt <= 3)
		{
			_currentIndex += celt;
			return S_OK;
		}
		_currentIndex = 3;
		return S_FALSE;
	}

	HRESULT STDMETHODCALLTYPE Reset()
	{
		_currentIndex = 0;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Clone(IEnumExplorerCommand** ppEnum)
	{
		if (!ppEnum) return E_POINTER;
		CSubCommandEnumerator* pNew = new (std::nothrow) CSubCommandEnumerator();
		if (!pNew) return E_OUTOFMEMORY;
		pNew->_currentIndex = _currentIndex;
		*ppEnum = pNew;
		return S_OK;
	}

private:
	long  _cRef;
	ULONG _currentIndex;
};

class CAppControlManagerCommand : public IExplorerCommand
{
public:
	CAppControlManagerCommand() : _cRef(1) { InterlockedIncrement(&g_cDllRef); }
	~CAppControlManagerCommand() { InterlockedDecrement(&g_cDllRef); }

	// IUnknown - Optimized QueryInterface using IsEqualIID
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv)
	{
		if (!ppv) return E_POINTER;
		*ppv = nullptr;

		if (IsEqualIID(riid, IID_IUnknown) ||
			IsEqualIID(riid, IID_IInitializeCommand) ||
			IsEqualIID(riid, IID_IExplorerCommand))
		{
			*ppv = static_cast<IExplorerCommand*>(this);
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef()
	{
		return InterlockedIncrement(&_cRef);
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		ULONG c = InterlockedDecrement(&_cRef);
		if (c == 0) delete this;
		return c;
	}

	// IInitializeCommand
	HRESULT STDMETHODCALLTYPE Initialize(PCWSTR /*pszCommandName*/, IPropertyBag* /*ppb*/)
	{
		return S_OK;
	}

	// IExplorerCommand
	HRESULT STDMETHODCALLTYPE GetTitle(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszName)
	{
		return SHStrDupW(L"AppControl Manager", ppszName);
	}

	HRESULT STDMETHODCALLTYPE GetIcon(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszIcon)
	{
		if (!ppszIcon) return E_POINTER;
		*ppszIcon = nullptr;

		if (g_iconLocationsCached)
		{
			return SHStrDupW(g_cachedMainIconLocation, ppszIcon);
		}
		return E_FAIL;
	}

	HRESULT STDMETHODCALLTYPE GetToolTip(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszInfotip)
	{
		if (!ppszInfotip) return E_POINTER;
		*ppszInfotip = nullptr;

		static constexpr std::wstring_view Tooltip =
			L"View all of the available options offered by the AppControl Manager application.";
		return SHStrDupW(Tooltip.data(), ppszInfotip);
	}

	HRESULT STDMETHODCALLTYPE GetCanonicalName(GUID* pguidCommandName)
	{
		*pguidCommandName = CLSID_AppControlManagerCommand;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE GetState(
		IShellItemArray* /*psiItemArray*/, BOOL /*fOkToBeSlow*/, EXPCMDSTATE* pCmdState)
	{
		*pCmdState = ECS_ENABLED;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE Invoke(
		IShellItemArray* /*psiItemArray*/, IBindCtx* /*pBindCtx*/)
	{
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE GetFlags(EXPCMDFLAGS* pFlags)
	{
		*pFlags = ECF_HASSUBCOMMANDS;
		return S_OK;
	}

	HRESULT STDMETHODCALLTYPE EnumSubCommands(IEnumExplorerCommand** ppEnum)
	{
		if (!ppEnum) return E_POINTER;
		CSubCommandEnumerator* pEnum = new (std::nothrow) CSubCommandEnumerator();
		if (!pEnum) return E_OUTOFMEMORY;
		*ppEnum = pEnum;
		return S_OK;
	}

private:
	long _cRef;
};

class CClassFactory : public IClassFactory
{
public:
	CClassFactory() : _cRef(1) { InterlockedIncrement(&g_cDllRef); }
	~CClassFactory() { InterlockedDecrement(&g_cDllRef); }

	// IUnknown - Optimized QueryInterface using IsEqualIID
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv)
	{
		if (!ppv) return E_POINTER;
		*ppv = nullptr;

		if (IsEqualIID(riid, IID_IUnknown) ||
			IsEqualIID(riid, IID_IClassFactory))
		{
			*ppv = static_cast<IClassFactory*>(this);
			AddRef();
			return S_OK;
		}

		return E_NOINTERFACE;
	}

	ULONG STDMETHODCALLTYPE AddRef()
	{
		return InterlockedIncrement(&_cRef);
	}

	ULONG STDMETHODCALLTYPE Release()
	{
		ULONG c = InterlockedDecrement(&_cRef);
		if (c == 0) delete this;
		return c;
	}

	HRESULT STDMETHODCALLTYPE CreateInstance(
		IUnknown* pUnkOuter, REFIID riid, void** ppv)
	{
		if (pUnkOuter) return CLASS_E_NOAGGREGATION;
		CAppControlManagerCommand* pCmd = new (std::nothrow) CAppControlManagerCommand();
		if (!pCmd) return E_OUTOFMEMORY;
		HRESULT hr = pCmd->QueryInterface(riid, ppv);
		pCmd->Release();
		return hr;
	}

	HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock)
	{
		if (fLock)   InterlockedIncrement(&g_cDllRef);
		else         InterlockedDecrement(&g_cDllRef);
		return S_OK;
	}

private:
	long _cRef;
};

_Use_decl_annotations_
STDAPI DllCanUnloadNow()
{
	return (g_cDllRef == 0) ? S_OK : S_FALSE;
}

_Use_decl_annotations_
STDAPI DllGetClassObject(
	REFCLSID clsid, REFIID riid, void** ppv)
{
	if (!ppv) return E_POINTER;
	*ppv = nullptr;
	if (IsEqualCLSID(clsid, CLSID_AppControlManagerCommand))
	{
		CClassFactory* pFactory = new (std::nothrow) CClassFactory();
		if (!pFactory) return E_OUTOFMEMORY;
		HRESULT hr = pFactory->QueryInterface(riid, ppv);
		pFactory->Release();
		return hr;
	}
	return CLASS_E_CLASSNOTAVAILABLE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID /*lpReserved*/)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = hModule;
		DisableThreadLibraryCalls(hModule);

		// Cache module path and pre-format icon location strings
		if (g_hModule)
		{
			wchar_t modulePath[MAX_PATH] = {};
			if (GetModuleFileNameW(g_hModule, modulePath, MAX_PATH))
			{
				swprintf_s(g_cachedMainIconLocation, MAX_PATH + 16,
					L"%s,%d", modulePath, ICON_RESOURCE_INDEX);
				swprintf_s(g_cachedPolicyEditorIconLocation, MAX_PATH + 16,
					L"%s,%d", modulePath, ICON_POLICY_EDITOR);
				swprintf_s(g_cachedFileSignatureIconLocation, MAX_PATH + 16,
					L"%s,%d", modulePath, ICON_FILE_SIGNATURE);
				swprintf_s(g_cachedFileHashesIconLocation, MAX_PATH + 16,
					L"%s,%d", modulePath, ICON_FILE_HASHES);
				g_iconLocationsCached = true;
			}
		}

		// Cache COM Application Activation Manager
		if (SUCCEEDED(CoCreateInstance(
			CLSID_ApplicationActivationManager,
			nullptr,
			CLSCTX_LOCAL_SERVER,
			IID_IApplicationActivationManager,
			reinterpret_cast<void**>(&g_cachedAppActivationManager))))
		{
			g_appActivationManagerCached = true;
		}
		break;

	case DLL_PROCESS_DETACH:
		// Release cached COM Application Activation Manager
		if (g_cachedAppActivationManager)
		{
			g_cachedAppActivationManager->Release();
			g_cachedAppActivationManager = nullptr;
		}
		g_appActivationManagerCached = false;
		break;
	}
	return TRUE;
}