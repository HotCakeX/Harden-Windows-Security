#include <Wbemidl.h>
#include <comdef.h>
#include <string>
#include <vector>
#include <sstream>
#include <cwchar>
#include <windows.h>

#include "../Globals.h"
#include "../StringUtilities.h"
#include "../ComHelpers.h"
#include "Virtualization.h"

using namespace std;

namespace Virtualization {

	// Helper for safe Get BSTR property into std::wstring (returns true if got a non-empty BSTR)
	static bool GetBstrProp(IWbemClassObject* obj, const wchar_t* name, wstring& out)
	{
		if (!obj || !name) return false;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return false;
		}
		bool ok = false;
		if (v.vt == VT_BSTR && v.bstrVal)
		{
			out.assign(v.bstrVal);
			ok = true;
		}
		VariantClear(&v);
		return ok;
	}

	// Helper to read integer property (VT_I2/I4/UI2/UI4) into LONG
	static bool GetLongProp(IWbemClassObject* obj, const wchar_t* name, LONG& outVal)
	{
		if (!obj || !name) return false;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return false;
		}
		bool ok = false;
		switch (v.vt)
		{
		case VT_I2:  outVal = v.iVal; ok = true; break;
		case VT_UI2: outVal = v.uiVal; ok = true; break;
		case VT_I4:  outVal = v.lVal; ok = true; break;
		case VT_UI4: outVal = static_cast<LONG>(v.ulVal); ok = true; break;
		default: break;
		}
		VariantClear(&v);
		return ok;
	}

	// Helper to try to read VT_BOOL or compatible representations into tri-state:
	// returns -1 for null/missing, 0 for false, 1 for true
	static int ReadBoolTriState(IWbemClassObject* obj, const wchar_t* name)
	{
		if (!obj || !name) return -1;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return -1;
		}

		// Resolve BYREF/VARIANT wrappers if any
		VARIANT eff; VariantInit(&eff);
		bool haveEff = CopyEffectiveVariant(v, eff);
		const VARIANT& r = haveEff ? eff : v;

		int result = -1;
		switch (r.vt)
		{
		case VT_BOOL:
			result = (r.boolVal == VARIANT_TRUE) ? 1 : 0;
			break;
		case VT_I4:
			result = (r.lVal != 0) ? 1 : 0;
			break;
		case VT_UI4:
			result = (r.ulVal != 0) ? 1 : 0;
			break;
		case VT_BSTR:
			if (r.bstrVal)
			{
				if (EqualsOrdinalIgnoreCase(r.bstrVal, L"true") || EqualsOrdinalIgnoreCase(r.bstrVal, L"1"))
					result = 1;
				else if (EqualsOrdinalIgnoreCase(r.bstrVal, L"false") || EqualsOrdinalIgnoreCase(r.bstrVal, L"0"))
					result = 0;
			}
			break;
		case VT_NULL:
		case VT_EMPTY:
		default:
			result = -1;
			break;
		}

		VariantClear(&eff);
		VariantClear(&v);
		return result;
	}

	// Helper to read integer property of potentially 64-bit type into long long.
	// Supports VT_I2/VT_UI2/VT_I4/VT_UI4/VT_I8/VT_UI8, and VT_BSTR.
	static bool GetInt64Prop(IWbemClassObject* obj, const wchar_t* name, long long& outVal)
	{
		if (!obj || !name) return false;
		VARIANT v; VariantInit(&v);
		HRESULT hr = obj->Get(_bstr_t(name), 0, &v, nullptr, nullptr);
		if (FAILED(hr))
		{
			VariantClear(&v);
			return false;
		}
		bool ok = false;
		switch (v.vt)
		{
		case VT_I2:  outVal = static_cast<long long>(v.iVal); ok = true; break;
		case VT_UI2: outVal = static_cast<long long>(v.uiVal); ok = true; break;
		case VT_I4:  outVal = static_cast<long long>(v.lVal); ok = true; break;
		case VT_UI4: outVal = static_cast<long long>(v.ulVal); ok = true; break;
		case VT_I8:  outVal = static_cast<long long>(v.llVal); ok = true; break;
		case VT_UI8: outVal = static_cast<long long>(v.ullVal); ok = true; break;
		case VT_BSTR:
			if (v.bstrVal && *v.bstrVal)
			{
				// WMI frequently encodes uint64 as a decimal string (VT_BSTR). Parse safely.
				const wchar_t* s = v.bstrVal;
				while (*s == L' ' || *s == L'\t' || *s == L'\n' || *s == L'\r') ++s; // trim lead ws
				if (*s)
				{
					const wchar_t* p = s;
					if (*p == L'+') ++p;
					bool any = false, bad = false;
					for (; *p; ++p)
					{
						if (*p >= L'0' && *p <= L'9') { any = true; continue; }
						if (*p == L' ' || *p == L'\t' || *p == L'\n' || *p == L'\r') break; // allow trailing ws
						bad = true; break;
					}
					if (!bad && any)
					{
						errno = 0;
						long long parsed = wcstoll(s, nullptr, 10);
						if (errno == 0) { outVal = parsed; ok = true; }
					}
				}
			}
			break;
		default: break;
		}
		VariantClear(&v);
		return ok;
	}

	// Helper to select the preferred VSSD from the associations of an Msvm_ComputerSystem instance.
	// Preference order:
	//   1) VirtualSystemType == "Microsoft:Hyper-V:System:Configuration"
	//   2) VirtualSystemType == "Microsoft:Hyper-V:System:Realized"
	//   3) VirtualSystemType == "Microsoft:Hyper-V:System:Planned"
	//   4) Fallback: SettingType == 3
	// Returns an AddRef'd pointer in ppOut (caller must Release) or nullptr if none.
	static IWbemClassObject* SelectPreferredVssd(IWbemServices* svc, const wstring& vmRelPath)
	{
		if (!svc || vmRelPath.empty())
			return nullptr;

		wstringstream assocWql;
		assocWql << L"ASSOCIATORS OF {" << vmRelPath << L"} WHERE AssocClass=Msvm_SettingsDefineState";

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = svc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(assocWql.str().c_str()),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
			return nullptr;

		IWbemClassObject* pConfig = nullptr;
		IWbemClassObject* pRealized = nullptr;
		IWbemClassObject* pPlanned = nullptr;
		IWbemClassObject* pFallbackSettingType3 = nullptr;

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			// Read VirtualSystemType if available
			wstring vst;
			(void)GetBstrProp(pObj, L"VirtualSystemType", vst);

			if (!vst.empty())
			{
				if (!pConfig && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Configuration"))
				{
					pConfig = pObj; // take ownership
					continue;
				}
				if (!pRealized && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Realized"))
				{
					pRealized = pObj; // take ownership
					continue;
				}
				if (!pPlanned && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Planned"))
				{
					pPlanned = pObj; // take ownership
					continue;
				}
			}

			// Fallback: SettingType == 3 (current)
			VARIANT v; VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"SettingType"), 0, &v, nullptr, nullptr)))
			{
				LONG st = -1;
				if (v.vt == VT_I2) st = v.iVal;
				else if (v.vt == VT_UI2) st = v.uiVal;
				else if (v.vt == VT_I4) st = v.lVal;
				else if (v.vt == VT_UI4) st = static_cast<LONG>(v.ulVal);
				if (st == 3 && !pFallbackSettingType3)
				{
					pFallbackSettingType3 = pObj; // take ownership
					VariantClear(&v);
					continue;
				}
			}
			VariantClear(&v);

			// Not used -> release
			pObj->Release();
		}

		pEnum->Release();

		// Return the best we have; release the rest.
		IWbemClassObject* chosen = nullptr;
		if (pConfig) chosen = pConfig;
		else if (pRealized) chosen = pRealized;
		else if (pPlanned) chosen = pPlanned;
		else if (pFallbackSettingType3) chosen = pFallbackSettingType3;

		// Release non-chosen
		if (chosen != pConfig && pConfig) pConfig->Release();
		if (chosen != pRealized && pRealized) pRealized->Release();
		if (chosen != pPlanned && pPlanned) pPlanned->Release();
		if (chosen != pFallbackSettingType3 && pFallbackSettingType3) pFallbackSettingType3->Release();

		return chosen; // may be nullptr
	}

	// Helper (LISTING) to select VSSD preferring Realized for read-only inventory.
	// Preference order for list:
	//   1) VirtualSystemType == "Microsoft:Hyper-V:System:Realized"   (reflects currently realized settings)
	//   2) VirtualSystemType == "Microsoft:Hyper-V:System:Configuration"
	//   3) VirtualSystemType == "Microsoft:Hyper-V:System:Planned"
	//   4) Fallback: SettingType == 3
	static IWbemClassObject* SelectVssdForList(IWbemServices* svc, const wstring& vmRelPath)
	{
		if (!svc || vmRelPath.empty())
			return nullptr;

		wstringstream assocWql;
		assocWql << L"ASSOCIATORS OF {" << vmRelPath << L"} WHERE AssocClass=Msvm_SettingsDefineState";

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = svc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(assocWql.str().c_str()),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
			return nullptr;

		IWbemClassObject* pRealized = nullptr;
		IWbemClassObject* pConfig = nullptr;
		IWbemClassObject* pPlanned = nullptr;
		IWbemClassObject* pFallbackSettingType3 = nullptr;

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			wstring vst;
			(void)GetBstrProp(pObj, L"VirtualSystemType", vst);

			if (!vst.empty())
			{
				if (!pRealized && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Realized"))
				{
					pRealized = pObj; // take ownership
					continue;
				}
				if (!pConfig && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Configuration"))
				{
					pConfig = pObj; // take ownership
					continue;
				}
				if (!pPlanned && EqualsOrdinalIgnoreCase(vst.c_str(), L"Microsoft:Hyper-V:System:Planned"))
				{
					pPlanned = pObj; // take ownership
					continue;
				}
			}

			VARIANT v; VariantInit(&v);
			if (SUCCEEDED(pObj->Get(_bstr_t(L"SettingType"), 0, &v, nullptr, nullptr)))
			{
				LONG st = -1;
				if (v.vt == VT_I2) st = v.iVal;
				else if (v.vt == VT_UI2) st = v.uiVal;
				else if (v.vt == VT_I4) st = v.lVal;
				else if (v.vt == VT_UI4) st = static_cast<LONG>(v.ulVal);
				if (st == 3 && !pFallbackSettingType3)
				{
					pFallbackSettingType3 = pObj; // take ownership
					VariantClear(&v);
					continue;
				}
			}
			VariantClear(&v);

			pObj->Release();
		}

		pEnum->Release();

		IWbemClassObject* chosen = nullptr;
		if (pRealized) chosen = pRealized;
		else if (pConfig) chosen = pConfig;
		else if (pPlanned) chosen = pPlanned;
		else if (pFallbackSettingType3) chosen = pFallbackSettingType3;

		if (chosen != pRealized && pRealized) pRealized->Release();
		if (chosen != pConfig && pConfig) pConfig->Release();
		if (chosen != pPlanned && pPlanned) pPlanned->Release();
		if (chosen != pFallbackSettingType3 && pFallbackSettingType3) pFallbackSettingType3->Release();

		return chosen;
	}

	// Helper to find the processor RASD associated to the VSSD.
	// Preference:
	//   - Instance with __CLASS == "Msvm_ProcessorSettingData"
	//   - Fallback: __CLASS == "CIM_ResourceAllocationSettingData" with ResourceType == 3 (Processor)
	// Returns AddRef'd pointer or nullptr if not found.
	static IWbemClassObject* GetProcessorSettingData(IWbemServices* svc, const wstring& vssdRelPath)
	{
		if (!svc || vssdRelPath.empty())
			return nullptr;

		wstringstream assocWql;
		assocWql << L"ASSOCIATORS OF {" << vssdRelPath
			<< L"} WHERE AssocClass=Msvm_VirtualSystemSettingDataComponent";

		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = svc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(assocWql.str().c_str()),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
			return nullptr;

		IWbemClassObject* pTyped = nullptr;
		IWbemClassObject* pGenericProcessor = nullptr;

		for (;;)
		{
			IWbemClassObject* pObj = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pObj, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pObj)
				break;

			// __CLASS
			wstring clsName;
			(void)GetBstrProp(pObj, L"__CLASS", clsName);

			if (!clsName.empty() && EqualsOrdinalIgnoreCase(clsName.c_str(), L"Msvm_ProcessorSettingData"))
			{
				if (!pTyped)
				{
					pTyped = pObj; // take ownership
					continue;
				}
			}
			else
			{
				// Fallback: generic with ResourceType == 3
				bool isGeneric = (!clsName.empty() && EqualsOrdinalIgnoreCase(clsName.c_str(), L"CIM_ResourceAllocationSettingData"));
				if (isGeneric)
				{
					VARIANT v; VariantInit(&v);
					if (SUCCEEDED(pObj->Get(_bstr_t(L"ResourceType"), 0, &v, nullptr, nullptr)))
					{
						LONG rt = -1;
						if (v.vt == VT_I2) rt = v.iVal;
						else if (v.vt == VT_UI2) rt = v.uiVal;
						else if (v.vt == VT_I4) rt = v.lVal;
						else if (v.vt == VT_UI4) rt = static_cast<LONG>(v.ulVal);

						if (rt == 3 && !pGenericProcessor)
						{
							pGenericProcessor = pObj; // take ownership
							VariantClear(&v);
							continue;
						}
					}
					VariantClear(&v);
				}
			}

			// Not needed
			pObj->Release();
		}

		pEnum->Release();

		IWbemClassObject* chosen = nullptr;
		if (pTyped) chosen = pTyped;
		else if (pGenericProcessor) chosen = pGenericProcessor;

		if (chosen != pTyped && pTyped) pTyped->Release();
		if (chosen != pGenericProcessor && pGenericProcessor) pGenericProcessor->Release();
		return chosen; // may be nullptr
	}

	// Helper to map EnabledState (Msvm_ComputerSystem) to friendly string label.
	static wstring MapEnabledStateToString(LONG code)
	{
		switch (code)
		{
		case 2:     return L"Running";     // Enabled
		case 3:     return L"Off";         // Disabled
		case 4:     return L"ShuttingDown";
		case 10:    return L"Offline";
		case 32768: return L"Paused";
		case 32769: return L"Saved";       // Suspended
		case 32770: return L"Starting";
		case 32771: return L"Snapshotting";
		case 32773: return L"Saving";
		case 32774: return L"Stopping";
		default:
			break;
		}
		// Unknown -> return the numeric code in parentheses for diagnostics
		wstringstream ss;
		ss << L"Unknown(" << code << L")";
		return ss.str();
	}

	// Wait for Msvm_ConcreteJob completion, returns true on success; false on failure with last error set
	static bool WaitConcreteJob(IWbemServices* svc, const wstring& jobPath)
	{
		if (!svc || jobPath.empty()) return false;

		for (;;)
		{
			IWbemClassObject* pJob = nullptr;
			HRESULT hr = svc->GetObject(_bstr_t(jobPath.c_str()), 0, nullptr, &pJob, nullptr);
			if (FAILED(hr) || !pJob)
			{
				SetLastErrorMsg(L"Failed to retrieve Msvm_ConcreteJob instance while waiting.");
				return false;
			}

			LONG jobState = 0;
			(void)GetLongProp(pJob, L"JobState", jobState);
			wstring errDesc; (void)GetBstrProp(pJob, L"ErrorDescription", errDesc);
			LONG errCode = 0; (void)GetLongProp(pJob, L"ErrorCode", errCode);

			pJob->Release();

			// 2=Starting, 3=Running, 4=Suspended, 7=Completed, 10=Terminated, 11=Killed, 12=Exception
			if (jobState == 7)
				return true;

			if (jobState == 10 || jobState == 11 || jobState == 12)
			{
				wstringstream ss;
				ss << L"Hyper-V job failed: ";
				if (!errDesc.empty()) ss << errDesc;
				else ss << L"JobState=" << jobState << L"; ErrorCode=" << errCode;
				SetLastErrorMsg(ss.str());
				return false;
			}

			::Sleep(250);
		}
	}

	// Serialize IWbemClassObject to CIM-XML (CIM DTD 2.0) using IWbemObjectTextSrc
	static bool ToCimXml(IWbemClassObject* obj, wstring& outXml)
	{
		outXml.clear();
		if (!obj) return false;

		IWbemObjectTextSrc* pText = nullptr;
		HRESULT hr = CoCreateInstance(CLSID_WbemObjectTextSrc, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemObjectTextSrc, reinterpret_cast<void**>(&pText));
		if (FAILED(hr) || !pText)
		{
			SetLastErrorMsg(L"Failed to create IWbemObjectTextSrc for serialization.");
			return false;
		}

		BSTR xml = nullptr;
		// WBEM_OBJ_TEXT_FORMAT_CIMDTD20 == 2
		hr = pText->GetText(0, obj, 2 /*CIMDTD20*/, nullptr, &xml);
		pText->Release();

		if (FAILED(hr) || !xml)
		{
			SetLastErrorMsg(L"Failed to serialize processor settings to CIM-XML.");
			if (xml) SysFreeString(xml);
			return false;
		}

		outXml.assign(xml, SysStringLen(xml));
		SysFreeString(xml);
		return true;
	}

	[[nodiscard]] bool GetVmProcessorExposeVirtualizationExtensions(vector<VmCpuInfo>& outList)
	{
		outList.clear();
		ClearLastErrorMsg();

		// Connect to root\virtualization\v2
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(L"root\\virtualization\\v2", &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false; // error already set
		}

		// Query VMs
		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			// Include Name (VMId) and EnabledState for requested details
			_bstr_t(L"SELECT __RELPATH, ElementName, Name, EnabledState FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for Msvm_ComputerSystem failed.");
			if (pEnum) pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		bool any = false;

		for (;;)
		{
			IWbemClassObject* pVm = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pVm, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pVm)
				break;

			any = true;

			// Get name, id, state code and path
			wstring vmName;
			(void)GetBstrProp(pVm, L"ElementName", vmName);

			wstring vmRelPath;
			(void)GetBstrProp(pVm, L"__RELPATH", vmRelPath);

			wstring vmId; // GUID
			(void)GetBstrProp(pVm, L"Name", vmId);

			LONG enabledState = 0;
			(void)GetLongProp(pVm, L"EnabledState", enabledState);

			// Default tri-state value: null
			int expose = -1;

			wstring version;
			wstring vmSubType;
			long long cpuCount = -1;

			// Resolve preferred VSSD FOR LISTING (prefer Realized)
			if (!vmRelPath.empty())
			{
				IWbemClassObject* pVssd = SelectVssdForList(pSvc, vmRelPath);
				if (pVssd)
				{
					// Need VSSD rel path to associate down to RASDs
					wstring vssdRelPath;
					(void)GetBstrProp(pVssd, L"__RELPATH", vssdRelPath);

					// Version (e.g., "12.0")
					(void)GetBstrProp(pVssd, L"Version", version);

					// VirtualMachineSubType mapping:
					// Prefer a friendly "Generation1/Generation2" label when we can infer from VirtualSystemSubType.
					wstring rawSubType;
					(void)GetBstrProp(pVssd, L"VirtualSystemSubType", rawSubType);
					if (!rawSubType.empty())
					{
						if (rawSubType.size() >= 2 && (rawSubType.back() == L'2' || rawSubType.find(L":2") != wstring::npos))
							vmSubType = L"Generation2";
						else if (rawSubType.size() >= 2 && (rawSubType.back() == L'1' || rawSubType.find(L":1") != wstring::npos))
							vmSubType = L"Generation1";
						else
							vmSubType = rawSubType;
					}

					// Get processor settings for VirtualQuantity (vCPU count) and ExposeVirtualizationExtensions
					IWbemClassObject* pCpu = nullptr;
					if (!vssdRelPath.empty())
					{
						pCpu = GetProcessorSettingData(pSvc, vssdRelPath);
					}

					if (pCpu)
					{
						// Read ExposeVirtualizationExtensions as tri-state
						expose = ReadBoolTriState(pCpu, L"ExposeVirtualizationExtensions");

						// Processor count from VirtualQuantity (commonly encoded as VT_BSTR by WMI)
						long long qty = -1;
						if (GetInt64Prop(pCpu, L"VirtualQuantity", qty) && qty >= 0)
							cpuCount = qty;

						pCpu->Release();
					}

					pVssd->Release();
				}
			}

			// Append result entry
			VmCpuInfo info;
			info.vmName = vmName;
			info.exposeVirtualizationExtensions = expose;
			info.version = version;
			info.virtualMachineSubType = vmSubType;
			info.processorCount = cpuCount;
			info.state = MapEnabledStateToString(enabledState);
			info.vmId = vmId;

			outList.push_back(std::move(info));

			pVm->Release();
		}

		pEnum->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (!any)
		{
			SetLastErrorMsg(L"No Hyper-V virtual machines were found.");
			return true; // empty list is not an execution error
		}

		return true;
	}

	[[nodiscard]] bool PrintVmProcessorExposeVirtualizationExtensionsJson()
	{
		vector<VmCpuInfo> items;
		if (!GetVmProcessorExposeVirtualizationExtensions(items))
		{
			// Error already set
			return false;
		}

		// Build JSON array
		wstringstream json;
		json << L"[";

		for (size_t i = 0; i < items.size(); ++i)
		{
			if (i != 0) json << L",";

			const VmCpuInfo& it = items[i];

			// Escape VMName and other string fields
			wstring escName = Utf8ToWide(escapeJSON(WideToUtf8(it.vmName.c_str())));
			wstring escVersion = it.version.empty() ? L"" : Utf8ToWide(escapeJSON(WideToUtf8(it.version.c_str())));
			wstring escVmSubType = it.virtualMachineSubType.empty() ? L"" : Utf8ToWide(escapeJSON(WideToUtf8(it.virtualMachineSubType.c_str())));
			wstring escState = it.state.empty() ? L"" : Utf8ToWide(escapeJSON(WideToUtf8(it.state.c_str())));
			wstring escVmId = it.vmId.empty() ? L"" : Utf8ToWide(escapeJSON(WideToUtf8(it.vmId.c_str())));

			json << L"{\"VMName\":\"" << escName << L"\",\"ExposeVirtualizationExtensions\":"; // keep existing shape

			if (it.exposeVirtualizationExtensions < 0)
			{
				json << L"null";
			}
			else
			{
				json << (it.exposeVirtualizationExtensions == 1 ? L"true" : L"false");
			}

			// Version (string or null)
			json << L",\"Version\":";
			if (it.version.empty()) json << L"null";
			else json << L"\"" << escVersion << L"\"";

			// VirtualMachineSubType (string or null)
			json << L",\"VirtualMachineSubType\":";
			if (it.virtualMachineSubType.empty()) json << L"null";
			else json << L"\"" << escVmSubType << L"\"";

			// ProcessorCount (number or null)
			json << L",\"ProcessorCount\":";
			if (it.processorCount < 0) json << L"null";
			else json << it.processorCount;

			// State (string or null)
			json << L",\"State\":";
			if (it.state.empty()) json << L"null";
			else json << L"\"" << escState << L"\"";

			// VMId (string or null)
			json << L",\"VMId\":";
			if (it.vmId.empty()) json << L"null";
			else json << L"\"" << escVmId << L"\"";

			json << L"}";
		}

		json << L"]";

		LogOut(json.str().c_str());
		return true;
	}

	// Core setter for a single VM IWbemClassObject (ComputerSystem)
	static bool SetExposeForVmObject(IWbemServices* svc, IWbemClassObject* pVm, bool enable)
	{
		if (!svc || !pVm) return false;

		// Name (for messages)
		wstring vmName;
		(void)GetBstrProp(pVm, L"ElementName", vmName);

		// State must be Off (EnabledState == 3)
		LONG state = 0;
		if (!GetLongProp(pVm, L"EnabledState", state))
		{
			SetLastErrorMsg(L"Failed to read VM EnabledState.");
			return false;
		}
		if (state != 3)
		{
			wstringstream ss;
			ss << L"VM '" << vmName << L"' must be Off to change ExposeVirtualizationExtensions. Current state code: " << state;
			SetLastErrorMsg(ss.str());
			return false;
		}

		// Resolve VSSD
		wstring vmRelPath;
		if (!GetBstrProp(pVm, L"__RELPATH", vmRelPath) || vmRelPath.empty())
		{
			SetLastErrorMsg(L"Failed to resolve VM object path.");
			return false;
		}

		IWbemClassObject* pVssd = SelectPreferredVssd(svc, vmRelPath);
		if (!pVssd)
		{
			wstringstream ss;
			ss << L"Could not select a VirtualSystemSettingData for VM '" << vmName << L"'.";
			SetLastErrorMsg(ss.str());
			return false;
		}

		wstring vssdRelPath;
		(void)GetBstrProp(pVssd, L"__RELPATH", vssdRelPath);

		// Get CPU RASD
		IWbemClassObject* pCpu = nullptr;
		if (!vssdRelPath.empty())
		{
			pCpu = GetProcessorSettingData(svc, vssdRelPath);
		}
		if (!pCpu)
		{
			wstringstream ss;
			ss << L"Could not find Msvm_ProcessorSettingData for VM '" << vmName << L"'.";
			SetLastErrorMsg(ss.str());
			pVssd->Release();
			return false;
		}

		// Ensure property exists
		VARIANT vProbe; VariantInit(&vProbe);
		HRESULT hrProbe = pCpu->Get(_bstr_t(L"ExposeVirtualizationExtensions"), 0, &vProbe, nullptr, nullptr);
		VariantClear(&vProbe);
		if (FAILED(hrProbe))
		{
			SetLastErrorMsg(L"Host does not expose 'ExposeVirtualizationExtensions' on Msvm_ProcessorSettingData (nested virtualization unsupported).");
			pCpu->Release();
			pVssd->Release();
			return false;
		}

		// Clone and set property
		IWbemClassObject* pClone = nullptr;
		HRESULT hr = pCpu->Clone(&pClone);
		if (FAILED(hr) || !pClone)
		{
			SetLastErrorMsg(L"Failed to clone Msvm_ProcessorSettingData.");
			pCpu->Release();
			pVssd->Release();
			return false;
		}

		VARIANT vSet; VariantInit(&vSet);
		vSet.vt = VT_BOOL;
		vSet.boolVal = enable ? VARIANT_TRUE : VARIANT_FALSE;
		hr = pClone->Put(_bstr_t(L"ExposeVirtualizationExtensions"), 0, &vSet, 0);
		VariantClear(&vSet);
		if (FAILED(hr))
		{
			SetLastErrorMsg(L"Failed to set ExposeVirtualizationExtensions on cloned processor settings.");
			pClone->Release();
			pCpu->Release();
			pVssd->Release();
			return false;
		}

		// Serialize to CIM-XML
		wstring xml;
		if (!ToCimXml(pClone, xml))
		{
			pClone->Release();
			pCpu->Release();
			pVssd->Release();
			return false;
		}

		pClone->Release();
		pCpu->Release();
		pVssd->Release();

		// Get Virtual System Management Service instance path
		IEnumWbemClassObject* pSvcEnum = nullptr;
		hr = svc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __RELPATH FROM Msvm_VirtualSystemManagementService"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pSvcEnum);
		if (FAILED(hr) || !pSvcEnum)
		{
			SetLastErrorMsg(L"Failed to query Msvm_VirtualSystemManagementService.");
			if (pSvcEnum) pSvcEnum->Release();
			return false;
		}

		IWbemClassObject* pSvcObj = nullptr;
		ULONG uRet = 0;
		hr = pSvcEnum->Next(WBEM_INFINITE, 1, &pSvcObj, &uRet);
		pSvcEnum->Release();
		if (hr != S_OK || uRet == 0 || !pSvcObj)
		{
			SetLastErrorMsg(L"Could not retrieve Msvm_VirtualSystemManagementService.");
			if (pSvcObj) pSvcObj->Release();
			return false;
		}

		wstring svcRelPath;
		(void)GetBstrProp(pSvcObj, L"__RELPATH", svcRelPath);
		pSvcObj->Release();
		if (svcRelPath.empty())
		{
			SetLastErrorMsg(L"Missing service instance path for Msvm_VirtualSystemManagementService.");
			return false;
		}

		// Prepare in-params for ModifyResourceSettings(ResourceSettings: string[])
		IWbemClassObject* pSvcClass = nullptr;
		hr = svc->GetObject(_bstr_t(L"Msvm_VirtualSystemManagementService"), 0, nullptr, &pSvcClass, nullptr);
		if (FAILED(hr) || !pSvcClass)
		{
			SetLastErrorMsg(L"Failed to get Msvm_VirtualSystemManagementService class.");
			if (pSvcClass) pSvcClass->Release();
			return false;
		}

		IWbemClassObject* pInDef = nullptr;
		hr = pSvcClass->GetMethod(_bstr_t(L"ModifyResourceSettings"), 0, &pInDef, nullptr);
		if (FAILED(hr) || !pInDef)
		{
			pSvcClass->Release();
			SetLastErrorMsg(L"Failed to get ModifyResourceSettings method definition.");
			if (pInDef) pInDef->Release();
			return false;
		}

		IWbemClassObject* pIn = nullptr;
		hr = pInDef->SpawnInstance(0, &pIn);
		pInDef->Release();
		pSvcClass->Release();
		if (FAILED(hr) || !pIn)
		{
			SetLastErrorMsg(L"Failed to spawn ModifyResourceSettings input instance.");
			if (pIn) pIn->Release();
			return false;
		}

		// Build SAFEARRAY of BSTR (1 element) for ResourceSettings
		SAFEARRAY* psa = nullptr;
		{
			vector<wstring> arr{ xml };
			HRESULT hrSa = CreateSafeArrayOfBSTR(arr, &psa);
			if (FAILED(hrSa) || !psa)
			{
				pIn->Release();
				SetLastErrorMsg(L"Failed to build SAFEARRAY for ResourceSettings.");
				return false;
			}
		}

		VARIANT vArr; VariantInit(&vArr);
		vArr.vt = VT_ARRAY | VT_BSTR;
		vArr.parray = psa;

		hr = pIn->Put(_bstr_t(L"ResourceSettings"), 0, &vArr, 0);
		if (FAILED(hr))
		{
			VariantClear(&vArr); // also destroys psa
			pIn->Release();
			SetLastErrorMsg(L"Failed to set ResourceSettings input parameter.");
			return false;
		}
		// Keep array alive through ExecMethod; VariantClear after.

		// Execute method
		IWbemClassObject* pOut = nullptr;
		hr = svc->ExecMethod(_bstr_t(svcRelPath.c_str()), _bstr_t(L"ModifyResourceSettings"), 0, nullptr, pIn, &pOut, nullptr);

		VariantClear(&vArr); // free array
		pIn->Release();

		if (FAILED(hr) || !pOut)
		{
			SetLastErrorMsg(L"ExecMethod ModifyResourceSettings failed.");
			if (pOut) pOut->Release();
			return false;
		}

		// Evaluate ReturnValue / Job
		LONG rv = -1;
		(void)GetLongProp(pOut, L"ReturnValue", rv);

		// Job path if any
		wstring jobPath;
		(void)GetBstrProp(pOut, L"Job", jobPath);
		pOut->Release();

		if (rv == 0)
		{
			wstringstream ss;
			ss << L"Success (sync): ExposeVirtualizationExtensions set to " << (enable ? L"true" : L"false")
				<< L" for '" << vmName << L"'.";
			LogOut(ss.str().c_str());
			return true;
		}
		else if (rv == 4096)
		{
			if (jobPath.empty())
			{
				SetLastErrorMsg(L"ModifyResourceSettings returned 4096 but no Job path.");
				return false;
			}
			if (!WaitConcreteJob(svc, jobPath))
			{
				// Last error already set by waiter
				return false;
			}
			wstringstream ss;
			ss << L"Success (job): ExposeVirtualizationExtensions set to " << (enable ? L"true" : L"false")
				<< L" for '" << vmName << L"'.";
			LogOut(ss.str().c_str());
			return true;
		}
		else
		{
			wstringstream ss;
			ss << L"ModifyResourceSettings failed for '" << vmName << L"' with ReturnValue=" << rv << L".";
			SetLastErrorMsg(ss.str());
			return false;
		}
	}

	[[nodiscard]] bool SetExposeVirtualizationExtensions_ByName(const wstring& vmName, bool enable)
	{
		ClearLastErrorMsg();

		// Connect to root\virtualization\v2
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(L"root\\virtualization\\v2", &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false; // error already set
		}

		// Query VMs
		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __RELPATH, ElementName, EnabledState FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for Msvm_ComputerSystem failed.");
			if (pEnum) pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		bool found = false;
		bool ok = false;

		for (;;)
		{
			IWbemClassObject* pVm = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pVm, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pVm)
				break;

			wstring name;
			(void)GetBstrProp(pVm, L"ElementName", name);
			if (!name.empty() && EqualsOrdinalIgnoreCase(name.c_str(), vmName.c_str()))
			{
				found = true;
				ok = SetExposeForVmObject(pSvc, pVm, enable);
				pVm->Release();
				break;
			}

			pVm->Release();
		}

		pEnum->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (!found)
		{
			wstringstream ss;
			ss << L"No VM found with name '" << vmName << L"'.";
			SetLastErrorMsg(ss.str());
			return false;
		}

		return ok;
	}

	[[nodiscard]] bool SetExposeVirtualizationExtensions_All(bool enable)
	{
		ClearLastErrorMsg();

		// Connect to root\virtualization\\v2
		IWbemLocator* pLoc = nullptr;
		IWbemServices* pSvc = nullptr;
		bool didInitCOM = false;
		if (!ConnectToWmiNamespace(L"root\\virtualization\\v2", &pLoc, &pSvc, didInitCOM) || !pSvc)
		{
			if (pLoc) pLoc->Release();
			if (pSvc) pSvc->Release();
			return false; // error already set
		}

		// Query VMs
		IEnumWbemClassObject* pEnum = nullptr;
		HRESULT hr = pSvc->ExecQuery(
			_bstr_t(L"WQL"),
			_bstr_t(L"SELECT __RELPATH, ElementName, EnabledState FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'"),
			WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
			nullptr,
			&pEnum);
		if (FAILED(hr) || !pEnum)
		{
			SetLastErrorMsg(L"ExecQuery for Msvm_ComputerSystem failed.");
			if (pEnum) pEnum->Release();
			pSvc->Release();
			pLoc->Release();
			if (!g_skipCOMInit && didInitCOM) CoUninitialize();
			return false;
		}

		bool any = false;
		size_t successCount = 0;
		size_t failCount = 0;

		for (;;)
		{
			IWbemClassObject* pVm = nullptr;
			ULONG uRet = 0;
			HRESULT hrNext = pEnum->Next(WBEM_INFINITE, 1, &pVm, &uRet);
			if (hrNext != S_OK || uRet == 0 || !pVm)
				break;

			any = true;

			bool oneOk = SetExposeForVmObject(pSvc, pVm, enable);
			if (oneOk) ++successCount;
			else
			{
				// Log per-VM error using the global error buffer to avoid cross-TU linkage on GetLastErrorMessage.
				wstring name; (void)GetBstrProp(pVm, L"ElementName", name);
				if (!name.empty())
					LogErr(L"[Virtualization] Failed to set ExposeVirtualizationExtensions for VM '", name.c_str(), L"': ", g_lastErrorMsg.c_str());
				else
					LogErr(L"[Virtualization] Failed to set ExposeVirtualizationExtensions for a VM: ", g_lastErrorMsg.c_str());
				++failCount;
			}

			pVm->Release();
		}

		pEnum->Release();
		pSvc->Release();
		pLoc->Release();
		if (!g_skipCOMInit && didInitCOM) CoUninitialize();

		if (!any)
		{
			SetLastErrorMsg(L"No Hyper-V virtual machines were found.");
			return false;
		}

		if (failCount == 0)
		{
			wstringstream ss;
			ss << L"Successfully set ExposeVirtualizationExtensions to " << (enable ? L"true" : L"false")
				<< L" for " << successCount << L" VM(s).";
			LogOut(ss.str().c_str());
			return true;
		}
		else
		{
			wstringstream ss;
			ss << L"Set operation completed with failures. Succeeded: " << successCount << L", Failed: " << failCount << L".";
			SetLastErrorMsg(ss.str());
			LogErr(ss.str().c_str());
			return false;
		}
	}
}
