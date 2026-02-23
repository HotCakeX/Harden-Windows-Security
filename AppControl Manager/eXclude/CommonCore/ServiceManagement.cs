// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CommonCore;

internal sealed class ServiceItem(
	string serviceName, string displayName, string description, string currentState,
	uint processID, string exitCodes, string controlsAccepted, string serviceFlags,
	string serviceType, string startType, string errorControl, string runAsAccount,
	string dependencies, string serviceSidType, string launchProtected, uint preShutdownTimeout,
	string requiredPrivileges, string failureActions, string triggers, string rawPath,
	string cleanPath, string peCompany, string peProduct, string peDescription,
	string peVersion, string peComments, string peInternalName, string peLegalCopyright,
	string peLegalTrademarks, string peOriginalFilename, string pePrivateBuild, string peSpecialBuild,
	string peProductVersion, bool hasPeInfo, uint rawStartType, bool isDelayedAutoStart,
	uint rawServiceType, uint rawErrorControl, uint rawLaunchProtected, string serviceGroup)
{
	internal string ServiceName => serviceName;
	internal string DisplayName => displayName;
	internal string Description => description;

	internal string CurrentState => currentState;
	internal uint ProcessId => processID;
	internal string ExitCodes => exitCodes;
	internal string ControlsAccepted => controlsAccepted;
	internal string ServiceFlags => serviceFlags;

	internal string ServiceType => serviceType;
	internal string StartType => startType;
	internal string ErrorControl => errorControl;
	internal string RunAsAccount => runAsAccount;
	internal string Dependencies => dependencies;
	internal string ServiceSidType => serviceSidType;
	internal string LaunchProtected => launchProtected;
	internal uint PreShutdownTimeout => preShutdownTimeout;
	internal string RequiredPrivileges => requiredPrivileges;

	internal string FailureActions => failureActions;
	internal string Triggers => triggers;

	internal string RawPath => rawPath;
	internal string CleanPath => cleanPath;

	internal string PeCompany => peCompany;
	internal string PeProduct => peProduct;
	internal string PeDescription => peDescription;
	internal string PeVersion => peVersion;
	internal string PeComments => peComments;
	internal string PeInternalName => peInternalName;
	internal string PeLegalCopyright => peLegalCopyright;
	internal string PeLegalTrademarks => peLegalTrademarks;
	internal string PeOriginalFilename => peOriginalFilename;
	internal string PePrivateBuild => pePrivateBuild;
	internal string PeSpecialBuild => peSpecialBuild;
	internal string PeProductVersion => peProductVersion;
	internal bool HasPeInfo => hasPeInfo;
	internal string ServiceGroup => serviceGroup;

	// Raw configurations specifically for accurate UI ComboBox tracking and application.
	internal uint RawStartType => rawStartType;
	internal bool IsDelayedAutoStart => isDelayedAutoStart;
	internal uint RawServiceType => rawServiceType;
	internal uint RawErrorControl => rawErrorControl;
	internal uint RawLaunchProtected => rawLaunchProtected;
}

internal unsafe static class ServiceManagement
{
	private struct PeVersionDetails
	{
		internal string FileVersion;
		internal string FileDescription;
		internal string CompanyName;
		internal string ProductName;
		internal string Comments;
		internal string InternalName;
		internal string LegalCopyright;
		internal string LegalTrademarks;
		internal string OriginalFilename;
		internal string PrivateBuild;
		internal string SpecialBuild;
		internal string ProductVersion;
		internal bool Success;
	}

	private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
	private const uint SERVICE_QUERY_CONFIG = 0x0001;
	private const uint SERVICE_TYPE_ALL = 0x0000003F;
	private const uint SERVICE_STATE_ALL = 0x00000003;
	private const int SC_ENUM_PROCESS_INFO = 0;
	private const uint SERVICE_CONFIG_DESCRIPTION = 1;
	private const uint SERVICE_CONFIG_FAILURE_ACTIONS = 2;
	private const uint SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 3;
	private const uint SERVICE_CONFIG_SERVICE_SID_INFO = 5;
	private const uint SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO = 6;
	private const uint SERVICE_CONFIG_PRESHUTDOWN_INFO = 7;
	private const uint SERVICE_CONFIG_TRIGGER_INFO = 8;
	private const uint SERVICE_CONFIG_LAUNCH_PROTECTED = 12;
	private const int ERROR_MORE_DATA = 234;
	private const int ERROR_INSUFFICIENT_BUFFER = 122;

	internal static List<ServiceItem> GetAllServices()
	{
		List<ServiceItem> servicesList = [];
		IntPtr scManager = NativeMethods.OpenSCManagerW(null, null, SC_MANAGER_ALL_ACCESS);
		if (scManager == IntPtr.Zero)
		{
			throw new System.ComponentModel.Win32Exception(Marshal.GetLastPInvokeError(), "Failed to open Service Control Manager.");
		}

		try
		{
			uint resumeHandle = 0;
			int enumResult = NativeMethods.EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, IntPtr.Zero, 0, out uint bytesNeeded, out uint servicesReturned, ref resumeHandle, null);

			int lastError = Marshal.GetLastPInvokeError();

			// If it fails with an error other than ERROR_MORE_DATA, it's a genuine API failure
			if (enumResult == 0 && lastError != ERROR_MORE_DATA)
			{
				throw new System.ComponentModel.Win32Exception(lastError, "Failed to query service status size.");
			}

			bool moreData = enumResult == 0 && lastError == ERROR_MORE_DATA && bytesNeeded > 0;

			while (moreData)
			{
				IntPtr serviceBuffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
				try
				{
					enumResult = NativeMethods.EnumServicesStatusExW(scManager, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL, serviceBuffer, bytesNeeded, out bytesNeeded, out servicesReturned, ref resumeHandle, null);
					lastError = Marshal.GetLastPInvokeError();

					if (enumResult != 0 || lastError == ERROR_MORE_DATA)
					{
						ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)serviceBuffer;

						for (uint i = 0; i < servicesReturned; i++)
						{
							string serviceName = new(services[i].lpServiceName);
							string displayName = new(services[i].lpDisplayName);
							SERVICE_STATUS_PROCESS status = services[i].ServiceStatusProcess;

							ServiceItem? item = ProcessService(scManager, serviceName, displayName, status);
							if (item is not null)
							{
								servicesList.Add(item);
							}
						}
					}
					else
					{
						// Genuine failure during the buffer read process
						throw new System.ComponentModel.Win32Exception(lastError, "Failed to enumerate services during buffer read.");
					}

					moreData = enumResult == 0 && lastError == ERROR_MORE_DATA && bytesNeeded > 0;
				}
				finally
				{
					NativeMemory.Free((void*)serviceBuffer);
				}
			}
		}
		finally { _ = NativeMethods.CloseServiceHandle(scManager); }

		return servicesList;
	}

	internal static ServiceItem? ProcessService(IntPtr scManager, string serviceName, string displayName, SERVICE_STATUS_PROCESS status)
	{
		IntPtr hService = NativeMethods.OpenServiceW(scManager, serviceName, SERVICE_QUERY_CONFIG);
		if (hService == IntPtr.Zero) return null;

		try
		{
			int configResult = NativeMethods.QueryServiceConfigW(hService, IntPtr.Zero, 0, out uint bytesNeeded);

			if (configResult == 0 && Marshal.GetLastPInvokeError() == ERROR_INSUFFICIENT_BUFFER && bytesNeeded > 0)
			{
				IntPtr configBuffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
				try
				{
					if (NativeMethods.QueryServiceConfigW(hService, configBuffer, bytesNeeded, out bytesNeeded) != 0)
					{
						QUERY_SERVICE_CONFIGW* config = (QUERY_SERVICE_CONFIGW*)configBuffer;

						// Base config
						string rawPath = config->lpBinaryPathName != null ? new string(config->lpBinaryPathName) : string.Empty;
						string startName = config->lpServiceStartName != null ? new string(config->lpServiceStartName) : "LocalSystem";
						string serviceGroup = config->lpLoadOrderGroup != null ? new string(config->lpLoadOrderGroup) : string.Empty;
						string[] dependencies = ParseDoubleNullTerminatedString(config->lpDependencies);

						// Extended configs via QueryServiceConfig2W
						string description = GetServiceDescription(hService);
						bool isDelayedAutoStart = GetServiceDelayedAutoStart(hService);
						string[] privileges = GetRequiredPrivileges(hService);
						uint sidType = GetServiceSidType(hService);
						uint launchProtected = GetLaunchProtected(hService);
						uint preShutdown = GetPreshutdownTimeout(hService);
						List<string> failureActions = GetFailureActions(hService);
						List<string> triggers = GetTriggers(hService);

						string cleanPath = string.IsNullOrWhiteSpace(rawPath) ? string.Empty : NormalizeServicePath(rawPath);
						PeVersionDetails details = string.IsNullOrWhiteSpace(cleanPath) ? new PeVersionDetails() : GetVersionDetails(cleanPath);

						return new ServiceItem
						(
							serviceName: serviceName,
							displayName: displayName,
							description: string.IsNullOrWhiteSpace(description) ? "None" : description,
							currentState: GetStateName(status.dwCurrentState),
							processID: status.dwProcessId,
							exitCodes: $"Win32: {status.dwWin32ExitCode}, Specific: {status.dwServiceSpecificExitCode}",
							controlsAccepted: GetControlsAcceptedNames(status.dwControlsAccepted),
							serviceFlags: GetServiceFlagsName(status.dwServiceFlags),
							serviceType: GetServiceTypeNames(config->dwServiceType),
							startType: GetStartTypeName(config->dwStartType, isDelayedAutoStart),
							errorControl: GetErrorControlName(config->dwErrorControl),
							runAsAccount: startName,
							dependencies: dependencies.Length > 0 ? string.Join(", ", dependencies) : "None",
							serviceSidType: GetSidTypeName(sidType),
							launchProtected: GetLaunchProtectedName(launchProtected),
							preShutdownTimeout: preShutdown,
							requiredPrivileges: privileges.Length > 0 ? string.Join(", ", privileges) : "None (All or Default)",
							failureActions: failureActions.Count > 0 ? string.Join(" -> ", failureActions) : "None",
							triggers: triggers.Count > 0 ? string.Join(" | ", triggers) : "None",
							rawPath: rawPath,
							cleanPath: cleanPath,
							peCompany: details.CompanyName ?? string.Empty,
							peProduct: details.ProductName ?? string.Empty,
							peDescription: details.FileDescription ?? string.Empty,
							peVersion: details.FileVersion ?? string.Empty,
							peComments: details.Comments ?? string.Empty,
							peInternalName: details.InternalName ?? string.Empty,
							peLegalCopyright: details.LegalCopyright ?? string.Empty,
							peLegalTrademarks: details.LegalTrademarks ?? string.Empty,
							peOriginalFilename: details.OriginalFilename ?? string.Empty,
							pePrivateBuild: details.PrivateBuild ?? string.Empty,
							peSpecialBuild: details.SpecialBuild ?? string.Empty,
							peProductVersion: details.ProductVersion ?? string.Empty,
							hasPeInfo: details.Success,
							rawStartType: config->dwStartType,
							isDelayedAutoStart: isDelayedAutoStart,
							rawServiceType: config->dwServiceType,
							rawErrorControl: config->dwErrorControl,
							rawLaunchProtected: launchProtected,
							serviceGroup: string.IsNullOrWhiteSpace(serviceGroup) ? "None" : serviceGroup
						);
					}
				}
				finally { NativeMemory.Free((void*)configBuffer); }
			}
		}
		finally { _ = NativeMethods.CloseServiceHandle(hService); }

		return null;
	}

	internal static string GetServiceDescription(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_DESCRIPTION, buffer, bytesNeeded, out _) != 0)
				{
					SERVICE_DESCRIPTIONW* desc = (SERVICE_DESCRIPTIONW*)buffer;
					if (desc->lpDescription != null) return new string(desc->lpDescription);
				}
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return string.Empty;
	}

	internal static bool GetServiceDelayedAutoStart(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, buffer, bytesNeeded, out _) != 0)
					return ((SERVICE_DELAYED_AUTO_START_INFO*)buffer)->fDelayedAutostart != 0;
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return false;
	}

	internal static string[] GetRequiredPrivileges(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, buffer, bytesNeeded, out _) != 0)
				{
					SERVICE_REQUIRED_PRIVILEGES_INFOW* privs = (SERVICE_REQUIRED_PRIVILEGES_INFOW*)buffer;
					return ParseDoubleNullTerminatedString(privs->pmszRequiredPrivileges);
				}
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return [];
	}

	internal static uint GetServiceSidType(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_SERVICE_SID_INFO, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_SERVICE_SID_INFO, buffer, bytesNeeded, out _) != 0)
					return ((SERVICE_SID_INFO*)buffer)->dwServiceSidType;
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return 0;
	}

	internal static uint GetLaunchProtected(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, buffer, bytesNeeded, out _) != 0)
					return ((SERVICE_LAUNCH_PROTECTED_INFO*)buffer)->dwLaunchProtected;
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return 0;
	}

	internal static uint GetPreshutdownTimeout(IntPtr hService)
	{
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_PRESHUTDOWN_INFO, buffer, bytesNeeded, out _) != 0)
					return ((SERVICE_PRESHUTDOWN_INFO*)buffer)->dwPreshutdownTimeout;
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return 0;
	}

	internal static List<string> GetFailureActions(IntPtr hService)
	{
		List<string> actions = [];
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_FAILURE_ACTIONS, buffer, bytesNeeded, out _) != 0)
				{
					SERVICE_FAILURE_ACTIONSW* failure = (SERVICE_FAILURE_ACTIONSW*)buffer;

					if (failure->lpsaActions != null)
					{
						for (uint i = 0; i < failure->cActions; i++)
						{
							SC_ACTION action = failure->lpsaActions[i];

							// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-sc_action#members
							string typeName = action.Type switch
							{
								0 => "None",
								1 => "Restart",
								2 => "Reboot",
								3 => "RunCommand",
								_ => "Unknown"
							};
							actions.Add($"{typeName} ({action.Delay}ms)");
						}
					}
				}
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return actions;
	}

	internal static List<string> GetTriggers(IntPtr hService)
	{
		List<string> triggerList = [];
		if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_TRIGGER_INFO, IntPtr.Zero, 0, out uint bytesNeeded) == 0 && bytesNeeded > 0)
		{
			IntPtr buffer = (IntPtr)NativeMemory.Alloc(bytesNeeded);
			try
			{
				if (NativeMethods.QueryServiceConfig2W(hService, SERVICE_CONFIG_TRIGGER_INFO, buffer, bytesNeeded, out _) != 0)
				{
					SERVICE_TRIGGER_INFO* info = (SERVICE_TRIGGER_INFO*)buffer;

					if (info->pTriggers != null)
					{
						for (uint i = 0; i < info->cTriggers; i++)
						{
							SERVICE_TRIGGER trigger = info->pTriggers[i];
							string action = trigger.dwAction == 1 ? "Start" : trigger.dwAction == 2 ? "Stop" : "Unknown Action";

							// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_trigger#members
							string type = trigger.dwTriggerType switch
							{
								1 => "Device Interface Arrival",
								2 => "IP Address",
								3 => "Domain Join",
								4 => "Firewall Port Event",
								5 => "Group Policy",
								6 => "Network Endpoint",
								20 => "Custom",
								_ => $"Type {trigger.dwTriggerType}"
							};
							triggerList.Add($"[{action} on {type}]");
						}
					}
				}
			}
			finally { NativeMemory.Free((void*)buffer); }
		}
		return triggerList;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process
	internal static string GetStateName(uint state) => state switch
	{
		1 => "Stopped",
		2 => "Start Pending",
		3 => "Stop Pending",
		4 => "Running",
		5 => "Continue Pending",
		6 => "Pause Pending",
		7 => "Paused",
		_ => $"Unknown ({state})"
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info
	internal static string GetSidTypeName(uint sidType) => sidType switch
	{
		0 => "None",
		1 => "Unrestricted",
		3 => "Restricted",
		_ => $"Unknown ({sidType})"
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_launch_protected_info
	internal static string GetLaunchProtectedName(uint lp) => lp switch
	{
		0 => "None",
		1 => "Windows",
		2 => "Windows Light",
		3 => "Antimalware Light",
		_ => $"Unknown ({lp})"
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status
	internal static string GetControlsAcceptedNames(uint controls)
	{
		List<string> accepted = [];
		if ((controls & 0x1) != 0) accepted.Add("Stop");
		if ((controls & 0x2) != 0) accepted.Add("Pause/Continue");
		if ((controls & 0x4) != 0) accepted.Add("Shutdown");
		if ((controls & 0x8) != 0) accepted.Add("Param Change");
		if ((controls & 0x10) != 0) accepted.Add("Netbind Change");
		if ((controls & 0x20) != 0) accepted.Add("Hardware Profile Change");
		if ((controls & 0x40) != 0) accepted.Add("Power Event");
		if ((controls & 0x80) != 0) accepted.Add("Session Change");
		if ((controls & 0x100) != 0) accepted.Add("Pre-shutdown");
		if ((controls & 0x200) != 0) accepted.Add("Time Change");
		if ((controls & 0x400) != 0) accepted.Add("Trigger Event");
		if ((controls & 0x800) != 0) accepted.Add("User Log Off");
		if ((controls & 0x2000) != 0) accepted.Add("Low Resources");
		if ((controls & 0x4000) != 0) accepted.Add("System Low Resources");
		return accepted.Count > 0 ? string.Join(", ", accepted) : "None";
	}

	internal static string GetServiceFlagsName(uint flags) => (flags & 0x1) != 0 ? "Runs in shared process" : "Standalone process";

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew
	internal static string GetServiceTypeNames(uint serviceType)
	{
		List<string> types = [];
		if ((serviceType & 0x1) != 0) types.Add("Kernel Driver");
		if ((serviceType & 0x2) != 0) types.Add("File System Driver");
		if ((serviceType & 0x10) != 0) types.Add("Win32 Own Process");
		if ((serviceType & 0x20) != 0) types.Add("Win32 Share Process");
		if ((serviceType & 0x40) != 0) types.Add("User Service");
		if ((serviceType & 0x80) != 0) types.Add("User Service Instance");
		if ((serviceType & 0x100) != 0) types.Add("Interactive Process");
		return types.Count > 0 ? string.Join(" | ", types) : $"Unknown (0x{serviceType:X})";
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew
	internal static string GetStartTypeName(uint startType, bool isDelayed)
	{
		string baseName = startType switch
		{
			0 => "Boot Start",
			1 => "System Start",
			2 => "Auto Start",
			3 => "Demand / Manual",
			4 => "Disabled",
			_ => "Unknown"
		};
		return (startType == 2 && isDelayed) ? baseName + " [Delayed]" : baseName;
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew
	internal static string GetErrorControlName(uint errorControl) => errorControl switch
	{
		0 => "Ignore",
		1 => "Normal",
		2 => "Severe",
		3 => "Critical",
		_ => "Unknown"
	};

	internal static string[] ParseDoubleNullTerminatedString(char* ptr)
	{
		if (ptr == null) return [];
		List<string> list = [];
		char* current = ptr;
		while (*current != '\0')
		{
			string s = new(current);
			list.Add(s);
			current += s.Length + 1;
		}
		return list.ToArray();
	}

	private static readonly string[] extensions = [".exe ", ".sys ", ".dll "];

	internal static string NormalizeServicePath(string rawPath)
	{
		string path = rawPath.Trim();
		if (string.IsNullOrWhiteSpace(path)) return string.Empty;

		if (path.StartsWith('"'))
		{
			int endQuote = path.IndexOf('"', 1);
			if (endQuote > 0) path = path[1..endQuote];
		}
		else
		{
			foreach (string ext in extensions)
			{
				int extIndex = path.IndexOf(ext, StringComparison.OrdinalIgnoreCase);
				if (extIndex > 0) { path = path[..(extIndex + ext.Length - 1)]; break; }
			}
		}

		if (path.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase)) path = path[4..];
		if (path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
			path = string.Concat(Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows", "\\", path.AsSpan(12));
		if (path.StartsWith(@"System32\", StringComparison.OrdinalIgnoreCase))
			path = (Environment.GetEnvironmentVariable("SystemRoot") ?? @"C:\Windows") + "\\" + path;

		uint expandedSize = NativeMethods.ExpandEnvironmentStringsW(path, IntPtr.Zero, 0);
		if (expandedSize > 0)
		{
			IntPtr expandBuffer = (IntPtr)NativeMemory.Alloc(expandedSize * 2);
			try
			{
				if (NativeMethods.ExpandEnvironmentStringsW(path, expandBuffer, expandedSize) > 0) path = new string((char*)expandBuffer);
			}
			finally { NativeMemory.Free((void*)expandBuffer); }
		}
		return path.Trim();
	}

	private static PeVersionDetails GetVersionDetails(string filePath)
	{
		PeVersionDetails details = new()
		{
			Success = false,
			FileVersion = string.Empty,
			FileDescription = string.Empty,
			CompanyName = string.Empty,
			ProductName = string.Empty,
			Comments = string.Empty,
			InternalName = string.Empty,
			LegalCopyright = string.Empty,
			LegalTrademarks = string.Empty,
			OriginalFilename = string.Empty,
			PrivateBuild = string.Empty,
			SpecialBuild = string.Empty,
			ProductVersion = string.Empty
		};

		uint size = NativeMethods.GetFileVersionInfoSizeW(filePath, out uint dwHandle);
		if (size == 0) return details;

		IntPtr buffer = (IntPtr)NativeMemory.Alloc(size);
		try
		{
			if (NativeMethods.GetFileVersionInfoW(filePath, dwHandle, size, buffer) == 0) return details;

			string hex = string.Empty;
			if (NativeMethods.VerQueryValueW(buffer, @"\VarFileInfo\Translation", out IntPtr transBuffer, out uint len) != 0 && len >= (uint)sizeof(LANGANDCODEPAGE))
			{
				LANGANDCODEPAGE* trans = (LANGANDCODEPAGE*)transBuffer;
				hex = $"{trans[0].wLanguage:X4}{trans[0].wCodePage:X4}";
			}

			string[] fallbacks = hex.Length > 0 ? [hex, "040904B0", "040904E4", "04090000"] : ["040904B0", "040904E4", "04090000"];
			string validHex = string.Empty;

			foreach (string tHex in fallbacks)
			{
				string testVersion = GetStringFileInfo(buffer, tHex, "FileVersion");
				string testDesc = GetStringFileInfo(buffer, tHex, "FileDescription");
				string testProd = GetStringFileInfo(buffer, tHex, "ProductName");

				// Check multiple properties to see if PE data exists
				if (!string.IsNullOrEmpty(testVersion) || !string.IsNullOrEmpty(testDesc) || !string.IsNullOrEmpty(testProd))
				{
					validHex = tHex;
					break;
				}
			}

			if (!string.IsNullOrEmpty(validHex))
			{
				details.FileVersion = GetStringFileInfo(buffer, validHex, "FileVersion");
				details.FileDescription = GetStringFileInfo(buffer, validHex, "FileDescription");
				details.CompanyName = GetStringFileInfo(buffer, validHex, "CompanyName");
				details.ProductName = GetStringFileInfo(buffer, validHex, "ProductName");
				details.Comments = GetStringFileInfo(buffer, validHex, "Comments");
				details.InternalName = GetStringFileInfo(buffer, validHex, "InternalName");
				details.LegalCopyright = GetStringFileInfo(buffer, validHex, "LegalCopyright");
				details.LegalTrademarks = GetStringFileInfo(buffer, validHex, "LegalTrademarks");
				details.OriginalFilename = GetStringFileInfo(buffer, validHex, "OriginalFilename");
				details.PrivateBuild = GetStringFileInfo(buffer, validHex, "PrivateBuild");
				details.SpecialBuild = GetStringFileInfo(buffer, validHex, "SpecialBuild");
				details.ProductVersion = GetStringFileInfo(buffer, validHex, "ProductVersion");
				details.Success = true;
			}
		}
		finally { NativeMemory.Free((void*)buffer); }

		return details;
	}

	internal static string GetStringFileInfo(IntPtr pBlock, string hex, string prop)
	{
		if (NativeMethods.VerQueryValueW(pBlock, $@"\StringFileInfo\{hex}\{prop}", out nint stringBuffer, out uint stringLength) != 0 && stringLength > 0 && stringBuffer != IntPtr.Zero)
			return new string((char*)stringBuffer);
		return string.Empty;
	}
}
