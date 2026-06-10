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
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CommonCore.Others;

internal static class AppContainerLoopbackManager
{
	private static readonly StringComparer SidComparer = StringComparer.OrdinalIgnoreCase;
	private static readonly StringComparer AppContainerNameComparer = StringComparer.OrdinalIgnoreCase;

	private enum NETISO_FLAG : uint
	{
		MAX = 0x2
	}

	private sealed class AppContainerInfo(string name, string displayName, string sid)
	{
		internal string Name => name;
		internal string DisplayName => displayName;
		internal string Sid => sid;
	}

	private sealed class AppContainerInventory(
		Dictionary<string, AppContainerInfo> byName,
		Dictionary<string, AppContainerInfo> bySid)
	{
		internal Dictionary<string, AppContainerInfo> ByName => byName;
		internal Dictionary<string, AppContainerInfo> BySid => bySid;
	}

	internal static void UpdatePackagedAppsLoopbackState(List<PackagedAppView> apps)
	{
		HashSet<string> exemptedSids = new(GetLoopbackExemptedSidStrings(), SidComparer);
		AppContainerInventory inventory = GetAppContainerInventory();

		foreach (PackagedAppView app in apps)
		{
			if (TryGetAppContainerInfo(app.PackageFamilyName, inventory, out AppContainerInfo? appContainerInfo) && appContainerInfo is not null)
			{
				bool isExempt = exemptedSids.Contains(appContainerInfo.Sid);
				app.SetLoopbackDetails(appContainerInfo.Sid, isExempt, isExempt ? Atlas.GetStr("LoopbackStatusExempt") : Atlas.GetStr("LoopbackStatusNotExempt"));
			}
			else
			{
				app.SetLoopbackDetails(string.Empty, false, Atlas.GetStr("LoopbackStatusUnavailable"));
			}
		}
	}

	internal static List<AppContainerLoopbackEntry> GetEntries(IEnumerable<PackagedAppView> installedApps)
	{
		HashSet<string> exemptedSids = new(GetLoopbackExemptedSidStrings(), SidComparer);
		AppContainerInventory inventory = GetAppContainerInventory();
		Dictionary<string, PackagedAppView> installedAppsByName = installedApps
			.Where(static app => !string.IsNullOrWhiteSpace(app.PackageFamilyName))
			.GroupBy(static app => app.PackageFamilyName, AppContainerNameComparer)
			.ToDictionary(static group => group.Key, static group => group.First(), AppContainerNameComparer);

		List<AppContainerLoopbackEntry> entries = new(exemptedSids.Count);
		foreach (string sid in exemptedSids.OrderBy(static currentSid => currentSid, StringComparer.OrdinalIgnoreCase))
		{
			if (inventory.BySid.TryGetValue(sid, out AppContainerInfo? appContainerInfo) && appContainerInfo is not null)
			{
				bool isInstalledApp = installedAppsByName.TryGetValue(appContainerInfo.Name, out PackagedAppView? installedApp);
				string displayName;
				string packageFamilyName;

				if (isInstalledApp && installedApp is not null)
				{
					displayName = installedApp.DisplayName;
					packageFamilyName = installedApp.PackageFamilyName;
				}
				else
				{
					displayName = string.IsNullOrWhiteSpace(appContainerInfo.DisplayName) ? appContainerInfo.Name : appContainerInfo.DisplayName;
					packageFamilyName = appContainerInfo.Name;
				}

				entries.Add(new(
					displayName: displayName,
					packageFamilyName: packageFamilyName,
					sid: sid,
					isInstalledApp: true,
					isExempt: true));
				continue;
			}

			entries.Add(new(
				displayName: Atlas.GetStr("LoopbackAppContainerNotFound"),
				packageFamilyName: string.Empty,
				sid: sid,
				isInstalledApp: false,
				isExempt: true));
		}

		return entries
			.OrderBy(static entry => entry.IsInstalledApp ? 0 : 1)
			.ThenBy(static entry => entry.DisplayName, StringComparer.CurrentCultureIgnoreCase)
			.ThenBy(static entry => entry.PackageFamilyName, StringComparer.OrdinalIgnoreCase)
			.ThenBy(static entry => entry.Sid, StringComparer.OrdinalIgnoreCase)
			.ToList();
	}

	internal static void SetLoopbackExemption(string sid, bool isExempt)
	{
		if (string.IsNullOrWhiteSpace(sid))
		{
			throw new InvalidOperationException(Atlas.GetStr("LoopbackStatusUnavailable"));
		}

		HashSet<string> exemptedSids = new(GetLoopbackExemptedSidStrings(), SidComparer);

		_ = isExempt ? exemptedSids.Add(sid) : exemptedSids.Remove(sid);

		SetLoopbackExemptedSidStrings(exemptedSids);
	}

	internal static void ClearLoopbackExemptions() => SetLoopbackExemptedSidStrings([]);

	/// <summary>
	/// Adds every resolvable installed app to the loopback exemption list and returns the number of newly added entries.
	/// </summary>
	internal static int AddLoopbackExemptions(IEnumerable<PackagedAppView> apps)
	{
		HashSet<string> exemptedSids = new(GetLoopbackExemptedSidStrings(), SidComparer);

		// Reuse a single native inventory snapshot so the bulk action does not repeatedly allocate native buffers.
		AppContainerInventory inventory = GetAppContainerInventory();
		int addedCount = 0;

		foreach (PackagedAppView app in apps)
		{
			if (!TryGetAppContainerInfo(app.PackageFamilyName, inventory, out AppContainerInfo? appContainerInfo) || appContainerInfo is null)
			{
				continue;
			}

			if (exemptedSids.Add(appContainerInfo.Sid))
			{
				addedCount++;
			}
		}

		if (addedCount > 0)
		{
			SetLoopbackExemptedSidStrings(exemptedSids);
		}

		return addedCount;
	}

	internal static bool TryDeriveAppContainerSidString(string? packageFamilyName, out string sidString)
	{
		sidString = string.Empty;

		if (string.IsNullOrWhiteSpace(packageFamilyName))
		{
			return false;
		}

		IntPtr sid = IntPtr.Zero;
		IntPtr stringSid = IntPtr.Zero;

		try
		{
			int result = NativeMethods.DeriveAppContainerSidFromAppContainerName(packageFamilyName, out sid);
			if (result != 0 || sid == IntPtr.Zero)
			{
				return false;
			}

			if (!NativeMethods.ConvertSidToStringSidW(sid, out stringSid) || stringSid == IntPtr.Zero)
			{
				return false;
			}

			sidString = Marshal.PtrToStringUni(stringSid) ?? string.Empty;
			return sidString.Length > 0;
		}
		finally
		{
			if (stringSid != IntPtr.Zero)
			{
				_ = NativeMethods.LocalFree(stringSid);
			}

			if (sid != IntPtr.Zero)
			{
				_ = NativeMethods.FreeSid(sid);
			}
		}
	}

	private static bool TryGetAppContainerInfo(string? packageFamilyName, AppContainerInventory inventory, out AppContainerInfo? appContainerInfo)
	{
		if (!string.IsNullOrWhiteSpace(packageFamilyName) && inventory.ByName.TryGetValue(packageFamilyName, out appContainerInfo))
		{
			return true;
		}

		if (!string.IsNullOrWhiteSpace(packageFamilyName) && TryDeriveAppContainerSidString(packageFamilyName, out string sid))
		{
			appContainerInfo = new(packageFamilyName, string.Empty, sid);
			return true;
		}

		appContainerInfo = null;
		return false;
	}

	private static unsafe AppContainerInventory GetAppContainerInventory()
	{
		uint result = NativeMethods.NetworkIsolationEnumAppContainers((uint)NETISO_FLAG.MAX, out uint count, out IntPtr appContainers);
		if (result != 0)
		{
			throw new Win32Exception(unchecked((int)result));
		}

		try
		{
			Dictionary<string, AppContainerInfo> byName = new(AppContainerNameComparer);
			Dictionary<string, AppContainerInfo> bySid = new(SidComparer);

			if (count == 0 || appContainers == IntPtr.Zero)
			{
				return new(byName, bySid);
			}

			int structSize = sizeof(INET_FIREWALL_APP_CONTAINER);
			for (int i = 0; i < count; i++)
			{
				INET_FIREWALL_APP_CONTAINER item = *(INET_FIREWALL_APP_CONTAINER*)IntPtr.Add(appContainers, i * structSize);
				string name = Marshal.PtrToStringUni(item.AppContainerName) ?? string.Empty;
				if (string.IsNullOrWhiteSpace(name))
				{
					continue;
				}

				string sid = ConvertSidToString(item.AppContainerSid);
				if (string.IsNullOrWhiteSpace(sid))
				{
					continue;
				}

				AppContainerInfo appContainerInfo = new(
					name,
					Marshal.PtrToStringUni(item.DisplayName) ?? string.Empty,
					sid);

				byName[name] = appContainerInfo;
				bySid[sid] = appContainerInfo;
			}

			return new(byName, bySid);
		}
		finally
		{
			if (appContainers != IntPtr.Zero)
			{
				NativeMethods.NetworkIsolationFreeAppContainers(appContainers);
			}
		}
	}

	private static string ConvertSidToString(IntPtr sid)
	{
		if (sid == IntPtr.Zero)
		{
			return string.Empty;
		}

		IntPtr stringSid = IntPtr.Zero;

		try
		{
			if (!NativeMethods.ConvertSidToStringSidW(sid, out stringSid) || stringSid == IntPtr.Zero)
			{
				return string.Empty;
			}

			return Marshal.PtrToStringUni(stringSid) ?? string.Empty;
		}
		finally
		{
			if (stringSid != IntPtr.Zero)
			{
				_ = NativeMethods.LocalFree(stringSid);
			}
		}
	}

	private static unsafe List<string> GetLoopbackExemptedSidStrings()
	{
		uint result = NativeMethods.NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr appContainerSids);
		if (result != 0)
		{
			throw new Win32Exception(unchecked((int)result));
		}

		try
		{
			List<string> sidStrings = [];
			if (count == 0 || appContainerSids == IntPtr.Zero)
			{
				return sidStrings;
			}

			int structSize = sizeof(SID_AND_ATTRIBUTES);
			for (int i = 0; i < count; i++)
			{
				SID_AND_ATTRIBUTES item = *(SID_AND_ATTRIBUTES*)IntPtr.Add(appContainerSids, i * structSize);
				if (item.Sid == IntPtr.Zero)
				{
					continue;
				}

				if (!NativeMethods.ConvertSidToStringSidW(item.Sid, out IntPtr stringSid) || stringSid == IntPtr.Zero)
				{
					throw new Win32Exception(Marshal.GetLastPInvokeError());
				}

				try
				{
					string? sid = Marshal.PtrToStringUni(stringSid);
					if (!string.IsNullOrWhiteSpace(sid))
					{
						sidStrings.Add(sid);
					}
				}
				finally
				{
					_ = NativeMethods.LocalFree(stringSid);
				}
			}

			return sidStrings;
		}
		finally
		{
			FreeAppContainerConfig(appContainerSids);
		}
	}

	private static void SetLoopbackExemptedSidStrings(IEnumerable<string> sidStrings)
	{
		string[] distinctSids = sidStrings
			.Where(static sid => !string.IsNullOrWhiteSpace(sid))
			.Distinct(SidComparer)
			.ToArray();

		List<IntPtr> allocatedSids = new(distinctSids.Length);
		SID_AND_ATTRIBUTES[] nativeEntries = new SID_AND_ATTRIBUTES[distinctSids.Length];

		try
		{
			if (distinctSids.Length == 0)
			{
				uint clearResult = NativeMethods.NetworkIsolationSetAppContainerConfig(0, IntPtr.Zero);
				if (clearResult != 0)
				{
					throw new Win32Exception(unchecked((int)clearResult));
				}

				return;
			}

			for (int i = 0; i < distinctSids.Length; i++)
			{
				if (!NativeMethods.ConvertStringSidToSidW(distinctSids[i], out IntPtr sid) || sid == IntPtr.Zero)
				{
					throw new Win32Exception(Marshal.GetLastPInvokeError());
				}

				allocatedSids.Add(sid);
				nativeEntries[i] = new SID_AND_ATTRIBUTES
				{
					Sid = sid,
					Attributes = 0
				};
			}

			uint result = NativeMethods.NetworkIsolationSetAppContainerConfig((uint)nativeEntries.Length, nativeEntries);
			if (result != 0)
			{
				throw new Win32Exception(unchecked((int)result));
			}
		}
		finally
		{
			foreach (IntPtr sid in allocatedSids)
			{
				if (sid != IntPtr.Zero)
				{
					_ = NativeMethods.LocalFree(sid);
				}
			}
		}
	}

	private static void FreeAppContainerConfig(IntPtr appContainerSids)
	{
		if (appContainerSids == IntPtr.Zero)
		{
			return;
		}

		_ = NativeMethods.LocalFree(appContainerSids);
	}
}

internal sealed partial class AppContainerLoopbackEntry(
	string displayName,
	string packageFamilyName,
	string sid,
	bool isInstalledApp,
	bool isExempt) : INPCImplant
{
	internal string DisplayName => displayName;
	internal string PackageFamilyName => packageFamilyName;
	internal string Sid => sid;
	internal bool IsInstalledApp => isInstalledApp;
	internal bool IsExempt
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				RaisePropertyChanged(nameof(StatusText));
				RaisePropertyChanged(nameof(ActionButtonText));
			}
		}
	} = isExempt;

	internal bool CanModify => IsExempt && !string.IsNullOrWhiteSpace(Sid);
	internal bool IsOrphanedEntry => !IsInstalledApp;
	internal string PackageFamilyNameOrPlaceholder => string.IsNullOrWhiteSpace(PackageFamilyName) ? Atlas.GetStr("LoopbackNoPackageFamilyName") : PackageFamilyName;
	internal string EntryTypeText => IsInstalledApp ? Atlas.GetStr("LoopbackInstalledAppEntryType") : Atlas.GetStr("LoopbackOrphanedEntryType");
	internal string StatusText => !CanModify ? Atlas.GetStr("LoopbackStatusUnavailable") : IsExempt ? Atlas.GetStr("LoopbackStatusExempt") : Atlas.GetStr("LoopbackStatusNotExempt");
	internal string ActionButtonText => !CanModify ? Atlas.GetStr("LoopbackUnavailableActionText") : IsInstalledApp ? Atlas.GetStr("LoopbackRemoveExemptionButtonText") : Atlas.GetStr("LoopbackRemoveEntryButtonText");

	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged([CallerMemberName] string? propertyName = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}
