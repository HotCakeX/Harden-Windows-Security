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
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace CommonCore.SecurityPolicy;

internal static class DataDump
{
	internal static async Task DumpSystemSecurityPoliciesData(string filePath)
	{
		await Task.Run(() =>
		{

			SystemAccessInfo systemAccess = SecurityPolicyReader.GetSystemAccess();
			Dictionary<string, string[]> privilegeRights = SecurityPolicyReader.GetPrivilegeRights();

			StringBuilder content = new();

			// Header
			_ = content.AppendLine("=".PadRight(80, '='));
			_ = content.AppendLine("SECURITY POLICY INFORMATION REPORT");
			_ = content.AppendLine("=".PadRight(80, '='));
			_ = content.AppendLine();

			_ = content.AppendLine("┌─ REPORT INFORMATION");
			_ = content.AppendLine($"│  Generated (Local): {DateTime.Now:yyyy-MM-dd HH:mm:ss} ({TimeZoneInfo.Local.DisplayName})");
			_ = content.AppendLine($"│  Generated (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
			_ = content.AppendLine("│  Report Format Version: 1.0");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// System Information
			_ = content.AppendLine("┌─ SYSTEM INFORMATION");
			_ = content.AppendLine($"│  Computer Name: {Environment.MachineName}");
			_ = content.AppendLine($"│  Domain/Workgroup: {GetDomainOrWorkgroup()}");
			_ = content.AppendLine($"│  Current User: {Environment.UserName}");
			_ = content.AppendLine($"│  User Domain: {Environment.UserDomainName}");
			_ = content.AppendLine($"│  User Is Administrator: {Atlas.IsElevated}");
			_ = content.AppendLine($"│  User SID: {GetCurrentUserSid()}");
			_ = content.AppendLine($"│  Interactive Session: {Environment.UserInteractive}");
			_ = content.AppendLine($"│  System Directory: {Environment.SystemDirectory}");
			_ = content.AppendLine($"│  Windows Directory: {Environment.GetFolderPath(Environment.SpecialFolder.Windows)}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Operating System Information
			_ = content.AppendLine("┌─ OPERATING SYSTEM");
			_ = content.AppendLine($"│  OS Version: {Environment.OSVersion}");
			_ = content.AppendLine($"│  OS Platform: {Environment.OSVersion.Platform}");
			_ = content.AppendLine($"│  OS Service Pack: {Environment.OSVersion.ServicePack}");
			_ = content.AppendLine($"│  Windows Version: {GetWindowsVersion()}");
			_ = content.AppendLine($"│  Windows Edition: {GetWindowsEdition()}");
			_ = content.AppendLine($"│  Windows Build: {GetWindowsBuild()}");
			_ = content.AppendLine($"│  Windows Update Build Revision: {GetWindowsUBR()}");
			_ = content.AppendLine($"│  System Architecture: {RuntimeInformation.OSArchitecture}");
			_ = content.AppendLine($"│  Process Architecture: {RuntimeInformation.ProcessArchitecture}");
			_ = content.AppendLine($"│  Is 64-bit OS: {Environment.Is64BitOperatingSystem}");
			_ = content.AppendLine($"│  Is 64-bit Process: {Environment.Is64BitProcess}");
			_ = content.AppendLine($"│  CLR Version: {Environment.Version}");
			_ = content.AppendLine($"│  .NET Framework: {RuntimeInformation.FrameworkDescription}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Hardware Information
			_ = content.AppendLine("┌─ HARDWARE INFORMATION");
			_ = content.AppendLine($"│  Processor Count: {Environment.ProcessorCount}");
			_ = content.AppendLine($"│  Processor Identifier: {GetProcessorIdentifier()}");
			_ = content.AppendLine($"│  Total Physical Memory: {GetTotalPhysicalMemory()}");
			_ = content.AppendLine($"│  Available Physical Memory: {GetAvailablePhysicalMemory()}");
			_ = content.AppendLine($"│  System Page Size: {Environment.SystemPageSize:N0} bytes");
			_ = content.AppendLine($"│  Working Set: {Environment.WorkingSet:N0} bytes");
			_ = content.AppendLine($"│  System Boot Time: {GetSystemBootTime()}");
			_ = content.AppendLine($"│  System Uptime: {GetSystemUptime()}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			using Process process = Process.GetCurrentProcess();

			// Security Context Information
			_ = content.AppendLine("┌─ SECURITY CONTEXT");
			_ = content.AppendLine($"│  Current Process ID: {Environment.ProcessId}");
			_ = content.AppendLine($"│  Process Name: {process.ProcessName}");
			_ = content.AppendLine($"│  Process Start Time: {process.StartTime:yyyy-MM-dd HH:mm:ss}");
			_ = content.AppendLine($"│  Elevated Process: {Atlas.IsElevated}");
			_ = content.AppendLine($"│  UAC Enabled: {IsUacEnabled()}");
			_ = content.AppendLine($"│  Current Culture: {CultureInfo.CurrentCulture.Name}");
			_ = content.AppendLine($"│  Current UI Culture: {CultureInfo.CurrentUICulture.Name}");
			_ = content.AppendLine($"│  Time Zone: {TimeZoneInfo.Local.Id}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// System Access Section
			_ = content.AppendLine("┌─ SYSTEM ACCESS POLICIES");
			_ = content.AppendLine("│");
			_ = content.AppendLine("│  Password Policies:");
			_ = content.AppendLine($"│    • Minimum Password Age: {systemAccess.MinimumPasswordAge} days");
			_ = content.AppendLine($"│    • Maximum Password Age: {systemAccess.MaximumPasswordAge} days");
			_ = content.AppendLine($"│    • Minimum Password Length: {systemAccess.MinimumPasswordLength} characters");
			_ = content.AppendLine($"│    • Password Complexity: {FormatBooleanValue(systemAccess.PasswordComplexity)}");
			_ = content.AppendLine($"│    • Password History Size: {systemAccess.PasswordHistorySize} passwords");
			_ = content.AppendLine($"│    • Clear Text Password: {FormatBooleanValue(systemAccess.ClearTextPassword)}");
			_ = content.AppendLine("│");
			_ = content.AppendLine("│  Account Lockout Policies:");
			_ = content.AppendLine($"│    • Lockout Bad Count: {systemAccess.LockoutBadCount} attempts");
			_ = content.AppendLine($"│    • Reset Lockout Count: {systemAccess.ResetLockoutCount} minutes");
			_ = content.AppendLine($"│    • Lockout Duration: {systemAccess.LockoutDuration} minutes");
			_ = content.AppendLine($"│    • Allow Administrator Lockout: {FormatBooleanValue(systemAccess.AllowAdministratorLockout)}");
			_ = content.AppendLine("│");
			_ = content.AppendLine("│  Account Settings:");
			_ = content.AppendLine($"│    • Require Logon to Change Password: {FormatBooleanValue(systemAccess.RequireLogonToChangePassword)}");
			_ = content.AppendLine($"│    • Force Logoff When Logon Hours Expire: {FormatBooleanValue(systemAccess.ForceLogoffWhenHourExpire)}");
			_ = content.AppendLine($"│    • Enable Admin Account: {FormatBooleanValue(systemAccess.EnableAdminAccount)}");
			_ = content.AppendLine($"│    • Enable Guest Account: {FormatBooleanValue(systemAccess.EnableGuestAccount)}");
			_ = content.AppendLine($"│    • New Administrator Name: {FormatStringValue(systemAccess.NewAdministratorName)}");
			_ = content.AppendLine($"│    • New Guest Name: {FormatStringValue(systemAccess.NewGuestName)}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Privilege Rights Section
			_ = content.AppendLine("┌─ USER RIGHTS ASSIGNMENTS");
			_ = content.AppendLine("│");

			if (privilegeRights.Count != 0)
			{
				// Group and sort privileges
				foreach (KeyValuePair<string, string[]> privilege in privilegeRights.OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase))
				{
					_ = content.AppendLine($"│  {FormatPrivilegeName(privilege.Key)}:");

					if (privilege.Value.Length > 0)
					{
						foreach (string user in privilege.Value.OrderBy(u => u, StringComparer.OrdinalIgnoreCase))
						{
							_ = content.AppendLine($"│    • {user}");
						}
					}
					else
					{
						_ = content.AppendLine("│    • (No assignments)");
					}
					_ = content.AppendLine("│");
				}
			}
			else
			{
				_ = content.AppendLine("│    (No privilege rights configured)");
				_ = content.AppendLine("│");
			}

			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Footer
			_ = content.AppendLine("=".PadRight(80, '='));
			_ = content.AppendLine("END OF REPORT");
			_ = content.AppendLine("=".PadRight(80, '='));

			File.WriteAllText(filePath, content.ToString(), Encoding.UTF8);

		});
	}

	private static string GetDomainOrWorkgroup()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
			return key?.GetValue("Domain")?.ToString() ?? Environment.UserDomainName;
		}
		catch
		{
			return Environment.UserDomainName;
		}
	}

	private static string GetCurrentUserSid()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			return identity.User?.ToString() ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetWindowsVersion()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
			string? productName = key?.GetValue("ProductName")?.ToString();
			string? displayVersion = key?.GetValue("DisplayVersion")?.ToString();

			if (!string.IsNullOrEmpty(displayVersion))
			{
				return $"{productName} (Version {displayVersion})";
			}
			return productName ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetWindowsEdition()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
			return key?.GetValue("EditionID")?.ToString() ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetWindowsBuild()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
			string? currentBuild = key?.GetValue("CurrentBuild")?.ToString();
			string? currentBuildNumber = key?.GetValue("CurrentBuildNumber")?.ToString();
			return currentBuild ?? currentBuildNumber ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetWindowsUBR()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
			object? ubr = key?.GetValue("UBR");
			return ubr?.ToString() ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetProcessorIdentifier()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
			return key?.GetValue("ProcessorNameString")?.ToString() ?? "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetTotalPhysicalMemory()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\RESOURCEMAP\System Resources\Physical Memory");
			if (key != null)
			{
				if (key.GetValue(".Translated") is byte[] data && data.Length >= 20)
				{
					long memory = BitConverter.ToInt64(data, 12);
					return FormatBytes(memory);
				}
			}
			return "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private unsafe static string GetAvailablePhysicalMemory()
	{
		try
		{
			PerformanceInformation perfInfo = new()
			{
				Size = (uint)sizeof(PerformanceInformation)
			};

			int structSize = sizeof(PerformanceInformation);

			if (NativeMethods.GetPerformanceInfo(ref perfInfo, structSize))
			{
				long availableMemory = perfInfo.PhysicalAvailable * perfInfo.PageSize;
				return FormatBytes(availableMemory);
			}
			else
			{
				int error = Marshal.GetLastPInvokeError();

				Logger.Write($"GetPerformanceInfo failed with error code: {error}", LogTypeIntel.Error);
			}

			return "Unknown";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetSystemBootTime()
	{
		try
		{
			long ticks = Environment.TickCount64;
			DateTime bootTime = DateTime.Now.AddMilliseconds(-ticks);
			return bootTime.ToString("yyyy-MM-dd HH:mm:ss");
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string GetSystemUptime()
	{
		try
		{
			TimeSpan uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
			return $"{uptime.Days} days, {uptime.Hours:D2}:{uptime.Minutes:D2}:{uptime.Seconds:D2}";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string IsUacEnabled()
	{
		try
		{
			using RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
			object? enableLua = key?.GetValue("EnableLUA");
			return enableLua?.ToString() == "1" ? "Yes" : "No";
		}
		catch
		{
			return "Unknown";
		}
	}

	private static string FormatBytes(long bytes)
	{
		string[] suffixes = ["B", "KB", "MB", "GB", "TB"];
		int suffixIndex = 0;
		double size = bytes;

		while (size >= 1024 && suffixIndex < suffixes.Length - 1)
		{
			size /= 1024;
			suffixIndex++;
		}

		return $"{size:F2} {suffixes[suffixIndex]} ({bytes:N0} bytes)";
	}

	private static string FormatStringValue(string? value) => string.IsNullOrEmpty(value) ? "Not configured" : $"\"{value}\"";

	private static string FormatBooleanValue(object? value)
	{
		if (value == null) return "Not configured";

		return value.ToString()?.ToLowerInvariant() switch
		{
			"1" or "true" or "enabled" => "Enabled",
			"0" or "false" or "disabled" => "Disabled",
			_ => value.ToString() ?? "Unknown"
		};
	}

	// Convert technical privilege names to a more readable format.
	// Names always start with the "Se" prefix and end with either "Privilege" or "Right",
	// e.g. "SeSecurityPrivilege" -> "Security Privilege", "SeInteractiveLogonRight" -> "InteractiveLogon Right".
	private static string FormatPrivilegeName(string privilegeName)
	{
		ReadOnlySpan<char> span = privilegeName.AsSpan().Trim();

		// Strip the leading "Se" prefix
		if (span.StartsWith("Se", StringComparison.OrdinalIgnoreCase))
		{
			span = span[2..];
		}

		// Insert a single space before the trailing "Privilege" suffix.
		if (span.EndsWith("Privilege", StringComparison.OrdinalIgnoreCase))
		{
			return string.Concat(span[..^"Privilege".Length].TrimEnd(), " Privilege");
		}

		// Insert a single space before the trailing "Right" suffix.
		if (span.EndsWith("Right", StringComparison.OrdinalIgnoreCase))
		{
			return string.Concat(span[..^"Right".Length].TrimEnd(), " Right");
		}

		return span.ToString();
	}
}
