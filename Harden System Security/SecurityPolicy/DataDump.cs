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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace HardenSystemSecurity.SecurityPolicy;

internal static class DataDump
{
	internal static async Task DumpSystemSecurityPoliciesData(string filePath)
	{
		await Task.Run(() =>
		{

			SecurityPolicyInfo policyInfo = SecurityPolicyReader.GetSecurityPolicyInfo();

			StringBuilder content = new();

			// Header
			_ = content.AppendLine("=".PadRight(80, '='));
			_ = content.AppendLine("SECURITY POLICY INFORMATION REPORT");
			_ = content.AppendLine("=".PadRight(80, '='));
			_ = content.AppendLine();

			_ = content.AppendLine("┌─ REPORT INFORMATION");
			_ = content.AppendLine($"│  Generated (Local): {DateTime.Now:yyyy-MM-dd HH:mm:ss} ({TimeZoneInfo.Local.DisplayName})");
			_ = content.AppendLine($"│  Generated (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
			_ = content.AppendLine($"│  Report Format Version: 1.0");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// System Information
			_ = content.AppendLine("┌─ SYSTEM INFORMATION");
			_ = content.AppendLine($"│  Computer Name: {Environment.MachineName}");
			_ = content.AppendLine($"│  Domain/Workgroup: {GetDomainOrWorkgroup()}");
			_ = content.AppendLine($"│  Current User: {Environment.UserName}");
			_ = content.AppendLine($"│  User Domain: {Environment.UserDomainName}");
			_ = content.AppendLine($"│  User Is Administrator: {IsCurrentUserAdministrator()}");
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

			// Security Context Information
			_ = content.AppendLine("┌─ SECURITY CONTEXT");
			_ = content.AppendLine($"│  Current Process ID: {Environment.ProcessId}");
			_ = content.AppendLine($"│  Process Name: {System.Diagnostics.Process.GetCurrentProcess().ProcessName}");
			_ = content.AppendLine($"│  Process Start Time: {System.Diagnostics.Process.GetCurrentProcess().StartTime:yyyy-MM-dd HH:mm:ss}");
			_ = content.AppendLine($"│  Elevated Process: {IsElevated()}");
			_ = content.AppendLine($"│  UAC Enabled: {IsUacEnabled()}");
			_ = content.AppendLine($"│  Current Culture: {CultureInfo.CurrentCulture.Name}");
			_ = content.AppendLine($"│  Current UI Culture: {CultureInfo.CurrentUICulture.Name}");
			_ = content.AppendLine($"│  Time Zone: {TimeZoneInfo.Local.Id}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// System Access Section
			_ = content.AppendLine("┌─ SYSTEM ACCESS POLICIES");
			_ = content.AppendLine("│");
			_ = content.AppendLine($"│  Password Policies:");
			_ = content.AppendLine($"│    • Minimum Password Age: {FormatValue(policyInfo.SystemAccess.MinimumPasswordAge)} days");
			_ = content.AppendLine($"│    • Maximum Password Age: {FormatValue(policyInfo.SystemAccess.MaximumPasswordAge)} days");
			_ = content.AppendLine($"│    • Minimum Password Length: {FormatValue(policyInfo.SystemAccess.MinimumPasswordLength)} characters");
			_ = content.AppendLine($"│    • Password Complexity: {FormatBooleanValue(policyInfo.SystemAccess.PasswordComplexity)}");
			_ = content.AppendLine($"│    • Password History Size: {FormatValue(policyInfo.SystemAccess.PasswordHistorySize)} passwords");
			_ = content.AppendLine($"│    • Clear Text Password: {FormatBooleanValue(policyInfo.SystemAccess.ClearTextPassword)}");
			_ = content.AppendLine("│");
			_ = content.AppendLine($"│  Account Lockout Policies:");
			_ = content.AppendLine($"│    • Lockout Bad Count: {FormatValue(policyInfo.SystemAccess.LockoutBadCount)} attempts");
			_ = content.AppendLine($"│    • Reset Lockout Count: {FormatValue(policyInfo.SystemAccess.ResetLockoutCount)} minutes");
			_ = content.AppendLine($"│    • Lockout Duration: {FormatValue(policyInfo.SystemAccess.LockoutDuration)} minutes");
			_ = content.AppendLine($"│    • Allow Administrator Lockout: {FormatBooleanValue(policyInfo.SystemAccess.AllowAdministratorLockout)}");
			_ = content.AppendLine("│");
			_ = content.AppendLine($"│  Account Settings:");
			_ = content.AppendLine($"│    • Require Logon to Change Password: {FormatBooleanValue(policyInfo.SystemAccess.RequireLogonToChangePassword)}");
			_ = content.AppendLine($"│    • Force Logoff When Hour Expire: {FormatBooleanValue(policyInfo.SystemAccess.ForceLogoffWhenHourExpire)}");
			_ = content.AppendLine($"│    • Enable Admin Account: {FormatBooleanValue(policyInfo.SystemAccess.EnableAdminAccount)}");
			_ = content.AppendLine($"│    • Enable Guest Account: {FormatBooleanValue(policyInfo.SystemAccess.EnableGuestAccount)}");
			_ = content.AppendLine($"│    • New Administrator Name: {FormatStringValue(policyInfo.SystemAccess.NewAdministratorName)}");
			_ = content.AppendLine($"│    • New Guest Name: {FormatStringValue(policyInfo.SystemAccess.NewGuestName)}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Event Audit Section
			_ = content.AppendLine("┌─ EVENT AUDIT POLICIES");
			_ = content.AppendLine("│");
			_ = content.AppendLine($"│    • Audit System Events: {FormatAuditValue(policyInfo.EventAudit.AuditSystemEvents)}");
			_ = content.AppendLine($"│    • Audit Logon Events: {FormatAuditValue(policyInfo.EventAudit.AuditLogonEvents)}");
			_ = content.AppendLine($"│    • Audit Object Access: {FormatAuditValue(policyInfo.EventAudit.AuditObjectAccess)}");
			_ = content.AppendLine($"│    • Audit Privilege Use: {FormatAuditValue(policyInfo.EventAudit.AuditPrivilegeUse)}");
			_ = content.AppendLine($"│    • Audit Policy Change: {FormatAuditValue(policyInfo.EventAudit.AuditPolicyChange)}");
			_ = content.AppendLine($"│    • Audit Account Management: {FormatAuditValue(policyInfo.EventAudit.AuditAccountManage)}");
			_ = content.AppendLine($"│    • Audit Process Tracking: {FormatAuditValue(policyInfo.EventAudit.AuditProcessTracking)}");
			_ = content.AppendLine($"│    • Audit Directory Service Access: {FormatAuditValue(policyInfo.EventAudit.AuditDSAccess)}");
			_ = content.AppendLine($"│    • Audit Account Logon: {FormatAuditValue(policyInfo.EventAudit.AuditAccountLogon)}");
			_ = content.AppendLine("└─");
			_ = content.AppendLine();

			// Privilege Rights Section
			_ = content.AppendLine("┌─ USER RIGHTS ASSIGNMENTS");
			_ = content.AppendLine("│");

			if (policyInfo.PrivilegeRights.Count != 0)
			{
				// Group and sort privileges
				Dictionary<string, string[]> sortedPrivileges = policyInfo.PrivilegeRights
					.OrderBy(kvp => kvp.Key, StringComparer.OrdinalIgnoreCase)
					.ToDictionary(kvp => kvp.Key, kvp => kvp.Value);

				foreach (KeyValuePair<string, string[]> privilege in sortedPrivileges)
				{
					_ = content.AppendLine($"│  {FormatPrivilegeName(privilege.Key)}:");

					if (privilege.Value != null && privilege.Value.Length > 0)
					{
						foreach (string user in privilege.Value.OrderBy(u => u, StringComparer.OrdinalIgnoreCase))
						{
							_ = content.AppendLine($"│    • {user}");
						}
					}
					else
					{
						_ = content.AppendLine($"│    • (No assignments)");
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

			// Registry Values Section
			_ = content.AppendLine("┌─ SECURITY POLICY REGISTRY VALUES");
			_ = content.AppendLine("│");

			if (policyInfo.RegistryValues.Count != 0)
			{
				// Group registry values by key path
				IGrouping<string, RegistryValue>[] groupedValues = policyInfo.RegistryValues
					.GroupBy(rv => GetRegistryKeyPath(rv.Name))
					.OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
					.ToArray();

				foreach (IGrouping<string, RegistryValue> group in groupedValues)
				{
					_ = content.AppendLine($"│  Registry Key: {group.Key}");

					foreach (RegistryValue regValue in group.OrderBy(rv => GetRegistryValueName(rv.Name), StringComparer.OrdinalIgnoreCase))
					{
						string valueName = GetRegistryValueName(regValue.Name);
						_ = content.AppendLine($"│    • {valueName}");
						_ = content.AppendLine($"│      Type: {regValue.Type}");
						_ = content.AppendLine($"│      Value: {FormatRegistryValue(regValue.Value, regValue.Type.ToString())}");
					}
					_ = content.AppendLine("│");
				}
			}
			else
			{
				_ = content.AppendLine("│    (No registry values configured)");
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

	private static string IsCurrentUserAdministrator()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			WindowsPrincipal principal = new(identity);
			return principal.IsInRole(WindowsBuiltInRole.Administrator) ? "Yes" : "No";
		}
		catch
		{
			return "Unknown";
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

	private static string IsElevated()
	{
		try
		{
			using WindowsIdentity identity = WindowsIdentity.GetCurrent();
			WindowsPrincipal principal = new(identity);
			return principal.IsInRole(WindowsBuiltInRole.Administrator) ? "Yes" : "No";
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

	private static string FormatValue(object? value)
	{
		return value?.ToString() ?? "Not configured";
	}

	private static string FormatStringValue(string? value)
	{
		return string.IsNullOrEmpty(value) ? "Not configured" : $"\"{value}\"";
	}

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

	private static string FormatAuditValue(object? value)
	{
		if (value == null) return "Not configured";

		return value.ToString() switch
		{
			"0" => "No auditing",
			"1" => "Success",
			"2" => "Failure",
			"3" => "Success and Failure",
			_ => value.ToString() ?? "Unknown"
		};
	}

	private static string FormatPrivilegeName(string privilegeName)
	{
		// Convert technical privilege names to more readable format
		return privilegeName.Replace("Se", "").Replace("Privilege", " Privilege")
			.Replace("Right", " Right").Trim();
	}

	private static string FormatRegistryValue(object? value, string? type)
	{
		if (value == null) return "(null)";

		return type?.ToLowerInvariant() switch
		{
			"reg_dword" => $"{value} (0x{Convert.ToInt32(value):X8})",
			"reg_binary" => value.ToString()?.Length > 50 ?
				$"{value.ToString()?[..50]}... ({value.ToString()?.Length} chars)" :
				value.ToString() ?? "(empty)",
			"reg_multi_sz" => value.ToString()?.Contains('\0') == true ?
				$"[{string.Join(", ", value.ToString()?.Split('\0', StringSplitOptions.RemoveEmptyEntries) ?? [])}]" :
				value.ToString() ?? "(empty)",
			_ => value.ToString() ?? "(empty)"
		};
	}

	private static string GetRegistryKeyPath(string fullPath)
	{
		int lastBackslash = fullPath.LastIndexOf('\\');
		return lastBackslash > 0 ? fullPath[..lastBackslash] : fullPath;
	}

	private static string GetRegistryValueName(string fullPath)
	{
		int lastBackslash = fullPath.LastIndexOf('\\');
		return lastBackslash > 0 && lastBackslash < fullPath.Length - 1 ?
			fullPath[(lastBackslash + 1)..] : fullPath;
	}
}
