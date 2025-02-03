using System;
using System.Diagnostics;
using System.IO;

namespace HardenWindowsSecurity;

public partial class ConfirmSystemComplianceMethods
{
	/// <summary>
	/// Get the security group policies by utilizing the Secedit.exe
	/// </summary>
	internal static void ExportSecurityPolicy()
	{
		// Create the process start info
		ProcessStartInfo processStartInfo = new()
		{
			FileName = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "Secedit.exe"),
			Arguments = $"/export /cfg \"{GlobalVars.securityPolicyInfPath}\"",
			// RedirectStandardOutput = false,
			RedirectStandardError = true,
			UseShellExecute = false,
			CreateNoWindow = true
		};

		// Start the process
		using Process? process = Process.Start(processStartInfo) ?? throw new InvalidOperationException("Failed to start Secedit.exe process.");

		// Read the output
		// string output = process.StandardOutput.ReadToEnd();
		string error = process.StandardError.ReadToEnd();

		process.WaitForExit();

		if (!string.IsNullOrEmpty(error))
		{
			Logger.LogMessage("Error: " + error, LogTypeIntel.Error);
		}
	}
}
