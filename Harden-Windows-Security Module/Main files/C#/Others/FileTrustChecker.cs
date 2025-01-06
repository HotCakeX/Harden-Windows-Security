using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using static HardenWindowsSecurity.GUIFileReputation;

namespace HardenWindowsSecurity;

internal static class FileTrustChecker
{
	// Defining the path to the MpClient.dll file
	private static readonly string defenderPath = Path.Combine(
	Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
	"Windows Defender", "MpClient.dll");

	/// <summary>
	/// Function to check the trust of a given file path
	/// </summary>
	/// <param name="filePath"></param>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static FileTrustResult CheckFileTrust(string filePath)
	{

		IntPtr fileHandle = default;

		try
		{

			// Initialize Params structure
			NativeMethods.Params parameters = new() { StructSize = 0x10 };

			ulong MpFileTrustExtraInfoCOUNT = 0; // Variable to store extra info count

			IntPtr extraInfoPtr = IntPtr.Zero;   // Pointer to extra info data

			// Load Windows Defender library dynamically
			IntPtr hModule = NativeMethods.LoadLibraryExW(defenderPath, IntPtr.Zero, 0);

			if (hModule == IntPtr.Zero)
			{
				throw new FileNotFoundException("MpClient.dll not found");
			}

			// Get the function address of 'MpQueryFileTrustByHandle2'
			IntPtr procAddress = NativeMethods.GetProcAddress(hModule, "MpQueryFileTrustByHandle2");

			if (procAddress == IntPtr.Zero)
			{
				throw new InvalidOperationException("MpQueryFileTrustByHandle2 not found");
			}

			// Create a delegate for the function from the address
			NativeMethods.MpQueryFileTrustByHandle2Delegate mpQueryFileTrust = Marshal.GetDelegateForFunctionPointer<NativeMethods.MpQueryFileTrustByHandle2Delegate>(procAddress);

			// Open the file and get its handle
			fileHandle = NativeMethods.CreateFile(filePath, 0x80000000, 0x00000001, IntPtr.Zero, 0x00000003, 0, IntPtr.Zero);

			// Check if file failed to open
			if (fileHandle == new IntPtr(-1))
			{
				throw new InvalidOperationException($"Error opening a handle to the file '{filePath}': {Marshal.GetLastWin32Error()}");
			}

			// Query the file's trust score using the function pointer and the file handle
			long result = mpQueryFileTrust(fileHandle, IntPtr.Zero, IntPtr.Zero, ref parameters, ref MpFileTrustExtraInfoCOUNT, ref extraInfoPtr);

			// If query is successful
			if (result is 0)
			{
				// Parse the trust score based on the enum
				TrustScore score = (TrustScore)parameters.TrustScore;

				// Output extra info if available
				if (MpFileTrustExtraInfoCOUNT > 0 && extraInfoPtr != IntPtr.Zero)
				{
					MpFileTrustExtraInfo extraInfo = Marshal.PtrToStructure<MpFileTrustExtraInfo>(extraInfoPtr);
					Logger.LogMessage($"There were extra info regarding file reputation check: {extraInfo.First}, {extraInfo.Second}, {extraInfo.DataSize}, {extraInfo.Data}", LogTypeIntel.Information);
				}
			}
			else
			{
				throw new InvalidOperationException($"Failed to query the reputation: {result}");
			}


			return new FileTrustResult()
			{
				Reputation = GetReputation((TrustScore)parameters.TrustScore),
				Source = GetTrustSource(),
				Duration = $"{parameters.ValidityDurationMs} ms",
				Handle = fileHandle.ToString(CultureInfo.InvariantCulture)
			};

		}

		finally
		{
			// Close the file handle after operation
			_ = NativeMethods.CloseHandle(fileHandle);
		}
	}

	// Map the trust score to a reputation string
	internal static string GetReputation(TrustScore score) => score switch
	{
		TrustScore.HighTrust => "High Trust",
		TrustScore.Good => "Good Trust",
		TrustScore.Unknown => "Unavailable or Unknown",
		TrustScore.PotentiallyUnwantedApplication => "Potentially Unwanted Application (PUA)",
		TrustScore.Malicious => "Malicious",
		_ => $"Unrecognized Score: ({(int)score})"
	};

	// Smart App Control when set in Eval or On state takes control of the file reputation verification, otherwise it's up to the SmartScreen to do it
	internal enum TrustSource
	{
		SmartAppControl,
		SmartScreen
	}

	internal static TrustSource GetTrustSource()
	{
		// Get the MSFT_MpComputerStatus and save them to the global variable GlobalVars.MDAVConfigCurrent
		GlobalVars.MDAVConfigCurrent = ConfigDefenderHelper.GetMpComputerStatus();

		if (!string.Equals(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty, "off", StringComparison.OrdinalIgnoreCase))
		{
			return TrustSource.SmartAppControl;
		}
		else
		{
			return TrustSource.SmartScreen;
		}
	}

	internal sealed class FileTrustResult
	{
		internal required string Reputation { get; set; }
		internal required TrustSource Source { get; set; }
		internal string? Duration { get; set; }
		internal required string Handle { get; set; }
	}

}
