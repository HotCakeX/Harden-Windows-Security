namespace HardenWindowsSecurity;

public static partial class MicrosoftDefender
{
	/// <summary>
	/// Turns on Smart App Control
	/// </summary>
	public static void MSFTDefender_SAC()
	{
		Logger.LogMessage("Turning on Smart App Control", LogTypeIntel.Information);

		RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState", "1", "DWORD", "AddOrModify");

		// Let the optional diagnostic data be enabled automatically
		GlobalVars.ShouldEnableOptionalDiagnosticData = true;
	}
}
