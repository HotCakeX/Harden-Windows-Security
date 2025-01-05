using System;
using System.IO;

namespace HardenWindowsSecurity;

public static partial class TLSSecurity
{
	/// <summary>
	/// This method only applies (TLS_RSA_WITH_AES_256_CBC_SHA) cipher suite for the BattleNet Client
	/// </summary>
	/// <exception cref="ArgumentNullException"></exception>
	public static void TLSSecurity_BattleNetClient()
	{

		Logger.LogMessage("Adding (TLS_RSA_WITH_AES_256_CBC_SHA) cipher suite for the BattleNet Client", LogTypeIntel.Information);

		LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "TLS Security", "For BattleNetClient", "registry.pol"), LGPORunner.FileType.POL);
	}

}
