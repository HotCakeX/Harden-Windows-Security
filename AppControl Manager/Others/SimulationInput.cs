using System.IO;

namespace AppControlManager.Others;

/// <summary>
/// Used by App Control Simulations
/// </summary>
internal sealed class SimulationInput(FileInfo filePath, ChainPackage[] allFileSigners, SignerX[] signerInfo, string[] ekuOids)
{
	// Adding public getters and setters for the properties
	internal FileInfo FilePath { get; set; } = filePath;
	internal ChainPackage[] AllFileSigners { get; set; } = allFileSigners;
	internal SignerX[] SignerInfo { get; set; } = signerInfo;
	internal string[] EKUOIDs { get; set; } = ekuOids;
}
