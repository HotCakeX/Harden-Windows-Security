using System.IO;

namespace AppControlManager.Others;

/// <summary>
/// Used by AppControl Simulations
/// </summary>
public sealed class SimulationInput(FileInfo filePath, ChainPackage[] allFileSigners, SignerX[] signerInfo, string[] ekuOids)
{
	// Adding public getters and setters for the properties
	public FileInfo FilePath { get; set; } = filePath;
	public ChainPackage[] AllFileSigners { get; set; } = allFileSigners;
	public SignerX[] SignerInfo { get; set; } = signerInfo;
	public string[] EKUOIDs { get; set; } = ekuOids;
}
