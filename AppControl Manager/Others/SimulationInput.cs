using System.Collections.Generic;
using System.IO;

namespace AppControlManager.Others;

/// <summary>
/// Used by App Control Simulations
/// </summary>
internal sealed class SimulationInput(FileInfo filePath, List<ChainPackage> allFileSigners, List<SignerX> signerInfo, List<string> ekuOids)
{
	// Adding public getters and setters for the properties
	internal FileInfo FilePath { get; set; } = filePath;
	internal List<ChainPackage> AllFileSigners { get; set; } = allFileSigners;
	internal List<SignerX> SignerInfo { get; set; } = signerInfo;
	internal List<string> EKUOIDs { get; set; } = ekuOids;
}
