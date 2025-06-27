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
using System.IO;

namespace AppControlManager.Others;

/// <summary>
/// Represents input for a simulation, encapsulating file information and associated signer details.
/// </summary>
/// <param name="filePath">Specifies the file associated with the simulation input.</param>
/// <param name="allFileSigners">Contains a list of all signers related to the file.</param>
/// <param name="signerInfo">Holds detailed information about the signers involved.</param>
/// <param name="ekuOids">Lists the Extended Key Usage Object Identifiers relevant to the simulation.</param>
internal sealed class SimulationInput(FileInfo filePath, List<ChainPackage> allFileSigners, List<SignerX> signerInfo, List<string> ekuOids)
{
	internal FileInfo FilePath => filePath;
	internal List<ChainPackage> AllFileSigners => allFileSigners;
	internal List<SignerX> SignerInfo => signerInfo;
	internal List<string> EKUOIDs => ekuOids;
}
