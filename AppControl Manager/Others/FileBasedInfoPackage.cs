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

namespace AppControlManager.Others;

/// <summary>
/// Used by the BuildSignerAndHashObjects method to store and return the output
/// </summary>
/// <param name="whqlFilepublishersigners">Data to create WHQLFilePublisher level rules for.</param>
/// <param name="filepublishersigners">Data to create FilePublisher level rules for.</param>
/// <param name="publishersigners">Data to create Publisher level rules for.</param>
/// <param name="completehashes">Data to create Hash rules for.</param>
/// <param name="filePaths">Data to create File path rules for.</param>
/// <param name="pfnRules">Data to create PFN (Package Family Name) rules for.</param>
internal sealed class FileBasedInfoPackage(
	List<WHQLFilePublisherSignerCreator> whqlFilepublishersigners,
	List<FilePublisherSignerCreator> filepublishersigners,
	List<PublisherSignerCreator> publishersigners,
	List<HashCreator> completehashes,
	List<FilePathCreator> filePaths,
	List<PFNRuleCreator> pfnRules)
{
	internal List<WHQLFilePublisherSignerCreator> WHQLFilePublisherSigners => whqlFilepublishersigners;
	internal List<FilePublisherSignerCreator> FilePublisherSigners => filepublishersigners;
	internal List<PublisherSignerCreator> PublisherSigners => publishersigners;
	internal List<HashCreator> CompleteHashes => completehashes;
	internal List<FilePathCreator> FilePaths => filePaths;
	internal List<PFNRuleCreator> PFNRules => pfnRules;
}
