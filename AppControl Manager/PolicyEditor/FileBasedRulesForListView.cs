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

namespace AppControlManager.PolicyEditor;

/// <summary>
/// Data model for the File Based Rules list view.
/// </summary>
/// <param name="id"></param>
/// <param name="friendlyName"></param>
/// <param name="fileName"></param>
/// <param name="internalName"></param>
/// <param name="fileDescription"></param>
/// <param name="productName"></param>
/// <param name="packageFamilyName"></param>
/// <param name="packageVersion"></param>
/// <param name="minimumFileVersion"></param>
/// <param name="maximumFileVersion"></param>
/// <param name="hash"></param>
/// <param name="appIDs"></param>
/// <param name="filePath"></param>
/// <param name="type"></param>
/// <param name="sourceType"></param>
/// <param name="source"></param>
internal sealed class FileBasedRulesForListView(
	string? id,
	string? friendlyName,
	string? fileName,
	string? internalName,
	string? fileDescription,
	string? productName,
	string? packageFamilyName,
	string? packageVersion,
	string? minimumFileVersion,
	string? maximumFileVersion,
	string? hash,
	string? appIDs,
	string? filePath,
	string? type,
	FileBasedRuleType sourceType,
	object source
	)
{
	internal string? Id => id;
	internal string? FriendlyName => friendlyName;
	internal string? FileName => fileName;
	internal string? InternalName => internalName;
	internal string? FileDescription => fileDescription;
	internal string? ProductName => productName;
	internal string? PackageFamilyName => packageFamilyName;
	internal string? PackageVersion => packageVersion;
	internal string? MinimumFileVersion => minimumFileVersion;
	internal string? MaximumFileVersion => maximumFileVersion;
	internal string? Hash => hash;
	internal string? AppIDs => appIDs;
	internal string? FilePath => filePath;
	internal string? Type => type;
	internal FileBasedRuleType SourceType => sourceType;
	internal object Source => source;
}
