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

using AppControlManager.ViewModels;

namespace AppControlManager.PolicyEditor;

/// <summary>
/// Data model for the Signature Based Rules list view.
/// </summary>
/// <param name="certRoot"></param>
/// <param name="certEKU"></param>
/// <param name="certIssuer"></param>
/// <param name="certPublisher"></param>
/// <param name="certOemID"></param>
/// <param name="name"></param>
/// <param name="id"></param>
/// <param name="sourceType"></param>
/// <param name="source"></param>
internal sealed class SignatureBasedRulesForListView(
	string? certRoot,
	string? certEKU,
	string? certIssuer,
	string? certPublisher,
	string? certOemID,
	string? name,
	string? id,
	SignatureBasedRuleType sourceType,
	object source,
	PolicyEditorVM parentViewModel
	)
{
	internal string? CertRoot => certRoot;
	internal string? CertificateEKU => certEKU;
	internal string? CertIssuer => certIssuer;
	internal string? CertPublisher => certPublisher;
	internal string? CertOemID => certOemID;
	internal string? Name => name;
	internal string? Id => id;
	internal SignatureBasedRuleType SourceType => sourceType;
	internal object Source => source;

	// A property for the parent view model of the Policy Editor page to store a reference to it
	// so we can access the variables in the View Model class via compiled binding in XAML.
	public PolicyEditorVM ParentViewModel => parentViewModel;
}
