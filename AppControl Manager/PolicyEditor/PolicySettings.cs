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

internal sealed partial class PolicySettings(
	PolicyEditorVM parentViewModel,
	string provider,
	string key,
	object? value,
	string? valueStr,
	string valueName,
	int type) : ViewModelBase
{

	// A property for the parent view model of the Policy Editor page to store a reference to it
	// so we can access the variables in the View Model class via compiled binding in XAML.
	internal PolicyEditorVM ParentViewModel => parentViewModel;

	internal string Provider { get; set => SP(ref field, value); } = provider;
	internal string Key { get; set => SP(ref field, value); } = key;
	internal object? Value { get; set => SP(ref field, value); } = value;
	internal string? ValueStr { get; set => SP(ref field, value); } = valueStr;
	internal string ValueName { get; set => SP(ref field, value); } = valueName;
	internal int Type { get; set => SP(ref field, value); } = type;
}
