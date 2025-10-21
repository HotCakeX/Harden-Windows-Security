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
using Microsoft.UI.Xaml;

namespace HardenSystemSecurity.Protect;

internal sealed partial class SubCategoryDefinition(
	SubCategories subCategory,
	string description,
	string? tip = null) : ViewModelBase
{
	internal SubCategories SubCategory => subCategory;
	internal string Description => description;
	internal string? Tip => tip;

	/// <summary>
	/// Whether the checkbox for this sub-category is checked or not.
	/// </summary>
	internal bool IsChecked { get; set => SP(ref field, value); }

	/// <summary>
	/// Used by XAML Compiled Binding.
	/// </summary>
	/// <param name="value"></param>
	/// <returns></returns>
	internal static Visibility HasTip(string? value) => string.IsNullOrEmpty(value) ? Visibility.Collapsed : Visibility.Visible;
}
