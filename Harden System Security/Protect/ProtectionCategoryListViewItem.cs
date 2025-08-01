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
using Microsoft.UI.Xaml.Media.Imaging;

namespace HardenSystemSecurity.Protect;

/// <summary>
/// Type used by the ListView in the Protect page.
/// </summary>
/// <param name="title"></param>
/// <param name="subTitle"></param>
/// <param name="logo"></param>
/// <param name="subCategories">Any sub-categories that the main category might be using.</param>
internal sealed class ProtectionCategoryListViewItem(
	Categories category,
	string title,
	string subTitle,
	BitmapImage logo,
	List<SubCategoryDefinition> subCategories)
{
	internal Categories Category => category;
	internal string Title => title;
	internal string Subtitle => subTitle;
	internal BitmapImage Logo => logo;
	internal List<SubCategoryDefinition> SubCategories => subCategories;
}
