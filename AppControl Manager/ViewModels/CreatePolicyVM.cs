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

using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class CreatePolicyVM : ViewModelBase
{

	#region UI-Bound Properties

	internal Visibility AllowMicrosoftInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility DefaultWindowsInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility SignedAndReputableInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	#endregion

}
