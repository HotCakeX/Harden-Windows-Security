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

	private Visibility _AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility AllowMicrosoftInfoBarActionButtonVisibility
	{
		get => _AllowMicrosoftInfoBarActionButtonVisibility;
		set => SetProperty(_AllowMicrosoftInfoBarActionButtonVisibility, value, newValue => _AllowMicrosoftInfoBarActionButtonVisibility = newValue);
	}


	private Visibility _DefaultWindowsInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility DefaultWindowsInfoBarActionButtonVisibility
	{
		get => _DefaultWindowsInfoBarActionButtonVisibility;
		set => SetProperty(_DefaultWindowsInfoBarActionButtonVisibility, value, newValue => _DefaultWindowsInfoBarActionButtonVisibility = newValue);
	}

	private Visibility _SignedAndReputableInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility SignedAndReputableInfoBarActionButtonVisibility
	{
		get => _SignedAndReputableInfoBarActionButtonVisibility;
		set => SetProperty(_SignedAndReputableInfoBarActionButtonVisibility, value, newValue => _SignedAndReputableInfoBarActionButtonVisibility = newValue);
	}

	private Visibility _MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility
	{
		get => _MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility;
		set => SetProperty(_MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility, value, newValue => _MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility = newValue);
	}

	private Visibility _StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility StrictKernelModeInfoBarActionButtonVisibility
	{
		get => _StrictKernelModeInfoBarActionButtonVisibility;
		set => SetProperty(_StrictKernelModeInfoBarActionButtonVisibility, value, newValue => _StrictKernelModeInfoBarActionButtonVisibility = newValue);
	}

	#endregion

}
