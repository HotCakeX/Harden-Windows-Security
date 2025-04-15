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

using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class DeploymentVM : ViewModelBase
{

	#region UI-Bound Properties

	private Visibility _MainInfoBarVisibility = Visibility.Collapsed;
	internal Visibility MainInfoBarVisibility
	{
		get => _MainInfoBarVisibility;
		set => SetProperty(_MainInfoBarVisibility, value, newValue => _MainInfoBarVisibility = newValue);
	}

	private bool _MainInfoBarIsOpen;
	internal bool MainInfoBarIsOpen
	{
		get => _MainInfoBarIsOpen;
		set => SetProperty(_MainInfoBarIsOpen, value, newValue => _MainInfoBarIsOpen = newValue);
	}

	private string? _MainInfoBarMessage;
	internal string? MainInfoBarMessage
	{
		get => _MainInfoBarMessage;
		set => SetProperty(_MainInfoBarMessage, value, newValue => _MainInfoBarMessage = newValue);
	}

	private InfoBarSeverity _MainInfoBarSeverity = InfoBarSeverity.Informational;
	internal InfoBarSeverity MainInfoBarSeverity
	{
		get => _MainInfoBarSeverity;
		set => SetProperty(_MainInfoBarSeverity, value, newValue => _MainInfoBarSeverity = newValue);
	}

	private bool _MainInfoBarIsClosable;
	internal bool MainInfoBarIsClosable
	{
		get => _MainInfoBarIsClosable;
		set => SetProperty(_MainInfoBarIsClosable, value, newValue => _MainInfoBarIsClosable = newValue);
	}


	private string _LocalOnlineStatusText = "Local Deployment is Currently Active";
	internal string LocalOnlineStatusText
	{
		get => _LocalOnlineStatusText;
		set => SetProperty(_LocalOnlineStatusText, value, newValue => _LocalOnlineStatusText = newValue);
	}


	/// <summary>
	/// Bound to the UI ListView and holds the Intune group Names/IDs
	/// </summary>
	internal readonly ObservableCollection<MicrosoftGraph.IntuneGroupItemListView> GroupNamesCollection = [];

	#endregion

}
