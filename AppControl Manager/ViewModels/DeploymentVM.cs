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

	internal Visibility UnsignedXMLFilesLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SignedXMLFilesLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal Visibility MainInfoBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }

	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }

	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;

	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal string LocalOnlineStatusText
	{
		get; set => SP(ref field, value);
	} = "Local Deployment is Currently Active";


	/// <summary>
	/// Bound to the UI ListView and holds the Intune group Names/IDs
	/// </summary>
	internal readonly ObservableCollection<MicrosoftGraph.IntuneGroupItemListView> GroupNamesCollection = [];

	#endregion

}
