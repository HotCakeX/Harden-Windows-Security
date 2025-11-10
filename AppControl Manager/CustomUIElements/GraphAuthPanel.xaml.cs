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

using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GraphAuthPanel : UserControl
{
	private AppSettings.Main AppSettings => App.Settings;

	public IGraphAuthHost Host
	{
		get { return (IGraphAuthHost)GetValue(HostProperty); }
		set { SetValue(HostProperty, value); }
	}

	internal static readonly DependencyProperty HostProperty =
		DependencyProperty.Register(
			nameof(Host),
			typeof(IGraphAuthHost),
			typeof(GraphAuthPanel),
			new PropertyMetadata(null));

	internal ThreadSafeObservableCollection<AuthenticatedAccounts> AuthenticatedAccounts => AuthenticationCompanion.AuthenticatedAccounts;

	internal GraphAuthPanel()
	{
		InitializeComponent();
	}
}
