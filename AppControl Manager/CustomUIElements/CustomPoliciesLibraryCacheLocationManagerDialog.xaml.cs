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

using System.ComponentModel;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;

namespace AppControlManager.CustomUIElements;

internal sealed partial class CustomPoliciesLibraryCacheLocationManagerDialog : ContentDialogV2, INPCImplant
{
	private CommonCore.AppSettings.Main AppSettings => GlobalVars.Settings;

	internal CustomPoliciesLibraryCacheLocationManagerDialog() => InitializeComponent();

	private async void BrowseAndSetCustomCacheDirectory()
	{
		try
		{
			AreElementsEnabled = false;

			string? directory = FileDialogHelper.ShowDirectoryPickerDialog();

			if (!string.IsNullOrEmpty(directory))
			{
				AppSettings.CustomSidebarPoliciesLibraryCacheLocation = directory;

				await ViewModelProvider.MainWindowVM.SetSidebarPoliciesLibraryCacheLocationToCustom();

				await ViewModelProvider.MainWindowVM.InitialPoliciesLibrarySetup();
			}
		}
		finally
		{
			AreElementsEnabled = true;
		}
	}

	private async void Clear()
	{
		try
		{
			AreElementsEnabled = false;

			await ViewModelProvider.MainWindowVM.SetSidebarPoliciesLibraryCacheLocationToDefault();

			// Clear the user-defined custom path after it was used to copy files to the default location
			AppSettings.CustomSidebarPoliciesLibraryCacheLocation = string.Empty;

			await ViewModelProvider.MainWindowVM.InitialPoliciesLibrarySetup();
		}
		finally
		{
			AreElementsEnabled = true;
		}
	}

	private async void Open() => await ViewModels.ViewModelBase.OpenFileInDefaultFileHandler(AppSettings.CustomSidebarPoliciesLibraryCacheLocation);

	private bool AreElementsEnabled
	{
		get; set
		{
			if (this.SP(ref field, value))
			{
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				ProgressRingIsActive = !field;
			}
		}
	} = true;

	private Visibility ProgressRingVisibility { get; set => this.SP(ref field, value); } = Visibility.Collapsed;
	private bool ProgressRingIsActive { get; set => this.SP(ref field, value); }

	#region IPropertyChangeHost Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	#endregion

}
