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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class SettingsVM : INotifyPropertyChanged
{

	public event PropertyChangedEventHandler? PropertyChanged;

	//private readonly DispatcherQueue Dispatch = DispatcherQueue.GetForCurrentThread();

	// To store the selectable Certificate common names
	internal readonly ObservableCollection<string> CertCommonNames = [];
	internal readonly List<string> CertCommonNamesList = [];

	#region UI-Bound Properties

#pragma warning disable CA1822 // Mark members as static
	internal bool IsElevated => App.IsElevated;
#pragma warning restore CA1822

	private string? _CertCNsAutoSuggestBoxText;
	internal string? CertCNsAutoSuggestBoxText
	{
		get => _CertCNsAutoSuggestBoxText;
		set => SetProperty(_CertCNsAutoSuggestBoxText, value, newValue => _CertCNsAutoSuggestBoxText = newValue);
	}

	private bool _CertCNAutoSuggestBoxIsSuggestionListOpen;
	internal bool CertCNAutoSuggestBoxIsSuggestionListOpen
	{
		get => _CertCNAutoSuggestBoxIsSuggestionListOpen;
		set => SetProperty(_CertCNAutoSuggestBoxIsSuggestionListOpen, value, newValue => _CertCNAutoSuggestBoxIsSuggestionListOpen = newValue);
	}

	// Set the version in the settings card to the current app version
	internal readonly string VersionTextBlockText = $"Version {App.currentAppVersion}";


	// Set the year for the copyright section
	internal readonly string CopyRightSettingsExpanderDescription = $"© {DateTime.Now.Year}. All rights reserved.";

	#endregion

	// If user never clicked on the Refresh button and directly clicks inside of the AutoSuggestBox instead,
	// The certs must be retrieved and displayed. If Refresh button is first used, it won't be retrieved again when clicked inside of the AutoSuggestBox.
	private bool _InitialFetchComplete;

	/// <summary>
	/// Get all of the common names of the certificates in the user/my certificate stores
	/// And add them to the observable collection that is the source of the AutoSuggestBox
	/// </summary>
	private async Task FetchLatestCertificateCNsPrivate()
	{
		_InitialFetchComplete = true;

		IEnumerable<string> certCNs = await Task.Run(CertCNFetcher.GetCertCNs);

		CertCommonNames.Clear();
		CertCommonNamesList.Clear();

		foreach (string item in certCNs)
		{
			CertCommonNames.Add(item);
			CertCommonNamesList.Add(item);
		}

		CertCNAutoSuggestBoxIsSuggestionListOpen = true;
	}

	/// <summary>
	/// For the Refresh button that retrieves the latest certificate CNs
	/// </summary>
	internal async void FetchLatestCertificateCNs()
	{
		await FetchLatestCertificateCNsPrivate();
	}

	/// <summary>
	/// Handles the GotFocus event for the Certificate Common Name auto-suggest box. It opens the suggestion list when the
	/// box gains focus. Without this, the suggestion list would not open when the box is clicked, user would have to type something first.
	/// </summary>
	internal async void CertificateCommonNameAutoSuggestBox_GotFocus()
	{
		if (!_InitialFetchComplete)
		{
			_InitialFetchComplete = true;

			await FetchLatestCertificateCNsPrivate();
		}

		CertCNAutoSuggestBoxIsSuggestionListOpen = true;
	}


	/// <summary>
	/// Event handler for AutoSuggestBox
	/// </summary>
	internal void CertificateCNAutoSuggestBox_TextChanged()
	{
		if (CertCNsAutoSuggestBoxText is null)
			return;

		// Filter menu items based on the search query
		List<string> suggestions = [.. CertCommonNamesList.Where(name => name.Contains(CertCNsAutoSuggestBoxText, StringComparison.OrdinalIgnoreCase))];

		CertCommonNames.Clear();

		foreach (string item in suggestions)
		{
			CertCommonNames.Add(item);
		}
	}



	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

}
