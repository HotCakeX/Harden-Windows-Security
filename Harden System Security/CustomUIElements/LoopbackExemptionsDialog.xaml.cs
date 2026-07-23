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
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using AppControlManager.CustomUIElements;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements;

internal sealed partial class LoopbackExemptionsDialog : ContentDialogV2, INPCImplant
{
	private readonly IReadOnlyList<PackagedAppView> _installedApps;

	internal LoopbackExemptionsDialog(IReadOnlyList<PackagedAppView> installedApps)
	{
		InitializeComponent();
		_installedApps = installedApps;

		Title = Atlas.GetStr("LoopbackDialogTitle");
		CloseButtonText = Atlas.GetStr("LoopbackDialogCloseButtonText");

		RefreshEntries();
	}

	internal ObservableCollection<AppContainerLoopbackEntry> Entries { get; private set => this.SP(ref field, value); } = [];
	internal string SummaryText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string InfoBarMessage { get; private set => this.SP(ref field, value); } = string.Empty;
	internal InfoBarSeverity InfoBarSeverity { get; private set => this.SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool IsInfoBarOpen { get; private set => this.SP(ref field, value); }
	internal bool IsBusy
	{
		get; private set
		{
			if (this.SP(ref field, value))
			{
				RaisePropertyChanged(nameof(BusyVisibility));
				RaisePropertyChanged(nameof(ActionsAreEnabled));
			}
		}
	}

	internal bool HasChanges { get; private set; }
	internal Visibility BusyVisibility => IsBusy ? Visibility.Visible : Visibility.Collapsed;
	internal bool ActionsAreEnabled => !IsBusy;

	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	private void RefreshEntries() => ApplyEntries(AppContainerLoopbackManager.GetEntries(_installedApps));

	private void ApplyEntries(List<AppContainerLoopbackEntry> entries)
	{
		Entries = new ObservableCollection<AppContainerLoopbackEntry>(entries);

		int orphanedCount = entries.Count(static entry => entry.IsOrphanedEntry);

		SummaryText = string.Format(
			CultureInfo.CurrentCulture,
			Atlas.GetStr("LoopbackDialogSummaryText"),
			entries.Count,
			entries.Count,
			orphanedCount);
	}

	private void ShowInfo(string message, InfoBarSeverity severity = InfoBarSeverity.Informational)
	{
		InfoBarMessage = message;
		InfoBarSeverity = severity;
		IsInfoBarOpen = true;
	}

	private void ClearInfo()
	{
		IsInfoBarOpen = false;
		InfoBarMessage = string.Empty;
	}

	private void RefreshButton_Click()
	{
		try
		{
			IsBusy = true;
			ClearInfo();
			RefreshEntries();
			ShowInfo(Atlas.GetStr("LoopbackDialogRefreshSucceeded"));
		}
		catch (Exception ex)
		{
			ShowInfo(ex.Message, InfoBarSeverity.Error);
		}
		finally
		{
			IsBusy = false;
		}
	}

	/// <summary>
	/// Adds every eligible installed app to the loopback exemption list in one pass.
	/// </summary>
	private void AddAllButton_Click()
	{
		try
		{
			IsBusy = true;
			ClearInfo();

			int addedCount = AppContainerLoopbackManager.AddLoopbackExemptions(_installedApps);
			RefreshEntries();

			if (addedCount > 0)
			{
				HasChanges = true;
			}

			ShowInfo(
				string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("LoopbackDialogAddAllSucceeded"), addedCount),
				addedCount > 0 ? InfoBarSeverity.Success : InfoBarSeverity.Informational);
		}
		catch (Exception ex)
		{
			ShowInfo(ex.Message, InfoBarSeverity.Error);
		}
		finally
		{
			IsBusy = false;
		}
	}

	private void ClearAllButton_Click()
	{
		try
		{
			IsBusy = true;
			ClearInfo();

			AppContainerLoopbackManager.ClearLoopbackExemptions();
			RefreshEntries();

			HasChanges = true;
			ShowInfo(Atlas.GetStr("LoopbackDialogClearAllSucceeded"), InfoBarSeverity.Success);
		}
		catch (Exception ex)
		{
			ShowInfo(ex.Message, InfoBarSeverity.Error);
		}
		finally
		{
			IsBusy = false;
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void EntryActionButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not Button button || button.DataContext is not AppContainerLoopbackEntry entry || !entry.CanModify)
		{
			return;
		}

		try
		{
			IsBusy = true;
			ClearInfo();

			AppContainerLoopbackManager.SetLoopbackExemption(entry.Sid, false);
			ShowInfo(
				string.Format(
					CultureInfo.CurrentCulture,
					entry.IsInstalledApp ? Atlas.GetStr("LoopbackDialogAppRemovedMessage") : Atlas.GetStr("LoopbackDialogOrphanRemovedMessage"),
					entry.IsInstalledApp ? entry.DisplayName : entry.Sid),
				InfoBarSeverity.Success);

			RefreshEntries();
			HasChanges = true;
		}
		catch (Exception ex)
		{
			ShowInfo(ex.Message, InfoBarSeverity.Error);
		}
		finally
		{
			IsBusy = false;
		}
	}
}
