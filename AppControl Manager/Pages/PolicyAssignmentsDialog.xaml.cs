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
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Pages;

internal sealed partial class PolicyAssignmentsDialog : ContentDialogV2, INotifyPropertyChanged
{
	internal PolicyAssignmentsDialog(CiPolicyInfo policy, ViewOnlinePoliciesVM viewModel)
	{
		InitializeComponent();
		_policy = policy;
		_viewModel = viewModel;
		FlowDirection = Enum.Parse<FlowDirection>(viewModel.AppSettings.ApplicationGlobalFlowDirection);
	}

	private readonly CiPolicyInfo _policy;
	private readonly ViewOnlinePoliciesVM _viewModel;

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	internal string PolicyName => _policy.FriendlyName ?? "Policy";

	internal string TitleString
	{
		get; set
		{
			field = value;
			OnPropertyChanged();
		}
	} = "Policy Assignments";

	internal bool IsLoading
	{
		get; set
		{
			field = value;
			OnPropertyChanged();
		}
	}

	internal Visibility NoAssignmentsVisibility
	{
		get; set
		{
			field = value;
			OnPropertyChanged();
		}
	} = Visibility.Collapsed;

	internal Visibility AssignmentsListVisibility
	{
		get; set
		{
			field = value;
			OnPropertyChanged();
		}
	} = Visibility.Collapsed;

	internal readonly ObservableCollection<PolicyAssignmentDisplay> Assignments = [];

	private async void PolicyAssignmentsDialog_Loaded(object sender, RoutedEventArgs e) => await LoadAssignments();

	private void UpdateTitle() => TitleString = $"Policy Assignments ({Assignments.Count})";

	private async Task LoadAssignments()
	{
		try
		{
			IsLoading = true;
			NoAssignmentsVisibility = Visibility.Collapsed;
			AssignmentsListVisibility = Visibility.Collapsed;
			Assignments.Clear();
			UpdateTitle();

			List<PolicyAssignmentDisplay> items = await _viewModel.GetPolicyAssignments(_policy);

			foreach (PolicyAssignmentDisplay item in items)
			{
				Assignments.Add(item);
			}

			UpdateTitle();

			if (Assignments.Count > 0)
			{
				AssignmentsListVisibility = Visibility.Visible;
				NoAssignmentsVisibility = Visibility.Collapsed;
			}
			else
			{
				AssignmentsListVisibility = Visibility.Collapsed;
				NoAssignmentsVisibility = Visibility.Visible;
			}
		}
		catch (Exception ex)
		{
			_viewModel.MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsLoading = false;
		}
	}

	private async void DeleteAssignment_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.DataContext is PolicyAssignmentDisplay assignment)
		{
			if (string.IsNullOrEmpty(assignment.AssignmentId) || string.IsNullOrEmpty(_policy.IntunePolicyObjectID))
			{
				return;
			}

			button.IsEnabled = false;
			IsLoading = true;

			try
			{
				await _viewModel.DeleteAssignmentAsync(
					_policy.IntunePolicyObjectID,
					assignment.AssignmentId,
					_policy.IsManagedInstaller);

				// Remove from local collection
				_ = Assignments.Remove(assignment);
				UpdateTitle();

				// Update visibility
				if (Assignments.Count == 0)
				{
					AssignmentsListVisibility = Visibility.Collapsed;
					NoAssignmentsVisibility = Visibility.Visible;
				}
			}
			catch (Exception ex)
			{
				_viewModel.MainInfoBar.WriteError(ex);
			}
			finally
			{
				button.IsEnabled = true;
				IsLoading = false;
			}
		}
	}
}
