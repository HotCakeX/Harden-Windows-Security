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

using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading.Tasks;

namespace AppControlManager.Pages;

/// <summary>
/// Provides a dashboard for reporting on WDAC blocks and audits with filtering capabilities.
/// </summary>
public sealed partial class WDACReporting : Page
{
    internal WDACReportingVM ViewModel { get; }
    internal GlobalVars Rizz { get; } = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="WDACReporting"/> class.
    /// </summary>
    public WDACReporting()
    {
        InitializeComponent();
        ViewModel = new WDACReportingVM(this);
    }

    /// <summary>
    /// Handles the click event of the Load Data button.
    /// </summary>
    /// <param name="sender">The source of the event.</param>
    /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
    private async void LoadData_Click(object sender, RoutedEventArgs e)
    {
        if (ViewModel.IsLoading)
            return;

        LoadDataButton.IsEnabled = false;
        try
        {
            await ViewModel.LoadEventsData();
        }
        catch (Exception ex)
        {
            Logger.Write(ex.Message);
            await MainWindow.ShowErrorDialogAsync(
                Rizz.GetString("ErrorDialogTitle"),
                Rizz.GetString("ErrorDialogContent"),
                ex.Message);
        }
        finally
        {
            LoadDataButton.IsEnabled = true;
        }
    }

    /// <summary>
    /// Handles the click event of the Apply Filter button.
    /// </summary>
    /// <param name="sender">The source of the event.</param>
    /// <param name="e">The <see cref="RoutedEventArgs"/> instance containing the event data.</param>
    private void ApplyFilter_Click(object sender, RoutedEventArgs e)
    {
        if (!ViewModel.IsDataLoaded || ViewModel.IsLoading)
            return;

        if (ValidateDateRange())
        {
            ViewModel.ApplyDateFilter();
        }
    }

    /// <summary>
    /// Validates that the date range is valid (start date is before end date).
    /// </summary>
    /// <returns><c>true</c> if the date range is valid; otherwise, <c>false</c>.</returns>
    private bool ValidateDateRange()
    {
        if (StartDatePicker.Date > EndDatePicker.Date)
        {
            _ = ShowInvalidDateRangeDialogAsync();
            return false;
        }

        return true;
    }

    /// <summary>
    /// Shows a dialog indicating that the date range is invalid.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    private async Task ShowInvalidDateRangeDialogAsync()
    {
        ContentDialog dialog = new()
        {
            XamlRoot = XamlRoot,
            Title = Rizz.GetString("InvalidDateRangeTitle"),
            Content = Rizz.GetString("InvalidDateRangeMessage"),
            CloseButtonText = Rizz.GetString("OKButtonText"),
            DefaultButton = ContentDialogButton.Close
        };

        await dialog.ShowAsync();
    }
}