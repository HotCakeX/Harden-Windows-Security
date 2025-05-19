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

using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.Pages;
using Microsoft.UI.Dispatching;

namespace AppControlManager.ViewModels;

internal sealed class WDACReportingVM
{
    private readonly DispatcherQueue _dispatcherQueue;
    private readonly WDACReporting _view;

    // Data collections
    internal HashSet<FileIdentity> AllEventData { get; private set; } = new();
    internal ObservableCollection<UserBlockStatistic> TopUserBlocks { get; } = new();
    internal ObservableCollection<FileBlockStatistic> TopFileBlocks { get; } = new();
    internal ObservableCollection<FileTypeBlockStatistic> TopFileTypeBlocks { get; } = new();
    internal ObservableCollection<DateBlockStatistic> BlocksByDate { get; } = new();

    // Filter properties
    internal DateTime StartDate { get; set; } = DateTime.Now.AddDays(-30);
    internal DateTime EndDate { get; set; } = DateTime.Now;
    internal bool IsDataLoaded { get; private set; }
    internal bool IsLoading { get; private set; }

    /// <summary>
    /// Initializes a new instance of the <see cref="WDACReportingVM"/> class.
    /// </summary>
    /// <param name="view">The view that owns this view model.</param>
    internal WDACReportingVM(WDACReporting view)
    {
        _view = view;
        _dispatcherQueue = DispatcherQueue.GetForCurrentThread();
    }

    /// <summary>
    /// Loads event data from event logs and processes it for reporting.
    /// </summary>
    /// <returns>A task representing the asynchronous operation.</returns>
    internal async Task LoadEventsData()
    {
        try
        {
            IsLoading = true;
            UpdateLoadingStatus(true, GlobalVars.Rizz.GetString("LoadingEventsMessage"));

            // Get event data from local logs
            HashSet<FileIdentity> eventData = await GetEventLogsData.GetAppControlEvents();
            
            AllEventData = eventData;
            IsDataLoaded = true;

            // Process and generate reports
            GenerateReports();

            UpdateLoadingStatus(false, "");
        }
        catch (Exception ex)
        {
            Logger.Write(ex.Message);
            _dispatcherQueue.TryEnqueue(() =>
            {
                MainWindow.ShowErrorDialogAsync(
                    GlobalVars.Rizz.GetString("ErrorDialogTitle"),
                    GlobalVars.Rizz.GetString("ErrorDialogContent"),
                    ex.Message).AsTask();
            });
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Applies date range filtering and regenerates reports.
    /// </summary>
    internal void ApplyDateFilter()
    {
        if (!IsDataLoaded)
            return;

        GenerateReports();
    }

    /// <summary>
    /// Processes data and generates all reports.
    /// </summary>
    private void GenerateReports()
    {
        try
        {
            UpdateLoadingStatus(true, GlobalVars.Rizz.GetString("GeneratingReportsMessage"));

            // Filter data by date range
            IEnumerable<FileIdentity> filteredData = AllEventData
                .Where(e => e.TimeCreated >= StartDate && e.TimeCreated <= EndDate);

            // Clear existing collections
            _dispatcherQueue.TryEnqueue(() =>
            {
                TopUserBlocks.Clear();
                TopFileBlocks.Clear();
                TopFileTypeBlocks.Clear();
                BlocksByDate.Clear();
            });

            // Generate top users report
            GenerateTopUsersReport(filteredData);

            // Generate top files report
            GenerateTopFilesReport(filteredData);

            // Generate file types report
            GenerateFileTypesReport(filteredData);

            // Generate time-based report
            GenerateTimeBasedReport(filteredData);

            UpdateLoadingStatus(false, "");
        }
        catch (Exception ex)
        {
            Logger.Write(ex.Message);
        }
    }

    /// <summary>
    /// Generates a report of top users triggering WDAC blocks.
    /// </summary>
    /// <param name="data">The filtered event data.</param>
    private void GenerateTopUsersReport(IEnumerable<FileIdentity> data)
    {
        var userGroups = data
            .Where(e => !string.IsNullOrEmpty(e.UserID) && e.Action == EventAction.Block)
            .GroupBy(e => e.UserID)
            .Select(g => new UserBlockStatistic
            {
                UserName = g.Key ?? "Unknown",
                BlockCount = g.Count(),
                UniqueFilesBlocked = g.Select(e => e.SHA256Hash ?? e.SHA256FlatHash ?? e.FilePath ?? e.FileName).Distinct().Count()
            })
            .OrderByDescending(u => u.BlockCount)
            .Take(10);

        _dispatcherQueue.TryEnqueue(() =>
        {
            foreach (var user in userGroups)
            {
                TopUserBlocks.Add(user);
            }
        });
    }

    /// <summary>
    /// Generates a report of top files blocked by WDAC.
    /// </summary>
    /// <param name="data">The filtered event data.</param>
    private void GenerateTopFilesReport(IEnumerable<FileIdentity> data)
    {
        var fileGroups = data
            .Where(e => e.Action == EventAction.Block)
            .GroupBy(e => new { Path = e.FilePath ?? "Unknown", Name = e.FileName ?? "Unknown" })
            .Select(g => new FileBlockStatistic
            {
                FilePath = g.Key.Path,
                FileName = g.Key.Name,
                BlockCount = g.Count(),
                UserCount = g.Select(e => e.UserID).Distinct().Count()
            })
            .OrderByDescending(f => f.BlockCount)
            .Take(10);

        _dispatcherQueue.TryEnqueue(() =>
        {
            foreach (var file in fileGroups)
            {
                TopFileBlocks.Add(file);
            }
        });
    }

    /// <summary>
    /// Generates a report of file types (extensions) most frequently blocked.
    /// </summary>
    /// <param name="data">The filtered event data.</param>
    private void GenerateFileTypesReport(IEnumerable<FileIdentity> data)
    {
        var fileTypeGroups = data
            .Where(e => e.Action == EventAction.Block && !string.IsNullOrEmpty(e.FileName))
            .GroupBy(e => GetFileExtension(e.FileName!))
            .Select(g => new FileTypeBlockStatistic
            {
                FileExtension = g.Key,
                BlockCount = g.Count(),
                UniqueFilesCount = g.Select(e => e.SHA256Hash ?? e.SHA256FlatHash ?? e.FilePath ?? e.FileName).Distinct().Count()
            })
            .OrderByDescending(t => t.BlockCount)
            .Take(10);

        _dispatcherQueue.TryEnqueue(() =>
        {
            foreach (var fileType in fileTypeGroups)
            {
                TopFileTypeBlocks.Add(fileType);
            }
        });
    }

    /// <summary>
    /// Generates a time-based report showing blocks by date.
    /// </summary>
    /// <param name="data">The filtered event data.</param>
    private void GenerateTimeBasedReport(IEnumerable<FileIdentity> data)
    {
        var dateGroups = data
            .Where(e => e.Action == EventAction.Block && e.TimeCreated.HasValue)
            .GroupBy(e => e.TimeCreated!.Value.Date)
            .Select(g => new DateBlockStatistic
            {
                Date = g.Key,
                BlockCount = g.Count(),
                UniqueUserCount = g.Select(e => e.UserID).Distinct().Count(),
                UniqueFilesCount = g.Select(e => e.SHA256Hash ?? e.SHA256FlatHash ?? e.FilePath ?? e.FileName).Distinct().Count()
            })
            .OrderBy(d => d.Date);

        _dispatcherQueue.TryEnqueue(() =>
        {
            foreach (var dateGroup in dateGroups)
            {
                BlocksByDate.Add(dateGroup);
            }
        });
    }

    /// <summary>
    /// Updates the loading status in the UI.
    /// </summary>
    /// <param name="isLoading">Whether data is currently loading.</param>
    /// <param name="message">The loading message to display.</param>
    private void UpdateLoadingStatus(bool isLoading, string message)
    {
        _dispatcherQueue.TryEnqueue(() =>
        {
            _view.LoadingIndicator.IsActive = isLoading;
            _view.LoadingMessage.Text = message;
            _view.LoadingMessage.Visibility = string.IsNullOrEmpty(message) ? Visibility.Collapsed : Visibility.Visible;
        });
    }

    /// <summary>
    /// Extracts the file extension from a file name.
    /// </summary>
    /// <param name="fileName">The file name.</param>
    /// <returns>The file extension, or "No Extension" if none is found.</returns>
    private static string GetFileExtension(string fileName)
    {
        int lastDotIndex = fileName.LastIndexOf('.');
        if (lastDotIndex < 0 || lastDotIndex == fileName.Length - 1)
            return "No Extension";
            
        string extension = fileName.Substring(lastDotIndex).ToLower();
        return string.IsNullOrEmpty(extension) ? "No Extension" : extension;
    }
}

/// <summary>
/// Represents statistics for a user triggering WDAC blocks.
/// </summary>
internal sealed class UserBlockStatistic
{
    public string UserName { get; set; } = string.Empty;
    public int BlockCount { get; set; }
    public int UniqueFilesBlocked { get; set; }
}

/// <summary>
/// Represents statistics for a file blocked by WDAC.
/// </summary>
internal sealed class FileBlockStatistic
{
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public int BlockCount { get; set; }
    public int UserCount { get; set; }
}

/// <summary>
/// Represents statistics for a file type blocked by WDAC.
/// </summary>
internal sealed class FileTypeBlockStatistic
{
    public string FileExtension { get; set; } = string.Empty;
    public int BlockCount { get; set; }
    public int UniqueFilesCount { get; set; }
}

/// <summary>
/// Represents statistics for WDAC blocks on a specific date.
/// </summary>
internal sealed class DateBlockStatistic
{
    public DateTime Date { get; set; }
    public int BlockCount { get; set; }
    public int UniqueUserCount { get; set; }
    public int UniqueFilesCount { get; set; }
}