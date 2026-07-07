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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;
using CommonCore.ToolKits;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Media.Core;
using Windows.Storage;
using Windows.Storage.FileProperties;
using Windows.Storage.Streams;

namespace HardenSystemSecurity.ViewModels;

internal enum DownloadState
{
	Queued,
	Running,
	Paused,
	Completed,
	Failed,
	Interrupted,
	Deleted
}

internal enum DownloadCompletionAction
{
	None,
	Shutdown,
	Sleep,
	Hibernate
}

internal enum ExistingDownloadConflictBehavior
{
	Ask,
	Overwrite,
	AddDuplicate
}

internal enum DownloadSpeedPreset
{
	Full,
	Medium,
	Slow
}

internal sealed partial class DownloadManagerItem : ViewModelBase
{
	internal static readonly Brush CompletedStatusBrush = new SolidColorBrush(Colors.SpringGreen);
	internal static readonly Brush DownloadingStatusBrush = new SolidColorBrush(Colors.DeepSkyBlue);
	internal static readonly Brush PausedStatusBrush = new SolidColorBrush(Colors.DarkOrange);
	internal static readonly Brush FailedStatusBrush = new SolidColorBrush(Colors.IndianRed);
	internal static readonly Brush InterruptedStatusBrush = new SolidColorBrush(Colors.OrangeRed);
	internal static readonly Brush QueuedStatusBrush = new SolidColorBrush(Colors.SlateGray);
	internal static readonly Brush DeletedStatusBrush = new SolidColorBrush(Colors.DimGray);
	internal static readonly Brush MissingFileStatusBrush = new SolidColorBrush(Colors.Goldenrod);
	internal static readonly Brush UnknownStatusBrush = new SolidColorBrush(Colors.Gray);

	internal string SourceUrl { get; set => _ = SP(ref field, value ?? string.Empty); } = string.Empty;

	internal string DisplayName
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = string.Empty;

	internal string DestinationDirectory
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = string.Empty;

	internal string FilePath
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = string.Empty;

	internal string TemporaryFilePath
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = string.Empty;

	internal string CheckpointFilePath
	{
		get; set
		{
			if (SP(ref field, value ?? string.Empty))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = string.Empty;

	internal DownloadState State
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = DownloadState.Queued;

	internal long BytesReceived
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal long? TotalBytes
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal bool SupportsRangeRequests
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal int ParallelConnectionsUsed
	{
		get; set
		{
			int normalized = Math.Max(1, value);
			if (SP(ref field, normalized))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	} = 1;

	internal long CurrentBytesPerSecond
	{
		get; set
		{
			long normalized = Math.Max(0, value);
			if (SP(ref field, normalized))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal ImageSource? PreviewImageSource
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal bool IsPreviewLoading
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal bool IsVideoPreviewHoverActive
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal string? ErrorMessage
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal DateTimeOffset CreatedAtUtc { get; init; } = DateTimeOffset.UtcNow;
	internal DateTimeOffset? ServerFileTimestampUtc
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(AddedAtText));
			}
		}
	}

	internal DateTimeOffset? CompletedAtUtc
	{
		get; set
		{
			if (SP(ref field, value))
			{
				NotifyComputedPropertiesChanged();
			}
		}
	}

	internal string StatusText => State switch
	{
		DownloadState.Queued => "Queued",
		DownloadState.Running => "Downloading",
		DownloadState.Paused => "Paused",
		DownloadState.Completed when !IsFileAvailable => "File missing",
		DownloadState.Completed => "Downloaded",
		DownloadState.Failed => "Failed",
		DownloadState.Interrupted => "Interrupted",
		DownloadState.Deleted => "Deleted",
		_ => "Unknown"
	};

	internal string ProgressText =>
		TotalBytes.HasValue && TotalBytes.Value > 0
			? $"{HomeVM.FormatDataSize(BytesReceived)} / {HomeVM.FormatDataSize(TotalBytes.Value)}"
			: HomeVM.FormatDataSize(BytesReceived);

	internal double ProgressValue =>
		TotalBytes.HasValue && TotalBytes.Value > 0
			? Math.Clamp(BytesReceived / (double)TotalBytes.Value * 100D, 0D, 100D)
			: State is DownloadState.Completed ? 100D : 0D;

	internal bool IsProgressIndeterminate => State is DownloadState.Running && (!TotalBytes.HasValue || TotalBytes.Value <= 0);

	internal Visibility ProgressVisibility =>
		State is DownloadState.Queued or DownloadState.Running || TotalBytes.HasValue
			? Visibility.Visible
			: Visibility.Collapsed;

	internal bool IsFileAvailable => File.Exists(FilePath);
	internal bool IsDirectoryAvailable => Directory.Exists(DestinationDirectory);
	internal bool CanResumeDownload => State is DownloadState.Paused or DownloadState.Interrupted or DownloadState.Failed;
	internal bool CanPauseOrResumeDownload => State is DownloadState.Running || CanResumeDownload;
	internal bool CanChangeDownloadLink => State is not DownloadState.Running and not DownloadState.Completed and not DownloadState.Deleted;
	internal string PauseOrResumeGlyph => State is DownloadState.Running ? "\uE769" : "\uE768";
	internal string PauseOrResumeToolTip => State is DownloadState.Running ? "Pause download" : "Resume download";
	internal Visibility PreviewVisibility => PreviewImageSource is null ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility PreviewPlaceholderVisibility => PreviewImageSource is null && !(IsVideoPreviewHoverActive && CanHoverPlayVideoPreview) ? Visibility.Visible : Visibility.Collapsed;
	internal Stretch PreviewImageStretch => HasFullBleedPreview ? Stretch.UniformToFill : Stretch.Uniform;
	internal Thickness PreviewImageMargin => HasFullBleedPreview ? new(0) : new(10);
	internal bool CanHoverPlayVideoPreview => IsFileAvailable && !string.IsNullOrWhiteSpace(FilePath) && DownloadManagerVM.VideoExtensions.Contains(Path.GetExtension(FilePath));
	internal Visibility HoverVideoPreviewVisibility => IsVideoPreviewHoverActive && CanHoverPlayVideoPreview ? Visibility.Visible : Visibility.Collapsed;
	internal MediaSource? HoverVideoPreviewSource => IsVideoPreviewHoverActive && CanHoverPlayVideoPreview ? MediaSource.CreateFromUri(new Uri(FilePath)) : null;
	internal Visibility VideoPreviewHintVisibility => CanHoverPlayVideoPreview && !IsVideoPreviewHoverActive ? Visibility.Visible : Visibility.Collapsed;
	internal string AddedAtText => ServerFileTimestampUtc.HasValue
		? $"Added {CreatedAtUtc.ToLocalTime():g} • Server {ServerFileTimestampUtc.Value.ToLocalTime():g}"
		: $"Added {CreatedAtUtc.ToLocalTime():g}";
	internal string DownloadSpeedText => CurrentBytesPerSecond > 0 ? $"{HomeVM.FormatDataSize(CurrentBytesPerSecond)}/s" : "Calculating speed...";
	internal string? TimeRemainingText
	{
		get
		{
			if (State is not DownloadState.Running || !TotalBytes.HasValue || TotalBytes.Value <= 0)
			{
				return null;
			}

			long remainingBytes = Math.Max(0, TotalBytes.Value - BytesReceived);
			if (remainingBytes == 0)
			{
				return "Remaining: 0 seconds";
			}
			if (CurrentBytesPerSecond <= 0)
			{
				return "Remaining: Calculating...";
			}
			long totalSeconds = remainingBytes / CurrentBytesPerSecond;
			if (remainingBytes % CurrentBytesPerSecond != 0)
			{
				totalSeconds++;
			}
			return $"Remaining: {FormatRemainingDuration(totalSeconds)}";
		}
	}

	internal Brush StatusForeground => State switch
	{
		DownloadState.Completed when !IsFileAvailable => MissingFileStatusBrush,
		DownloadState.Completed => CompletedStatusBrush,
		DownloadState.Running => DownloadingStatusBrush,
		DownloadState.Paused => PausedStatusBrush,
		DownloadState.Failed => FailedStatusBrush,
		DownloadState.Interrupted => InterruptedStatusBrush,
		DownloadState.Queued => QueuedStatusBrush,
		DownloadState.Deleted => DeletedStatusBrush,
		_ => UnknownStatusBrush
	};

	internal string PreviewPlaceholderText => IsPreviewLoading
		? "Loading preview..."
		: IsFileAvailable
			? "Preview unavailable"
			: "No preview yet";

	internal string StatusSummary =>
		ErrorMessage is not null && State is DownloadState.Failed or DownloadState.Interrupted
			? $"{StatusText}: {ErrorMessage}"
			: State is DownloadState.Running
				? $"{StatusText} • {DownloadSpeedText} • {ProgressText} • {TimeRemainingText}"
				: $"{StatusText} • {ProgressText}";

	internal string TransferModeSummary => SupportsRangeRequests
		? ParallelConnectionsUsed > 1
			? $"Resumable • {ParallelConnectionsUsed} parallel connections"
			: "Resumable • Single Connection"
		: "Not Resumable";

	private void NotifyComputedPropertiesChanged()
	{
		OnPropertyChanged(nameof(StatusText));
		OnPropertyChanged(nameof(ProgressText));
		OnPropertyChanged(nameof(ProgressValue));
		OnPropertyChanged(nameof(IsProgressIndeterminate));
		OnPropertyChanged(nameof(ProgressVisibility));
		OnPropertyChanged(nameof(IsFileAvailable));
		OnPropertyChanged(nameof(IsDirectoryAvailable));
		OnPropertyChanged(nameof(CanResumeDownload));
		OnPropertyChanged(nameof(CanPauseOrResumeDownload));
		OnPropertyChanged(nameof(CanChangeDownloadLink));
		OnPropertyChanged(nameof(PauseOrResumeGlyph));
		OnPropertyChanged(nameof(PauseOrResumeToolTip));
		OnPropertyChanged(nameof(AddedAtText));
		OnPropertyChanged(nameof(DownloadSpeedText));
		OnPropertyChanged(nameof(TimeRemainingText));
		OnPropertyChanged(nameof(StatusForeground));
		OnPropertyChanged(nameof(PreviewVisibility));
		OnPropertyChanged(nameof(PreviewPlaceholderVisibility));
		OnPropertyChanged(nameof(PreviewImageStretch));
		OnPropertyChanged(nameof(PreviewImageMargin));
		OnPropertyChanged(nameof(PreviewPlaceholderText));
		OnPropertyChanged(nameof(CanHoverPlayVideoPreview));
		OnPropertyChanged(nameof(HoverVideoPreviewVisibility));
		OnPropertyChanged(nameof(HoverVideoPreviewSource));
		OnPropertyChanged(nameof(VideoPreviewHintVisibility));
		OnPropertyChanged(nameof(StatusSummary));
		OnPropertyChanged(nameof(TransferModeSummary));
	}

	private static string FormatRemainingDuration(long totalSeconds)
	{
		const long SecondsPerMinute = 60;
		const long SecondsPerHour = SecondsPerMinute * 60;
		const long SecondsPerDay = SecondsPerHour * 24;
		if (totalSeconds <= 0)
		{
			return "0 seconds";
		}
		if (totalSeconds >= SecondsPerDay)
		{
			long days = totalSeconds / SecondsPerDay;
			long hours = totalSeconds % SecondsPerDay / SecondsPerHour;
			return hours > 0 ? $"{FormatDurationUnit(days, "day")} {FormatDurationUnit(hours, "hour")}" : FormatDurationUnit(days, "day");
		}
		if (totalSeconds >= SecondsPerHour)
		{
			long hours = totalSeconds / SecondsPerHour;
			long minutes = totalSeconds % SecondsPerHour / SecondsPerMinute;
			return minutes > 0 ? $"{FormatDurationUnit(hours, "hour")} {FormatDurationUnit(minutes, "minute")}" : FormatDurationUnit(hours, "hour");
		}
		if (totalSeconds >= SecondsPerMinute)
		{
			long minutes = totalSeconds / SecondsPerMinute;
			long seconds = totalSeconds % SecondsPerMinute;
			return seconds > 0 ? $"{FormatDurationUnit(minutes, "minute")} {FormatDurationUnit(seconds, "second")}" : FormatDurationUnit(minutes, "minute");
		}
		return FormatDurationUnit(totalSeconds, "second");
	}
	private static string FormatDurationUnit(long value, string singularUnit) => value == 1 ? $"1 {singularUnit}" : $"{value} {singularUnit}s";
	private bool HasFullBleedPreview
	{
		get
		{
			if (string.IsNullOrWhiteSpace(FilePath))
			{
				return false;
			}

			string extension = Path.GetExtension(FilePath);
			return DownloadManagerVM.VideoExtensions.Contains(extension) || DownloadManagerVM.PictureExtensions.Contains(extension);
		}
	}
}

internal sealed partial class DownloadManagerVM : ViewModelBase
{
	// Download Manager persistence overview:
	//
	// 1. The in-app history list is saved to DownloadManagerHistory.json in the app-local data folder
	//    (ApplicationData.Current.LocalFolder). Each entry stores the user-facing metadata that must
	//    survive app restarts, such as the original URL, display name, selected destination directory,
	//    current state, byte counters, timestamps, and the last effective connection count the runtime used.
	//
	// 2. Every individual download also has two durable files that preserve resume state:
	//    - <filename>.hssdownload.part : the partial payload stored in the same target directory and named
	//      from the final file path, so while a download is in progress the .part file exists there and is
	//      later renamed in-place to the final name without extra copies.
	//    - a checkpoint JSON stored under ApplicationData.Current.LocalFolder\DownloadManagerCheckpoints,
	//      keyed by the final file path. That JSON contains the segment map, total size, range-support
	//      information, and the file paths required to recover the download after shutdown, crashes, or
	//      sudden power loss without cluttering the user's Downloads folder.
	//
	// 3. The final file itself is written into the resolved download directory (default OS Downloads
	//    folder unless the user selected a custom directory). Resume recovery works by reopening the
	//    checkpoint sidecar, continuing to write into the .part file, and only replacing the final file
	//    when the checkpoint proves that all byte ranges were completed successfully.
	//
	// 4. History and checkpoint writes are done atomically, so both the list-view state and the resumable
	//    on-disk state remain consistent even when the app or the OS stops unexpectedly mid-download.
	[method: JsonConstructor]
	private sealed class DownloadHistoryRecord(
		string sourceUrl,
		string displayName,
		string destinationDirectory,
		string filePath,
		DownloadState state,
		long bytesReceived,
		long? totalBytes,
		string? errorMessage,
		DateTimeOffset createdAtUtc,
		DateTimeOffset? completedAtUtc,
		string temporaryFilePath = "",
		string checkpointFilePath = "",
		bool supportsRangeRequests = false,
		int parallelConnectionsUsed = 1,
		DateTimeOffset? serverFileTimestampUtc = null)
	{
		public string SourceUrl => sourceUrl;
		public string DisplayName => displayName;
		public string DestinationDirectory => destinationDirectory;
		public string FilePath => filePath;
		public DownloadState State => state;
		public long BytesReceived => bytesReceived;
		public long? TotalBytes => totalBytes;
		public string? ErrorMessage => errorMessage;
		public DateTimeOffset CreatedAtUtc => createdAtUtc;
		public DateTimeOffset? CompletedAtUtc => completedAtUtc;
		public string TemporaryFilePath => temporaryFilePath;
		public string CheckpointFilePath => checkpointFilePath;
		public bool SupportsRangeRequests => supportsRangeRequests;
		public int ParallelConnectionsUsed => parallelConnectionsUsed;
		public DateTimeOffset? ServerFileTimestampUtc => serverFileTimestampUtc;
	}

	private sealed partial class DownloadMetadataResponse(HttpResponseMessage response, bool canReuseResponseBody, DateTimeOffset? serverFileTimestampUtc) : IDisposable
	{
		internal HttpResponseMessage Response => response;
		internal bool CanReuseResponseBody => canReuseResponseBody;
		internal DateTimeOffset? ServerFileTimestampUtc => serverFileTimestampUtc;

		public void Dispose() => response.Dispose();
	}

	private sealed class DownloadCheckpointRecord
	{
		public string SourceUrl { get; set; } = string.Empty;
		public string DestinationDirectory { get; set; } = string.Empty;
		public string FinalFilePath { get; set; } = string.Empty;
		public string TemporaryFilePath { get; set; } = string.Empty;
		public string CheckpointFilePath { get; set; } = string.Empty;
		public long? TotalBytes { get; set; }
		public bool SupportsRangeRequests { get; set; }
		public int ParallelConnectionsUsed { get; set; } = 1;
		public DateTimeOffset CreatedAtUtc { get; set; }
		public DateTimeOffset? ServerFileTimestampUtc { get; set; }
		public DateTimeOffset UpdatedAtUtc { get; set; } = DateTimeOffset.UtcNow;
		public List<DownloadSegmentRecord> Segments { get; set; } = [];
	}

	private sealed class DownloadSegmentRecord
	{
		public long StartOffset { get; set; }
		public long EndOffsetInclusive { get; set; } = -1;
		public long NextOffset { get; set; }
	}

	private sealed class DownloadRuntimeState(DownloadCheckpointRecord checkpoint)
	{
		internal DownloadCheckpointRecord Checkpoint => checkpoint;

		internal readonly Lock SyncRoot = new();
		internal DateTimeOffset LastCheckpointPersistUtc { get; set; } = DateTimeOffset.MinValue;
		internal DateTimeOffset LastHistoryPersistUtc { get; set; } = DateTimeOffset.MinValue;
		internal DateTimeOffset LastUiRefreshUtc { get; set; } = DateTimeOffset.MinValue;
		internal DateTimeOffset LastDataFlushUtc { get; set; } = DateTimeOffset.MinValue;
		internal DateTimeOffset LastSpeedSampleUtc { get; set; } = DateTimeOffset.MinValue;
		internal long LastSpeedSampleBytes { get; set; }
		internal double SmoothedBytesPerSecond { get; set; }
	}

	private sealed class ActiveDownloadOperation(CancellationTokenSource cancellationTokenSource)
	{
		internal CancellationTokenSource CancellationTokenSource => cancellationTokenSource;
		internal bool PauseRequested { get; set; }
		internal bool RestartRequested { get; set; }
		internal bool DeleteRequested { get; set; }
		internal readonly TaskCompletionSource<bool> CompletionSource = new(TaskCreationOptions.RunContinuationsAsynchronously);
	}

	private sealed class DownloadPreparationResult(
		DownloadCheckpointRecord checkpoint,
		bool useParallelConnections,
		HttpResponseMessage? initialResponse = null)
	{
		internal DownloadCheckpointRecord Checkpoint => checkpoint;
		internal bool UseParallelConnections => useParallelConnections;
		internal HttpResponseMessage? InitialResponse => initialResponse;
	}

	internal sealed class SettingOption(string label, int value)
	{
		internal string Label => label;
		internal int Value => value;

		public override string ToString() => Label;
	}

	private sealed class SharedDownloadRateLimiter
	{
		private readonly Lock _lock = new();
		private long _nextAvailableTimestamp;

		internal void Reset()
		{
			lock (_lock)
			{
				_nextAvailableTimestamp = 0;
			}
		}

		internal async Task WaitAsync(int bytes, Func<int> getBytesPerSecond, CancellationToken cancellationToken)
		{
			if (bytes <= 0)
			{
				return;
			}

			int bytesPerSecond = getBytesPerSecond();
			if (bytesPerSecond <= 0)
			{
				return;
			}

			TimeSpan delay;

			lock (_lock)
			{
				long now = Stopwatch.GetTimestamp();
				long effectiveTimestamp = Math.Max(now, _nextAvailableTimestamp);
				long requiredTicks = (long)Math.Ceiling(bytes * (double)Stopwatch.Frequency / bytesPerSecond);
				_nextAvailableTimestamp = checked(effectiveTimestamp + requiredTicks);
				long delayTicks = effectiveTimestamp - now;
				if (delayTicks <= 0)
				{
					return;
				}

				delay = TimeSpan.FromSeconds(delayTicks / (double)Stopwatch.Frequency);
			}

			while (delay > TimeSpan.Zero)
			{
				TimeSpan boundedDelay = delay > TimeSpan.FromMilliseconds(250)
					? TimeSpan.FromMilliseconds(250)
					: delay;
				await Task.Delay(boundedDelay, cancellationToken).ConfigureAwait(false);
				delay -= boundedDelay;
			}
		}
	}

	private static readonly Regex LinkRegex = MyRegex();

	private static readonly HttpClient DownloadHttpClient = new(new SocketsHttpHandler
	{
		PooledConnectionLifetime = TimeSpan.FromMinutes(15)
	});

	private static readonly string _checkpointDirectoryPath = Path.Join(ApplicationData.Current.LocalFolder.Path, "DownloadManagerCheckpoints");

	internal static readonly HashSet<string> PictureExtensions = new(StringComparer.OrdinalIgnoreCase) { ".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".tif", ".tiff" };

	internal static readonly HashSet<string> VideoExtensions = new(StringComparer.OrdinalIgnoreCase) { ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v", ".mpeg", ".mpg" };

	private static readonly FrozenSet<string> MarkOfTheWebExtensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
	{
		".appinstaller", ".application", ".appref-ms", ".appx", ".appxbundle", ".bat", ".cab", ".cmd", ".com",
		".cpl", ".dll", ".exe", ".hta", ".inf", ".ins", ".isp", ".jar", ".js", ".jse", ".lnk", ".msc", ".msi",
		".msix", ".msixbundle", ".msp", ".mst", ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".psd1",
		".psm1", ".reg", ".scr", ".sct", ".sys", ".vb", ".vbe", ".vbs", ".vxd", ".wsc", ".wsf", ".wsh"
	}.ToFrozenSet<string>(StringComparer.OrdinalIgnoreCase);

	private static readonly Lock _atomicWriteLock = new();

	private static readonly FrozenSet<HttpStatusCode> RetryableStatusCodes = new HashSet<HttpStatusCode>
	{
		HttpStatusCode.RequestTimeout,
		HttpStatusCode.TooManyRequests,
		HttpStatusCode.InternalServerError,
		HttpStatusCode.BadGateway,
		HttpStatusCode.ServiceUnavailable,
		HttpStatusCode.GatewayTimeout
	}.ToFrozenSet();

	private const int MaxTransientRetryAttempts = 3;
	private const uint TokenAdjustPrivileges = 0x00000020;
	private const uint TokenQuery = 0x00000008;
	private const uint SePrivilegeEnabled = 0x00000002;
	private const uint EwxShutdown = 0x00000001;
	private const uint EwxPowerOff = 0x00000008;
	private const uint EwxForce = 0x00000004;
	private const uint ShtdnReasonMajorOperatingSystem = 0x00020000;
	private const uint ShtdnReasonMinorReconfig = 0x00000004;
	private const uint ShtdnReasonFlagPlanned = 0x80000000;
	private const string ShutdownPrivilegeName = "SeShutdownPrivilege";
	internal static readonly Guid DownloadsFolderGuid = new("374DE290-123F-4565-9164-39C4925E467B");

	static DownloadManagerVM() => DownloadHttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(Atlas.UserAgent);

	private readonly Queue<DownloadManagerItem> _pendingDownloads = new();
	private readonly Lock _queueLock = new();
	private readonly Lock _historyLock = new();
	private readonly Lock _activeDownloadsLock = new();
	private readonly Lock _completionActionLock = new();
	private readonly SharedDownloadRateLimiter _rateLimiter = new();
	private readonly Dictionary<DownloadManagerItem, ActiveDownloadOperation> _activeDownloads = [];
	private readonly Dictionary<DownloadManagerItem, DownloadRuntimeState> _activeDownloadRuntimes = [];
	private readonly List<DownloadManagerItem> _selectedDownloadItems = [];
	private readonly ListViewHelper.SortState _sortState = new();
	private readonly string _historyFilePath = Path.Join(ApplicationData.Current.LocalFolder.Path, "DownloadManagerHistory.json");
	private FrameworkElement? _downloadManagerPresetsSectionHeader;
	private int _activeDownloadCount;
	private bool _completionActionTriggered;
	private bool _scrollPresetLimitsIntoViewOnNextSettingsNavigation;

	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly ObservableCollection<DownloadManagerItem> DownloadItems = [];
	internal readonly ObservableCollection<DownloadManagerItem> FilteredDownloadItems = [];
	internal readonly List<SettingOption> DownloadCompletionActionOptions =
	[
		new("Do nothing", (int)DownloadCompletionAction.None),
		new("Shut down the computer", (int)DownloadCompletionAction.Shutdown),
		new("Put the computer to sleep", (int)DownloadCompletionAction.Sleep),
		new("Hibernate the computer", (int)DownloadCompletionAction.Hibernate)
	];

	internal readonly List<SettingOption> ExistingDownloadConflictBehaviorOptions =
	[
		new("Ask", (int)ExistingDownloadConflictBehavior.Ask),
		new("Overwrite", (int)ExistingDownloadConflictBehavior.Overwrite),
		new("Add duplicate", (int)ExistingDownloadConflictBehavior.AddDuplicate)
	];

	internal DownloadManagerVM()
	{
		FullPresetKilobytesPerSecond = Math.Clamp(Atlas.Settings.DownloadManagerFullPresetKilobytesPerSecond > 0
				? Atlas.Settings.DownloadManagerFullPresetKilobytesPerSecond
				: Math.Max(MediumPresetKilobytesPerSecond, 1_000), 1, 1_048_576);

		ActiveSpeedPreset = Atlas.Settings.DownloadManagerSelectedSpeedPreset switch
		{
			(int)DownloadSpeedPreset.Slow => DownloadSpeedPreset.Slow,
			(int)DownloadSpeedPreset.Medium => DownloadSpeedPreset.Medium,
			_ => DownloadSpeedPreset.Full
		};
		CompletionAction = (DownloadCompletionAction)Math.Clamp(Atlas.Settings.DownloadManagerCompletionAction, 0, (int)DownloadCompletionAction.Hibernate);
		ExistingDownloadConflictBehavior = (ExistingDownloadConflictBehavior)Math.Clamp(Atlas.Settings.DownloadManagerExistingDownloadConflictBehavior, 0, (int)ExistingDownloadConflictBehavior.AddDuplicate);
		RemoveCompletedDownloadsFromList = Atlas.Settings.DownloadManagerRemoveCompletedItemsFromList;
		LoadHistory();
		_ = ApplyParallelConnectionsPreferenceToAllItemsAsync(ParallelConnectionsPerDownload);

		foreach (DownloadManagerItem item in DownloadItems)
		{
			if (item.IsFileAvailable)
			{
				_ = RefreshPreviewAsync(item);
			}
		}

		RefreshFilteredDownloadItemsCore(DownloadItems.ToList());
		UpdateEmptyStateVisibility();
	}

	internal string CustomDownloadDirectorySetting
	{
		get; set
		{
			string normalized = string.IsNullOrWhiteSpace(value)
				? string.Empty
				: Path.GetFullPath(value);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerDirectory = field;
				OnPropertyChanged(nameof(ResolvedDownloadDirectory));
				OnPropertyChanged(nameof(IsUsingDefaultDownloadDirectory));
				OnPropertyChanged(nameof(CanRestoreDefaultDownloadDirectory));
			}
		}
	} = Atlas.Settings.DownloadManagerDirectory;

	internal bool IsFullPresetUnlimited
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.DownloadManagerIsFullPresetUnlimited = field;
				OnPropertyChanged(nameof(CanEditFullPresetLimit));
				OnPropertyChanged(nameof(ActiveSpeedPresetText));
				OnPropertyChanged(nameof(ActiveSpeedPresetToolTip));
				OnPropertyChanged(nameof(ActiveSpeedPresetGlyph));
				OnPropertyChanged(nameof(ActiveSpeedPresetBrush));
				_ = RefreshActiveDownloadRateLimitsAsync();
			}
		}
	} = Atlas.Settings.DownloadManagerIsFullPresetUnlimited;

	internal DownloadSpeedPreset ActiveSpeedPreset
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.DownloadManagerSelectedSpeedPreset = (int)field;
				OnPropertyChanged(nameof(ActiveSpeedPresetText));
				OnPropertyChanged(nameof(ActiveSpeedPresetToolTip));
				OnPropertyChanged(nameof(ActiveSpeedPresetGlyph));
				OnPropertyChanged(nameof(ActiveSpeedPresetBrush));
				_ = RefreshActiveDownloadRateLimitsAsync();
			}
		}
	}

	internal int MaximumSimultaneousDownloads
	{
		get; set
		{
			int normalized = Math.Clamp(value, 1, 16);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerMaximumSimultaneousDownloads = field;
				OnPropertyChanged(nameof(MaximumSimultaneousDownloadsValue));
				ProcessPendingDownloads();
			}
		}
	} = Atlas.Settings.DownloadManagerMaximumSimultaneousDownloads;

	internal int ParallelConnectionsPerDownload
	{
		get; set
		{
			int normalized = Math.Clamp(value, 1, 32);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerParallelConnectionsPerDownload = field;
				OnPropertyChanged(nameof(ParallelConnectionsPerDownloadValue));
				_ = ApplyParallelConnectionsPreferenceToAllItemsAsync(normalized);
			}
		}
	} = Atlas.Settings.DownloadManagerParallelConnectionsPerDownload;

	internal int SlowPresetKilobytesPerSecond
	{
		get; set
		{
			int normalized = Math.Clamp(value, 1, 1_048_576);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerSlowPresetKilobytesPerSecond = field;
				OnPropertyChanged(nameof(SlowPresetKilobytesPerSecondValue));
				OnPropertyChanged(nameof(ActiveSpeedPresetText));
				OnPropertyChanged(nameof(ActiveSpeedPresetToolTip));
				OnPropertyChanged(nameof(ActiveSpeedPresetGlyph));
				OnPropertyChanged(nameof(ActiveSpeedPresetBrush));
				_ = RefreshActiveDownloadRateLimitsAsync();
			}
		}
	} = Atlas.Settings.DownloadManagerSlowPresetKilobytesPerSecond;

	internal int MediumPresetKilobytesPerSecond
	{
		get; set
		{
			int normalized = Math.Clamp(value, 1, 1_048_576);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerMediumPresetKilobytesPerSecond = field;
				OnPropertyChanged(nameof(MediumPresetKilobytesPerSecondValue));
				OnPropertyChanged(nameof(ActiveSpeedPresetText));
				OnPropertyChanged(nameof(ActiveSpeedPresetToolTip));
				OnPropertyChanged(nameof(ActiveSpeedPresetGlyph));
				OnPropertyChanged(nameof(ActiveSpeedPresetBrush));
				_ = RefreshActiveDownloadRateLimitsAsync();
			}
		}
	} = Atlas.Settings.DownloadManagerMediumPresetKilobytesPerSecond;

	internal int FullPresetKilobytesPerSecond
	{
		get; set
		{
			int normalized = Math.Clamp(value, 1, 1_048_576);
			if (SP(ref field, normalized))
			{
				Atlas.Settings.DownloadManagerFullPresetKilobytesPerSecond = field;
				OnPropertyChanged(nameof(FullPresetKilobytesPerSecondValue));
				OnPropertyChanged(nameof(ActiveSpeedPresetText));
				OnPropertyChanged(nameof(ActiveSpeedPresetToolTip));
				OnPropertyChanged(nameof(ActiveSpeedPresetGlyph));
				OnPropertyChanged(nameof(ActiveSpeedPresetBrush));
				_ = RefreshActiveDownloadRateLimitsAsync();
			}
		}
	}

	internal DownloadCompletionAction CompletionAction
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.DownloadManagerCompletionAction = (int)field;
				OnPropertyChanged(nameof(CompletionActionValue));
			}
		}
	}

	internal ExistingDownloadConflictBehavior ExistingDownloadConflictBehavior
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.DownloadManagerExistingDownloadConflictBehavior = (int)field;
				OnPropertyChanged(nameof(ExistingDownloadConflictBehaviorValue));
			}
		}
	}

	internal bool RemoveCompletedDownloadsFromList
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.DownloadManagerRemoveCompletedItemsFromList = field;
			}
		}
	}

	internal string ResolvedDownloadDirectory => string.IsNullOrWhiteSpace(CustomDownloadDirectorySetting)
		? ResolveDefaultDownloadsDirectory()
		: CustomDownloadDirectorySetting;

	internal bool IsUsingDefaultDownloadDirectory => string.IsNullOrWhiteSpace(CustomDownloadDirectorySetting);
	internal bool CanRestoreDefaultDownloadDirectory => !IsUsingDefaultDownloadDirectory;
	internal bool CanEditFullPresetLimit => !IsFullPresetUnlimited;
	internal double MaximumSimultaneousDownloadsValue { get => MaximumSimultaneousDownloads; set => MaximumSimultaneousDownloads = (int)Math.Round(value); }
	internal double ParallelConnectionsPerDownloadValue { get => ParallelConnectionsPerDownload; set => ParallelConnectionsPerDownload = (int)Math.Round(value); }
	internal double SlowPresetKilobytesPerSecondValue { get => SlowPresetKilobytesPerSecond; set => SlowPresetKilobytesPerSecond = (int)Math.Round(value); }
	internal double MediumPresetKilobytesPerSecondValue { get => MediumPresetKilobytesPerSecond; set => MediumPresetKilobytesPerSecond = (int)Math.Round(value); }
	internal double FullPresetKilobytesPerSecondValue { get => FullPresetKilobytesPerSecond; set => FullPresetKilobytesPerSecond = (int)Math.Round(value); }
	internal int CompletionActionValue { get => (int)CompletionAction; set => CompletionAction = (DownloadCompletionAction)value; }
	internal int ExistingDownloadConflictBehaviorValue { get => (int)ExistingDownloadConflictBehavior; set => ExistingDownloadConflictBehavior = (ExistingDownloadConflictBehavior)value; }

	internal Visibility EmptyStateVisibility { get; set => SP(ref field, value); } = Visibility.Visible;
	internal string EmptyStateText => DownloadItems.Count == 0 ? "No downloads have been added yet." : "No downloads match your search.";
	internal int SelectedDownloadCount => _selectedDownloadItems.Count;
	internal bool HasSelectedDownloads => SelectedDownloadCount > 0;
	internal string SelectedDownloadsText => SelectedDownloadCount == 1 ? "1 selected" : $"{SelectedDownloadCount} selected";
	internal bool CanSelectAllDownloads => FilteredDownloadItems.Count > 0 && SelectedDownloadCount < FilteredDownloadItems.Count;
	internal bool CanDeselectAllDownloads => SelectedDownloadCount > 0;
	internal bool CanPauseSelectedDownloads => _selectedDownloadItems.Any(static item => item.State is DownloadState.Running);
	internal bool CanResumeSelectedDownloads => _selectedDownloadItems.Any(static item => item.CanResumeDownload);
	internal bool CanDeleteSelectedDownloads => HasSelectedDownloads;
	internal bool CanRemoveSelectedDownloads => HasSelectedDownloads;
	internal Visibility SelectionActionsVisibility => HasSelectedDownloads ? Visibility.Visible : Visibility.Collapsed;
	internal string ActiveSortToolTip => GetActiveSortDescription();
	internal string? SearchText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				_ = RefreshFilteredDownloadItemsAsync();
			}
		}
	}

	internal string ActiveSpeedPresetText => ActiveSpeedPreset switch
	{
		DownloadSpeedPreset.Slow => Atlas.GetStr("Slow/Text"),
		DownloadSpeedPreset.Medium => Atlas.GetStr("Medium/Text"),
		DownloadSpeedPreset.Full => Atlas.GetStr("Full/Text"),
		_ => Atlas.GetStr("Full/Text")
	};

	internal string ActiveSpeedPresetToolTip => ActiveSpeedPreset switch
	{
		DownloadSpeedPreset.Slow => $"Slow preset limit: {HomeVM.FormatDataSize(checked((long)SlowPresetKilobytesPerSecond * 1024))}/s",
		DownloadSpeedPreset.Medium => $"Medium preset limit: {HomeVM.FormatDataSize(checked((long)MediumPresetKilobytesPerSecond * 1024))}/s",
		DownloadSpeedPreset.Full => IsFullPresetUnlimited
			? "Full preset limit: Unlimited"
			: $"Full preset limit: {HomeVM.FormatDataSize(checked((long)FullPresetKilobytesPerSecond * 1024))}/s",
		_ => IsFullPresetUnlimited
			? "Full preset limit: Unlimited"
			: $"Full preset limit: {HomeVM.FormatDataSize(checked((long)FullPresetKilobytesPerSecond * 1024))}/s"
	};

	internal string ActiveSpeedPresetGlyph => ActiveSpeedPreset switch
	{
		DownloadSpeedPreset.Slow => "\uEC48",
		DownloadSpeedPreset.Medium => "\uEC49",
		DownloadSpeedPreset.Full => "\uEC4A",
		_ => "\uEC4A"
	};

	internal Brush ActiveSpeedPresetBrush => ActiveSpeedPreset switch
	{
		DownloadSpeedPreset.Slow => DownloadManagerItem.FailedStatusBrush,
		DownloadSpeedPreset.Medium => DownloadManagerItem.PausedStatusBrush,
		DownloadSpeedPreset.Full => DownloadManagerItem.CompletedStatusBrush,
		_ => DownloadManagerItem.CompletedStatusBrush
	};

	internal async void ShowAddLinksDialogAsync()
	{
		try
		{
			List<Uri> detectedLinks = [];
			string clipboardText = string.Join(Environment.NewLine, ExtractLinks(await GetClipboardTextAsync()).Select(static link => link.AbsoluteUri));

			TextBox inputTextBox = new()
			{
				AcceptsReturn = true,
				TextWrapping = TextWrapping.Wrap,
				MinHeight = 180,
				PlaceholderText = "Paste one or more HTTP/HTTPS links here."
			};

			TextBlock countTextBlock = new()
			{
				Text = "0 links detected",
				TextWrapping = TextWrapping.Wrap
			};

			StackPanel panel = new()
			{
				Spacing = 12
			};

			panel.Children.Add(new TextBlock
			{
				Text = "Paste one or multiple direct download links. The count updates as you type or paste.",
				TextWrapping = TextWrapping.Wrap
			});
			panel.Children.Add(inputTextBox);
			panel.Children.Add(countTextBlock);

			using ContentDialogV2 dialog = new()
			{
				Title = "Add download links",
				Content = panel,
				PrimaryButtonText = "Start downloading",
				CloseButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary,
				IsPrimaryButtonEnabled = false
			};

			void UpdateDetectedLinks(string inputText)
			{
				detectedLinks = ExtractLinks(inputText);
				countTextBlock.Text = detectedLinks.Count == 1 ? "1 link detected" : $"{detectedLinks.Count} links detected";
				dialog.IsPrimaryButtonEnabled = detectedLinks.Count > 0;
			}

			inputTextBox.TextChanged += (_, _) => UpdateDetectedLinks(inputTextBox.Text);
			inputTextBox.Paste += async (_, e) =>
			{
				e.Handled = true;

				// Only normalize on paste. This keeps manual typing/selection untouched while still fixing
				// repeated mixed-text pastes by replacing the box contents with freshly extracted links.
				string normalizedClipboardText = string.Join(Environment.NewLine, ExtractLinks(await GetClipboardTextAsync()).Select(static link => link.AbsoluteUri));
				inputTextBox.Text = normalizedClipboardText;
				inputTextBox.SelectionStart = inputTextBox.Text.Length;
				UpdateDetectedLinks(normalizedClipboardText);
			};

			if (!string.IsNullOrWhiteSpace(clipboardText))
			{
				inputTextBox.Text = clipboardText;
			}

			UpdateDetectedLinks(inputTextBox.Text);

			if (await dialog.ShowAsync() is ContentDialogResult.Primary)
			{
				await QueueDownloadsAsync(detectedLinks);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void PasteLinksKeyboardAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		args.Handled = true;

		try
		{
			string clipboardText = await GetClipboardTextAsync();
			List<Uri> clipboardLinks = ExtractLinks(clipboardText);

			if (clipboardLinks.Count == 0)
			{
				MainInfoBar.WriteWarning("No valid links were found in the clipboard.");
				return;
			}

			await QueueDownloadsAsync(clipboardLinks);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal void OpenContainingFolderButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			OpenContainingDirectory(item);
		}
	}

	internal async void OpenDownloadedFileMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await OpenDownloadedFileAsync(item);
		}
	}

	internal async void DeleteDownloadedFileMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			using ContentDialogV2 dialog = new()
			{
				Title = "Delete download",
				Content = new TextBlock
				{
					Text = $"Delete '{item.DisplayName}' and its file?",
					TextWrapping = TextWrapping.Wrap
				},
				PrimaryButtonText = "Delete",
				CloseButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Close
			};

			if (await dialog.ShowAsync() is not ContentDialogResult.Primary)
			{
				return;
			}

			_ = await DeleteDownloadedFileAsync(item);
		}
	}

	internal void CopyDownloadLinkMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			ClipboardManagement.CopyText(item.SourceUrl);
			MainInfoBar.WriteSuccess("The download link(s) was/were copied to the clipboard.");
		}
	}

	internal async void ChangeDownloadLinkMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is not FrameworkElement { Tag: DownloadManagerItem item })
		{
			return;
		}

		if (!item.CanChangeDownloadLink)
		{
			MainInfoBar.WriteWarning("Only queued, paused, interrupted, or failed downloads can change their link.");
			return;
		}

		TextBox linkTextBox = new()
		{
			Text = item.SourceUrl,
			PlaceholderText = "Paste the replacement HTTP/HTTPS link here.",
			TextWrapping = TextWrapping.Wrap
		};

		StackPanel panel = new()
		{
			Spacing = 10
		};
		panel.Children.Add(new TextBlock
		{
			Text = "The replacement link must resolve to the same file name, and when size metadata is available it must also match the existing download size.",
			TextWrapping = TextWrapping.Wrap
		});
		panel.Children.Add(linkTextBox);

		using ContentDialogV2 dialog = new()
		{
			Title = "Change download link",
			Content = panel,
			PrimaryButtonText = "Save",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Primary
		};

		if (await dialog.ShowAsync() is not ContentDialogResult.Primary)
		{
			return;
		}

		if (!Uri.TryCreate(linkTextBox.Text.Trim(), UriKind.Absolute, out Uri? replacementUri)
			|| (replacementUri.Scheme != Uri.UriSchemeHttp && replacementUri.Scheme != Uri.UriSchemeHttps))
		{
			MainInfoBar.WriteWarning("Enter a valid HTTP or HTTPS download link.");
			return;
		}

		string expectedFileName = SanitizeFileName(!string.IsNullOrWhiteSpace(item.FilePath)
			? Path.GetFileName(item.FilePath)
			: item.DisplayName);

		try
		{
			using CancellationTokenSource validationCts = new(TimeSpan.FromSeconds(30));
			using DownloadMetadataResponse metadata = await GetDownloadMetadataResponseAsync(replacementUri, validationCts.Token).ConfigureAwait(false);
			string resolvedFileName = SanitizeFileName(GetSuggestedFileName(metadata.Response, replacementUri));
			string comparableExpectedFileName = SanitizeFileName($"{MyRegex1().Replace(Path.GetFileNameWithoutExtension(expectedFileName), string.Empty)}{Path.GetExtension(expectedFileName)}");
			string comparableResolvedFileName = SanitizeFileName($"{MyRegex1().Replace(Path.GetFileNameWithoutExtension(resolvedFileName), string.Empty)}{Path.GetExtension(resolvedFileName)}");
			long? resolvedTotalBytes = metadata.Response.Content.Headers.ContentLength;
			DateTimeOffset? resolvedServerFileTimestampUtc = metadata.ServerFileTimestampUtc;
			if (resolvedTotalBytes.HasValue && resolvedTotalBytes.Value <= 0)
			{
				resolvedTotalBytes = null;
			}

			if (!string.Equals(expectedFileName, resolvedFileName, StringComparison.OrdinalIgnoreCase)
				&& !string.Equals(comparableExpectedFileName, comparableResolvedFileName, StringComparison.OrdinalIgnoreCase))
			{
				MainInfoBar.WriteWarning($"The replacement link resolves to '{resolvedFileName}', not '{expectedFileName}'.");
				return;
			}

			if (item.TotalBytes.HasValue)
			{
				if (!resolvedTotalBytes.HasValue)
				{
					MainInfoBar.WriteWarning("The replacement link did not expose enough metadata to verify it is the same file size.");
					return;
				}

				if (resolvedTotalBytes.Value != item.TotalBytes.Value)
				{
					MainInfoBar.WriteWarning("The replacement link resolves to a different file size.");
					return;
				}
			}

			string replacementSourceUrl = replacementUri.AbsoluteUri;

			if (TryLoadCheckpoint(item, out DownloadCheckpointRecord? checkpoint))
			{
				checkpoint.SourceUrl = replacementSourceUrl;
				checkpoint.ServerFileTimestampUtc = resolvedServerFileTimestampUtc ?? checkpoint.ServerFileTimestampUtc;
				if (resolvedTotalBytes.HasValue)
				{
					checkpoint.TotalBytes = resolvedTotalBytes.Value;
				}
				SaveCheckpoint(checkpoint);
			}

			// Link validation runs after background metadata requests, so any bound item updates must
			// be marshalled back through the dispatcher instead of touching the UI-bound item here.
			await UpdateItemAsync(item, current =>
			{
				current.SourceUrl = replacementSourceUrl;
				current.ServerFileTimestampUtc = resolvedServerFileTimestampUtc ?? current.ServerFileTimestampUtc;
				if (resolvedTotalBytes.HasValue)
				{
					current.TotalBytes = resolvedTotalBytes.Value;
				}

				current.ErrorMessage = null;
			}).ConfigureAwait(false);
			await SaveHistoryAsync().ConfigureAwait(false);
			await RefreshFilteredDownloadItemsAsync().ConfigureAwait(false);
			MainInfoBar.WriteSuccess($"Updated the link for '{item.DisplayName}'.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void ShowSha2256MenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await ShowFileHashDialogAsync(item, "SHA-2 256", HashAlgorithmName.SHA256);
		}
	}

	internal async void ShowSha2512MenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await ShowFileHashDialogAsync(item, "SHA-2 512", HashAlgorithmName.SHA512);
		}
	}

	internal async void ShowSha3256MenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await ShowFileHashDialogAsync(item, "SHA3 256", HashAlgorithmName.SHA3_256);
		}
	}

	internal async void ShowSha3384MenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await ShowFileHashDialogAsync(item, "SHA3 384", HashAlgorithmName.SHA3_384);
		}
	}

	internal async void ShowSha3512MenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			await ShowFileHashDialogAsync(item, "SHA3 512", HashAlgorithmName.SHA3_512);
		}
	}

	internal async void PauseOrResumeButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			if (item.State is DownloadState.Running)
			{
				RequestDownloadPause(item);
				return;
			}

			if (item.CanResumeDownload)
			{
				_ = await ResumeDownloadAsync(item);
			}
		}
	}

	internal async void RemoveFromListMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item })
		{
			_ = await RemoveItemFromListAsync(item);
		}
	}

	internal void DownloadItemsListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (sender is not ListViewBase listView)
		{
			return;
		}

		_selectedDownloadItems.Clear();
		_selectedDownloadItems.AddRange(listView.SelectedItems.OfType<DownloadManagerItem>());
		NotifySelectedDownloadsChanged();
	}

	internal void DownloadItemsListView_DragItemsStarting(object sender, DragItemsStartingEventArgs e)
	{
		try
		{
			List<string> dragPaths = [];

			foreach (DownloadManagerItem item in e.Items.OfType<DownloadManagerItem>())
			{
				string? dragPath = item.IsFileAvailable
					? item.FilePath
					: File.Exists(item.TemporaryFilePath) ? item.TemporaryFilePath
						: null;
				if (string.IsNullOrWhiteSpace(dragPath))
				{
					continue;
				}

				dragPaths.Add(dragPath);
			}

			if (dragPaths.Count == 0)
			{
				e.Cancel = true;
				MainInfoBar.WriteWarning("The selected downloads do not have a file or partial file available to drag yet.");
				return;
			}

			e.Data.RequestedOperation = DataPackageOperation.Copy;
			e.Data.SetDataProvider(StandardDataFormats.StorageItems, async request =>
			{
				DataProviderDeferral deferral = request.GetDeferral();
				try
				{
					List<IStorageItem> filesToDrag = [];
					foreach (string dragPath in dragPaths)
					{
						filesToDrag.Add(await StorageFile.GetFileFromPathAsync(dragPath));
					}

					request.SetData(filesToDrag);
				}
				catch (Exception ex)
				{
					MainInfoBar.WriteError(ex);
				}
				finally
				{
					deferral.Complete();
				}
			});
		}
		catch (Exception ex)
		{
			e.Cancel = true;
			MainInfoBar.WriteError(ex);
		}
	}

	internal void DownloadManagerGrid_DragOver(object sender, DragEventArgs e)
	{
		if (CanDropLinks(e.DataView))
		{
			e.AcceptedOperation = DataPackageOperation.Copy;
			e.DragUIOverride.Caption = "Drop links to add them to Download Manager";
			e.DragUIOverride.IsCaptionVisible = true;
			e.DragUIOverride.IsContentVisible = true;
		}
		else
		{
			e.AcceptedOperation = DataPackageOperation.None;
		}
	}

	internal async void DownloadManagerGrid_Drop(object sender, DragEventArgs e)
	{
		try
		{
			List<Uri> droppedLinks = await ExtractDroppedLinksAsync(e.DataView);
			if (droppedLinks.Count == 0)
			{
				MainInfoBar.WriteWarning("No valid HTTP or HTTPS links were found in the dropped content.");
				return;
			}

			await QueueDownloadsAsync(droppedLinks);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void DownloadItemBorder_DoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item } && item.IsFileAvailable)
		{
			await OpenDownloadedFileAsync(item);
		}
	}

	internal void ApplySlowPresetMenuFlyoutItem_Click() => ActiveSpeedPreset = DownloadSpeedPreset.Slow;
	internal void ApplyMediumPresetMenuFlyoutItem_Click() => ActiveSpeedPreset = DownloadSpeedPreset.Medium;
	internal void ApplyFullPresetMenuFlyoutItem_Click() => ActiveSpeedPreset = DownloadSpeedPreset.Full;

	internal async void OpenPresetLimitsSettingsMenuFlyoutItem_Click()
	{
		_scrollPresetLimitsIntoViewOnNextSettingsNavigation = true;
		await ViewModelProvider.NavigationService.Navigate(typeof(Pages.Extras.DownloadManagerSettings), null);
		await TryScrollPresetsSectionIntoViewAsync();
	}

	internal void SortByNameMenuFlyoutItem_Click() => ApplySort("Name");
	internal void SortBySizeMenuFlyoutItem_Click() => ApplySort("Size");
	internal void SortByDateAddedMenuFlyoutItem_Click() => ApplySort("DateAdded");

	internal void PauseSelectedDownloadsAppBarButton_Click()
	{
		int count = 0;

		foreach (DownloadManagerItem item in _selectedDownloadItems)
		{
			if (item.State is not DownloadState.Running)
			{
				continue;
			}

			RequestDownloadPause(item);
			count++;
		}

		if (count == 0)
		{
			MainInfoBar.WriteWarning("Select one or more running downloads to pause.");
			return;
		}

		MainInfoBar.WriteSuccess(count == 1 ? "Pausing 1 download." : $"Pausing {count} downloads.");
	}

	internal async void ResumeSelectedDownloadsAppBarButton_Click()
	{
		int resumedCount = 0;

		foreach (DownloadManagerItem item in _selectedDownloadItems.ToList())
		{
			if (await ResumeDownloadAsync(item, false))
			{
				resumedCount++;
			}
		}

		if (resumedCount == 0)
		{
			MainInfoBar.WriteWarning("Select one or more paused, interrupted, or failed downloads to resume.");
			return;
		}

		MainInfoBar.WriteSuccess(resumedCount == 1 ? "Queued 1 selected download." : $"Queued {resumedCount} selected downloads.");
	}

	internal async void DeleteSelectedDownloadsAppBarButton_Click()
	{
		List<DownloadManagerItem> selectedItems = _selectedDownloadItems.ToList();
		if (selectedItems.Count == 0)
		{
			return;
		}

		using ContentDialogV2 dialog = new()
		{
			Title = selectedItems.Count == 1 ? "Delete selected download" : "Delete selected downloads",
			Content = new TextBlock
			{
				Text = selectedItems.Count == 1
					? $"Delete '{selectedItems[0].DisplayName}' and its file if it exists?"
					: $"Delete {selectedItems.Count} selected downloads and their files if they exist?",
				TextWrapping = TextWrapping.Wrap
			},
			PrimaryButtonText = "Delete",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Close
		};

		if (await dialog.ShowAsync() is not ContentDialogResult.Primary)
		{
			return;
		}

		int deletedCount = 0;
		int removedCount = 0;

		foreach (DownloadManagerItem item in selectedItems)
		{
			if (item.State is DownloadState.Deleted || !item.IsFileAvailable)
			{
				if (await RemoveItemFromListAsync(item, false))
				{
					removedCount++;
				}

				continue;
			}

			if (await DeleteDownloadedFileAsync(item, false))
			{
				deletedCount++;
			}
		}

		if (deletedCount == 0 && removedCount == 0)
		{
			MainInfoBar.WriteWarning("Select one or more downloads to delete.");
			return;
		}

		if (deletedCount > 0 && removedCount > 0)
		{
			MainInfoBar.WriteSuccess($"Deleted {deletedCount} selected download(s) and removed {removedCount} missing item(s) from the list.");
			return;
		}

		if (deletedCount > 0)
		{
			MainInfoBar.WriteSuccess(deletedCount == 1 ? "Deleted 1 selected download." : $"Deleted {deletedCount} selected downloads.");
			return;
		}

		MainInfoBar.WriteSuccess(removedCount == 1
			? "Removed 1 missing selected download from the list."
			: $"Removed {removedCount} missing selected downloads from the list.");
	}

	internal async void RemoveSelectedDownloadsAppBarButton_Click()
	{
		int removedCount = 0;

		foreach (DownloadManagerItem item in _selectedDownloadItems.ToList())
		{
			if (await RemoveItemFromListAsync(item, false))
			{
				removedCount++;
			}
		}

		if (removedCount == 0)
		{
			MainInfoBar.WriteWarning("Select one or more downloads to remove.");
			return;
		}

		MainInfoBar.WriteSuccess(removedCount == 1 ? "Removed 1 selected download from the list." : $"Removed {removedCount} selected downloads from the list.");
	}

	internal async void BrowseDownloadDirectoryAsync()
	{
		try
		{
			string? selectedDirectory = FileDialogHelper.ShowDirectoryPickerDialog();
			if (string.IsNullOrWhiteSpace(selectedDirectory))
			{
				return;
			}

			_ = Directory.CreateDirectory(selectedDirectory);
			CustomDownloadDirectorySetting = selectedDirectory;
			await SaveHistoryAsync();
			MainInfoBar.WriteSuccess($"Download directory set to '{ResolvedDownloadDirectory}'.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	internal async void RestoreDefaultDownloadDirectoryAsync()
	{
		CustomDownloadDirectorySetting = string.Empty;
		await SaveHistoryAsync();
		MainInfoBar.WriteSuccess($"Download directory restored to '{ResolvedDownloadDirectory}'.");
	}

	internal void OpenDownloadManagerStorageLocation()
	{
		Process? process = null;

		try
		{
			process = Process.Start(new ProcessStartInfo
			{
				FileName = Directory.CreateDirectory(ApplicationData.Current.LocalFolder.Path).FullName,
				UseShellExecute = true
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			process?.Dispose();
		}
	}

	internal async void OpenSettingsPageAsync() => await ViewModelProvider.NavigationService.Navigate(typeof(Pages.Extras.DownloadManagerSettings), null);

	internal async void DownloadManagerPresetsSectionHeader_Loaded(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement element)
		{
			_downloadManagerPresetsSectionHeader = element;
			await TryScrollPresetsSectionIntoViewAsync();
		}
	}

	internal void OpenContainingDirectory(DownloadManagerItem item)
	{
		Process? process = null;
		try
		{
			if (item.IsFileAvailable)
			{
				process = Process.Start(new ProcessStartInfo
				{
					FileName = "explorer.exe",
					Arguments = $"/select,\"{item.FilePath}\"",
					UseShellExecute = true
				});
				return;
			}

			if (item.IsDirectoryAvailable)
			{
				process = Process.Start(new ProcessStartInfo
				{
					FileName = item.DestinationDirectory,
					UseShellExecute = true
				});
				return;
			}

			MainInfoBar.WriteWarning("The saved location is no longer available.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			process?.Dispose();
		}
	}

	internal async Task OpenDownloadedFileAsync(DownloadManagerItem item)
	{
		if (!item.IsFileAvailable)
		{
			MainInfoBar.WriteWarning("The downloaded file is no longer available.");
			return;
		}

		await OpenFileInDefaultFileHandler(item.FilePath);
	}

	internal async Task<bool> DeleteDownloadedFileAsync(DownloadManagerItem item, bool announce = true)
	{
		try
		{
			// Deletion must honor the user's request even for queued/running entries, so stop any in-flight work
			// first and only then remove the item plus every on-disk artifact associated with it.
			await StopDownloadForRemovalAsync(item).ConfigureAwait(false);

			DeleteFileIfExists(item.FilePath);
			DeleteFileIfExists(item.TemporaryFilePath);
			DeleteFileIfExists(item.CheckpointFilePath);

			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				_ = DownloadItems.Remove(item);
				RemovePendingItem(item);
			}).ConfigureAwait(false);

			await RefreshFilteredDownloadItemsAsync();
			await SaveHistoryAsync();
			if (announce)
			{
				MainInfoBar.WriteSuccess($"Deleted '{item.DisplayName}'.");
			}

			return true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			return false;
		}
	}

	private async Task ShowFileHashDialogAsync(DownloadManagerItem item, string hashDisplayName, HashAlgorithmName hashAlgorithmName)
	{
		if (!item.IsFileAvailable)
		{
			MainInfoBar.WriteWarning("The downloaded file is no longer available.");
			return;
		}

		try
		{
			byte[] hash = await ComputeFileHashAsync(item.FilePath, hashAlgorithmName).ConfigureAwait(false);
			string hashText = Convert.ToHexString(hash);

			await Atlas.AppDispatcher.EnqueueAsync(async () =>
			{
				Button copyButton = new()
				{
					Content = new SymbolIcon(Symbol.Copy),
					HorizontalAlignment = HorizontalAlignment.Right,
					VerticalAlignment = VerticalAlignment.Center
				};
				ToolTipService.SetToolTip(copyButton, "Copy hash");
				copyButton.Click += (_, _) =>
				{
					ClipboardManagement.CopyText(hashText);
					MainInfoBar.WriteSuccess($"{hashDisplayName} copied to the clipboard.");
				};

				TextBox hashTextBox = new()
				{
					Text = hashText,
					IsReadOnly = true,
					TextWrapping = TextWrapping.Wrap,
					AcceptsReturn = true
				};

				Grid dialogContent = new()
				{
					ColumnSpacing = 8
				};
				dialogContent.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
				dialogContent.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
				hashTextBox.SetValue(Grid.ColumnProperty, 0);
				copyButton.SetValue(Grid.ColumnProperty, 1);
				dialogContent.Children.Add(copyButton);
				dialogContent.Children.Add(hashTextBox);

				using ContentDialogV2 dialog = new()
				{
					Title = hashDisplayName,
					Content = dialogContent,
					CloseButtonText = Atlas.GetStr("OK"),
					DefaultButton = ContentDialogButton.Close
				};

				_ = await dialog.ShowAsync();
			}).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private static Task<byte[]> ComputeFileHashAsync(string filePath, HashAlgorithmName hashAlgorithmName) =>
		Task.Run(async () =>
		{
			const int BufferSize = 1024 * 1024;

			await using FileStream fileStream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, BufferSize, useAsync: true);
			using IncrementalHash incrementalHash = IncrementalHash.CreateHash(hashAlgorithmName);

			byte[] buffer = GC.AllocateUninitializedArray<byte>(BufferSize);

			while (true)
			{
				int bytesRead = await fileStream.ReadAsync(buffer.AsMemory(0, buffer.Length)).ConfigureAwait(false);
				if (bytesRead == 0)
				{
					break;
				}

				incrementalHash.AppendData(buffer.AsSpan(0, bytesRead));
			}

			return incrementalHash.GetHashAndReset();
		});

	internal async Task<bool> ResumeDownloadAsync(DownloadManagerItem item, bool announce = true)
	{
		if (!item.CanResumeDownload)
		{
			return false;
		}

		item.ErrorMessage = null;
		item.CompletedAtUtc = null;
		item.CurrentBytesPerSecond = 0;
		item.State = DownloadState.Queued;

		if (TryEnqueuePendingItem(item))
		{
			ArmCompletionAction();
			await SaveHistoryAsync();
			ProcessPendingDownloads();
			if (announce)
			{
				MainInfoBar.WriteSuccess($"Queued '{item.DisplayName}' for download.");
			}

			return true;
		}

		return false;
	}

	internal async Task<bool> RemoveItemFromListAsync(DownloadManagerItem item, bool announce = true)
	{
		await StopDownloadForRemovalAsync(item).ConfigureAwait(false);

		string? finalFilePath = !string.IsNullOrWhiteSpace(item.FilePath)
			? item.FilePath
			: item.TemporaryFilePath.EndsWith(".hssdownload.part", StringComparison.OrdinalIgnoreCase)
				? item.TemporaryFilePath[..^".hssdownload.part".Length]
				: null;

		if (TryLoadCheckpoint(item, out DownloadCheckpointRecord? checkpoint))
		{
			DeleteFileIfExists(checkpoint.CheckpointFilePath);
		}

		DeleteFileIfExists(item.CheckpointFilePath);
		if (!string.IsNullOrWhiteSpace(finalFilePath))
		{
			DeleteFileIfExists(GetCheckpointFilePath(finalFilePath));
		}

		// Completed downloads can be auto-removed directly from the background download worker, so the
		// bound collection mutation has to be marshalled back to the UI thread.
		await Atlas.AppDispatcher.EnqueueAsync(() =>
		{
			_ = DownloadItems.Remove(item);
			RemovePendingItem(item);
		}).ConfigureAwait(false);

		await RefreshFilteredDownloadItemsAsync();
		await SaveHistoryAsync();
		if (announce)
		{
			MainInfoBar.WriteSuccess($"Removed '{item.DisplayName}' from the list.");
		}

		return true;
	}

	private async Task QueueDownloadsAsync(List<Uri> links)
	{
		if (links.Count == 0)
		{
			MainInfoBar.WriteWarning("No valid links were detected.");
			return;
		}

		try
		{
			_ = Directory.CreateDirectory(ResolvedDownloadDirectory);
			ArmCompletionAction();
			int queuedCount = 0;

			foreach (Uri link in links)
			{
				// Some download endpoints expose the real file name only in the query string (for example
				// download.php?file=example.svg). Prefer that before falling back to the raw path segment so
				// we do not seed the item with placeholders like download.php or watch.
				string displayName = GetSuggestedFileNameFromQuery(link)
					?? GetMeaningfulFileNameFromUri(link)
					?? GetDisplayNameFromUri(link);
				string? initialFilePath = await ResolveInitialFilePathAsync(link, displayName).ConfigureAwait(false);
				if (string.IsNullOrWhiteSpace(initialFilePath))
				{
					continue;
				}

				DownloadManagerItem item = new()
				{
					SourceUrl = link.AbsoluteUri,
					DisplayName = displayName,
					DestinationDirectory = ResolvedDownloadDirectory,
					FilePath = initialFilePath,
					TemporaryFilePath = GetTemporaryFilePath(initialFilePath),
					CheckpointFilePath = GetCheckpointFilePath(initialFilePath),
					ParallelConnectionsUsed = ParallelConnectionsPerDownload,
					State = DownloadState.Queued,
					CreatedAtUtc = DateTimeOffset.UtcNow
				};

				DownloadItems.Insert(0, item);
				_ = TryEnqueuePendingItem(item);
				queuedCount++;
			}

			await RefreshFilteredDownloadItemsAsync();
			if (queuedCount == 0)
			{
				MainInfoBar.WriteWarning("No new downloads were queued.");
				return;
			}

			await SaveHistoryAsync();
			ProcessPendingDownloads();
			MainInfoBar.WriteSuccess(queuedCount == 1 ? "Queued 1 download." : $"Queued {queuedCount} downloads.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private void ProcessPendingDownloads()
	{
		List<DownloadManagerItem> itemsToStart = [];

		lock (_queueLock)
		{
			while (_activeDownloadCount < Math.Max(1, MaximumSimultaneousDownloads) && _pendingDownloads.Count > 0)
			{
				DownloadManagerItem nextItem = _pendingDownloads.Dequeue();
				if (nextItem.State is not DownloadState.Queued)
				{
					continue;
				}

				itemsToStart.Add(nextItem);
				_activeDownloadCount++;
			}
		}

		foreach (DownloadManagerItem item in itemsToStart)
		{
			_ = DownloadAsync(item);
		}
	}

	private async Task DownloadAsync(DownloadManagerItem item)
	{
		using CancellationTokenSource cancellationTokenSource = new();
		ActiveDownloadOperation activeDownloadOperation = new(cancellationTokenSource);

		if (item.State is DownloadState.Deleted)
		{
			lock (_queueLock)
			{
				_activeDownloadCount = Math.Max(0, _activeDownloadCount - 1);
			}

			ProcessPendingDownloads();
			await MaybeRunCompletionActionAsync().ConfigureAwait(false);
			_ = activeDownloadOperation.CompletionSource.TrySetResult(true);
			return;
		}

		lock (_activeDownloadsLock)
		{
			_activeDownloads[item] = activeDownloadOperation;
		}

		DownloadPreparationResult? preparation = null;
		DownloadRuntimeState? runtime = null;

		try
		{
			await UpdateItemAsync(item, static current =>
			{
				current.State = DownloadState.Running;
				current.ErrorMessage = null;
				current.CompletedAtUtc = null;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);

			_ = Directory.CreateDirectory(item.DestinationDirectory);

			if (TryLoadCheckpoint(item, out DownloadCheckpointRecord? existingCheckpoint))
			{
				if (ApplyParallelConnectionsPreference(existingCheckpoint, ParallelConnectionsPerDownload))
				{
					SaveCheckpoint(existingCheckpoint);
				}

				preparation = new(
					existingCheckpoint,
					existingCheckpoint.SupportsRangeRequests && existingCheckpoint.ParallelConnectionsUsed > 1);
			}
			else
			{
				Uri sourceUri = new(item.SourceUrl);
				DownloadMetadataResponse metadata = await GetDownloadMetadataResponseAsync(sourceUri, cancellationTokenSource.Token).ConfigureAwait(false);

				bool keepInitialResponse = false;

				try
				{
					string suggestedFileName = GetSuggestedFileName(metadata.Response, sourceUri);
					string finalFilePath;
					if (!string.IsNullOrWhiteSpace(item.FilePath))
					{
						string currentFileName = Path.GetFileName(item.FilePath);
						string sanitizedSuggestedFileName = SanitizeFileName(suggestedFileName);
						bool currentFileNameMatchesSourcePath = string.Equals(
							currentFileName,
							GetDisplayNameFromUri(sourceUri),
							StringComparison.OrdinalIgnoreCase);

						bool shouldReplaceInitialFileName =
							!string.IsNullOrWhiteSpace(currentFileName)
							&& !string.IsNullOrWhiteSpace(sanitizedSuggestedFileName)
							&& !string.Equals(currentFileName, sanitizedSuggestedFileName, StringComparison.OrdinalIgnoreCase)
							// Allow metadata to replace placeholder names that came from generic/raw URL paths
							// once we have a verified file name from the response headers or final request URI.
							&& (IsGenericDownloadName(currentFileName) || !Path.HasExtension(currentFileName) || currentFileNameMatchesSourcePath)
							&& !IsGenericDownloadName(sanitizedSuggestedFileName)
							&& (Path.HasExtension(sanitizedSuggestedFileName) || !Path.HasExtension(currentFileName));

						if (!shouldReplaceInitialFileName)
						{
							finalFilePath = item.FilePath;
						}
						else
						{
							string? resolvedFilePath = await ResolveInitialFilePathAsync(new Uri(item.SourceUrl), sanitizedSuggestedFileName, item).ConfigureAwait(false);
							finalFilePath = string.IsNullOrWhiteSpace(resolvedFilePath)
								? item.FilePath
								: resolvedFilePath;
						}
					}
					else
					{
						finalFilePath = GetUniqueDestinationPath(item.DestinationDirectory, suggestedFileName);
					}

					string temporaryFilePath = GetTemporaryFilePath(finalFilePath);
					string checkpointFilePath = GetCheckpointFilePath(finalFilePath);

					DeleteFileIfExists(temporaryFilePath);
					DeleteFileIfExists(checkpointFilePath);

					(bool supportsRangeRequests, long? totalBytes) = await DetectRangeSupportAsync(sourceUri, metadata.Response, cancellationTokenSource.Token).ConfigureAwait(false);
					int effectiveParallelConnections = GetEffectiveParallelConnections(totalBytes, supportsRangeRequests, ParallelConnectionsPerDownload);

					List<DownloadSegmentRecord> segments = supportsRangeRequests && totalBytes.HasValue && totalBytes.Value > 0
						? CreateSegments(totalBytes.Value, effectiveParallelConnections)
						: [new DownloadSegmentRecord { StartOffset = 0, EndOffsetInclusive = totalBytes.HasValue ? totalBytes.Value - 1 : -1, NextOffset = 0 }];

					DownloadCheckpointRecord checkpoint = new()
					{
						SourceUrl = item.SourceUrl,
						DestinationDirectory = item.DestinationDirectory,
						FinalFilePath = finalFilePath,
						TemporaryFilePath = temporaryFilePath,
						CheckpointFilePath = checkpointFilePath,
						TotalBytes = totalBytes,
						SupportsRangeRequests = supportsRangeRequests,
						ParallelConnectionsUsed = Math.Max(1, effectiveParallelConnections),
						CreatedAtUtc = item.CreatedAtUtc,
						ServerFileTimestampUtc = metadata.ServerFileTimestampUtc,
						UpdatedAtUtc = DateTimeOffset.UtcNow,
						Segments = segments
					};

					if (supportsRangeRequests && totalBytes.HasValue && totalBytes.Value > 0)
					{
						using FileStream stream = new(checkpoint.TemporaryFilePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite);
						if (stream.Length != totalBytes.Value)
						{
							stream.SetLength(totalBytes.Value);
						}
					}

					SaveCheckpoint(checkpoint);

					keepInitialResponse = metadata.CanReuseResponseBody && effectiveParallelConnections == 1;

					preparation = new(
						checkpoint,
						effectiveParallelConnections > 1,
						keepInitialResponse ? metadata.Response : null);
				}
				finally
				{
					if (!keepInitialResponse)
					{
						metadata.Response.Dispose();
					}
				}
			}
			runtime = new(preparation.Checkpoint);

			lock (_activeDownloadsLock)
			{
				_activeDownloadRuntimes[item] = runtime;
			}

			await UpdateItemAsync(item, current =>
			{
				current.DisplayName = Path.GetFileName(runtime.Checkpoint.FinalFilePath);
				current.DestinationDirectory = runtime.Checkpoint.DestinationDirectory;
				current.FilePath = runtime.Checkpoint.FinalFilePath;
				current.TemporaryFilePath = runtime.Checkpoint.TemporaryFilePath;
				current.CheckpointFilePath = runtime.Checkpoint.CheckpointFilePath;
				current.TotalBytes = runtime.Checkpoint.TotalBytes;
				current.BytesReceived = CalculateReceivedBytes(runtime.Checkpoint);
				current.SupportsRangeRequests = runtime.Checkpoint.SupportsRangeRequests;
				current.ParallelConnectionsUsed = runtime.Checkpoint.ParallelConnectionsUsed;
				current.ServerFileTimestampUtc = runtime.Checkpoint.ServerFileTimestampUtc;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);

			await RefreshFilteredDownloadItemsAsync().ConfigureAwait(false);
			await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);

			if (IsCheckpointComplete(runtime.Checkpoint))
			{
				await FinalizeSuccessfulDownloadAsync(item, runtime).ConfigureAwait(false);
				return;
			}

			if (preparation.UseParallelConnections)
			{
				await DownloadInParallelAsync(item, runtime, cancellationTokenSource.Token).ConfigureAwait(false);
			}
			else
			{
				await DownloadSingleConnectionAsync(item, runtime, preparation.InitialResponse, cancellationTokenSource.Token).ConfigureAwait(false);
			}

			await FinalizeSuccessfulDownloadAsync(item, runtime).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (activeDownloadOperation.PauseRequested)
		{
			if (runtime is not null)
			{
				await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
			}

			await UpdateItemAsync(item, current =>
			{
				current.State = activeDownloadOperation.RestartRequested ? DownloadState.Queued : DownloadState.Paused;
				current.ErrorMessage = null;
				current.CompletedAtUtc = null;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);

			if (activeDownloadOperation.RestartRequested)
			{
				_ = TryEnqueuePendingItem(item);
			}

			await SaveHistoryAsync().ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (activeDownloadOperation.DeleteRequested)
		{
			await UpdateItemAsync(item, static current =>
			{
				current.State = DownloadState.Deleted;
				current.ErrorMessage = null;
				current.CompletedAtUtc = null;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			if (runtime is not null)
			{
				await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
			}

			await UpdateItemAsync(item, current =>
			{
				current.State = runtime is not null && (CalculateReceivedBytes(runtime.Checkpoint) > 0
					|| File.Exists(runtime.Checkpoint.CheckpointFilePath)
					|| File.Exists(runtime.Checkpoint.TemporaryFilePath))
					? DownloadState.Interrupted
					: DownloadState.Failed;
				current.ErrorMessage = ex.Message;
				current.CompletedAtUtc = null;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);

			await SaveHistoryAsync().ConfigureAwait(false);
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			lock (_activeDownloadsLock)
			{
				_ = _activeDownloads.Remove(item);
				_ = _activeDownloadRuntimes.Remove(item);
			}
			preparation?.InitialResponse?.Dispose();

			lock (_queueLock)
			{
				_activeDownloadCount = Math.Max(0, _activeDownloadCount - 1);
			}

			ProcessPendingDownloads();
			await MaybeRunCompletionActionAsync().ConfigureAwait(false);
			_ = activeDownloadOperation.CompletionSource.TrySetResult(true);
		}
	}

	private async Task DownloadInParallelAsync(DownloadManagerItem item, DownloadRuntimeState runtime, CancellationToken cancellationToken)
	{
		List<Task> segmentTasks = [];

		foreach (DownloadSegmentRecord segment in runtime.Checkpoint.Segments)
		{
			if (segment.EndOffsetInclusive >= 0 && segment.NextOffset > segment.EndOffsetInclusive)
			{
				continue;
			}

			segmentTasks.Add(DownloadRangeSegmentAsync(item, runtime, segment, cancellationToken));
		}

		await Task.WhenAll(segmentTasks).ConfigureAwait(false);
		await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
	}

	private async Task DownloadRangeSegmentAsync(DownloadManagerItem item, DownloadRuntimeState runtime, DownloadSegmentRecord segment, CancellationToken cancellationToken)
	{
		int bufferSize = GetBufferSize();
		byte[] buffer = GC.AllocateUninitializedArray<byte>(bufferSize);
		Uri sourceUri = new(item.SourceUrl);
		int transientFailureCount = 0;

		while (true)
		{
			long startOffset;
			long endOffsetInclusive;

			lock (runtime.SyncRoot)
			{
				startOffset = segment.NextOffset;
				endOffsetInclusive = segment.EndOffsetInclusive;
			}

			if (endOffsetInclusive >= 0 && startOffset > endOffsetInclusive)
			{
				return;
			}

			try
			{
				using HttpResponseMessage response = await SendDownloadRequestWithRetriesAsync(() =>
				{
					HttpRequestMessage request = new(HttpMethod.Get, sourceUri);
					request.Headers.Range = new RangeHeaderValue(startOffset, endOffsetInclusive >= 0 ? endOffsetInclusive : null);
					return request;
				}, cancellationToken).ConfigureAwait(false);

				if (response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable)
				{
					lock (runtime.SyncRoot)
					{
						segment.NextOffset = endOffsetInclusive >= 0 ? endOffsetInclusive + 1 : segment.NextOffset;
					}

					await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
					return;
				}

				if (response.StatusCode != HttpStatusCode.PartialContent)
				{
					_ = response.EnsureSuccessStatusCode();
					throw new HttpRequestException($"The server returned {FormatDownloadHttpStatus(response)} instead of HTTP 206 Partial Content for the requested byte range.");
				}

				await using Stream sourceStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
				await using FileStream destinationStream = new(runtime.Checkpoint.TemporaryFilePath, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite, bufferSize, useAsync: true);
				_ = destinationStream.Seek(startOffset, SeekOrigin.Begin);

				long currentOffset = startOffset;

				while (true)
				{
					int maximumChunkSize = GetReadChunkSize(buffer.Length);
					int maxRead = endOffsetInclusive >= 0
						? (int)Math.Min(maximumChunkSize, endOffsetInclusive - currentOffset + 1)
						: maximumChunkSize;

					if (maxRead <= 0)
					{
						break;
					}

					int bytesRead = await sourceStream.ReadAsync(buffer.AsMemory(0, maxRead), cancellationToken).ConfigureAwait(false);
					if (bytesRead == 0)
					{
						break;
					}

					await _rateLimiter.WaitAsync(bytesRead, GetSpeedLimitBytesPerSecond, cancellationToken).ConfigureAwait(false);
					await destinationStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
					currentOffset += bytesRead;

					lock (runtime.SyncRoot)
					{
						segment.NextOffset = currentOffset;
					}

					if (ShouldFlushDataFile(runtime))
					{
						await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
					}

					await PersistRuntimeProgressAsync(item, runtime, force: false).ConfigureAwait(false);
				}

				await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);

				lock (runtime.SyncRoot)
				{
					if (currentOffset > segment.NextOffset)
					{
						segment.NextOffset = currentOffset;
					}
				}

				transientFailureCount = 0;

				if (endOffsetInclusive < 0 || currentOffset > endOffsetInclusive)
				{
					await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
					return;
				}
			}
			catch (Exception ex) when (IsTransientDownloadException(ex, cancellationToken) && ++transientFailureCount <= MaxTransientRetryAttempts)
			{
				await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
				await Task.Delay(GetTransientRetryDelay(transientFailureCount), cancellationToken).ConfigureAwait(false);
			}
		}
	}

	private async Task DownloadSingleConnectionAsync(DownloadManagerItem item, DownloadRuntimeState runtime, HttpResponseMessage? initialResponse, CancellationToken cancellationToken)
	{
		int bufferSize = GetBufferSize();
		byte[] buffer = GC.AllocateUninitializedArray<byte>(bufferSize);
		Uri sourceUri = new(item.SourceUrl);
		DownloadSegmentRecord segment = runtime.Checkpoint.Segments[0];
		int transientFailureCount = 0;

		while (true)
		{
			long startOffset;

			lock (runtime.SyncRoot)
			{
				startOffset = segment.NextOffset;
			}

			try
			{
				HttpResponseMessage response;
				if (initialResponse is not null)
				{
					response = initialResponse;
					initialResponse = null;
				}
				else
				{
					response = await SendDownloadRequestWithRetriesAsync(() =>
					{
						HttpRequestMessage request = new(HttpMethod.Get, sourceUri);
						if (startOffset > 0)
						{
							request.Headers.Range = new RangeHeaderValue(startOffset, null);
						}

						return request;
					}, cancellationToken).ConfigureAwait(false);
				}

				using (response)
				{
					if (startOffset > 0 && response.StatusCode == HttpStatusCode.RequestedRangeNotSatisfiable)
					{
						lock (runtime.SyncRoot)
						{
							if (runtime.Checkpoint.TotalBytes.HasValue)
							{
								segment.NextOffset = runtime.Checkpoint.TotalBytes.Value;
								if (segment.EndOffsetInclusive < runtime.Checkpoint.TotalBytes.Value - 1)
								{
									segment.EndOffsetInclusive = runtime.Checkpoint.TotalBytes.Value - 1;
								}
							}
						}

						await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
						return;
					}

					bool appendMode = startOffset > 0 && response.StatusCode == HttpStatusCode.PartialContent;

					if (startOffset > 0 && !appendMode)
					{
						DeleteFileIfExists(runtime.Checkpoint.TemporaryFilePath);

						lock (runtime.SyncRoot)
						{
							segment.NextOffset = 0;
							if (runtime.Checkpoint.TotalBytes.HasValue)
							{
								segment.EndOffsetInclusive = runtime.Checkpoint.TotalBytes.Value - 1;
							}
						}

						await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
						continue;
					}

					_ = response.EnsureSuccessStatusCode();

					if (!appendMode && response.StatusCode != HttpStatusCode.OK)
					{
						throw new HttpRequestException($"The server returned {FormatDownloadHttpStatus(response)} instead of HTTP 200 OK for the download payload.");
					}

					long? totalBytes = response.Content.Headers.ContentRange?.Length
						?? (response.Content.Headers.ContentLength.HasValue
							? startOffset + response.Content.Headers.ContentLength.Value
							: null);

					if (totalBytes.HasValue && totalBytes.Value > 0)
					{
						runtime.Checkpoint.TotalBytes = totalBytes.Value;
						if (runtime.Checkpoint.Segments.Count == 1)
						{
							runtime.Checkpoint.Segments[0].EndOffsetInclusive = totalBytes.Value - 1;
						}
					}

					FileMode fileMode = appendMode ? FileMode.OpenOrCreate : FileMode.Create;
					await using FileStream destinationStream = new(runtime.Checkpoint.TemporaryFilePath, fileMode, FileAccess.Write, FileShare.ReadWrite, bufferSize, useAsync: true);

					if (appendMode)
					{
						_ = destinationStream.Seek(startOffset, SeekOrigin.Begin);
					}
					else
					{
						lock (runtime.SyncRoot)
						{
							segment.NextOffset = 0;
						}
					}

					await using Stream sourceStream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

					while (true)
					{
						int bytesRead = await sourceStream.ReadAsync(
							buffer.AsMemory(0, GetReadChunkSize(buffer.Length)),
							cancellationToken).ConfigureAwait(false);
						if (bytesRead == 0)
						{
							break;
						}

						await _rateLimiter.WaitAsync(bytesRead, GetSpeedLimitBytesPerSecond, cancellationToken).ConfigureAwait(false);
						await destinationStream.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);

						lock (runtime.SyncRoot)
						{
							segment.NextOffset += bytesRead;
						}

						if (ShouldFlushDataFile(runtime))
						{
							await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);
						}

						await PersistRuntimeProgressAsync(item, runtime, force: false).ConfigureAwait(false);
					}

					await destinationStream.FlushAsync(cancellationToken).ConfigureAwait(false);

					if (!runtime.Checkpoint.TotalBytes.HasValue)
					{
						lock (runtime.SyncRoot)
						{
							// Unknown-length downloads must not look complete until the response stream actually
							// reaches EOF. Advancing the segment end here prevents finalization from trying to
							// move a .part file before any payload has been written.
							segment.EndOffsetInclusive = segment.NextOffset - 1;
						}
					}

					await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
				}

				transientFailureCount = 0;

				if (!runtime.Checkpoint.TotalBytes.HasValue || IsCheckpointComplete(runtime.Checkpoint))
				{
					return;
				}
			}
			catch (Exception ex) when (IsTransientDownloadException(ex, cancellationToken) && ++transientFailureCount <= MaxTransientRetryAttempts)
			{
				await PersistRuntimeProgressAsync(item, runtime, force: true).ConfigureAwait(false);
				await Task.Delay(GetTransientRetryDelay(transientFailureCount), cancellationToken).ConfigureAwait(false);
			}
		}
	}

	private async Task FinalizeSuccessfulDownloadAsync(DownloadManagerItem item, DownloadRuntimeState runtime)
	{
		DownloadCheckpointRecord checkpoint = CreateCheckpointSnapshot(runtime.Checkpoint);
		if (!checkpoint.TotalBytes.HasValue && File.Exists(checkpoint.TemporaryFilePath))
		{
			checkpoint.TotalBytes = new FileInfo(checkpoint.TemporaryFilePath).Length;
		}

		if (!File.Exists(checkpoint.TemporaryFilePath) && File.Exists(checkpoint.FinalFilePath))
		{
			ApplyMarkOfTheWebIfNeeded(checkpoint.FinalFilePath, checkpoint.SourceUrl);

			await UpdateItemAsync(item, current =>
			{
				current.State = DownloadState.Completed;
				current.ErrorMessage = null;
				current.BytesReceived = checkpoint.TotalBytes ?? current.BytesReceived;
				current.TotalBytes = checkpoint.TotalBytes ?? current.TotalBytes;
				current.CompletedAtUtc = DateTimeOffset.UtcNow;
				current.TemporaryFilePath = string.Empty;
				current.CheckpointFilePath = string.Empty;
				current.CurrentBytesPerSecond = 0;
			}).ConfigureAwait(false);

			DeleteFileIfExists(checkpoint.CheckpointFilePath);
			if (RemoveCompletedDownloadsFromList)
			{
				_ = await RemoveItemFromListAsync(item, announce: false).ConfigureAwait(false);
				return;
			}

			await SaveHistoryAsync().ConfigureAwait(false);
			_ = RefreshPreviewAsync(item);
			return;
		}

		if (File.Exists(checkpoint.FinalFilePath))
		{
			DeleteFileIfExists(checkpoint.FinalFilePath);
		}

		File.Move(checkpoint.TemporaryFilePath, checkpoint.FinalFilePath, overwrite: true);
		ApplyMarkOfTheWebIfNeeded(checkpoint.FinalFilePath, checkpoint.SourceUrl);
		DeleteFileIfExists(checkpoint.CheckpointFilePath);

		await UpdateItemAsync(item, current =>
		{
			current.State = DownloadState.Completed;
			current.ErrorMessage = null;
			current.FilePath = checkpoint.FinalFilePath;
			current.BytesReceived = checkpoint.TotalBytes ?? new FileInfo(checkpoint.FinalFilePath).Length;
			current.TotalBytes ??= current.BytesReceived;
			current.CompletedAtUtc = DateTimeOffset.UtcNow;
			current.TemporaryFilePath = string.Empty;
			current.CheckpointFilePath = string.Empty;
			current.CurrentBytesPerSecond = 0;
		}).ConfigureAwait(false);

		if (RemoveCompletedDownloadsFromList)
		{
			_ = await RemoveItemFromListAsync(item, announce: false).ConfigureAwait(false);
			return;
		}

		await SaveHistoryAsync().ConfigureAwait(false);
		_ = RefreshPreviewAsync(item);
	}

	private static readonly char[] TrimEndChars = ['.', ',', ';', ')', ']', '}'];

	private static List<Uri> ExtractLinks(string? text)
	{
		List<Uri> results = [];
		if (string.IsNullOrWhiteSpace(text))
		{
			return results;
		}

		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

		foreach (Match match in LinkRegex.Matches(text))
		{
			string candidate = match.Value.TrimEnd(TrimEndChars);
			if (Uri.TryCreate(candidate, UriKind.Absolute, out Uri? uri)
				&& (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps)
				&& seen.Add(uri.AbsoluteUri))
			{
				results.Add(uri);
			}
		}

		return results;
	}

	private void LoadHistory()
	{
		try
		{
			if (!File.Exists(_historyFilePath))
			{
				return;
			}

			List<DownloadHistoryRecord>? records = JsonSerializer.Deserialize(
				File.ReadAllText(_historyFilePath),
				DownloadManagerJsonContext.Default.ListDownloadHistoryRecord);
			if (records is null)
			{
				return;
			}

			foreach (DownloadHistoryRecord record in CollectionsMarshal.AsSpan(records))
			{
				bool fileExists = !string.IsNullOrWhiteSpace(record.FilePath) && File.Exists(record.FilePath);
				DownloadState state = record.State switch
				{
					DownloadState.Queued or DownloadState.Running or DownloadState.Interrupted or DownloadState.Failed when fileExists => DownloadState.Completed,
					DownloadState.Queued or DownloadState.Running => DownloadState.Interrupted,
					DownloadState.Completed when !fileExists => DownloadState.Deleted,
					_ => record.State
				};

				DownloadManagerItem item = new()
				{
					SourceUrl = record.SourceUrl,
					DisplayName = string.IsNullOrWhiteSpace(record.DisplayName) ? GetDisplayNameFromUri(new Uri(record.SourceUrl)) : record.DisplayName,
					DestinationDirectory = string.IsNullOrWhiteSpace(record.DestinationDirectory) ? ResolvedDownloadDirectory : record.DestinationDirectory,
					FilePath = record.FilePath,
					TemporaryFilePath = record.TemporaryFilePath,
					CheckpointFilePath = record.CheckpointFilePath,
					State = state,
					BytesReceived = record.BytesReceived,
					TotalBytes = record.TotalBytes,
					ErrorMessage = record.ErrorMessage,
					SupportsRangeRequests = record.SupportsRangeRequests,
					ParallelConnectionsUsed = Math.Max(1, record.ParallelConnectionsUsed > 0 ? record.ParallelConnectionsUsed : ParallelConnectionsPerDownload),
					CreatedAtUtc = record.CreatedAtUtc,
					ServerFileTimestampUtc = record.ServerFileTimestampUtc,
					CompletedAtUtc = record.CompletedAtUtc
				};

				if (!string.IsNullOrWhiteSpace(item.FilePath))
				{
					item.CheckpointFilePath = GetCheckpointFilePath(item.FilePath);
				}

				if (string.IsNullOrWhiteSpace(item.TemporaryFilePath) && !string.IsNullOrWhiteSpace(item.FilePath))
				{
					item.TemporaryFilePath = GetTemporaryFilePath(item.FilePath);
				}

				DownloadItems.Add(item);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async Task SaveHistoryAsync()
	{
		try
		{
			List<DownloadHistoryRecord> records = await Atlas.AppDispatcher.EnqueueAsync(() => DownloadItems.Select(static item => new DownloadHistoryRecord(
					item.SourceUrl,
					item.DisplayName,
					item.DestinationDirectory,
					item.FilePath,
					item.State,
					item.BytesReceived,
					item.TotalBytes,
					item.ErrorMessage,
					item.CreatedAtUtc,
					item.CompletedAtUtc,
					item.TemporaryFilePath,
					item.CheckpointFilePath,
					item.SupportsRangeRequests,
					item.ParallelConnectionsUsed,
					item.ServerFileTimestampUtc)).ToList()).ConfigureAwait(false);
			string json = JsonSerializer.Serialize(records, DownloadManagerJsonContext.Default.ListDownloadHistoryRecord);

			lock (_historyLock)
			{
				WriteTextAtomically(_historyFilePath, json);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private bool TryLoadCheckpoint(DownloadManagerItem item, [NotNullWhen(true)] out DownloadCheckpointRecord? checkpoint)
	{
		checkpoint = null;
		string checkpointPath = item.CheckpointFilePath;

		if (!string.IsNullOrWhiteSpace(item.FilePath))
		{
			checkpointPath = GetCheckpointFilePath(item.FilePath);
		}

		if (!File.Exists(checkpointPath))
		{
			return false;
		}

		try
		{
			DownloadCheckpointRecord? loaded = JsonSerializer.Deserialize(
				File.ReadAllText(checkpointPath),
				DownloadManagerJsonContext.Default.DownloadCheckpointRecord);
			if (loaded is null || string.IsNullOrWhiteSpace(loaded.FinalFilePath) || loaded.Segments.Count == 0)
			{
				return false;
			}

			if (!string.Equals(loaded.SourceUrl, item.SourceUrl, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}

			bool finalFileExists = File.Exists(loaded.FinalFilePath);
			bool temporaryFileExists = File.Exists(loaded.TemporaryFilePath);

			if (!finalFileExists && !temporaryFileExists)
			{
				return false;
			}

			if (!temporaryFileExists && !IsCheckpointComplete(loaded))
			{
				return false;
			}

			loaded.CheckpointFilePath = checkpointPath;
			checkpoint = loaded;
			return true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
			return false;
		}
	}

	private async Task<(bool SupportsRangeRequests, long? TotalBytes)> DetectRangeSupportAsync(Uri sourceUri, HttpResponseMessage metadataResponse, CancellationToken cancellationToken)
	{
		long? totalBytes = metadataResponse.Content.Headers.ContentLength;

		if (totalBytes.HasValue && totalBytes.Value <= 0)
		{
			totalBytes = null;
		}

		if (metadataResponse.Headers.AcceptRanges.Any(static range => string.Equals(range, "bytes", StringComparison.OrdinalIgnoreCase)) && totalBytes.HasValue)
		{
			return (true, totalBytes);
		}

		using HttpResponseMessage probeResponse = await SendDownloadRequestWithRetriesAsync(() =>
		{
			HttpRequestMessage probeRequest = new(HttpMethod.Get, sourceUri);
			probeRequest.Headers.Range = new RangeHeaderValue(0, 0);
			return probeRequest;
		}, cancellationToken).ConfigureAwait(false);
		if (probeResponse.StatusCode == HttpStatusCode.PartialContent)
		{
			totalBytes ??= probeResponse.Content.Headers.ContentRange?.Length;
			return (true, totalBytes);
		}

		if (probeResponse.StatusCode != HttpStatusCode.OK)
		{
			throw new HttpRequestException($"The server returned {FormatDownloadHttpStatus(probeResponse)} while probing byte-range support.");
		}

		totalBytes ??= probeResponse.Content.Headers.ContentLength;
		return (false, totalBytes);
	}

	private async Task<DownloadMetadataResponse> GetDownloadMetadataResponseAsync(Uri sourceUri, CancellationToken cancellationToken)
	{
		HttpResponseMessage headResponse = await SendDownloadRequestWithRetriesAsync(
			() => new HttpRequestMessage(HttpMethod.Head, sourceUri),
			cancellationToken).ConfigureAwait(false);
		// Different download endpoints are inconsistent about which verb exposes Last-Modified. Capture the
		// HEAD value up front and carry it forward so we still show the server timestamp even if the later
		// fallback GET omits it (or vice versa).
		DateTimeOffset? headServerFileTimestampUtc = GetServerFileTimestampUtc(headResponse);
		bool canUseHeadResponse;
		if (!headResponse.IsSuccessStatusCode || headResponse.StatusCode == HttpStatusCode.NoContent)
		{
			canUseHeadResponse = false;
		}
		else if (!string.IsNullOrWhiteSpace(GetContentDispositionFileName(headResponse))
			|| headResponse.Content.Headers.ContentLength is > 0
			|| headResponse.Headers.AcceptRanges.Any(static range => string.Equals(range, "bytes", StringComparison.OrdinalIgnoreCase)))
		{
			canUseHeadResponse = true;
		}
		else
		{
			string? mediaType = headResponse.Content.Headers.ContentType?.MediaType;
			if (!string.IsNullOrWhiteSpace(mediaType)
				&& !string.Equals(mediaType, "application/octet-stream", StringComparison.OrdinalIgnoreCase))
			{
				canUseHeadResponse = true;
			}
			else
			{
				string suggestedFileNameFromHead = GetSuggestedFileName(headResponse, sourceUri);
				canUseHeadResponse = Path.HasExtension(suggestedFileNameFromHead) && !IsGenericDownloadName(suggestedFileNameFromHead);
			}
		}

		if (canUseHeadResponse)
		{
			return new(headResponse, canReuseResponseBody: false, headServerFileTimestampUtc);
		}

		headResponse.Dispose();
		HttpResponseMessage getResponse = await SendDownloadRequestWithRetriesAsync(
			() => new HttpRequestMessage(HttpMethod.Get, sourceUri),
			cancellationToken).ConfigureAwait(false);
		_ = getResponse.EnsureSuccessStatusCode();
		return new(getResponse, canReuseResponseBody: true, GetServerFileTimestampUtc(getResponse) ?? headServerFileTimestampUtc);
	}

	private async Task<HttpResponseMessage> SendDownloadRequestWithRetriesAsync(Func<HttpRequestMessage> requestFactory, CancellationToken cancellationToken)
	{
		TimeSpan delay = TimeSpan.FromSeconds(1);

		for (int attempt = 0; ; attempt++)
		{
			cancellationToken.ThrowIfCancellationRequested();

			try
			{
				using HttpRequestMessage request = requestFactory();
				HttpResponseMessage response = await DownloadHttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);
				if (attempt < MaxTransientRetryAttempts && RetryableStatusCodes.Contains(response.StatusCode))
				{
					response.Dispose();
					await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
					delay = delay >= TimeSpan.FromSeconds(4) ? delay : delay + delay;
					continue;
				}

				return response;
			}
			catch (Exception ex) when (attempt < MaxTransientRetryAttempts && IsTransientDownloadException(ex, cancellationToken))
			{
				await Task.Delay(delay, cancellationToken).ConfigureAwait(false);
				delay = delay >= TimeSpan.FromSeconds(4) ? delay : delay + delay;
			}
		}
	}

	private static string FormatDownloadHttpStatus(HttpResponseMessage response)
	{
		string reasonPhrase = string.IsNullOrWhiteSpace(response.ReasonPhrase)
			? response.StatusCode.ToString()
			: response.ReasonPhrase;

		return $"HTTP {(int)response.StatusCode} {reasonPhrase}";
	}

	private static bool IsTransientDownloadException(Exception ex, CancellationToken cancellationToken) => ex switch
	{
		OperationCanceledException => !cancellationToken.IsCancellationRequested,
		HttpRequestException => true,
		IOException => true,
		TimeoutException => true,
		_ => false
	};

	private static TimeSpan GetTransientRetryDelay(int failureCount) => TimeSpan.FromSeconds(Math.Min(Math.Max(1, 1 << Math.Max(0, failureCount - 1)), 4));

	private async Task PersistRuntimeProgressAsync(DownloadManagerItem item, DownloadRuntimeState runtime, bool force)
	{
		DownloadCheckpointRecord? checkpointSnapshot = null;
		long bytesReceived;
		long? totalBytes;
		bool supportsRangeRequests;
		int parallelConnectionsUsed;
		long currentBytesPerSecond;
		bool shouldPersistCheckpoint = false;
		bool shouldPersistHistory = false;
		bool shouldRefreshUi = false;
		DateTimeOffset now = DateTimeOffset.UtcNow;

		lock (runtime.SyncRoot)
		{
			runtime.Checkpoint.UpdatedAtUtc = now;
			bytesReceived = CalculateReceivedBytes(runtime.Checkpoint);
			totalBytes = runtime.Checkpoint.TotalBytes;
			supportsRangeRequests = runtime.Checkpoint.SupportsRangeRequests;
			parallelConnectionsUsed = runtime.Checkpoint.ParallelConnectionsUsed;
			currentBytesPerSecond = 0;

			if (runtime.LastSpeedSampleUtc == DateTimeOffset.MinValue)
			{
				runtime.LastSpeedSampleUtc = now;
				runtime.LastSpeedSampleBytes = bytesReceived;
			}
			else
			{
				TimeSpan elapsed = now - runtime.LastSpeedSampleUtc;
				if (elapsed >= TimeSpan.FromSeconds(1))
				{
					double instantaneousBytesPerSecond = Math.Max(0, bytesReceived - runtime.LastSpeedSampleBytes) / elapsed.TotalSeconds;
					runtime.SmoothedBytesPerSecond = runtime.SmoothedBytesPerSecond <= 0
						? instantaneousBytesPerSecond
						: (runtime.SmoothedBytesPerSecond * 0.6D) + (instantaneousBytesPerSecond * 0.4D);

					runtime.LastSpeedSampleUtc = now;
					runtime.LastSpeedSampleBytes = bytesReceived;
				}
			}

			currentBytesPerSecond = (long)Math.Max(0, Math.Round(runtime.SmoothedBytesPerSecond));

			shouldRefreshUi = force || now - runtime.LastUiRefreshUtc >= TimeSpan.FromMilliseconds(250);
			shouldPersistCheckpoint = force || now - runtime.LastCheckpointPersistUtc >= TimeSpan.FromSeconds(1);
			shouldPersistHistory = force || now - runtime.LastHistoryPersistUtc >= TimeSpan.FromSeconds(1);

			if (shouldRefreshUi)
			{
				runtime.LastUiRefreshUtc = now;
			}

			if (shouldPersistCheckpoint)
			{
				runtime.LastCheckpointPersistUtc = now;
				checkpointSnapshot = CreateCheckpointSnapshot(runtime.Checkpoint);
			}

			if (shouldPersistHistory)
			{
				runtime.LastHistoryPersistUtc = now;
			}
		}

		if (shouldRefreshUi)
		{
			await UpdateItemAsync(item, current =>
			{
				current.BytesReceived = bytesReceived;
				current.TotalBytes = totalBytes;
				current.SupportsRangeRequests = supportsRangeRequests;
				current.ParallelConnectionsUsed = parallelConnectionsUsed;
				current.CurrentBytesPerSecond = currentBytesPerSecond;
			}).ConfigureAwait(false);
		}

		if (checkpointSnapshot is not null)
		{
			SaveCheckpoint(checkpointSnapshot);
		}

		if (shouldPersistHistory)
		{
			await SaveHistoryAsync().ConfigureAwait(false);
		}
	}

	private async Task RefreshPreviewAsync(DownloadManagerItem item)
	{
		if (!item.IsFileAvailable)
		{
			await UpdateItemAsync(item, static current =>
			{
				current.PreviewImageSource = null;
				current.IsPreviewLoading = false;
			}).ConfigureAwait(false);
			return;
		}

		await UpdateItemAsync(item, static current => current.IsPreviewLoading = true).ConfigureAwait(false);

		string filePath = item.FilePath;
		string extension = Path.GetExtension(filePath);

		try
		{
			ImageSource? previewImageSource = null;

			if (string.Equals(extension, ".svg", StringComparison.OrdinalIgnoreCase))
			{
				string svgMarkup = await File.ReadAllTextAsync(filePath).ConfigureAwait(false);
				string normalizedSvgMarkup = NormalizeSvgMarkupForSvgImageSource(svgMarkup);

				try
				{
					previewImageSource = await Atlas.AppDispatcher.EnqueueAsync(async () =>
					{
						using InMemoryRandomAccessStream svgStream = new();
						using DataWriter svgWriter = new(svgStream);

						svgWriter.WriteBytes(Encoding.UTF8.GetBytes(normalizedSvgMarkup));
						_ = await svgWriter.StoreAsync();
						_ = await svgWriter.FlushAsync();
						_ = svgWriter.DetachStream();

						svgStream.Seek(0);

						SvgImageSource svgImageSource = new();
						return await svgImageSource.SetSourceAsync(svgStream) is SvgImageSourceLoadStatus.Success ? svgImageSource : (ImageSource?)null;
					}
					).ConfigureAwait(false);
				}
				catch (COMException ex)
				{
					Logger.Write(ex);
				}

				await UpdateItemAsync(item, current =>
				{
					current.PreviewImageSource = previewImageSource;
					current.IsPreviewLoading = false;
				}).ConfigureAwait(false);

				return;
			}

			try
			{
				StorageFile file = await StorageFile.GetFileFromPathAsync(filePath);

				ThumbnailMode thumbnailMode = VideoExtensions.Contains(extension)
					? ThumbnailMode.VideosView
					: PictureExtensions.Contains(extension)
						? ThumbnailMode.PicturesView
						: ThumbnailMode.SingleItem;

				StorageItemThumbnail thumbnail = await file.GetThumbnailAsync(thumbnailMode, 160, ThumbnailOptions.UseCurrentScale);

				if (thumbnail is not null)
				{
					using (thumbnail)
					{
						thumbnail.Seek(0);

						previewImageSource = await Atlas.AppDispatcher.EnqueueAsync(async () =>
						{
							BitmapImage bitmap = new();
							await bitmap.SetSourceAsync(thumbnail);
							return (ImageSource)bitmap;
						}).ConfigureAwait(false);
					}
				}
			}
			catch (COMException ex)
			{
				Logger.Write(ex);
			}

			await UpdateItemAsync(item, current =>
			{
				current.PreviewImageSource = previewImageSource;
				current.IsPreviewLoading = false;
			}).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			await UpdateItemAsync(item, static current =>
			{
				current.PreviewImageSource = null;
				current.IsPreviewLoading = false;
			}).ConfigureAwait(false);
		}
	}

	/// <summary>
	/// Some SVG files use color rules only through internal CSS classes in a <style> block (.cls-1, .cls-2).
	/// In such cases, we cannot feed the raw SVG into WinUI SvgImageSource because that renderer does not reliably honor those class-based style rules,
	/// And if we do that, the shapes fall back to the default black fill; Therefore we normalize styled SVGs for preview rendering with this method.
	/// class-based style properties are inlined onto the matching SVG elements before loading the preview, so the preview now keeps its intended colors.
	/// </summary>
	/// <param name="svgMarkup"></param>
	/// <returns></returns>
	private static string NormalizeSvgMarkupForSvgImageSource(string svgMarkup)
	{
		if (string.IsNullOrWhiteSpace(svgMarkup) || !svgMarkup.Contains("<style", StringComparison.OrdinalIgnoreCase))
		{
			return svgMarkup;
		}

		try
		{
			XDocument svgDocument = XDocument.Parse(svgMarkup, LoadOptions.PreserveWhitespace);
			Dictionary<string, IReadOnlyDictionary<string, string>> classStyles = [];

			foreach (XElement styleElement in svgDocument
				.Descendants()
				.Where(static element => string.Equals(element.Name.LocalName, "style", StringComparison.OrdinalIgnoreCase)))
			{
				foreach ((string className, IReadOnlyDictionary<string, string> properties) in ParseSvgClassStyles(styleElement.Value))
				{
					classStyles[className] = properties;
				}
			}

			if (classStyles.Count == 0)
			{
				return svgMarkup;
			}

			bool updated = false;

			foreach (XElement element in svgDocument.Descendants())
			{
				XAttribute? classAttribute = element.Attribute("class");
				if (classAttribute is null || string.IsNullOrWhiteSpace(classAttribute.Value))
				{
					continue;
				}

				Dictionary<string, string> mergedProperties = [];
				foreach (string className in classAttribute.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
				{
					if (!classStyles.TryGetValue(className, out IReadOnlyDictionary<string, string>? classProperties))
					{
						continue;
					}

					foreach ((string propertyName, string propertyValue) in classProperties)
					{
						mergedProperties[propertyName] = propertyValue;
					}
				}

				if (mergedProperties.Count == 0)
				{
					continue;
				}

				HashSet<string> inlineStyleProperties = GetInlineStylePropertyNames((string?)element.Attribute("style"));
				foreach ((string propertyName, string propertyValue) in mergedProperties)
				{
					if (element.Attribute(propertyName) is not null || inlineStyleProperties.Contains(propertyName))
					{
						continue;
					}

					element.SetAttributeValue(propertyName, propertyValue);
					updated = true;
				}
			}

			if (!updated)
			{
				return svgMarkup;
			}

			return svgDocument.ToString(SaveOptions.DisableFormatting);
		}
		catch
		{
			return svgMarkup;
		}
	}

	private static IEnumerable<KeyValuePair<string, IReadOnlyDictionary<string, string>>> ParseSvgClassStyles(string styleMarkup)
	{
		if (string.IsNullOrWhiteSpace(styleMarkup))
		{
			yield break;
		}

		foreach (Match ruleMatch in MyRegex2().Matches(styleMarkup))
		{
			Dictionary<string, string> properties = [];
			foreach (string declaration in ruleMatch.Groups["body"].Value.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
			{
				int separatorIndex = declaration.IndexOf(':');
				if (separatorIndex <= 0 || separatorIndex >= declaration.Length - 1)
				{
					continue;
				}

				string propertyName = declaration[..separatorIndex].Trim();
				string propertyValue = declaration[(separatorIndex + 1)..].Trim();
				if (propertyName.Length == 0 || propertyValue.Length == 0)
				{
					continue;
				}

				properties[propertyName] = propertyValue;
			}

			if (properties.Count == 0)
			{
				continue;
			}

			foreach (string selector in ruleMatch.Groups["selectors"].Value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
			{
				if (!selector.StartsWith('.') || selector.Length <= 1)
				{
					continue;
				}

				yield return new KeyValuePair<string, IReadOnlyDictionary<string, string>>(selector[1..], properties);
			}
		}
	}

	private static HashSet<string> GetInlineStylePropertyNames(string? styleAttributeValue)
	{
		HashSet<string> properties = new(StringComparer.OrdinalIgnoreCase);

		if (string.IsNullOrWhiteSpace(styleAttributeValue))
		{
			return properties;
		}

		foreach (string declaration in styleAttributeValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			int separatorIndex = declaration.IndexOf(':');
			if (separatorIndex > 0)
			{
				_ = properties.Add(declaration[..separatorIndex].Trim());
			}
		}

		return properties;
	}

	private static async Task UpdateItemAsync(DownloadManagerItem item, Action<DownloadManagerItem> updateAction) =>
		await Atlas.AppDispatcher.EnqueueAsync(() => updateAction(item)).ConfigureAwait(false);

	private async Task StopDownloadForRemovalAsync(DownloadManagerItem item)
	{
		await UpdateItemAsync(item, static current =>
		{
			current.State = DownloadState.Deleted;
			current.ErrorMessage = null;
			current.CompletedAtUtc = null;
			current.CurrentBytesPerSecond = 0;
		}).ConfigureAwait(false);

		ActiveDownloadOperation? activeDownloadOperation;

		lock (_activeDownloadsLock)
		{
			_ = _activeDownloads.TryGetValue(item, out activeDownloadOperation);
			if (activeDownloadOperation is not null)
			{
				activeDownloadOperation.DeleteRequested = true;
				activeDownloadOperation.PauseRequested = false;
				activeDownloadOperation.RestartRequested = false;
#pragma warning disable CA1849 // Can't await in a Lock.
				_ = activeDownloadOperation.CancellationTokenSource.CancelAsync();
#pragma warning restore CA1849
			}
		}

		RemovePendingItem(item);

		if (activeDownloadOperation is not null)
		{
			_ = await activeDownloadOperation.CompletionSource.Task.ConfigureAwait(false);
		}
	}

	private void RequestDownloadPause(DownloadManagerItem item)
	{
		lock (_activeDownloadsLock)
		{
			if (!_activeDownloads.TryGetValue(item, out ActiveDownloadOperation? activeDownloadOperation))
			{
				return;
			}

			activeDownloadOperation.PauseRequested = true;
			activeDownloadOperation.CancellationTokenSource.Cancel();
		}
	}

	private bool TryEnqueuePendingItem(DownloadManagerItem item)
	{
		lock (_queueLock)
		{
			if (_pendingDownloads.Contains(item) || item.State is DownloadState.Running)
			{
				return false;
			}

			_pendingDownloads.Enqueue(item);
			return true;
		}
	}

	private void RemovePendingItem(DownloadManagerItem item)
	{
		lock (_queueLock)
		{
			if (_pendingDownloads.Count == 0)
			{
				return;
			}

			Queue<DownloadManagerItem> remaining = new();
			while (_pendingDownloads.Count > 0)
			{
				DownloadManagerItem current = _pendingDownloads.Dequeue();
				if (!ReferenceEquals(current, item))
				{
					remaining.Enqueue(current);
				}
			}

			while (remaining.Count > 0)
			{
				_pendingDownloads.Enqueue(remaining.Dequeue());
			}
		}
	}

	private void UpdateEmptyStateVisibility()
	{
		EmptyStateVisibility = FilteredDownloadItems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
		OnPropertyChanged(nameof(EmptyStateText));
	}

	private void ArmCompletionAction()
	{
		lock (_completionActionLock)
		{
			_completionActionTriggered = false;
		}
	}

	private async Task RefreshFilteredDownloadItemsAsync()
	{
		List<DownloadManagerItem> items = await Atlas.AppDispatcher.EnqueueAsync(() => DownloadItems.ToList()).ConfigureAwait(false);
		await Atlas.AppDispatcher.EnqueueAsync(() => RefreshFilteredDownloadItemsCore(items)).ConfigureAwait(false);
	}

	private void RefreshFilteredDownloadItemsCore(IReadOnlyList<DownloadManagerItem> items)
	{
		string query = (SearchText ?? string.Empty).Trim();
		IEnumerable<DownloadManagerItem> filtered = string.IsNullOrWhiteSpace(query)
			? items
			: items.Where(item =>
				item.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
				|| item.SourceUrl.Contains(query, StringComparison.OrdinalIgnoreCase)
				|| item.FilePath.Contains(query, StringComparison.OrdinalIgnoreCase)
				|| item.DestinationDirectory.Contains(query, StringComparison.OrdinalIgnoreCase)
				|| item.StatusText.Contains(query, StringComparison.OrdinalIgnoreCase));
		List<DownloadManagerItem> filteredList = ApplyActiveSort(filtered).ToList();

		FilteredDownloadItems.Clear();
		foreach (DownloadManagerItem item in filteredList)
		{
			FilteredDownloadItems.Add(item);
		}

		_ = _selectedDownloadItems.RemoveAll(item => !FilteredDownloadItems.Contains(item));
		NotifySelectedDownloadsChanged();
		UpdateEmptyStateVisibility();
	}

	private void NotifySelectedDownloadsChanged()
	{
		OnPropertyChanged(nameof(HasSelectedDownloads));
		OnPropertyChanged(nameof(SelectedDownloadCount));
		OnPropertyChanged(nameof(SelectedDownloadsText));
		OnPropertyChanged(nameof(CanSelectAllDownloads));
		OnPropertyChanged(nameof(CanDeselectAllDownloads));
		OnPropertyChanged(nameof(CanPauseSelectedDownloads));
		OnPropertyChanged(nameof(CanResumeSelectedDownloads));
		OnPropertyChanged(nameof(CanDeleteSelectedDownloads));
		OnPropertyChanged(nameof(CanRemoveSelectedDownloads));
		OnPropertyChanged(nameof(SelectionActionsVisibility));
	}

	private void ApplySort(string sortKey)
	{
		if (string.Equals(_sortState.CurrentSortKey, sortKey, StringComparison.OrdinalIgnoreCase))
		{
			_sortState.IsDescending = !_sortState.IsDescending;
		}
		else
		{
			_sortState.CurrentSortKey = sortKey;
			_sortState.IsDescending = sortKey is "Size" or "DateAdded";
		}

		OnPropertyChanged(nameof(ActiveSortToolTip));
		_ = RefreshFilteredDownloadItemsAsync();
	}

	private IEnumerable<DownloadManagerItem> ApplyActiveSort(IEnumerable<DownloadManagerItem> items)
	{
		Func<DownloadManagerItem, object?>? keySelector = _sortState.CurrentSortKey switch
		{
			"Name" => static item => item.DisplayName,
			"Size" => static item => item.TotalBytes ?? item.BytesReceived,
			"DateAdded" => static item => item.CreatedAtUtc,
			_ => null
		};

		if (keySelector is null)
		{
			return items;
		}

		return _sortState.IsDescending
			? items.OrderByDescending(keySelector).ThenByDescending(static item => item.CreatedAtUtc)
			: items.OrderBy(keySelector).ThenBy(static item => item.CreatedAtUtc);
	}

	private string GetActiveSortDescription()
	{
		if (string.IsNullOrWhiteSpace(_sortState.CurrentSortKey))
		{
			return "Sort downloads";
		}

		return _sortState.CurrentSortKey switch
		{
			"Name" => _sortState.IsDescending ? "Sorted by name (Z to A)" : "Sorted by name (A to Z)",
			"Size" => _sortState.IsDescending ? "Sorted by size (largest first)" : "Sorted by size (smallest first)",
			"DateAdded" => _sortState.IsDescending ? "Sorted by date added (newest first)" : "Sorted by date added (oldest first)",
			_ => "Sort downloads"
		};
	}

	private async Task TryScrollPresetsSectionIntoViewAsync()
	{
		if (!_scrollPresetLimitsIntoViewOnNextSettingsNavigation || _downloadManagerPresetsSectionHeader is null)
		{
			return;
		}

		_scrollPresetLimitsIntoViewOnNextSettingsNavigation = false;
		await Atlas.AppDispatcher.EnqueueAsync(() =>
		{
			_downloadManagerPresetsSectionHeader.UpdateLayout();
			_downloadManagerPresetsSectionHeader.StartBringIntoView();
		}).ConfigureAwait(false);
	}

	private async Task<string?> ResolveInitialFilePathAsync(Uri link, string displayName, DownloadManagerItem? itemToIgnore = null)
	{
		string preferredPath = Path.Join(ResolvedDownloadDirectory, SanitizeFileName(displayName));

		List<DownloadManagerItem> existingItems = await Atlas.AppDispatcher.EnqueueAsync(() => DownloadItems.ToList()).ConfigureAwait(false);

		List<DownloadManagerItem> conflictingItems = existingItems
			.Where(candidate =>
				!ReferenceEquals(candidate, itemToIgnore)
				&& candidate.State is not DownloadState.Deleted
				&& (string.Equals(candidate.SourceUrl, link.AbsoluteUri, StringComparison.OrdinalIgnoreCase)
					|| (!string.IsNullOrWhiteSpace(candidate.FilePath)
						&& string.Equals(candidate.FilePath, preferredPath, StringComparison.OrdinalIgnoreCase))))
			.ToList();

		bool hasActiveConflict = conflictingItems.Any(static item => item.State is DownloadState.Queued or DownloadState.Running);

		bool hasDiskConflict = File.Exists(preferredPath) || File.Exists(GetTemporaryFilePath(preferredPath)) || File.Exists(GetCheckpointFilePath(preferredPath));

		if ((!hasDiskConflict && conflictingItems.Count == 0) || hasActiveConflict)
		{
			return hasActiveConflict ? GetUniqueDestinationPath(ResolvedDownloadDirectory, displayName) : preferredPath;
		}

		string? resolvedPath = ExistingDownloadConflictBehavior switch
		{
			ExistingDownloadConflictBehavior.Overwrite => preferredPath,
			ExistingDownloadConflictBehavior.AddDuplicate => GetUniqueDestinationPath(ResolvedDownloadDirectory, displayName),
			_ => await ShowExistingDownloadConflictDialogAsync(preferredPath, displayName).ConfigureAwait(false)
		};

		if (!string.IsNullOrWhiteSpace(resolvedPath)
			&& string.Equals(resolvedPath, preferredPath, StringComparison.OrdinalIgnoreCase)
			&& conflictingItems.Count > 0)
		{
			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				foreach (DownloadManagerItem conflictingItem in conflictingItems)
				{
					if (conflictingItem.State is DownloadState.Queued or DownloadState.Running)
					{
						continue;
					}

					_ = DownloadItems.Remove(conflictingItem);
					RemovePendingItem(conflictingItem);
				}
			}).ConfigureAwait(false);
		}

		return resolvedPath;
	}

	private async Task<string?> ShowExistingDownloadConflictDialogAsync(string preferredPath, string displayName)
	{
		ContentDialogResult result = ContentDialogResult.None;

		await Atlas.AppDispatcher.EnqueueAsync(async () =>
		{
			StackPanel content = new()
			{
				Spacing = 8
			};

			content.Children.Add(new TextBlock
			{
				Text = $"A download named '{displayName}' already exists.",
				TextWrapping = TextWrapping.WrapWholeWords
			});
			content.Children.Add(new TextBlock
			{
				Text = preferredPath,
				TextWrapping = TextWrapping.WrapWholeWords,
				IsTextSelectionEnabled = true
			});
			content.Children.Add(new TextBlock
			{
				Text = "Overwrite replaces the existing file entry. Add duplicate keeps both downloads by creating a unique file name.",
				TextWrapping = TextWrapping.WrapWholeWords,
				Foreground = new SolidColorBrush(Colors.Gray)
			});

			using ContentDialogV2 dialog = new()
			{
				Title = "Choose what to do with the existing download",
				Content = content,
				PrimaryButtonText = "Overwrite",
				SecondaryButtonText = "Add duplicate",
				CloseButtonText = Atlas.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Secondary
			};

			result = await dialog.ShowAsync();
		}).ConfigureAwait(false);

		return result switch
		{
			ContentDialogResult.Primary => preferredPath,
			ContentDialogResult.Secondary => TryGetDirectoryPath(preferredPath, out string? directory)
				? GetUniqueDestinationPath(directory, Path.GetFileName(preferredPath))
				: preferredPath,
			_ => null
		};
	}

	private async Task MaybeRunCompletionActionAsync()
	{
		if (CompletionAction is DownloadCompletionAction.None)
		{
			return;
		}

		bool noActiveOrQueuedWork;
		lock (_queueLock)
		{
			noActiveOrQueuedWork = _activeDownloadCount == 0 && _pendingDownloads.Count == 0;
		}

		if (!noActiveOrQueuedWork)
		{
			return;
		}

		List<DownloadManagerItem> items = await Atlas.AppDispatcher.EnqueueAsync(() => DownloadItems.ToList()).ConfigureAwait(false);
		if (items.Any(static item => item.State is DownloadState.Queued or DownloadState.Running))
		{
			return;
		}

		lock (_completionActionLock)
		{
			if (_completionActionTriggered)
			{
				return;
			}

			_completionActionTriggered = true;
		}

		await ExecuteCompletionActionAsync(CompletionAction).ConfigureAwait(false);
	}

	private static Task ExecuteCompletionActionAsync(DownloadCompletionAction action)
	{
		if (action is DownloadCompletionAction.None)
		{
			return Task.CompletedTask;
		}

		if (!NativeMethods.OpenProcessToken(NativeMethods.GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out IntPtr tokenHandle))
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to open the current process token for privilege '{ShutdownPrivilegeName}'.");
		}

		try
		{
			if (!NativeMethods.LookupPrivilegeValueW(null, ShutdownPrivilegeName, out LUID luid))
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to look up privilege '{ShutdownPrivilegeName}'.");
			}

			TOKEN_PRIVILEGES tokenPrivileges = new()
			{
				PrivilegeCount = 1,
				Privileges = new LUID_AND_ATTRIBUTES
				{
					Luid = luid,
					Attributes = SePrivilegeEnabled
				}
			};

			if (!NativeMethods.AdjustTokenPrivileges(tokenHandle, false, ref tokenPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError(), $"Failed to enable privilege '{ShutdownPrivilegeName}'.");
			}

			int adjustError = Marshal.GetLastPInvokeError();

			if (adjustError != 0)
			{
				throw new Win32Exception(adjustError, $"The process token does not allow enabling privilege '{ShutdownPrivilegeName}'.");
			}
		}
		finally
		{
			_ = NativeMethods.CloseHandle(tokenHandle);
		}

		switch (action)
		{
			case DownloadCompletionAction.Shutdown:
				if (!NativeMethods.ExitWindowsEx(
					EwxShutdown | EwxPowerOff | EwxForce,
					ShtdnReasonMajorOperatingSystem | ShtdnReasonMinorReconfig | ShtdnReasonFlagPlanned))
				{
					throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to shut down the computer after all downloads completed.");
				}

				break;
			case DownloadCompletionAction.Sleep:
				if (!NativeMethods.SetSuspendState(false, false, false))
				{
					throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to put the computer to sleep after all downloads completed.");
				}

				break;
			case DownloadCompletionAction.Hibernate:
				if (!NativeMethods.SetSuspendState(true, false, false))
				{
					throw new Win32Exception(Marshal.GetLastPInvokeError(), "Failed to hibernate the computer after all downloads completed.");
				}

				break;
			case DownloadCompletionAction.None:
				break;
			default:
				break;
		}

		return Task.CompletedTask;
	}

	internal static string ResolveDefaultDownloadsDirectory()
	{
		IntPtr pathPointer = IntPtr.Zero;

		try
		{
			Guid downloadsFolderGuid = DownloadsFolderGuid;
			int result = NativeMethods.SHGetKnownFolderPath(ref downloadsFolderGuid, 0, IntPtr.Zero, out pathPointer);
			if (result == 0)
			{
				string? downloadsPath = Marshal.PtrToStringUni(pathPointer);
				if (!string.IsNullOrWhiteSpace(downloadsPath))
				{
					return downloadsPath;
				}
			}
		}
		finally
		{
			if (pathPointer != IntPtr.Zero)
			{
				Marshal.FreeCoTaskMem(pathPointer);
			}
		}

		return Path.Join(UserProfile, "Downloads");
	}

	private static string GetDisplayNameFromUri(Uri uri)
	{
		string lastSegment = uri.Segments.LastOrDefault() ?? string.Empty;
		lastSegment = Uri.UnescapeDataString(lastSegment).Trim('/');
		return string.IsNullOrWhiteSpace(lastSegment) ? uri.Host : SanitizeFileName(lastSegment);
	}

	private static string GetSuggestedFileName(HttpResponseMessage response, Uri sourceUri)
	{
		string? contentDispositionFileName = GetContentDispositionFileName(response);
		string? contentType = response.Content.Headers.ContentType?.MediaType;
		string? contentDispositionCandidate = null;

		if (!string.IsNullOrWhiteSpace(contentDispositionFileName))
		{
			contentDispositionCandidate = EnsureFileNameHasExtension(SanitizeFileName(contentDispositionFileName.Trim('"')), contentType);
			if (!IsGenericDownloadName(contentDispositionCandidate))
			{
				return contentDispositionCandidate;
			}
		}

		Uri? responseUri = response.RequestMessage?.RequestUri;

		string? candidate = GetSuggestedFileNameFromQuery(responseUri);
		if (!string.IsNullOrWhiteSpace(candidate))
		{
			return EnsureFileNameHasExtension(candidate, contentType);
		}

		candidate = GetMeaningfulFileNameFromUri(responseUri);
		if (!string.IsNullOrWhiteSpace(candidate))
		{
			return EnsureFileNameHasExtension(candidate, contentType);
		}

		candidate = GetSuggestedFileNameFromQuery(sourceUri);
		if (!string.IsNullOrWhiteSpace(candidate))
		{
			return EnsureFileNameHasExtension(candidate, contentType);
		}

		candidate = GetMeaningfulFileNameFromUri(sourceUri);
		if (!string.IsNullOrWhiteSpace(candidate))
		{
			return EnsureFileNameHasExtension(candidate, contentType);
		}

		if (!string.IsNullOrWhiteSpace(contentDispositionCandidate))
		{
			return contentDispositionCandidate;
		}

		return EnsureFileNameHasExtension($"download-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.bin", contentType);
	}

	private static string? GetContentDispositionFileName(HttpResponseMessage response)
	{
		string? parsedFileName = response.Content.Headers.ContentDisposition?.FileNameStar
			?? response.Content.Headers.ContentDisposition?.FileName;
		if (!string.IsNullOrWhiteSpace(parsedFileName))
		{
			return parsedFileName.Trim('"');
		}

		// Some responses expose Content-Disposition in the raw headers, but HttpClient leaves
		// Content.Headers.ContentDisposition unset for them. Fall back to parsing the raw header so
		// Such links still upgrade placeholder URL names to the actual downloaded file name.
		return TryGetContentDispositionFileNameFromHeaders(response.Content.Headers)
			?? TryGetContentDispositionFileNameFromHeaders(response.Headers);
	}

	private static string? TryGetContentDispositionFileNameFromHeaders(HttpHeaders headers)
	{
		if (!headers.TryGetValues("Content-Disposition", out IEnumerable<string>? headerValues))
		{
			return null;
		}

		foreach (string headerValue in headerValues)
		{
			string? fileNameStar = TryExtractContentDispositionParameter(headerValue, "filename*");
			if (!string.IsNullOrWhiteSpace(fileNameStar))
			{
				return fileNameStar;
			}

			string? fileName = TryExtractContentDispositionParameter(headerValue, "filename");
			if (!string.IsNullOrWhiteSpace(fileName))
			{
				return fileName;
			}
		}

		return null;
	}

	private static string? TryExtractContentDispositionParameter(string headerValue, string parameterName)
	{
		if (string.IsNullOrWhiteSpace(headerValue) || string.IsNullOrWhiteSpace(parameterName))
		{
			return null;
		}

		foreach (string segment in headerValue.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
		{
			int separatorIndex = segment.IndexOf('=');
			if (separatorIndex <= 0)
			{
				continue;
			}

			string name = segment[..separatorIndex].Trim();
			if (!name.Equals(parameterName, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			string value = segment[(separatorIndex + 1)..].Trim().Trim('"');
			if (string.IsNullOrWhiteSpace(value))
			{
				return null;
			}

			if (parameterName.Equals("filename*", StringComparison.OrdinalIgnoreCase))
			{
				int charsetSeparatorIndex = value.IndexOf("''", StringComparison.Ordinal);
				if (charsetSeparatorIndex >= 0 && charsetSeparatorIndex + 2 < value.Length)
				{
					value = value[(charsetSeparatorIndex + 2)..];
				}

				value = Uri.UnescapeDataString(value);
			}

			return value;
		}

		return null;
	}

	private static string GetUniqueDestinationPath(string directory, string fileName)
	{
		string sanitizedFileName = SanitizeFileName(fileName);
		string baseName = Path.GetFileNameWithoutExtension(sanitizedFileName);
		string extension = Path.GetExtension(sanitizedFileName);
		string candidate = Path.Join(directory, sanitizedFileName);
		int suffix = 1;

		while (File.Exists(candidate) || File.Exists(GetTemporaryFilePath(candidate)) || File.Exists(GetCheckpointFilePath(candidate)))
		{
			candidate = Path.Join(directory, $"{baseName} ({suffix++}){extension}");
		}

		return candidate;
	}

	private static string SanitizeFileName(string fileName)
	{
		// Fast path because nothing to sanitize so avoid any allocation
		if (string.IsNullOrEmpty(fileName) || fileName.IndexOfAny(Atlas.InvalidFileNameChars.Value) < 0)
		{
			return string.IsNullOrWhiteSpace(fileName) ? "download.bin" : fileName;
		}

		// Single buffer pass
		Span<char> buffer = fileName.Length <= 256 ? stackalloc char[fileName.Length] : new char[fileName.Length];
		fileName.CopyTo(buffer);

		for (int i = 0; i < buffer.Length; i++)
		{
			if (Array.IndexOf(Atlas.InvalidFileNameChars.Value, buffer[i]) >= 0)
			{
				buffer[i] = '_';
			}
		}

		string sanitized = new(buffer);
		return string.IsNullOrWhiteSpace(sanitized) ? "download.bin" : sanitized;
	}

	private static string? GetMeaningfulFileNameFromUri(Uri? uri)
	{
		if (uri is null)
		{
			return null;
		}

		string candidate = GetDisplayNameFromUri(uri);
		return string.IsNullOrWhiteSpace(candidate) || IsGenericDownloadName(candidate)
			? null
			: candidate;
	}

	private static bool IsGenericDownloadName(string fileName)
	{
		string normalizedName = Path.GetFileNameWithoutExtension(fileName).Trim();
		return !fileName.Contains('.')
			&& (normalizedName.Equals("get", StringComparison.OrdinalIgnoreCase)
				|| normalizedName.Equals("download", StringComparison.OrdinalIgnoreCase)
				|| normalizedName.Equals("file", StringComparison.OrdinalIgnoreCase)
				|| normalizedName.Equals("attachment", StringComparison.OrdinalIgnoreCase));
	}

	private static string? GetSuggestedFileNameFromQuery(Uri? uri)
	{
		if (uri is null || string.IsNullOrWhiteSpace(uri.Query))
		{
			return null;
		}

		foreach (string pair in uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
		{
			int separatorIndex = pair.IndexOf('=');
			string key = Uri.UnescapeDataString((separatorIndex >= 0 ? pair[..separatorIndex] : pair).Replace('+', ' '));
			string value = Uri.UnescapeDataString((separatorIndex >= 0 ? pair[(separatorIndex + 1)..] : string.Empty).Replace('+', ' '));

			if (string.IsNullOrWhiteSpace(value))
			{
				continue;
			}

			if (key.Equals("filename", StringComparison.OrdinalIgnoreCase)
				|| key.Equals("file", StringComparison.OrdinalIgnoreCase)
				|| key.Equals("name", StringComparison.OrdinalIgnoreCase)
				|| key.Equals("download", StringComparison.OrdinalIgnoreCase)
				|| key.Equals("attachment", StringComparison.OrdinalIgnoreCase))
			{
				return SanitizeFileName(Path.GetFileName(value));
			}

			string? nestedCandidate = Uri.TryCreate(value, UriKind.Absolute, out Uri? nestedUri)
				? GetSuggestedFileNameFromQuery(nestedUri) ?? GetMeaningfulFileNameFromUri(nestedUri)
				: TryGetFileNameFromJwtPayload(value);
			if (!string.IsNullOrWhiteSpace(nestedCandidate))
			{
				return nestedCandidate;
			}
		}

		return null;
	}

	private static string? TryGetFileNameFromJwtPayload(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		string[] parts = value.Split('.');
		if (parts.Length != 3)
		{
			return null;
		}

		try
		{
			byte[] payloadBytes = DecodeBase64Url(parts[1]);
			using JsonDocument payload = JsonDocument.Parse(payloadBytes);

			if (TryGetNamedJsonString(payload.RootElement, "filename", out string? fileName)
				|| TryGetNamedJsonString(payload.RootElement, "fileName", out fileName)
				|| TryGetNamedJsonString(payload.RootElement, "name", out fileName))
			{
				return SanitizeFileName(Path.GetFileName(fileName));
			}

			if ((TryGetNamedJsonString(payload.RootElement, "url", out string? nestedUrl)
					|| TryGetNamedJsonString(payload.RootElement, "uri", out nestedUrl))
				&& Uri.TryCreate(nestedUrl, UriKind.Absolute, out Uri? nestedUri))
			{
				return GetSuggestedFileNameFromQuery(nestedUri) ?? GetMeaningfulFileNameFromUri(nestedUri);
			}
		}
		catch
		{
			return null;
		}

		return null;
	}

	private static bool TryGetNamedJsonString(JsonElement element, string name, [NotNullWhen(true)] out string? value)
	{
		if (element.ValueKind is JsonValueKind.Object)
		{
			foreach (JsonProperty property in element.EnumerateObject())
			{
				if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
					&& property.Value.ValueKind is JsonValueKind.String)
				{
					value = property.Value.GetString();
					return !string.IsNullOrWhiteSpace(value);
				}
			}
		}

		value = null;
		return false;
	}

	private static byte[] DecodeBase64Url(string value)
	{
		string normalized = value.Replace('-', '+').Replace('_', '/');
		int paddingLength = (4 - (normalized.Length % 4)) % 4;
		if (paddingLength > 0)
		{
			normalized = normalized.PadRight(normalized.Length + paddingLength, '=');
		}

		return Convert.FromBase64String(normalized);
	}

	private static string EnsureFileNameHasExtension(string fileName, string? mediaType)
	{
		if (!string.IsNullOrWhiteSpace(Path.GetExtension(fileName)))
		{
			return fileName;
		}

		string? extension = mediaType?.ToLowerInvariant() switch
		{
			"application/pdf" => ".pdf",
			"application/zip" => ".zip",
			"application/json" => ".json",
			"application/octet-stream" => null,
			"audio/mpeg" => ".mp3",
			"image/gif" => ".gif",
			"image/jpeg" => ".jpg",
			"image/png" => ".png",
			"image/webp" => ".webp",
			"text/plain" => ".txt",
			"video/mp4" => ".mp4",
			"video/quicktime" => ".mov",
			"video/webm" => ".webm",
			_ => null
		};

		return extension is null ? fileName : $"{fileName}{extension}";
	}

	private int GetSpeedLimitBytesPerSecond() => ActiveSpeedPreset switch
	{
		DownloadSpeedPreset.Slow => checked(SlowPresetKilobytesPerSecond * 1024),
		DownloadSpeedPreset.Medium => checked(MediumPresetKilobytesPerSecond * 1024),
		DownloadSpeedPreset.Full => IsFullPresetUnlimited ? 0 : checked(FullPresetKilobytesPerSecond * 1024),
		_ => IsFullPresetUnlimited ? 0 : checked(FullPresetKilobytesPerSecond * 1024)
	};

	private int GetBufferSize()
	{
		int speedLimitBytes = GetSpeedLimitBytesPerSecond();
		return speedLimitBytes <= 0
			? 81_920
			: Math.Clamp(speedLimitBytes / 2, 1_024, 81_920);
	}

	private int GetReadChunkSize(int bufferLength)
	{
		int speedLimitBytes = GetSpeedLimitBytesPerSecond();
		return speedLimitBytes <= 0
			? bufferLength
			: Math.Clamp(speedLimitBytes / 10, 1_024, bufferLength);
	}

	private static int GetEffectiveParallelConnections(long? totalBytes, bool supportsRangeRequests, int requestedParallelConnections)
	{
		if (!supportsRangeRequests || !totalBytes.HasValue || totalBytes.Value <= 1)
		{
			return 1;
		}

		return Math.Clamp((int)Math.Min(totalBytes.Value, requestedParallelConnections), 1, 32);
	}

	private static List<DownloadSegmentRecord> CreateSegments(long totalBytes, int parallelConnections)
	{
		int connectionCount = Math.Clamp(parallelConnections, 1, (int)Math.Min(totalBytes, 32));
		List<DownloadSegmentRecord> segments = [];
		long baseSegmentLength = totalBytes / connectionCount;
		long remainder = totalBytes % connectionCount;
		long nextStart = 0;

		for (int i = 0; i < connectionCount; i++)
		{
			long currentSegmentLength = baseSegmentLength + (i < remainder ? 1 : 0);
			long endOffsetInclusive = nextStart + currentSegmentLength - 1;

			segments.Add(new DownloadSegmentRecord
			{
				StartOffset = nextStart,
				EndOffsetInclusive = endOffsetInclusive,
				NextOffset = nextStart
			});

			nextStart = endOffsetInclusive + 1;
		}

		return segments;
	}

	private static long CalculateReceivedBytes(DownloadCheckpointRecord checkpoint) =>
		checkpoint.Segments.Sum(static segment => Math.Max(0, segment.NextOffset - segment.StartOffset));

	private static bool IsCheckpointComplete(DownloadCheckpointRecord checkpoint)
	{
		if (checkpoint.TotalBytes.HasValue)
		{
			return CalculateReceivedBytes(checkpoint) >= checkpoint.TotalBytes.Value;
		}

		return checkpoint.Segments.All(static segment => segment.EndOffsetInclusive >= 0 && segment.NextOffset > segment.EndOffsetInclusive);
	}

	private static string GetTemporaryFilePath(string finalFilePath) => $"{finalFilePath}.hssdownload.part";

	private static string GetCheckpointFilePath(string finalFilePath)
	{
		string normalizedPath = Path.GetFullPath(finalFilePath).ToUpperInvariant();
		string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalizedPath)));
		string fileName = SanitizeFileName(Path.GetFileName(finalFilePath));
		return Path.Join(_checkpointDirectoryPath, $"{fileName}.{hash}.hssdownload.json");
	}

	private static DownloadCheckpointRecord CreateCheckpointSnapshot(DownloadCheckpointRecord checkpoint) => new()
	{
		SourceUrl = checkpoint.SourceUrl,
		DestinationDirectory = checkpoint.DestinationDirectory,
		FinalFilePath = checkpoint.FinalFilePath,
		TemporaryFilePath = checkpoint.TemporaryFilePath,
		CheckpointFilePath = checkpoint.CheckpointFilePath,
		TotalBytes = checkpoint.TotalBytes,
		SupportsRangeRequests = checkpoint.SupportsRangeRequests,
		ParallelConnectionsUsed = checkpoint.ParallelConnectionsUsed,
		CreatedAtUtc = checkpoint.CreatedAtUtc,
		ServerFileTimestampUtc = checkpoint.ServerFileTimestampUtc,
		UpdatedAtUtc = checkpoint.UpdatedAtUtc,
		Segments = checkpoint.Segments.Select(static segment => new DownloadSegmentRecord
		{
			StartOffset = segment.StartOffset,
			EndOffsetInclusive = segment.EndOffsetInclusive,
			NextOffset = segment.NextOffset
		}).ToList()
	};

	private static void SaveCheckpoint(DownloadCheckpointRecord checkpoint)
	{
		string json = JsonSerializer.Serialize(checkpoint, DownloadManagerJsonContext.Default.DownloadCheckpointRecord);
		WriteTextAtomically(checkpoint.CheckpointFilePath, json);
	}

	private static bool ShouldFlushDataFile(DownloadRuntimeState runtime)
	{
		DateTimeOffset now = DateTimeOffset.UtcNow;

		lock (runtime.SyncRoot)
		{
			if (now - runtime.LastDataFlushUtc < TimeSpan.FromSeconds(2))
			{
				return false;
			}

			runtime.LastDataFlushUtc = now;
			return true;
		}
	}

	private static void WriteTextAtomically(string path, string content)
	{
		if (!TryGetDirectoryPath(path, out string? directory))
		{
			throw new InvalidOperationException($"Unable to determine the parent directory for '{path}'.");
		}

		_ = Directory.CreateDirectory(directory);

		lock (_atomicWriteLock)
		{
			string temporaryPath = Path.Join(directory, $"{Path.GetFileName(path)}.{Guid.CreateVersion7():N}.tmp");

			try
			{
				File.WriteAllText(temporaryPath, content);
				File.Move(temporaryPath, path, overwrite: true);
			}
			finally
			{
				DeleteFileIfExists(temporaryPath);
			}
		}
	}

	private static bool TryGetDirectoryPath(string path, [NotNullWhen(true)] out string? directory)
	{
		directory = Path.GetDirectoryName(path);
		return !string.IsNullOrWhiteSpace(directory);
	}

	private static void DeleteFileIfExists(string? path)
	{
		if (File.Exists(path))
			File.Delete(path);
	}

	private static void ApplyMarkOfTheWebIfNeeded(string filePath, string sourceUrl)
	{
		if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(sourceUrl) || !MarkOfTheWebExtensions.Contains(Path.GetExtension(filePath)))
		{
			return;
		}

		try
		{
			string sanitizedSourceUrl = sourceUrl.Replace("\r", string.Empty).Replace("\n", string.Empty);
			string zoneIdentifierContent =
				$"[ZoneTransfer]{Environment.NewLine}ZoneId=3{Environment.NewLine}ReferrerUrl={sanitizedSourceUrl}{Environment.NewLine}HostUrl={sanitizedSourceUrl}{Environment.NewLine}";
			File.WriteAllText($"{filePath}:Zone.Identifier", zoneIdentifierContent, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static async Task<string> GetClipboardTextAsync()
	{
		DataPackageView clipboardContent = Clipboard.GetContent();
		if (!clipboardContent.Contains(StandardDataFormats.Text))
		{
			return string.Empty;
		}

		string? clipboardText = await clipboardContent.GetTextAsync();
		return clipboardText ?? string.Empty;
	}

	private static DateTimeOffset? GetServerFileTimestampUtc(HttpResponseMessage response)
	{
		DateTimeOffset? typedLastModified = response.Content.Headers.LastModified;
		if (typedLastModified.HasValue)
		{
			return typedLastModified.Value.ToUniversalTime();
		}

		return TryGetServerFileTimestampUtc(response.Content.Headers)
			?? TryGetServerFileTimestampUtc(response.Headers);
	}

	private static DateTimeOffset? TryGetServerFileTimestampUtc(HttpHeaders headers)
	{
		// Some CDNs send a raw Last-Modified header without hydrating the typed header property. Parse the
		// raw value too so those responses still populate the server-side timestamp in the list view.
		if (!headers.TryGetValues("Last-Modified", out IEnumerable<string>? values))
		{
			return null;
		}

		foreach (string value in values)
		{
			if (DateTimeOffset.TryParse(
				value,
				CultureInfo.InvariantCulture,
				DateTimeStyles.AllowWhiteSpaces | DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
				out DateTimeOffset parsed))
			{
				return parsed.ToUniversalTime();
			}
		}

		return null;
	}

	private static bool CanDropLinks(DataPackageView dataView) =>
		dataView.Contains(StandardDataFormats.WebLink) || dataView.Contains(StandardDataFormats.Text);

	private static async Task<List<Uri>> ExtractDroppedLinksAsync(DataPackageView dataView)
	{
		List<Uri> links = [];
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

		if (dataView.Contains(StandardDataFormats.WebLink))
		{
			Uri? webLink = await dataView.GetWebLinkAsync();
			if (webLink is not null
				&& (webLink.Scheme == Uri.UriSchemeHttp || webLink.Scheme == Uri.UriSchemeHttps)
				&& seen.Add(webLink.AbsoluteUri))
			{
				links.Add(webLink);
			}
		}

		if (dataView.Contains(StandardDataFormats.Text))
		{
			string? droppedText = await dataView.GetTextAsync();
			foreach (Uri link in ExtractLinks(droppedText))
			{
				if (seen.Add(link.AbsoluteUri))
				{
					links.Add(link);
				}
			}
		}

		return links;
	}

	private async Task RefreshActiveDownloadRateLimitsAsync()
	{
		try
		{
			List<KeyValuePair<DownloadManagerItem, DownloadRuntimeState>> activeDownloads;

			lock (_activeDownloadsLock)
			{
				activeDownloads = [.. _activeDownloadRuntimes];
			}

			if (activeDownloads.Count == 0)
			{
				_rateLimiter.Reset();
				return;
			}

			_rateLimiter.Reset();

			foreach (KeyValuePair<DownloadManagerItem, DownloadRuntimeState> activeDownload in activeDownloads)
			{
				lock (activeDownload.Value.SyncRoot)
				{
					activeDownload.Value.LastSpeedSampleUtc = DateTimeOffset.MinValue;
					activeDownload.Value.LastSpeedSampleBytes = CalculateReceivedBytes(activeDownload.Value.Checkpoint);
					activeDownload.Value.SmoothedBytesPerSecond = 0;
				}

				await UpdateItemAsync(activeDownload.Key, static current => current.CurrentBytesPerSecond = 0).ConfigureAwait(false);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private async Task ApplyParallelConnectionsPreferenceToAllItemsAsync(int requestedConnections)
	{
		try
		{
			bool anyChanged = false;
			int normalized = Math.Clamp(requestedConnections, 1, 32);
			List<DownloadManagerItem> items = await Atlas.AppDispatcher.EnqueueAsync(() => DownloadItems.ToList()).ConfigureAwait(false);

			foreach (DownloadManagerItem item in items)
			{
				bool isActiveDownload;

				lock (_activeDownloadsLock)
				{
					isActiveDownload = _activeDownloads.ContainsKey(item) || _activeDownloadRuntimes.ContainsKey(item);
				}

				// Do not mutate active or already-started downloads. Their checkpoint segment map was created
				// for the connection count that was active when the download started.
				if (isActiveDownload || !(item.BytesReceived <= 0 && item.State is DownloadState.Queued or DownloadState.Failed))
				{
					continue;
				}

				int effective = normalized;
				bool checkpointChanged = false;

				if (TryLoadCheckpoint(item, out DownloadCheckpointRecord? checkpoint))
				{
					checkpointChanged = ApplyParallelConnectionsPreference(checkpoint, normalized);
					effective = checkpoint.ParallelConnectionsUsed;

					if (checkpointChanged)
					{
						SaveCheckpoint(checkpoint);
					}
				}

				bool itemChanged = item.ParallelConnectionsUsed != effective;
				if (itemChanged)
				{
					await UpdateItemAsync(item, current => current.ParallelConnectionsUsed = effective).ConfigureAwait(false);
				}

				anyChanged |= itemChanged || checkpointChanged;
			}

			if (anyChanged)
			{
				await SaveHistoryAsync().ConfigureAwait(false);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	private static bool ApplyParallelConnectionsPreference(DownloadCheckpointRecord checkpoint, int requestedConnections)
	{
		int effective = GetEffectiveParallelConnections(checkpoint.TotalBytes, checkpoint.SupportsRangeRequests, requestedConnections);
		if (checkpoint.ParallelConnectionsUsed == effective)
		{
			return false;
		}

		// Segment boundaries are created from the original parallel connection count. Once any byte has
		// been received, changing only ParallelConnectionsUsed would make the checkpoint/history claim a
		// different connection count than the one actually used by the existing segment map.
		if (CalculateReceivedBytes(checkpoint) > 0)
		{
			return false;
		}

		checkpoint.ParallelConnectionsUsed = effective;
		checkpoint.UpdatedAtUtc = DateTimeOffset.UtcNow;

		if (checkpoint.SupportsRangeRequests && checkpoint.TotalBytes.HasValue && checkpoint.TotalBytes.Value > 0)
		{
			checkpoint.Segments = CreateSegments(checkpoint.TotalBytes.Value, effective);
		}

		return true;
	}

	internal void PreviewSurface_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item } && item.CanHoverPlayVideoPreview)
		{
			item.IsVideoPreviewHoverActive = true;
		}
		AnimatePreviewSurface(sender as FrameworkElement, scale: 1.03, translateY: -2D);
	}

	internal void PreviewSurface_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement { Tag: DownloadManagerItem item } && item.IsVideoPreviewHoverActive)
		{
			item.IsVideoPreviewHoverActive = false;
		}
		AnimatePreviewSurface(sender as FrameworkElement, scale: 1D, translateY: 0D);
	}

	private static void AnimatePreviewSurface(FrameworkElement? previewSurface, double scale, double translateY)
	{
		if (previewSurface is null)
		{
			return;
		}

		if (previewSurface.RenderTransform is not CompositeTransform transform)
		{
			transform = new();
			previewSurface.RenderTransform = transform;
		}

		Duration duration = new(TimeSpan.FromMilliseconds(180));
		CubicEase easing = new() { EasingMode = EasingMode.EaseOut };
		Storyboard storyboard = new();

		storyboard.Children.Add(CreatePreviewAnimation(previewSurface, "(UIElement.RenderTransform).(CompositeTransform.ScaleX)", transform.ScaleX, scale, duration, easing));
		storyboard.Children.Add(CreatePreviewAnimation(previewSurface, "(UIElement.RenderTransform).(CompositeTransform.ScaleY)", transform.ScaleY, scale, duration, easing));
		storyboard.Children.Add(CreatePreviewAnimation(previewSurface, "(UIElement.RenderTransform).(CompositeTransform.TranslateY)", transform.TranslateY, translateY, duration, easing));

		storyboard.Begin();
	}

	private static DoubleAnimation CreatePreviewAnimation(DependencyObject target, string propertyPath, double from, double to, Duration duration, EasingFunctionBase easing)
	{
		DoubleAnimation animation = new()
		{
			From = from,
			To = to,
			Duration = duration,
			EasingFunction = easing
		};

		Storyboard.SetTarget(animation, target);
		Storyboard.SetTargetProperty(animation, propertyPath);
		return animation;
	}

	internal static void HoverPreviewPlayer_Loaded(object sender, RoutedEventArgs e)
	{
		if (sender is MediaPlayerElement mediaPlayerElement && mediaPlayerElement.MediaPlayer is not null)
		{
			// Hover previews are meant to be visual-only; keep them muted and non-interactive so recycled
			// list items never surface unexpected audio or transport controls.
			mediaPlayerElement.MediaPlayer.IsMuted = true;
			mediaPlayerElement.MediaPlayer.CommandManager.IsEnabled = false;
		}
	}

	[JsonSourceGenerationOptions(WriteIndented = true)]
	[JsonSerializable(typeof(DownloadCheckpointRecord))]
	[JsonSerializable(typeof(List<DownloadHistoryRecord>))]
	private sealed partial class DownloadManagerJsonContext : JsonSerializerContext
	{
	}

	[GeneratedRegex(@"https?://[^\s<>""']+", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
	private static partial Regex MyRegex();

	[GeneratedRegex(@" \(\d+\)$", RegexOptions.CultureInvariant)]
	private static partial Regex MyRegex1();

	[GeneratedRegex(@"(?<selectors>(?:\s*\.[\w-]+\s*,)*\s*\.[\w-]+\s*)\{(?<body>[^}]*)\}", RegexOptions.CultureInvariant)]
	private static partial Regex MyRegex2();
}
