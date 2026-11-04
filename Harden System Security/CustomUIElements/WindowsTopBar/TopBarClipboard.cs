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
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;
using Windows.Storage;
using Windows.Storage.FileProperties;
using Windows.Storage.Streams;
using Windows.System;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// The clipboard part of <see cref="TopBar"/>. Clipboard entries are held in buckets inside collections. The index of the
/// collections and the rich formats of every clip are persisted as current-user DPAPI protected files under the app's
/// LocalCacheFolder.
/// </summary>
internal sealed partial class TopBarClipboardCommand(Action execute) : ICommand
{
	public event EventHandler? CanExecuteChanged { add { } remove { } }
	public bool CanExecute(object? parameter) => true;
	public void Execute(object? parameter) => execute();
}

/// <summary>
/// The rich formats of a clip, which are kept in the clip's own encrypted payload file instead of the index.
/// </summary>
[Flags]
internal enum TopBarClipboardFormats
{
	None = 0,
	Html = 1,
	Rtf = 2,
	Bitmap = 4
}

internal sealed class TopBarClipboardPreview
{
	internal BitmapImage? Image { get; init; }
	internal string PreviewText { get; init; } = string.Empty;
	internal string ToolTip { get; init; } = string.Empty;

	// A clip that is only a color shows the color with its text on top.
	internal SolidColorBrush? Swatch { get; init; }
	internal SolidColorBrush? SwatchForeground { get; init; }
	internal Visibility SwatchVisibility => Swatch is null ? Visibility.Collapsed : Visibility.Visible;

	// The title shown over the image of a link card.
	internal string LinkTitle { get; init; } = string.Empty;
	internal Visibility LinkVisibility => LinkTitle.Length == 0 ? Visibility.Collapsed : Visibility.Visible;
}

/// <summary>
/// A named group of buckets. Every collection has its own routing choice and holds at most 1000 buckets.
/// </summary>
internal sealed partial class TopBarClipboardCollection : INotifyPropertyChanged
{
	internal TopBarClipboardCollection(string name, bool isDefault)
	{
		Name = name;
		IsDefault = isDefault;
		Buckets.CollectionChanged += OnBucketsChanged;
	}
	internal string Name
	{
		get; set
		{
			field = value;
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Name)));
		}
	}
	internal bool IsDefault { get; }
	internal string Glyph => IsDefault ? "\uE81C" : "\uE8B7";
	internal ObservableCollection<TopBarClipboardBucket> Buckets { get; } = new();
	internal string CountText => Buckets.Count.ToString(CultureInfo.CurrentCulture);

	// The bucket that receives captures while new-bucket mode is off. A full collection reuses the bucket after it.
	internal TopBarClipboardBucket? Target { get; set; }
	internal bool UseNewBucket { get; set; } = true;

	// Bucket numbers follow list positions, so only the buckets from the first changed position onward are renumbered.
	private void OnBucketsChanged(object? sender, NotifyCollectionChangedEventArgs args)
	{
		int start = args.OldStartingIndex < 0 ? Math.Max(0, args.NewStartingIndex)
			: args.NewStartingIndex < 0 ? args.OldStartingIndex
			: Math.Min(args.OldStartingIndex, args.NewStartingIndex);

		for (int index = start; index < Buckets.Count; index++)
		{
			Buckets[index].SetDisplayNumber(index + 1);
		}

		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(CountText)));
	}
	public event PropertyChangedEventHandler? PropertyChanged;
	public override string ToString() => Name;
}

internal sealed partial class TopBarClipboardBucket : INotifyPropertyChanged
{
	internal TopBarClipboardBucket(TopBarClipboardCollection collection, Action<TopBarClipboardBucket> openDetailsAction, Action<TopBarClipboardBucket> deleteAction)
	{
		Collection = collection;
		OpenDetailsCommand = new TopBarClipboardCommand(() => openDetailsAction(this));
		DeleteCommand = new TopBarClipboardCommand(() => deleteAction(this));
	}
	internal TopBarClipboardCollection Collection { get; }
	internal int DisplayNumber { get; private set; }
	internal string? CustomName { get; private set; }
	internal ICommand OpenDetailsCommand { get; }
	internal ICommand DeleteCommand { get; }
	internal List<TopBarClipboardEntry> Entries { get; } = new();
	private TopBarClipboardPreview[] _previews = [];
	internal bool HasPreviews => _previews.Length > 0;
	internal TopBarClipboardPreview? Preview1 => _previews.Length > 0 ? _previews[0] : null;
	internal TopBarClipboardPreview? Preview2 => _previews.Length > 1 ? _previews[1] : null;
	internal TopBarClipboardPreview? Preview3 => _previews.Length > 2 ? _previews[2] : null;
	internal TopBarClipboardPreview? Preview4 => _previews.Length > 3 ? _previews[3] : null;
	internal Visibility Preview1Visibility => Preview1 is null ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility Preview2Visibility => Preview2 is null ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility Preview3Visibility => Preview3 is null ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility Preview4Visibility => Preview4 is null ? Visibility.Collapsed : Visibility.Visible;
	internal int Preview1RowSpan => _previews.Length <= 2 ? 2 : 1;
	internal int Preview2RowSpan => _previews.Length == 2 ? 2 : 1;
	internal int Preview1ColumnSpan => _previews.Length == 1 ? 2 : 1;
	internal string Title => string.IsNullOrWhiteSpace(CustomName)
		? "Bucket " + DisplayNumber.ToString(CultureInfo.InvariantCulture)
		: CustomName;
	internal string CountText => Entries.Count.ToString(CultureInfo.InvariantCulture) + " clip" + (Entries.Count == 1 ? string.Empty : "s");
	internal Visibility HighlightVisibility => IsHighlighted ? Visibility.Visible : Visibility.Collapsed;

	// Set on the bucket that holds the current search match.
	internal bool IsHighlighted
	{
		get; set
		{
			if (field == value)
			{
				return;
			}
			field = value;
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(HighlightVisibility)));
		}
	}

	// Raised whenever the entries change, so a preview job that started earlier does not publish previews of older entries.
	internal int PreviewVersion { get; set; }

	// The realized card that shows this bucket. Only realized cards hold previews, which bounds the decoded images to the
	// cards near the viewport however many buckets a collection holds.
	internal SelectorItem? RealizedContainer { get; set; }
	internal bool IsPreviewQueued { get; set; }

	internal void SetPreviews(TopBarClipboardPreview[] previews)
	{
		_previews = previews;
		NotifyContentChanged();
	}

	internal bool SetCustomName(string? customName)
	{
		string? normalizedName = string.IsNullOrWhiteSpace(customName) ? null : customName.Trim();
		if (string.Equals(CustomName, normalizedName, StringComparison.Ordinal))
		{
			return false;
		}
		CustomName = normalizedName;
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Title)));
		return true;
	}

	internal void SetDisplayNumber(int displayNumber)
	{
		if (DisplayNumber == displayNumber)
		{
			return;
		}
		DisplayNumber = displayNumber;
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Title)));
	}

	internal void NotifyContentChanged()
	{
		ReadOnlySpan<string> propertyNames =
		[
			nameof(CountText),
			nameof(Preview1),
			nameof(Preview2),
			nameof(Preview3),
			nameof(Preview4),
			nameof(Preview1Visibility),
			nameof(Preview2Visibility),
			nameof(Preview3Visibility),
			nameof(Preview4Visibility),
			nameof(Preview1RowSpan),
			nameof(Preview2RowSpan),
			nameof(Preview1ColumnSpan)
		];
		for (int index = 0; index < propertyNames.Length; index++)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyNames[index]));
		}
	}
	public event PropertyChangedEventHandler? PropertyChanged;
	public override string ToString() => Title;
}

internal sealed class TopBarClipboardEntry
{
	internal DateTimeOffset CapturedAt { get; init; }
	internal string? Text { get; init; }
	internal TopBarClipboardFormats Formats { get; init; }

	// The encrypted file that holds the HTML, RTF and bitmap formats of this clip, or null when it has none of them.
	internal Guid? PayloadId { get; set; }
	internal bool HasBitmap => (Formats & TopBarClipboardFormats.Bitmap) != 0;
	internal List<TopBarClipboardFile> Files { get; init; } = new(0);
	internal string Summary { get; init; } = string.Empty;

	// The card of a clip that is a single web address. Its image is kept in an encrypted file of its own.
	internal string? LinkTitle { get; set; }
	internal string? LinkDescription { get; set; }
	internal Guid? LinkImageId { get; set; }
	internal bool ShowsLinkCard => (LinkTitle is not null || LinkImageId is not null) && Atlas.Settings.WindowsTopBarClipboardLinkPreviews;

	internal string DisplayName => Files.Count == 1 ? Files[0].Name
		: ShowsLinkCard && LinkTitle is not null ? LinkTitle
		: GetTextPreview();

	internal string Metadata => Files.Count == 1
		? Files[0].Path + "  |  " + FormatFileSize(Files[0].Size)
		: ShowsLinkCard ? (LinkDescription is null ? string.Empty : LinkDescription + "  |  ") + GetTextPreview()
		: Summary + "  |  " + CapturedAt.LocalDateTime.ToString("g", CultureInfo.CurrentCulture);

	internal string GetTextPreview()
	{
		string source = Text ?? Summary;
		string normalized = string.Join(' ', source.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
		return normalized.Length <= 160 ? normalized : normalized[..157] + "...";
	}

	internal static string FormatFileSize(ulong size) => size switch
	{
		>= 1UL << 30 => (size / (double)(1UL << 30)).ToString("0.##", CultureInfo.CurrentCulture) + " GB",
		>= 1UL << 20 => (size / (double)(1UL << 20)).ToString("0.##", CultureInfo.CurrentCulture) + " MB",
		>= 1UL << 10 => (size / (double)(1UL << 10)).ToString("0.##", CultureInfo.CurrentCulture) + " KB",
		_ => size.ToString(CultureInfo.CurrentCulture) + " bytes"
	};
	public override string ToString() => DisplayName;
}

internal sealed class TopBarClipboardFile
{
	internal string Name { get; init; } = string.Empty;
	internal string Path { get; init; } = string.Empty;
	internal string FileType { get; init; } = string.Empty;
	internal ulong Size { get; init; }
}

internal sealed partial class TopBarClipboardViewerItem(TopBarClipboardEntry entry, Action deleteAction) : INotifyPropertyChanged
{
	internal TopBarClipboardEntry Entry => entry;
	internal string DisplayName => Entry.DisplayName;
	internal string Metadata => Entry.Metadata;
	internal ICommand DeleteCommand { get; } = new TopBarClipboardCommand(deleteAction);

	// Built while the row is realized and released when the row is recycled.
	internal TopBarClipboardPreview? Preview
	{
		get; set
		{
			if (ReferenceEquals(field, value))
			{
				return;
			}
			field = value;
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(Preview)));
		}
	}
	internal SelectorItem? RealizedContainer { get; set; }
	public event PropertyChangedEventHandler? PropertyChanged;
}

/// <summary>
/// A compact top-level clipboard explorer.
/// </summary>
internal sealed class TopBarClipboardExplorerWindow : Window
{
	private const double ExplorerPreferredWidthDips = 720.0;
	private const double ExplorerPreferredHeightDips = 420.0;
	private const double ExplorerMinimumWidthDips = 360.0;
	private const double ExplorerMinimumHeightDips = 180.0;
	private const double ExplorerDisplayWidthFraction = 0.72;
	private const double ExplorerDisplayHeightFraction = 0.58;
	private const double ExplorerHeaderHeightDips = 48.0;
	private const double ExplorerItemHeightDips = 89.0;
	private const double ExplorerVerticalPaddingDips = 32.0;
	private readonly TextBlock _title = new()
	{
		FontSize = 20.0,
		FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
		TextTrimming = TextTrimming.CharacterEllipsis
	};

	// The clips of the bucket. Each row can be dragged to another application or onto another bucket.
	internal ListView ItemsList { get; } = new() { SelectionMode = ListViewSelectionMode.None, CanDragItems = true };

	internal TopBarClipboardExplorerWindow(ElementTheme theme)
	{
		// Capture the owner's effective theme once. Reopening creates a new window with the current theme.
		bool isDark = theme == ElementTheme.Dark;
		Title = "Clipboard bucket";
		AppWindow.IsShownInSwitchers = false;
		ExtendsContentIntoTitleBar = true;
		OverlappedPresenter presenter = OverlappedPresenter.Create();
		presenter.IsAlwaysOnTop = true;
		presenter.IsResizable = false;
		presenter.IsMaximizable = false;
		presenter.IsMinimizable = false;
		AppWindow.SetPresenter(presenter);
		AppWindow.TitleBar.PreferredTheme = isDark ? TitleBarTheme.Dark : TitleBarTheme.Light;
		AppWindow.TitleBar.ExtendsContentIntoTitleBar = true;
		AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Collapsed;

		Grid root = new()
		{
			Padding = new Thickness(16.0),
			RowSpacing = 12.0,
			RequestedTheme = theme,
			Background = new SolidColorBrush(isDark
				? Windows.UI.Color.FromArgb(255, 24, 24, 28)
				: Windows.UI.Color.FromArgb(255, 243, 243, 245))
		};
		root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
		root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1.0, GridUnitType.Star) });
		Grid header = new() { ColumnSpacing = 12.0 };
		header.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1.0, GridUnitType.Star) });
		header.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
		header.Children.Add(_title);
		Button closeButton = new()
		{
			Width = 40.0,
			Height = 40.0,
			Padding = new Thickness(0.0),
			HorizontalAlignment = HorizontalAlignment.Right,
			VerticalAlignment = VerticalAlignment.Center,
			Content = new FontIcon { Glyph = "\uE711", FontSize = 16.0 }
		};
		ToolTipService.SetToolTip(closeButton, "Close bucket details");
		closeButton.Click += OnCloseButtonClick;
		Grid.SetColumn(closeButton, 1);
		header.Children.Add(closeButton);
		root.Children.Add(header);
		Grid.SetRow(ItemsList, 1);
		root.Children.Add(ItemsList);
		Content = root;
	}

	internal void ShowForBucket(string title, int itemCount, RectInt32 anchor,
		RectInt32 displayBounds, double rasterizationScale, bool dockToBottom)
	{
		SetTitle(title);
		double scale = rasterizationScale > 0.0 ? rasterizationScale : 1.0;
		int availableWidth = Math.Max(1, displayBounds.Width - 24);
		int availableHeight = Math.Max(1, displayBounds.Height - 48);
		int minimumWidth = Math.Min((int)Math.Round(ExplorerMinimumWidthDips * scale), availableWidth);
		int minimumHeight = Math.Min((int)Math.Round(ExplorerMinimumHeightDips * scale), availableHeight);
		int maximumWidth = Math.Min(Math.Max(minimumWidth, (int)Math.Round(displayBounds.Width * ExplorerDisplayWidthFraction)), availableWidth);
		int maximumHeight = Math.Min(Math.Max(minimumHeight, (int)Math.Round(displayBounds.Height * ExplorerDisplayHeightFraction)), availableHeight);
		int width = Math.Clamp((int)Math.Round(ExplorerPreferredWidthDips * scale), minimumWidth, maximumWidth);
		double requiredHeightDips = ExplorerVerticalPaddingDips + ExplorerHeaderHeightDips + (Math.Min(itemCount, 4) * ExplorerItemHeightDips);
		int requiredHeight = (int)Math.Ceiling(requiredHeightDips * scale);
		int preferredHeight = (int)Math.Round(ExplorerPreferredHeightDips * scale);
		int height = Math.Clamp(Math.Min(requiredHeight, preferredHeight), minimumHeight, maximumHeight);
		int x = Math.Clamp(anchor.X + ((anchor.Width - width) / 2), displayBounds.X + 12, displayBounds.X + displayBounds.Width - width - 12);
		int gap = Math.Max(6, (int)Math.Round(8.0 * scale));
		int preferredY = dockToBottom ? anchor.Y - height - gap : anchor.Y + anchor.Height + gap;
		int y = Math.Clamp(preferredY, displayBounds.Y + 12, displayBounds.Y + displayBounds.Height - height - 12);
		Activate();
		AppWindow.ResizeClient(new SizeInt32(width, height));
		AppWindow.Move(new PointInt32(x, y));
	}

	internal void SetTitle(string title) => _title.Text = title;

	private void OnCloseButtonClick(object sender, RoutedEventArgs args) => Close();
}

internal sealed partial class TopBar
{
	// Every collection holds at most this many buckets. A full collection reuses its buckets in turn.
	private const int ClipboardCollectionCapacity = 1000;

	// The collections that can be created next to the Default collection.
	private const int MaximumClipboardCollections = 10;
	private const int MaximumClipboardCollectionNameLength = 16;
	private const int MaximumClipboardBucketNameLength = 18;

	// The layout version of the index and payload files. Raise it when their layout changes and keep reading every older
	// version, so an update of the app keeps the saved clips.
	private const int ClipboardStoreVersion = 1;

	// Individual bitmap and file payloads are capped before allocating a managed byte array or reading persisted data.
	private const int MaximumClipboardPayloadBytes = 64 * 1024 * 1024;

	// The most that is read of a copied web page or of its card image.
	private const int MaximumClipboardLinkBytes = 4 * 1024 * 1024;
	private const double ClipboardSearchWidthDips = 208.0;
	private const string ClipboardIndexFileName = "Index.dat";
	private const string ClipboardDragSourceProperty = "HardenSystemSecurity.TopBar.ClipboardBucketDrag";
	private const string ClipboardOnStatus = "Clipboard history is on and encrypted for this user.";
	private const string ClipboardOffStatus = "Clipboard history is off.";

	// Bucket cards draw previews at most 246 DIPs wide and explorer rows at 64 DIPs. Previews are decoded at that width
	// rather than at full resolution because right-size decoding is disabled when SetSourceAsync runs before the image
	// joins the tree. Physical pixels are used because a logical decode of an image outside the tree uses scale 1.0.
	private const double ClipboardPreviewDecodeWidthDips = 246.0;
	private const double ClipboardRowPreviewDecodeWidthDips = 64.0;
	private static readonly TimeSpan ClipboardLinkTimeout = TimeSpan.FromSeconds(15);
	private static readonly byte[] ClipboardEntropy = Encoding.UTF8.GetBytes("HotCakeX");
	private static string ClipboardStoreFolder => field ??= Path.Join(ApplicationData.Current.LocalCacheFolder.Path, "TopBarClipboard");

	// Link cards are read the way social sites read them. Redirects are followed by GetFollowingRedirectsAsync, the request
	// names a link preview crawler, and connections only reach public addresses, so copying the address of a device on the
	// local network never sends it a request. A proxy is never used, because it would connect to any address it is given.
	private readonly HttpClient _clipboardLinkClient = new(new SocketsHttpHandler
	{
		AllowAutoRedirect = false,
		UseProxy = false,
		SslOptions = { CertificateRevocationCheckMode = X509RevocationMode.Online },
		ConnectCallback = ConnectToPublicAddressAsync
	})
	{
		DefaultRequestHeaders = { { "User-Agent", Atlas.UserAgent } }
	};

	private readonly ObservableCollection<TopBarClipboardCollection> _clipboardCollections = new();
	private readonly ObservableCollection<TopBarClipboardViewerItem> _clipboardViewerEntries = new();

	// Previews are built one at a time, so scrolling through many buckets never decodes many images at once.
	private readonly Queue<Func<Task>> _clipboardPreviewQueue = new();
	private readonly SemaphoreSlim _clipboardGate = new(1, 1);
	private readonly CancellationTokenSource _clipboardCancellation = new();
	private readonly Storyboard _clipboardSearchStoryboard = new();
	private readonly DoubleAnimation _clipboardSearchAnimation = new()
	{
		EnableDependentAnimation = true,
		EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
	};

	/// <summary>
	/// Pulses the ring of the power button while clipboard history is off. <see cref="UpdateClipboardEnableHint"/>.
	/// </summary>
	private readonly Storyboard _clipboardEnableHintStoryboard = new();
	private Task _clipboardDisposalTask = Task.CompletedTask;

	// The shown collection, which receives new captures.
	private TopBarClipboardCollection _clipboardCollection = new("Default", isDefault: true);

	// The last clipboard sequence this view published or captured. Captures skip it, which also absorbs duplicate
	// notifications and captures queued behind an earlier capture of the same clipboard content.
	private uint _clipboardHandledSequence;

	// The capture time and entry count of the last capture. Every entry that capture added holds this time, which identifies
	// them in a bucket.
	private DateTimeOffset _clipboardLastCapturedAt;
	private int _clipboardLastCaptureCount;

	// The hash of the payload of the last capture, which is compared instead of reading the payload file back.
	private byte[]? _clipboardLastPayloadHash;

	// The payload files that the saved index refers to, plus the ones written since. Saving deletes those it no longer refers to.
	private HashSet<Guid> _clipboardStoredBlobs = [];
	private bool _clipboardInitializing;
	private bool _clipboardEnabled;
	private bool _clipboardListenerRegistered;
	private bool _clipboardStoreLoaded;
	private bool _clipboardPreviewQueueRunning;
	private TopBarClipboardBucket? _clipboardViewerBucket;
	private TopBarClipboardExplorerWindow? _clipboardExplorer;

	// The bucket and the clip of the drag in progress. The clip is null while a whole bucket is dragged.
	private TopBarClipboardBucket? _clipboardDragBucket;
	private TopBarClipboardEntry? _clipboardDragEntry;
	private TopBarClipboardBucket? _clipboardSearchMatch;

	// The collection that the new-collection flyout renames, or null while the flyout creates a collection.
	private TopBarClipboardCollection? _clipboardRenamedCollection;

	/// <summary>
	/// Identifies the newest reading of the store size. <see cref="QueueClipboardStoreSizeRefresh"/>
	/// </summary>
	private int _clipboardSizeGeneration;

	/// <summary>
	/// Binds the view, restores the encrypted store, and registers this window for clipboard change notifications.
	/// </summary>
	private void InitializeClipboardView()
	{
		_viewTiles[TopBarView.Clipboard] = [new TopBarTile(ClipboardPanel, AttachEntranceTransform(ClipboardPanel))];
		Storyboard.SetTarget(_clipboardSearchAnimation, ClipboardSearchHost);
		Storyboard.SetTargetProperty(_clipboardSearchAnimation, "Width");
		_clipboardSearchStoryboard.Children.Add(_clipboardSearchAnimation);
		_clipboardSearchStoryboard.Completed += OnClipboardSearchAnimationCompleted;
		DoubleAnimation enableHintAnimation = new()
		{
			From = 0.15,
			To = 1.0,
			Duration = TimeSpan.FromMilliseconds(900),
			AutoReverse = true,
			RepeatBehavior = RepeatBehavior.Forever,
			EasingFunction = new SineEase { EasingMode = EasingMode.EaseInOut }
		};
		Storyboard.SetTarget(enableHintAnimation, ClipboardEnableHint);
		Storyboard.SetTargetProperty(enableHintAnimation, "Opacity");
		_clipboardEnableHintStoryboard.Children.Add(enableHintAnimation);
		_clipboardCollections.Add(_clipboardCollection);
		ClipboardCollectionsList.ItemsSource = _clipboardCollections;
		ShowClipboardCollection(_clipboardCollection);
		ClipboardEnabledToggle.IsChecked = Atlas.Settings.WindowsTopBarClipboardMonitoring;
		ClipboardLinkPreviewToggle.IsChecked = Atlas.Settings.WindowsTopBarClipboardLinkPreviews;
		UpdateClipboardControls();

		// Saved data takes space even while clipboard history is off, when no operation reads the size.
		QueueClipboardStoreSizeRefresh();
		if (Atlas.Settings.WindowsTopBarClipboardMonitoring)
		{
			OnClipboardEnabledToggled();
		}
	}

	/// <summary>
	/// Enables or disables clipboard processing. The listener is registered only while enabled, so the default disabled
	/// state performs no monitoring, capture, serialization, or clipboard replacement work.
	/// </summary>
	private async void OnClipboardEnabledToggled()
	{
		_clipboardEnabled = ClipboardEnabledToggle.IsChecked == true;
		Atlas.Settings.WindowsTopBarClipboardMonitoring = _clipboardEnabled;
		UpdateClipboardControls();

		if (!_clipboardEnabled)
		{
			UnregisterClipboardListener();
			ClipboardStatusText.Text = ClipboardOffStatus;
			return;
		}

		if (!RegisterClipboardListener())
		{
			ClipboardEnabledToggle.IsChecked = false;
			_clipboardEnabled = false;
			Atlas.Settings.WindowsTopBarClipboardMonitoring = false;
			UpdateClipboardControls();
			ClipboardStatusText.Text = "Clipboard monitoring could not start.";
			return;
		}

		ClipboardStatusText.Text = ClipboardOnStatus;
		if (!_clipboardStoreLoaded)
		{
			// Marking the store as loaded before the load starts prevents toggling again during the load from starting a second load.
			_clipboardStoreLoaded = true;
			await RunClipboardOperationAsync(LoadClipboardStoreAsync, "The encrypted clipboard store could not be opened.");
		}
		else
		{
			// Copies made while clipboard history was off were not saved, so the bucket shown as selected is placed on the
			// clipboard again. The first time, loading the store does this when it shows the saved collection.
			await PublishSelectedClipboardBucketAsync(announce: false);
		}
	}

	/// <summary>
	/// Collections, buckets and their buttons only respond while clipboard history is on.
	/// </summary>
	private void UpdateClipboardControls()
	{
		ClipboardBucketsList.IsEnabled = _clipboardEnabled;
		ClipboardNewBucketToggle.IsEnabled = _clipboardEnabled;
		ClipboardCollectionsList.IsEnabled = _clipboardEnabled;
		ClipboardAddCollectionButton.IsEnabled = _clipboardEnabled && _clipboardCollections.Count <= MaximumClipboardCollections;
		ClipboardTransferButton.IsEnabled = _clipboardEnabled;
		UpdateClipboardEnableHint();
	}

	/// <summary>
	/// Pulses a ring around the power button while clipboard history is off and the Clipboard view is on screen, which shows
	/// what turns the view on. The pulse repeats forever, so it only runs while it can be seen, and it stays lit without
	/// pulsing while animations are turned off in Windows.
	/// </summary>
	private void UpdateClipboardEnableHint()
	{
		bool show = !_clipboardEnabled && _activeView == TopBarView.Clipboard && _isExpandedHostAttached;
		if (!show || !_uiSettings.AnimationsEnabled)
		{
			_clipboardEnableHintStoryboard.Stop();
			ClipboardEnableHint.Opacity = show ? 1.0 : 0.0;
		}
		else if (_clipboardEnableHintStoryboard.GetCurrentState() != ClockState.Active)
		{
			_clipboardEnableHintStoryboard.Begin();
		}
	}

	/// <summary>
	/// Registers the top bar HWND for clipboard notifications exactly once.
	/// </summary>
	private bool RegisterClipboardListener()
	{
		if (_clipboardListenerRegistered)
		{
			return true;
		}
		_clipboardListenerRegistered = NativeMethods.AddClipboardFormatListener(_windowHandle);
		return _clipboardListenerRegistered;
	}

	/// <summary>
	/// Removes clipboard notifications when monitoring is disabled or the top bar closes.
	/// </summary>
	private void UnregisterClipboardListener()
	{
		if (!_clipboardListenerRegistered)
		{
			return;
		}
		_ = NativeMethods.RemoveClipboardFormatListener(_windowHandle);
		_clipboardListenerRegistered = false;
	}

	/// <summary>
	/// Runs a clipboard operation under the shared serialization gate with the clipboard cancellation token. Cancellation
	/// during teardown is silent, and any other failure is logged and reported with <paramref name="failureMessage"/>.
	/// </summary>
	private async Task RunClipboardOperationAsync(Func<CancellationToken, Task> operation, string failureMessage)
	{
		// Teardown sets _isClosed before it cancels and disposes the token source and the gate. Every caller runs on the UI
		// thread, so checking it first means neither of them is used after disposal.
		if (_isClosed)
		{
			return;
		}
		CancellationToken cancellationToken = _clipboardCancellation.Token;
		try
		{
			await _clipboardGate.WaitAsync(cancellationToken);
			try
			{
				await operation(cancellationToken);
			}
			finally
			{
				_ = _clipboardGate.Release();
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
		catch (Exception ex)
		{
			Logger.Write(ex);
			if (!_isClosed) ClipboardStatusText.Text = failureMessage;
		}

		// Every change to the files of the store runs here, including one that failed partway.
		QueueClipboardStoreSizeRefresh();
	}

	/// <summary>
	/// Reads the size of every file in the store folder off the UI thread for the Standard notch of the Clipboard view.
	/// Readings can overlap, so a reading is only shown when no newer one has started since.
	/// </summary>
	private void QueueClipboardStoreSizeRefresh()
	{
		int generation = ++_clipboardSizeGeneration;
		_ = Task.Run(() =>
		{
			long? size = GetAppsList.GetDirectorySizeInBytes(ClipboardStoreFolder);
			_ = DispatcherQueue.TryEnqueue(() =>
			{
				if (!_isClosed && size is long bytes && generation == _clipboardSizeGeneration)
				{
					CollapsedClipboardSizeText.Text = TopBarClipboardEntry.FormatFileSize((ulong)bytes);
				}
			});
		});
	}

	/// <summary>
	/// Asks for confirmation before everything is deleted.
	/// </summary>
	private void OnClearClipboardHistoryClick() => OpenClipboardTip(ClipboardClearTip);

	/// <summary>
	/// Offers to export every collection to a zip file or to replace them with the collections of one.
	/// </summary>
	private void OnClipboardTransferClick() => OpenClipboardTip(ClipboardTransferTip);

	/// <summary>
	/// Opens the tip of a header button of the Clipboard view next to that button. The bar does not retract while the tip is open.
	/// </summary>
	private void OpenClipboardTip(TeachingTip tip)
	{
		tip.PreferredPlacement = _dockToBottom ? TeachingTipPlacementMode.Top : TeachingTipPlacementMode.Bottom;
		tip.IsOpen = true;
	}

	// The tips of the Clipboard view are not light dismissed, so they keep the bar expanded while they are open.
	private bool IsClipboardTipOpen => ClipboardClearTip.IsOpen || ClipboardTransferTip.IsOpen;

	/// <summary>
	/// Permanently removes every collection and the encrypted LocalCacheFolder store.
	/// Monitoring remains in its current enabled or disabled state.
	/// </summary>
	private async void OnClearClipboardHistoryConfirmed()
	{
		ClipboardClearTip.IsOpen = false;
		await RunClipboardOperationAsync(async _ =>
		{
			ReplaceClipboardCollections([new TopBarClipboardCollection("Default", isDefault: true)], 0);
			_clipboardStoredBlobs = [];
			await Task.Run(static () =>
			{
				if (Directory.Exists(ClipboardStoreFolder))
				{
					Directory.Delete(ClipboardStoreFolder, recursive: true);
				}
			}, CancellationToken.None);
			ClipboardStatusText.Text = "All saved clipboard data was deleted.";
		}, "Clipboard history could not be cleared.");
	}

	private async void OnClipboardExportClick() => await RunClipboardTransferAsync(
		static () => FileDialogHelper.ShowSaveFileDialog(Atlas.ZIPFilePickerFilter, "Clipboard history " + DateTime.Now.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + ".zip"),
		ExportClipboardStoreAsync,
		"Clipboard history could not be exported.");

	private async void OnClipboardImportClick() => await RunClipboardTransferAsync(
		static () => FileDialogHelper.ShowFilePickerDialog(Atlas.ZIPFilePickerFilter),
		ImportClipboardStoreAsync,
		"Clipboard history could not be imported from this file.");

	/// <summary>
	/// Asks for the zip file of an export or an import and then runs the transfer under the serialization gate. The tip stays
	/// open while the file dialog is shown, which keeps the bar from retracting behind the dialog.
	/// </summary>
	private async Task RunClipboardTransferAsync(Func<string?> pickFile, Func<string, CancellationToken, Task> transfer, string failureMessage)
	{
		try
		{
			string? path = pickFile();

			// The bar can be closed while the file dialog is open.
			if (_isClosed)
			{
				return;
			}
			ClipboardTransferTip.IsOpen = false;
			if (path is null)
			{
				return;
			}
			await RunClipboardOperationAsync(cancellationToken =>
			{
				// The tip stays open when clipboard history is turned off. The collections might never have been loaded then,
				// and an import would not be saved.
				if (!_clipboardEnabled)
				{
					ClipboardStatusText.Text = ClipboardOffStatus;
					return Task.CompletedTask;
				}
				return transfer(path, cancellationToken);
			}, failureMessage);
		}
		catch (Exception ex)
		{
			// Only the file dialog throws here, because the clipboard operation reports its own failures.
			Logger.Write(ex);
			if (!_isClosed)
			{
				ClipboardTransferTip.IsOpen = false;
				ClipboardStatusText.Text = failureMessage;
			}
		}
	}

	/// <summary>
	/// Writes every collection with its clips, and the decrypted payload files that they refer to, into an unencrypted zip
	/// file that <see cref="ImportClipboardStoreAsync"/> restores, for example after Windows is installed again.
	/// </summary>
	private async Task ExportClipboardStoreAsync(string path, CancellationToken cancellationToken)
	{
		int activeIndex = _clipboardCollections.IndexOf(_clipboardCollection);

		// The caller holds the serialization gate, so the collections do not change while they are written off the UI thread.
		await Task.Run(() => WriteClipboardExport(path, activeIndex), cancellationToken);
		ClipboardStatusText.Text = "Clipboard history was exported to " + Path.GetFileName(path) + ".";
	}

	/// <summary>
	/// Writes the index in its unencrypted layout and every payload file it refers to. A payload file that cannot be read is
	/// left out, which leaves its clip with its text and file references the same way a damaged payload file does. A zip
	/// file that could not be written completely is deleted.
	/// </summary>
	private void WriteClipboardExport(string path, int activeIndex)
	{
		try
		{
			using FileStream file = new(path, FileMode.Create, FileAccess.Write, FileShare.None);
			using ZipArchive archive = new(file, ZipArchiveMode.Create);
			HashSet<Guid> referencedBlobs = [];
			using (MemoryStream index = WriteClipboardStore(activeIndex, referencedBlobs))
			{
				byte[] plainBuffer = index.GetBuffer();
				WriteClipboardExportEntry(archive, ClipboardIndexFileName, plainBuffer.AsSpan(0, (int)index.Length));
				CryptographicOperations.ZeroMemory(plainBuffer);
			}
			foreach (Guid id in referencedBlobs)
			{
				byte[] plainBytes;
				try
				{
					plainBytes = ProtectedData.Unprotect(File.ReadAllBytes(GetClipboardBlobPath(id)), ClipboardEntropy, DataProtectionScope.CurrentUser);
				}
				catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException)
				{
					continue;
				}
				try
				{
					WriteClipboardExportEntry(archive, GetClipboardBlobFileName(id), plainBytes);
				}
				finally
				{
					CryptographicOperations.ZeroMemory(plainBytes);
				}
			}
		}
		catch
		{
			DeleteClipboardFile(path);
			throw;
		}
	}

	private static void WriteClipboardExportEntry(ZipArchive archive, string name, ReadOnlySpan<byte> content)
	{
		using Stream stream = archive.CreateEntry(name, CompressionLevel.Fastest).Open();
		stream.Write(content);
	}

	/// <summary>
	/// Replaces every collection with the collections of a zip file that <see cref="ExportClipboardStoreAsync"/> wrote, and
	/// encrypts its payload files for the current user.
	/// </summary>
	private async Task ImportClipboardStoreAsync(string path, CancellationToken cancellationToken)
	{
		List<TopBarClipboardCollection> collections = new(MaximumClipboardCollections + 1);
		HashSet<Guid> importedBlobs = [];
		try
		{
			int activeIndex = await Task.Run(() => ReadClipboardExport(path, collections, importedBlobs), cancellationToken);
			ReplaceClipboardCollections(collections, activeIndex);
		}
		finally
		{
			// The payload files written by an import that failed partway are deleted by the next save or load.
			_clipboardStoredBlobs.UnionWith(importedBlobs);
		}
		await SaveClipboardStoreAsync(cancellationToken);
		ClipboardStatusText.Text = "Clipboard history was imported from " + Path.GetFileName(path) + ".";
	}

	/// <summary>
	/// Reads the collections of an exported zip file with the same validation as the saved index, and writes its payload
	/// files encrypted under new names, so an import never replaces a payload file that the current collections refer to.
	/// Returns the index of the collection that was shown.
	/// </summary>
	private int ReadClipboardExport(string path, List<TopBarClipboardCollection> collections, HashSet<Guid> importedBlobs)
	{
		using ZipArchive archive = ZipFile.OpenRead(path);
		HashSet<Guid> referencedBlobs = [];
		byte[] plainBytes = ReadClipboardExportEntry(archive.GetEntry(ClipboardIndexFileName)
			?? throw new InvalidDataException("The file is not an exported clipboard history."));
		int activeIndex;
		try
		{
			activeIndex = ReadClipboardIndex(plainBytes, collections, referencedBlobs);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(plainBytes);
		}

		// A payload file that is missing from the zip file leaves its clip with its text and file references.
		Dictionary<Guid, Guid> newIds = new(referencedBlobs.Count);
		foreach (Guid id in referencedBlobs)
		{
			Guid newId = Guid.NewGuid();
			newIds.Add(id, newId);
			if (archive.GetEntry(GetClipboardBlobFileName(id)) is not { } entry)
			{
				continue;
			}
			byte[] payload = ReadClipboardExportEntry(entry);
			try
			{
				WriteClipboardBlob(newId, payload);
				_ = importedBlobs.Add(newId);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(payload);
			}
		}
		foreach (TopBarClipboardEntry entry in collections.SelectMany(static collection => collection.Buckets).SelectMany(static bucket => bucket.Entries))
		{
			entry.PayloadId = entry.PayloadId is Guid payloadId ? newIds[payloadId] : null;
			entry.LinkImageId = entry.LinkImageId is Guid imageId ? newIds[imageId] : null;
		}
		return activeIndex;
	}

	private static byte[] ReadClipboardExportEntry(ZipArchiveEntry entry)
	{
		byte[] content = new byte[checked((int)entry.Length)];
		using Stream stream = entry.Open();
		stream.ReadExactly(content);
		return content;
	}

	/// <summary>
	/// Queues a capture for a clipboard change. The capture skips the sequences this view published or already handled.
	/// </summary>
	private void OnClipboardUpdated()
	{
		if (!_clipboardEnabled)
		{
			return;
		}
		_ = RunClipboardOperationAsync(CaptureClipboardAsync, "This clipboard item could not be saved.");
	}

	/// <summary>
	/// Captures supported formats from one clipboard update and routes the resulting entries to the configured bucket of the
	/// shown collection. Text and file-reference metadata are persisted in the index, and the HTML, RTF and bitmap formats in
	/// a payload file of their own, all with current-user DPAPI protection. Original files are never copied.
	/// </summary>
	private async Task CaptureClipboardAsync(CancellationToken cancellationToken)
	{
		// The sequence is read after the gate is acquired, so it is compared after any activation that published content.
		uint sequence = NativeMethods.GetClipboardSequenceNumber();

		// The toggle can be switched off while this capture is waiting for the serialization gate.
		if (!_clipboardEnabled || sequence == _clipboardHandledSequence)
		{
			return;
		}
		_clipboardHandledSequence = sequence;
		(TopBarClipboardEntry Entry, ArraySegment<byte> Payload)? capture = await ReadClipboardEntryWithRetryAsync(cancellationToken);
		if (capture is null)
		{
			return;
		}
		(TopBarClipboardEntry entry, ArraySegment<byte> payload) = capture.Value;
		try
		{
			if (_isClosed)
			{
				return;
			}

			// A multi-file clipboard package represents several independently explorable items. Store one entry per file in
			// the same destination bucket instead of collapsing every file into one card and one explorer row.
			List<TopBarClipboardEntry> entries = entry.Files.Count > 1
				? entry.Files.ConvertAll(file => new TopBarClipboardEntry { CapturedAt = entry.CapturedAt, Files = [file], Summary = "File" })
				: [entry];
			byte[]? payloadHash = payload.Count == 0 ? null : SHA256.HashData(payload);

			// Apps such as Sticky Notes place a copy on the clipboard and then flush it, which raises a second clipboard update
			// with the same content. A capture that repeats the last capture while that is still the newest in its bucket is skipped.
			if (IsRepeatedClipboardCapture(entries, payloadHash))
			{
				return;
			}
			if (entry.PayloadId is Guid payloadId)
			{
				await WriteClipboardBlobAsync(payloadId, payload, cancellationToken);
				_ = _clipboardStoredBlobs.Add(payloadId);
			}

			// The ListView selection is the routing authority. A selected bucket must always receive new captures,
			// even if the saved new-bucket mode has not yet been synchronized with the selection state.
			TopBarClipboardCollection collection = _clipboardCollection;
			TopBarClipboardBucket bucket = SelectedClipboardBucket ?? GetNewClipboardBucket(collection);
			bucket.Entries.InsertRange(0, entries);

			// The newly captured entries are at the front, so removing repeated paths keeps the new copy
			// and removes every older occurrence from this destination bucket.
			RemoveDuplicateClipboardFiles(bucket);
			collection.Target = bucket;
			_clipboardLastCapturedAt = entry.CapturedAt;
			_clipboardLastCaptureCount = entries.Count;
			_clipboardLastPayloadHash = payloadHash;
			OnClipboardBucketChanged(bucket);
			await SaveClipboardStoreAsync(cancellationToken);
			ClipboardStatusText.Text = "Saved to " + bucket.Title + " in " + collection.Name + ".";
			if (entries.Count == 1 && Atlas.Settings.WindowsTopBarClipboardLinkPreviews && TryGetClipboardLink(entry, out Uri? link))
			{
				_ = LoadClipboardLinkPreviewAsync(entry, link, cancellationToken);
			}
		}
		finally
		{
			CryptographicOperations.ZeroMemory(payload.Array);
		}
	}

	/// <summary>
	/// Returns a new bucket at the end of a collection. A full collection instead reuses the bucket after the one that
	/// received the last capture, and the new entries join the entries that bucket already holds.
	/// </summary>
	private TopBarClipboardBucket GetNewClipboardBucket(TopBarClipboardCollection collection)
	{
		if (collection.Buckets.Count < ClipboardCollectionCapacity)
		{
			TopBarClipboardBucket bucket = CreateClipboardBucket(collection);
			collection.Buckets.Add(bucket);
			return bucket;
		}
		return collection.Buckets[collection.Target is null ? 0 : (collection.Buckets.IndexOf(collection.Target) + 1) % collection.Buckets.Count];
	}

	private TopBarClipboardBucket CreateClipboardBucket(TopBarClipboardCollection collection) =>
		new(collection, OpenClipboardBucketDetails, DeleteClipboardBucketAsync);

	/// <summary>
	/// Materializes the standard text, HTML, RTF, bitmap, and storage-item formats contained in a clipboard package.
	/// Multiple available formats are retained together so applications can choose the format they understand on paste.
	/// </summary>
	private static async Task<(TopBarClipboardEntry Entry, ArraySegment<byte> Payload)?> ReadClipboardEntryWithRetryAsync(CancellationToken cancellationToken)
	{
		const int ClipboardCannotOpenHResult = unchecked((int)0x800401D0);
		const int RpcServerUnavailableHResult = unchecked((int)0x800706BA);
		const int RpcCallFailedHResult = unchecked((int)0x800706BE);
		const int RpcCallFailedDidNotExecuteHResult = unchecked((int)0x800706BF);
		const int RpcDisconnectedHResult = unchecked((int)0x80010108);
		const int MaximumAttempts = 12;
		const int InitialRetryDelayMilliseconds = 10;
		const int MaximumRetryDelayMilliseconds = 640;
		for (int attempt = 1; attempt <= MaximumAttempts; attempt++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				// Acquire a fresh view on every attempt because delayed-rendered data can change while another
				// application temporarily owns the shared clipboard.
				return await ReadClipboardEntryAsync(Clipboard.GetContent(), cancellationToken);
			}
			catch (COMException ex) when (ex.HResult == ClipboardCannotOpenHResult)
			{
				if (attempt == MaximumAttempts)
				{
					// Clipboard contention is expected. A future WM_CLIPBOARDUPDATE will retry without
					// writing a transient system condition to the application error log.
					return null;
				}
				int exponentialDelayMilliseconds = InitialRetryDelayMilliseconds << (attempt - 1);
				int delayMilliseconds = Math.Min(exponentialDelayMilliseconds, MaximumRetryDelayMilliseconds);
				await Task.Delay(TimeSpan.FromMilliseconds(delayMilliseconds), cancellationToken);
			}
			catch (COMException ex) when (ex.HResult is RpcServerUnavailableHResult or RpcCallFailedHResult or RpcCallFailedDidNotExecuteHResult or RpcDisconnectedHResult)
			{
				// An app that copies through a data object keeps the content in its own process until it flushes it, so the
				// formats are read from that app, and it closed or released the content while it was being read. A flush as
				// it closes raises another clipboard update that saves the content, and otherwise nothing is left on the
				// clipboard to save, so this is not an error either.
				return null;
			}
		}
		return null;
	}

	/// <summary>
	/// Reads one clipboard package. The returned payload is the unencrypted layout of the clip's payload file, which the
	/// caller zeroes once it is written, and it is empty when the clip has no HTML, RTF or bitmap format.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(StorageFile))]
	private static async Task<(TopBarClipboardEntry Entry, ArraySegment<byte> Payload)?> ReadClipboardEntryAsync(DataPackageView view, CancellationToken cancellationToken)
	{
		if (await IsClipboardContentExcludedAsync(view, cancellationToken))
		{
			return null;
		}
		string? text = view.Contains(StandardDataFormats.Text) ? await view.GetTextAsync() : null;
		string? html = view.Contains(StandardDataFormats.Html) ? await view.GetHtmlFormatAsync() : null;
		string? rtf = view.Contains(StandardDataFormats.Rtf) ? await view.GetRtfAsync() : null;
		byte[]? bitmap = null;
		if (view.Contains(StandardDataFormats.Bitmap))
		{
			RandomAccessStreamReference reference = await view.GetBitmapAsync();
			using IRandomAccessStreamWithContentType stream = await reference.OpenReadAsync();
			bitmap = await ReadStreamAsync(stream, cancellationToken);
		}
		List<TopBarClipboardFile> files = new();
		if (view.Contains(StandardDataFormats.StorageItems))
		{
			IReadOnlyList<IStorageItem> items = await view.GetStorageItemsAsync();
			_ = files.EnsureCapacity(items.Count);
			foreach (IStorageItem item in items)
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (item is not StorageFile file || !IsUsableClipboardFilePath(file.Path))
				{
					// Virtual and provider-backed files can lack a filesystem path. This store intentionally retains
					// path-only references, so such items cannot be restored reliably after the clipboard package expires.
					continue;
				}
				BasicProperties properties = await file.GetBasicPropertiesAsync();
				files.Add(new TopBarClipboardFile
				{
					Name = file.Name,
					Path = file.Path,
					FileType = file.FileType,
					Size = properties.Size
				});
			}
		}

		if (text is null && html is null && rtf is null && bitmap is null && files.Count == 0)
		{
			return null;
		}

		List<string> parts = new(5);
		if (text is not null) parts.Add("Text");
		if (html is not null) parts.Add("HTML");
		if (rtf is not null) parts.Add("RTF");
		if (bitmap is not null) parts.Add("Picture");
		if (files.Count > 0) parts.Add(files.Count.ToString(CultureInfo.InvariantCulture) + " file(s)");

		// A package of several files is stored as one entry per file, which keeps no other format.
		TopBarClipboardFormats formats = files.Count > 1 ? TopBarClipboardFormats.None
			: (html is null ? TopBarClipboardFormats.None : TopBarClipboardFormats.Html) |
			  (rtf is null ? TopBarClipboardFormats.None : TopBarClipboardFormats.Rtf) |
			  (bitmap is null ? TopBarClipboardFormats.None : TopBarClipboardFormats.Bitmap);

		ArraySegment<byte> payload = formats == TopBarClipboardFormats.None ? default : CreateClipboardPayload(html, rtf, bitmap);

		CryptographicOperations.ZeroMemory(bitmap);

		return (new TopBarClipboardEntry
		{
			CapturedAt = DateTimeOffset.Now,
			Text = text,
			Formats = formats,
			PayloadId = payload.Count == 0 ? null : Guid.NewGuid(),
			Files = files,
			Summary = string.Join(" + ", parts)
		}, payload);
	}

	/// <summary>
	/// Returns whether the source application asked clipboard monitors not to retain the content, as password managers do.
	/// Any data in ExcludeClipboardContentFromMonitorProcessing excludes the content, and CanIncludeInClipboardHistory holds a
	/// DWORD where zero excludes it. Clipboard Viewer Ignore is the older convention that applications still set.
	/// https://learn.microsoft.com/windows/win32/dataxchg/clipboard-formats#cloud-clipboard-and-clipboard-history-formats
	/// </summary>
	private static async Task<bool> IsClipboardContentExcludedAsync(DataPackageView view, CancellationToken cancellationToken)
	{
		if (view.Contains("ExcludeClipboardContentFromMonitorProcessing") || view.Contains("Clipboard Viewer Ignore"))
		{
			return true;
		}
		if (!view.Contains("CanIncludeInClipboardHistory"))
		{
			return false;
		}

		// A marker whose value cannot be read is treated as an exclusion.
		using IRandomAccessStream? stream = await view.GetDataAsync("CanIncludeInClipboardHistory") as IRandomAccessStream;
		if (stream is null)
		{
			return true;
		}
		byte[] value = await ReadStreamAsync(stream, cancellationToken);
		return value.Length < sizeof(uint) || BitConverter.ToUInt32(value) == 0U;
	}

	/// <summary>
	/// Reads a clipboard stream only after enforcing the per-payload allocation limit.
	/// </summary>
	private static async Task<byte[]> ReadStreamAsync(IRandomAccessStream stream, CancellationToken cancellationToken)
	{
		if ((long)stream.Size > MaximumClipboardPayloadBytes)
		{
			throw new IOException("The clipboard payload is larger than 64 MB.");
		}
		byte[] data = new byte[checked((int)stream.Size)];
		using DataReader reader = new(stream.GetInputStreamAt(0));
		uint loaded = await reader.LoadAsync((uint)data.Length).AsTask(cancellationToken);
		if (loaded != data.Length)
		{
			Array.Resize(ref data, checked((int)loaded));
		}
		reader.ReadBytes(data);
		return data;
	}

	/// <summary>
	/// Returns whether captured entries hold the same content, in the same order, as the entries of the last capture while
	/// all of those are still the newest entries of the routing bucket. Text is compared exactly because letter case is part
	/// of the content, the rich formats through the hash of their payload, and file paths ignore case to match Windows paths.
	/// </summary>
	private bool IsRepeatedClipboardCapture(List<TopBarClipboardEntry> entries, byte[]? payloadHash)
	{
		List<TopBarClipboardEntry>? newest = _clipboardCollection.Target?.Entries;
		return newest is not null && entries.Count == _clipboardLastCaptureCount && newest.Count >= entries.Count &&
			payloadHash.AsSpan().SequenceEqual(_clipboardLastPayloadHash) &&
			entries.Zip(newest).All(pair =>
				pair.Second.CapturedAt == _clipboardLastCapturedAt &&
				string.Equals(pair.First.Text, pair.Second.Text, StringComparison.Ordinal) &&
				pair.First.Formats == pair.Second.Formats &&
				pair.First.Files.Count == pair.Second.Files.Count &&
				pair.First.Files.Zip(pair.Second.Files).All(static files =>
					string.Equals(files.First.Path, files.Second.Path, StringComparison.OrdinalIgnoreCase) && files.First.Size == files.Second.Size));
	}

	/// <summary>
	/// Removes repeated path-backed files from one bucket while retaining the newest occurrence.
	/// File path comparisons use ordinal case-insensitive semantics to match Windows path behavior.
	/// </summary>
	private static void RemoveDuplicateClipboardFiles(TopBarClipboardBucket bucket)
	{
		HashSet<string> uniqueFilePaths = new(StringComparer.OrdinalIgnoreCase);
		for (int entryIndex = 0; entryIndex < bucket.Entries.Count; entryIndex++)
		{
			TopBarClipboardEntry entry = bucket.Entries[entryIndex];
			bool removeEntry = false;
			for (int fileIndex = 0; fileIndex < entry.Files.Count; fileIndex++)
			{
				string filePath = entry.Files[fileIndex].Path;
				if (IsUsableClipboardFilePath(filePath) && !uniqueFilePaths.Add(filePath))
				{
					removeEntry = true;
					break;
				}
			}
			if (removeEntry)
			{
				bucket.Entries.RemoveAt(entryIndex);
				entryIndex--;
			}
		}
	}

	/// <summary>
	/// Makes the plus card the routing target. Each future copy advances to another bucket until a bucket select button is used.
	/// </summary>
	private async void OnClipboardNewBucketClick()
	{
		if (!_clipboardEnabled)
		{
			return;
		}
		SetSelectedClipboardBucket(_clipboardCollection, null);
		await SaveClipboardRoutingAsync();
	}

	/// <summary>
	/// Makes the selected bucket the destination for future captures and publishes the complete bucket payload so normal
	/// Windows paste commands use it. Programmatic selection changes are suppressed by <see cref="SetSelectedClipboardBucket"/>.
	/// A Ctrl+click on the selected bucket clears the selection, which is restored because selecting the new-bucket card is
	/// how a bucket stops receiving captures.
	/// </summary>
	private async void OnClipboardBucketSelectionChanged(object sender, SelectionChangedEventArgs args)
	{
		if (!_clipboardEnabled || _clipboardInitializing)
		{
			return;
		}
		if (ClipboardBucketsList.SelectedItem is not TopBarClipboardBucket bucket)
		{
			// A bucket that was removed from the list, or that belongs to the collection shown before, is not restored.
			if (args.RemovedItems is [TopBarClipboardBucket removed] && _clipboardCollection.Buckets.Contains(removed))
			{
				SetSelectedClipboardBucket(_clipboardCollection, removed);
			}
			return;
		}
		SetSelectedClipboardBucket(bucket.Collection, bucket);

		// Persist the routing choice before publishing the bucket to the Windows clipboard. This makes the selected
		// bucket survive even when the Top Bar is closed immediately after the selection changes.
		await SaveClipboardRoutingAsync();
		await PublishSelectedClipboardBucketAsync(announce: true);
	}

	/// <summary>
	/// Publishes the selected bucket again when it is clicked. Copies that are not saved, such as ones an app marks as private,
	/// and a clipboard that another app kept busy can leave something else on the clipboard, so clicking the selected bucket
	/// always publishes it. ItemClick is raised before a click changes the selection, so a click on another bucket is
	/// published by <see cref="OnClipboardBucketSelectionChanged"/> instead.
	/// </summary>
	private async void OnClipboardBucketItemClick(object sender, ItemClickEventArgs args)
	{
		if (ReferenceEquals(args.ClickedItem, ClipboardBucketsList.SelectedItem))
		{
			await PublishSelectedClipboardBucketAsync(announce: true);
		}
	}

	/// <summary>
	/// Publishes the bucket shown as selected through the shared serialization gate. See <see cref="ActivateClipboardBucketAsync"/>.
	/// </summary>
	private Task PublishSelectedClipboardBucketAsync(bool announce) => RunClipboardOperationAsync(
		cancellationToken => ActivateClipboardBucketAsync(announce, cancellationToken),
		"The selected content could not be placed on the clipboard.");

	/// <summary>
	/// Persists the updated routing state through the shared serialization gate instead of waiting for another capture.
	/// </summary>
	private Task SaveClipboardRoutingAsync() =>
		RunClipboardOperationAsync(SaveClipboardStoreAsync, "The clipboard routing choice could not be saved.");

	private async void OnClipboardBucketNameLostFocus(object sender, RoutedEventArgs args)
	{
		if (sender is TextBox { DataContext: TopBarClipboardBucket bucket } textBox)
		{
			await CommitClipboardBucketNameAsync(bucket, textBox.Text);
		}
	}

	private async void OnClipboardBucketNameKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs args)
	{
		if (args.Key != VirtualKey.Enter || sender is not TextBox { DataContext: TopBarClipboardBucket bucket } textBox)
		{
			return;
		}
		args.Handled = true;
		await CommitClipboardBucketNameAsync(bucket, textBox.Text);
		_ = RootGrid.Focus(FocusState.Programmatic);
	}

	private async Task CommitClipboardBucketNameAsync(TopBarClipboardBucket bucket, string customName)
	{
		string boundedName = customName.Length <= MaximumClipboardBucketNameLength
			? customName
			: customName[..MaximumClipboardBucketNameLength];

		if (!bucket.SetCustomName(boundedName))
		{
			return;
		}
		await RunClipboardOperationAsync(SaveClipboardStoreAsync, "The bucket name could not be saved.");
	}

	/// <summary>
	/// Opens the details window of a bucket on a double-click or double-tap. Double-taps on the name box or the card
	/// buttons are left to those controls, so renaming or deleting a bucket never opens the window as well.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(DependencyObject))]
	[DynamicWindowsRuntimeCast(typeof(TextBox))]
	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void OnClipboardBucketDoubleTapped(object sender, Microsoft.UI.Xaml.Input.DoubleTappedRoutedEventArgs args)
	{
		if (sender is not FrameworkElement { DataContext: TopBarClipboardBucket bucket })
		{
			return;
		}
		DependencyObject? element = args.OriginalSource as DependencyObject;
		while (element is not null && !ReferenceEquals(element, sender))
		{
			if (element is TextBox or Button)
			{
				return;
			}
			element = VisualTreeHelper.GetParent(element);
		}
		args.Handled = true;
		OpenClipboardBucketDetails(bucket);
	}

	/// <summary>
	/// Shows the collection the user selected and makes it the destination of the captures that follow.
	/// </summary>
	private async void OnClipboardCollectionSelectionChanged()
	{
		if (ClipboardCollectionsList.SelectedItem is not TopBarClipboardCollection collection || ReferenceEquals(collection, _clipboardCollection))
		{
			return;
		}
		ClearClipboardSearchMatch();
		ShowClipboardCollection(collection);
		await SaveClipboardRoutingAsync();
	}

	/// <summary>
	/// Shows the buckets of a collection, which then receives the captures that follow. The previews of the collection that
	/// was shown before are released, and the selected bucket of the collection shown now is published, however the
	/// collection came to be shown.
	/// </summary>
	private void ShowClipboardCollection(TopBarClipboardCollection collection)
	{
		if (!ReferenceEquals(collection, _clipboardCollection))
		{
			foreach (TopBarClipboardBucket bucket in _clipboardCollection.Buckets)
			{
				ReleaseClipboardPreviews(bucket);
			}
			_clipboardCollection = collection;

			// The bucket shown as selected is always the one that gets pasted. A caller that holds the serialization gate has
			// this operation wait for it, and the status line keeps what the caller reports.
			_ = PublishSelectedClipboardBucketAsync(announce: false);
		}
		ClipboardBucketsList.ItemsSource = collection.Buckets;
		ClipboardCollectionsList.SelectedItem = collection;
		ClipboardCollectionsList.ScrollIntoView(collection);
		EnsureSelectedClipboardBucketVisible();
	}

	/// <summary>
	/// Replaces every collection after the store is loaded or cleared, and shows the collection at <paramref name="activeIndex"/>.
	/// </summary>
	private void ReplaceClipboardCollections(List<TopBarClipboardCollection> collections, int activeIndex)
	{
		_clipboardExplorer?.Close();
		ClearClipboardSearchMatch();
		_clipboardCollections.Clear();
		foreach (TopBarClipboardCollection collection in collections)
		{
			_clipboardCollections.Add(collection);
		}
		ShowClipboardCollection(collections[activeIndex]);
		UpdateClipboardControls();
	}

	/// <summary>
	/// Creates a collection with the name typed in the new-collection flyout, or a numbered name when none was typed, and shows it.
	/// The flyout renames a collection instead while it was opened from the menu of that collection.
	/// </summary>
	private async void OnClipboardCreateCollectionClick()
	{
		// The box allows at most 16 characters, which is the longest collection name.
		string name = ClipboardCollectionNameBox.Text.Trim();
		TopBarClipboardCollection? renamedCollection = _clipboardRenamedCollection;
		ClipboardCollectionNameBox.Text = string.Empty;
		ClipboardAddCollectionFlyout.Hide();
		if (renamedCollection is not null)
		{
			await RenameClipboardCollectionAsync(renamedCollection, name);
			return;
		}
		await RunClipboardOperationAsync(async cancellationToken =>
		{
			if (!_clipboardEnabled || _clipboardCollections.Count > MaximumClipboardCollections)
			{
				return;
			}
			TopBarClipboardCollection collection = new(name.Length == 0
				? "Collection " + _clipboardCollections.Count.ToString(CultureInfo.InvariantCulture)
				: name, isDefault: false);
			_clipboardCollections.Add(collection);
			ClearClipboardSearchMatch();
			ShowClipboardCollection(collection);
			UpdateClipboardControls();
			await SaveClipboardStoreAsync(cancellationToken);
			ClipboardStatusText.Text = collection.Name + " was created.";
		}, "The collection could not be created.");
	}

	private void OnClipboardCollectionNameKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs args)
	{
		if (args.Key == VirtualKey.Enter)
		{
			args.Handled = true;
			OnClipboardCreateCollectionClick();
		}
	}

	/// <summary>
	/// Returns the new-collection flyout to creating a collection after it was opened to rename one. A name typed for a new
	/// collection stays in the box when the flyout is closed without creating the collection.
	/// </summary>
	private void OnClipboardAddCollectionFlyoutClosed(object? sender, object e)
	{
		OnFlyoutClosed(sender, e);
		if (_clipboardRenamedCollection is not null)
		{
			_clipboardRenamedCollection = null;
			ClipboardCollectionNameBox.Text = string.Empty;
			ClipboardCollectionNameButton.Content = "Create";
		}
	}

	/// <summary>
	/// Offers to rename or delete a collection that the user created. The Default collection cannot be renamed or deleted.
	/// </summary>
	private void OnClipboardCollectionRightTapped(object sender, Microsoft.UI.Xaml.Input.RightTappedRoutedEventArgs args)
	{
		if (!_clipboardEnabled || sender is not FrameworkElement { DataContext: TopBarClipboardCollection { IsDefault: false } collection } element)
		{
			return;
		}

		// Rename reuses the new-collection flyout, which opens next to the collection with its name ready to edit.
		MenuFlyoutItem rename = new() { Text = "Rename " + collection.Name, Icon = new FontIcon { Glyph = "\uE8AC" } };
		rename.Click += (_, _) =>
		{
			_clipboardRenamedCollection = collection;
			ClipboardCollectionNameBox.Text = collection.Name;
			ClipboardCollectionNameButton.Content = "Rename";
			ClipboardAddCollectionFlyout.ShowAt(element);
		};
		MenuFlyoutItem delete = new() { Text = "Delete " + collection.Name, Icon = new FontIcon { Glyph = "\uE74D" } };
		delete.Click += async (_, _) => await DeleteClipboardCollectionAsync(collection);
		MenuFlyout menu = new() { ShouldConstrainToRootBounds = false, Items = { rename, delete } };
		TrackFlyout(menu);
		menu.ShowAt(element);
		args.Handled = true;
	}

	/// <summary>
	/// Renames a collection that the user created. An empty name keeps the current name.
	/// </summary>
	private Task RenameClipboardCollectionAsync(TopBarClipboardCollection collection, string name) => RunClipboardOperationAsync(async cancellationToken =>
	{
		if (!_clipboardEnabled || name.Length == 0 || !_clipboardCollections.Contains(collection))
		{
			return;
		}
		string oldName = collection.Name;
		collection.Name = name;
		await SaveClipboardStoreAsync(cancellationToken);
		ClipboardStatusText.Text = oldName + " was renamed to " + name + ".";
	}, "The collection could not be renamed.");

	/// <summary>
	/// Deletes a collection with all of its buckets. The Default collection is shown when the deleted one was shown.
	/// </summary>
	private Task DeleteClipboardCollectionAsync(TopBarClipboardCollection collection) => RunClipboardOperationAsync(async cancellationToken =>
	{
		if (!_clipboardCollections.Contains(collection))
		{
			return;
		}
		if (ReferenceEquals(collection, _clipboardCollection))
		{
			ShowClipboardCollection(_clipboardCollections[0]);
		}
		if (ReferenceEquals(_clipboardViewerBucket?.Collection, collection))
		{
			_clipboardExplorer?.Close();
		}
		if (ReferenceEquals(_clipboardSearchMatch?.Collection, collection))
		{
			ClearClipboardSearchMatch();
		}
		_ = _clipboardCollections.Remove(collection);
		UpdateClipboardControls();
		await SaveClipboardStoreAsync(cancellationToken);
		ClipboardStatusText.Text = collection.Name + " was deleted.";
	}, "The collection could not be deleted.");

	private async void DeleteClipboardBucketAsync(TopBarClipboardBucket bucket) => await RunClipboardOperationAsync(async cancellationToken =>
	{
		RemoveClipboardBucket(bucket);
		await SaveClipboardStoreAsync(cancellationToken);
		ClipboardStatusText.Text = bucket.Title + " was deleted.";
	}, "The clipboard bucket could not be deleted.");

	/// <summary>
	/// Publishes a change to the entries of a bucket. An empty bucket is removed. Otherwise the previews of its card are
	/// built again, and the explorer rows follow when the explorer shows this bucket.
	/// </summary>
	private void OnClipboardBucketChanged(TopBarClipboardBucket bucket)
	{
		if (bucket.Entries.Count == 0)
		{
			RemoveClipboardBucket(bucket);
			return;
		}
		bucket.PreviewVersion++;
		bucket.NotifyContentChanged();
		if (bucket.RealizedContainer is not null)
		{
			QueueClipboardPreviews(bucket);
		}
		if (ReferenceEquals(_clipboardViewerBucket, bucket))
		{
			SyncClipboardViewerEntries();
			_clipboardExplorer?.SetTitle(bucket.Title + "  |  " + bucket.CountText);
		}
	}

	/// <summary>
	/// Empties a bucket, removes it from its collection, and releases the routing selection, the search match and the
	/// explorer that refer to it. An explorer that a clip is being dragged from closes when the drag ends.
	/// </summary>
	private void RemoveClipboardBucket(TopBarClipboardBucket bucket)
	{
		bucket.Entries.Clear();
		ReleaseClipboardPreviews(bucket);
		TopBarClipboardCollection collection = bucket.Collection;
		_ = collection.Buckets.Remove(bucket);
		if (ReferenceEquals(collection.Target, bucket))
		{
			collection.Target = null;
			SetSelectedClipboardBucket(collection, null);
		}
		if (ReferenceEquals(_clipboardSearchMatch, bucket))
		{
			ClearClipboardSearchMatch();
		}
		if (ReferenceEquals(_clipboardViewerBucket, bucket) && _clipboardDragBucket is null)
		{
			_clipboardExplorer?.Close();
		}
	}

	/// <summary>
	/// The bucket shown as selected in the shown collection, which is the one on the clipboard, or null while the new-bucket
	/// card is selected.
	/// </summary>
	private TopBarClipboardBucket? SelectedClipboardBucket => _clipboardCollection.UseNewBucket ? null : _clipboardCollection.Target;

	/// <summary>
	/// Restores the selected bucket and brings it into the horizontal viewport after the Clipboard view has completed layout.
	/// </summary>
	private void EnsureSelectedClipboardBucketVisible()
	{
		// Restoring the selection through SetSelectedClipboardBucket suppresses the selection handler, so returning to this
		// view does not publish the bucket to the Windows clipboard again.
		SetSelectedClipboardBucket(_clipboardCollection, SelectedClipboardBucket);
		if (SelectedClipboardBucket is { } bucket)
		{
			ScrollClipboardBucketIntoView(bucket);
		}
	}

	private void ScrollClipboardBucketIntoView(TopBarClipboardBucket bucket) =>
		// SetActiveView makes the previously collapsed panel visible in this dispatcher turn. Scroll only after
		// that visibility change has produced a viewport and realized the horizontal item containers.
		_ = DispatcherQueue.TryEnqueue(Microsoft.UI.Dispatching.DispatcherQueuePriority.Low, () =>
		{
			if (_isClosed || _activeView != TopBarView.Clipboard || !_clipboardCollection.Buckets.Contains(bucket))
			{
				return;
			}
			ClipboardBucketsList.UpdateLayout();
			ClipboardBucketsList.ScrollIntoView(bucket, ScrollIntoViewAlignment.Default);
		});

	/// <summary>
	/// Makes a bucket, or the new-bucket card when <paramref name="selectedBucket"/> is null, the routing target of a
	/// collection and synchronizes the selection state of the shown collection without publishing anything to the
	/// Windows clipboard.
	/// </summary>
	private void SetSelectedClipboardBucket(TopBarClipboardCollection collection, TopBarClipboardBucket? selectedBucket)
	{
		collection.UseNewBucket = selectedBucket is null;
		if (selectedBucket is not null)
		{
			collection.Target = selectedBucket;
		}
		if (!ReferenceEquals(collection, _clipboardCollection))
		{
			return;
		}
		ClipboardNewBucketToggle.IsChecked = collection.UseNewBucket;
		if (!ReferenceEquals(ClipboardBucketsList.SelectedItem, selectedBucket))
		{
			bool wasInitializing = _clipboardInitializing;
			_clipboardInitializing = true;
			ClipboardBucketsList.SelectedItem = selectedBucket;
			_clipboardInitializing = wasInitializing;
		}
	}

	private bool IsLiveClipboardBucket(TopBarClipboardBucket bucket) =>
		_clipboardCollections.Contains(bucket.Collection) && bucket.Collection.Buckets.Contains(bucket);

	/// <summary>
	/// Removes the search highlight from the bucket that holds the current match.
	/// </summary>
	private void ClearClipboardSearchMatch()
	{
		_clipboardSearchMatch?.IsHighlighted = false;
		_clipboardSearchMatch = null;
	}

	private static void ReleaseClipboardPreviews(TopBarClipboardBucket bucket)
	{
		bucket.RealizedContainer = null;
		if (bucket.HasPreviews)
		{
			bucket.SetPreviews([]);
		}
	}

	/// <summary>
	/// Builds the previews of a bucket card when its container is realized and releases them when it is recycled.
	/// </summary>
	private void OnClipboardBucketContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		if (args.Item is not TopBarClipboardBucket bucket)
		{
			return;
		}
		if (args.InRecycleQueue)
		{
			if (ReferenceEquals(bucket.RealizedContainer, args.ItemContainer))
			{
				ReleaseClipboardPreviews(bucket);
			}
			return;
		}
		bucket.RealizedContainer = args.ItemContainer;
		if (!bucket.HasPreviews && bucket.Entries.Count > 0)
		{
			QueueClipboardPreviews(bucket);
		}
	}

	/// <summary>
	/// Builds the preview of an explorer row when its container is realized and releases it when it is recycled.
	/// </summary>
	private void OnClipboardViewerContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		if (args.Item is not TopBarClipboardViewerItem item)
		{
			return;
		}
		if (args.InRecycleQueue)
		{
			if (ReferenceEquals(item.RealizedContainer, args.ItemContainer))
			{
				item.RealizedContainer = null;
				item.Preview = null;
			}
			return;
		}
		args.ItemContainer.HorizontalContentAlignment = HorizontalAlignment.Stretch;
		item.RealizedContainer = args.ItemContainer;
		if (item.Preview is null)
		{
			EnqueueClipboardPreviewJob(async () =>
			{
				if (item.RealizedContainer is null || item.Preview is not null)
				{
					return;
				}
				TopBarClipboardPreview preview = await CreateClipboardPreviewAsync(item.Entry, compact: true);
				if (item.RealizedContainer is not null)
				{
					item.Preview = preview;
				}
			});
		}
	}

	/// <summary>
	/// Queues the previews of the four newest entries of a realized bucket card. Previews that finish after the entries
	/// changed or after the card was recycled are dropped.
	/// </summary>
	private void QueueClipboardPreviews(TopBarClipboardBucket bucket)
	{
		if (bucket.IsPreviewQueued)
		{
			return;
		}
		bucket.IsPreviewQueued = true;
		EnqueueClipboardPreviewJob(async () =>
		{
			bucket.IsPreviewQueued = false;
			if (bucket.RealizedContainer is null)
			{
				return;
			}
			int version = bucket.PreviewVersion;
			TopBarClipboardEntry[] entries = [.. bucket.Entries.Take(4)];
			TopBarClipboardPreview[] previews = new TopBarClipboardPreview[entries.Length];
			for (int index = 0; index < entries.Length; index++)
			{
				previews[index] = await CreateClipboardPreviewAsync(entries[index], compact: false);
			}
			if (bucket.RealizedContainer is not null && version == bucket.PreviewVersion)
			{
				bucket.SetPreviews(previews);
			}
		});
	}

	private void EnqueueClipboardPreviewJob(Func<Task> job)
	{
		_clipboardPreviewQueue.Enqueue(job);
		if (!_clipboardPreviewQueueRunning)
		{
			_ = RunClipboardPreviewQueueAsync();
		}
	}

	private async Task RunClipboardPreviewQueueAsync()
	{
		_clipboardPreviewQueueRunning = true;

		// Yielding first lets the list finish realizing its containers before the first preview is built.
		await Task.Yield();
		while (!_isClosed && _clipboardPreviewQueue.TryDequeue(out Func<Task>? job))
		{
			try
			{
				await job();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}
		_clipboardPreviewQueueRunning = false;
	}

	/// <summary>
	/// Builds the preview of one entry. A clip that is only a color shows the color, a web address with a card shows the
	/// card, and pictures and files show their image. Compact previews are the small images of explorer rows.
	/// </summary>
	private async Task<TopBarClipboardPreview> CreateClipboardPreviewAsync(TopBarClipboardEntry entry, bool compact)
	{
		if (TryParseClipboardColor(entry, out Windows.UI.Color color))
		{
			return new TopBarClipboardPreview
			{
				ToolTip = entry.Text?.Trim() ?? string.Empty,
				Swatch = new SolidColorBrush(color),
				SwatchForeground = new SolidColorBrush(IsLightClipboardColor(color) ? Microsoft.UI.Colors.Black : Microsoft.UI.Colors.White)
			};
		}
		bool card = entry.ShowsLinkCard;
		BitmapImage? image = await LoadClipboardPreviewImageAsync(entry, compact ? ClipboardRowPreviewDecodeWidthDips : ClipboardPreviewDecodeWidthDips);
		return new TopBarClipboardPreview
		{
			Image = image,
			PreviewText = compact ? string.Empty : !card ? entry.GetTextPreview() : image is null ? entry.DisplayName : string.Empty,
			ToolTip = card ? entry.Text ?? string.Empty : entry.DisplayName,
			LinkTitle = card && !compact && image is not null ? entry.LinkTitle ?? string.Empty : string.Empty
		};
	}

	/// <summary>
	/// Decodes the picture of a clip or of its link card from its encrypted payload file, or requests the thumbnail of the
	/// first file through the Windows shell thumbnail pipeline. File content is never copied.
	/// </summary>
	private async Task<BitmapImage?> LoadClipboardPreviewImageAsync(TopBarClipboardEntry entry, double widthDips)
	{
		int decodePixelWidth = (int)Math.Round(widthDips * _rasterizationScale);
		Guid? imageId = entry.HasBitmap ? entry.PayloadId : entry.ShowsLinkCard ? entry.LinkImageId : null;
		try
		{
			if (imageId is Guid id)
			{
				byte[]? bitmap = (await ReadClipboardPayloadAsync(id)).Bitmap;
				if (bitmap is null)
				{
					return null;
				}
				try
				{
					using MemoryStream memoryStream = new(bitmap, writable: false);
					using IRandomAccessStream stream = memoryStream.AsRandomAccessStream();
					BitmapImage image = new() { DecodePixelWidth = decodePixelWidth };
					await image.SetSourceAsync(stream);
					return image;
				}
				finally
				{
					CryptographicOperations.ZeroMemory(bitmap);
				}
			}
			if (entry.Files.Count == 0 || !IsUsableClipboardFilePath(entry.Files[0].Path))
			{
				return null;
			}
			StorageFile file = await StorageFile.GetFileFromPathAsync(entry.Files[0].Path);
			using StorageItemThumbnail thumbnail = await file.GetThumbnailAsync(
				ThumbnailMode.SingleItem,
				512,
				ThumbnailOptions.UseCurrentScale);
			if (thumbnail is null || thumbnail.Size == 0UL)
			{
				return null;
			}
			BitmapImage thumbnailImage = new() { DecodePixelWidth = decodePixelWidth };
			await thumbnailImage.SetSourceAsync(thumbnail);
			return thumbnailImage;
		}
		catch (Exception)
		{
			// Missing files, unavailable drives, and bitmap formats without an installed decoder keep their text or metadata preview.
			return null;
		}
	}

	/// <summary>
	/// Returns whether black text reads better than white text on a color. Translucent colors are measured as they appear
	/// over the dark bar.
	/// </summary>
	private static bool IsLightClipboardColor(Windows.UI.Color color)
	{
		double Linear(byte channel)
		{
			double value = ((channel * color.A) + (32.0 * (255 - color.A))) / (255.0 * 255.0);
			return value <= 0.04045 ? value / 12.92 : Math.Pow((value + 0.055) / 1.055, 2.4);
		}
		return (0.2126 * Linear(color.R)) + (0.7152 * Linear(color.G)) + (0.0722 * Linear(color.B)) > 0.179;
	}

	/// <summary>
	/// Reads a clip that is only a color: a hex color with a leading # and 3, 4, 6 or 8 digits, a bare hex color of 6 digits
	/// that mixes numbers and letters, or an rgb(), rgba(), hsl(), hsla() or hwb() color in either CSS syntax.
	/// </summary>
	private static bool TryParseClipboardColor(TopBarClipboardEntry entry, out Windows.UI.Color color)
	{
		color = default;
		if (entry.Files.Count > 0 || entry.HasBitmap || entry.Text is null)
		{
			return false;
		}
		ReadOnlySpan<char> text = entry.Text.AsSpan().Trim();
		if (text.Length is 0 or > 64)
		{
			return false;
		}
		bool hasHash = text[0] == '#';
		ReadOnlySpan<char> hex = hasHash ? text[1..] : text;

		// A bare hex color needs both numbers and letters, so plain numbers and words such as "facade" are not taken for colors.
		if ((hasHash ? hex.Length is 3 or 4 or 6 or 8 : hex.Length == 6 && hex.ContainsAnyInRange('0', '9') && hex.ContainsAnyExceptInRange('0', '9')) &&
			uint.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint value))
		{
			int bits = hex.Length <= 4 ? 4 : 8;
			int channels = hex.Length is 4 or 8 ? 4 : 3;
			Span<byte> parts = [255, 255, 255, 255];
			for (int index = 0; index < channels; index++)
			{
				uint part = (value >> ((channels - 1 - index) * bits)) & ((1U << bits) - 1U);
				parts[index] = (byte)(bits == 4 ? part * 17U : part);
			}
			color = Windows.UI.Color.FromArgb(parts[3], parts[0], parts[1], parts[2]);
			return true;
		}

		Match match = ClipboardColorFunctionRegex().Match(entry.Text.Trim());
		if (!match.Success)
		{
			return false;
		}
		string name = match.Groups["name"].Value;
		bool isRgb = name.StartsWith("rgb", StringComparison.OrdinalIgnoreCase);
		string[] arguments = match.Groups["arguments"].Value.Replace(',', ' ').Replace('/', ' ').Split(' ', StringSplitOptions.RemoveEmptyEntries);
		double alpha = 1.0;

		// Red, green and blue are numbers up to 255 or percentages. Saturation, lightness, whiteness and blackness are
		// percentages, or numbers up to 100 in the newer syntax.
		if (arguments.Length is not (3 or 4) ||
			(arguments.Length == 4 && !TryParseClipboardColorNumber(arguments[3], 1.0, 1.0, out alpha)) ||
			!(isRgb ? TryParseClipboardColorNumber(arguments[0], 255.0, 1.0, out double first) : TryParseClipboardHue(arguments[0], out first)) ||
			!TryParseClipboardColorNumber(arguments[1], isRgb ? 255.0 : 1.0, isRgb ? 1.0 : 0.01, out double second) ||
			!TryParseClipboardColorNumber(arguments[2], isRgb ? 255.0 : 1.0, isRgb ? 1.0 : 0.01, out double third))
		{
			return false;
		}
		if (!isRgb)
		{
			// The conversions of the CSS Color specification. The hue is in degrees, and the other two values are from 0 to 1.
			double hue = first;
			double saturation = Math.Clamp(second, 0.0, 1.0);
			double lightness = Math.Clamp(third, 0.0, 1.0);
			bool isHwb = string.Equals(name, "hwb", StringComparison.OrdinalIgnoreCase);
			double Channel(int n)
			{
				if (isHwb && saturation + lightness >= 1.0)
				{
					return saturation / (saturation + lightness) * 255.0;
				}
				double s = isHwb ? 1.0 : saturation;
				double l = isHwb ? 0.5 : lightness;
				double k = (n + (hue / 30.0)) % 12.0;
				double hsl = l - (s * Math.Min(l, 1.0 - l) * Math.Max(-1.0, Math.Min(Math.Min(k - 3.0, 9.0 - k), 1.0)));
				return (isHwb ? (hsl * (1.0 - saturation - lightness)) + saturation : hsl) * 255.0;
			}
			first = Channel(0);
			second = Channel(8);
			third = Channel(4);
		}
		color = Windows.UI.Color.FromArgb(ToClipboardColorByte(alpha * 255.0), ToClipboardColorByte(first), ToClipboardColorByte(second), ToClipboardColorByte(third));
		return true;
	}

	// CSS rounds a channel that falls halfway between two values up.
	private static byte ToClipboardColorByte(double value) => (byte)Math.Round(Math.Clamp(value, 0.0, 255.0), MidpointRounding.AwayFromZero);

	/// <summary>
	/// Reads a color argument. A percentage is scaled by <paramref name="percentScale"/> per 100 percent, and a plain number
	/// by <paramref name="numberScale"/>.
	/// </summary>
	private static bool TryParseClipboardColorNumber(string argument, double percentScale, double numberScale, out double value)
	{
		bool percent = argument.EndsWith('%');
		bool parsed = double.TryParse(percent ? argument.AsSpan(0, argument.Length - 1) : argument.AsSpan(), NumberStyles.Float, CultureInfo.InvariantCulture, out value) &&
			double.IsFinite(value);
		value *= percent ? percentScale / 100.0 : numberScale;
		return parsed;
	}

	/// <summary>
	/// Reads a hue in degrees, gradians, radians or turns, and returns it in degrees from 0 to 360.
	/// </summary>
	private static bool TryParseClipboardHue(string argument, out double degrees)
	{
		ReadOnlySpan<char> number = argument;
		double scale = 1.0;
		if (argument.EndsWith("deg", StringComparison.OrdinalIgnoreCase))
		{
			number = number[..^3];
		}
		else if (argument.EndsWith("grad", StringComparison.OrdinalIgnoreCase))
		{
			number = number[..^4];
			scale = 0.9;
		}
		else if (argument.EndsWith("rad", StringComparison.OrdinalIgnoreCase))
		{
			number = number[..^3];
			scale = 180.0 / Math.PI;
		}
		else if (argument.EndsWith("turn", StringComparison.OrdinalIgnoreCase))
		{
			number = number[..^4];
			scale = 360.0;
		}
		bool parsed = double.TryParse(number, NumberStyles.Float, CultureInfo.InvariantCulture, out degrees);
		degrees = ((degrees * scale % 360.0) + 360.0) % 360.0;
		return parsed && double.IsFinite(degrees);
	}

	[GeneratedRegex(@"^(?<name>rgba?|hsla?|hwb)\(\s*(?<arguments>[^()]*)\)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
	private static partial Regex ClipboardColorFunctionRegex();

	/// <summary>
	/// Shows or hides the cards of copied web addresses. While it is on, a card is read for every web address that is copied
	/// on its own.
	/// </summary>
	private void OnClipboardLinkPreviewToggled()
	{
		Atlas.Settings.WindowsTopBarClipboardLinkPreviews = ClipboardLinkPreviewToggle.IsChecked == true;

		// The cards that were read before show or hide with the setting.
		foreach (TopBarClipboardBucket bucket in _clipboardCollection.Buckets)
		{
			if (bucket.RealizedContainer is not null)
			{
				OnClipboardBucketChanged(bucket);
			}
		}
		RefreshClipboardViewerRows(null);
	}

	/// <summary>
	/// Returns the web address of a clip that is a single http or https address and nothing else.
	/// </summary>
	private static bool TryGetClipboardLink(TopBarClipboardEntry entry, [NotNullWhen(true)] out Uri? link)
	{
		link = null;
		return entry.Files.Count == 0 && !entry.HasBitmap && entry.Text is not null &&
			ClipboardLinkRegex().IsMatch(entry.Text.AsSpan().Trim()) && TryGetWebsiteUri(entry.Text, out link);
	}

	/// <summary>
	/// Reads the card of a copied web address and stores it with the clip. Nothing is stored when the page offers no title
	/// and no image, or when the clip was deleted while the card was being read.
	/// </summary>
	private async Task LoadClipboardLinkPreviewAsync(TopBarClipboardEntry entry, Uri link, CancellationToken cancellationToken)
	{
		try
		{
			using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
			timeout.CancelAfter(ClipboardLinkTimeout);
			// The page is read and parsed off the UI thread.
			(string? title, string? description, byte[]? image) = await Task.Run(() => ReadClipboardLinkCardAsync(link, timeout.Token), timeout.Token);
			if (title is null && image is null)
			{
				return;
			}
			await RunClipboardOperationAsync(async token =>
			{
				TopBarClipboardBucket? bucket = _clipboardCollections.SelectMany(static collection => collection.Buckets).FirstOrDefault(bucket => bucket.Entries.Contains(entry));
				if (!_clipboardEnabled || bucket is null)
				{
					return;
				}
				if (image is not null)
				{
					Guid imageId = Guid.NewGuid();
					await WriteClipboardBlobAsync(imageId, CreateClipboardPayload(null, null, image), token);
					_ = _clipboardStoredBlobs.Add(imageId);
					entry.LinkImageId = imageId;
				}
				entry.LinkTitle = title;
				entry.LinkDescription = description;
				OnClipboardBucketChanged(bucket);
				RefreshClipboardViewerRows(entry);
				await SaveClipboardStoreAsync(token);
			}, "The link preview could not be saved.");
		}
		catch (Exception ex)
		{
			// Pages that cannot be reached or that time out simply get no card.
			if (!_isClosed && ex is not (HttpRequestException or IOException or OperationCanceledException))
			{
				Logger.Write(ex);
			}
		}
	}

	/// <summary>
	/// Reads the card that social sites show for a web address: the Open Graph or Twitter/X title, description and image of
	/// the page, or the picture itself when the address is a picture. Website icons are not used.
	/// </summary>
	private async Task<(string? Title, string? Description, byte[]? Image)> ReadClipboardLinkCardAsync(Uri link, CancellationToken cancellationToken)
	{
		(byte[] data, Uri location, string? mediaType) = await DownloadAsync(_clipboardLinkClient, link, MaximumClipboardLinkBytes + 1, cancellationToken);
		if (mediaType?.StartsWith("image/", StringComparison.OrdinalIgnoreCase) == true)
		{
			return (null, null, data.Length is 0 or > MaximumClipboardLinkBytes ? null : data);
		}
		if (data.Length == 0 || (mediaType is not null && !mediaType.Contains("html", StringComparison.OrdinalIgnoreCase)))
		{
			return default;
		}

		// The card is described by meta tags in the head of the page, and the first tag of a property is the one that counts.
		string page = Encoding.UTF8.GetString(data);
		int headEnd = page.IndexOf("</head>", StringComparison.OrdinalIgnoreCase);
		if (headEnd >= 0)
		{
			page = page[..headEnd];
		}
		Dictionary<string, string> properties = new(StringComparer.OrdinalIgnoreCase);
		foreach (Match tag in ClipboardMetaTagRegex().Matches(page))
		{
			string? key = null;
			string? content = null;
			foreach (Match attribute in ClipboardMetaAttributeRegex().Matches(tag.Value))
			{
				if (string.Equals(attribute.Groups["name"].Value, "content", StringComparison.OrdinalIgnoreCase))
				{
					content = attribute.Groups["value"].Value;
				}
				else
				{
					key ??= attribute.Groups["value"].Value;
				}
			}
			if (key is not null && content is not null)
			{
				_ = properties.TryAdd(key, WebUtility.HtmlDecode(content));
			}
		}
		Match titleTag = ClipboardTitleRegex().Match(page);
		string? title = NormalizeClipboardLinkText(GetClipboardLinkProperty(properties, "og:title", "twitter:title") ??
			(titleTag.Success ? WebUtility.HtmlDecode(titleTag.Groups["title"].Value) : null));
		string? description = NormalizeClipboardLinkText(GetClipboardLinkProperty(properties, "og:description", "twitter:description", "description"));
		foreach (string key in ClipboardLinkImageProperties)
		{
			if (!properties.TryGetValue(key, out string? address) || !Uri.TryCreate(location, address.Trim(), out Uri? imageUri) || !IsWebUri(imageUri))
			{
				continue;
			}
			try
			{
				// A text response is the page that some sites serve in place of a missing image.
				(byte[] image, _, string? imageType) = await DownloadAsync(_clipboardLinkClient, imageUri, MaximumClipboardLinkBytes + 1, cancellationToken);
				if (image.Length is > 0 and <= MaximumClipboardLinkBytes && imageType?.StartsWith("text/", StringComparison.OrdinalIgnoreCase) != true)
				{
					return (title, description, image);
				}
			}
			catch (HttpRequestException)
			{
				// The next image property is tried, and the card keeps its title without an image when none can be read.
			}
		}
		return (title, description, null);
	}

	// The meta properties that name the image of a card, in the order in which they are tried.
	private static readonly string[] ClipboardLinkImageProperties = ["og:image", "og:image:secure_url", "og:image:url", "twitter:image", "twitter:image:src"];

	private static string? GetClipboardLinkProperty(Dictionary<string, string> properties, params ReadOnlySpan<string> keys)
	{
		foreach (string key in keys)
		{
			if (properties.TryGetValue(key, out string? value) && !string.IsNullOrWhiteSpace(value))
			{
				return value;
			}
		}
		return null;
	}

	/// <summary>
	/// Joins the lines of a card title or description and shortens it to 300 characters.
	/// </summary>
	private static string? NormalizeClipboardLinkText(string? value)
	{
		if (value is null)
		{
			return null;
		}
		string normalized = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
		return normalized.Length == 0 ? null : normalized.Length <= 300 ? normalized : normalized[..297] + "...";
	}

	[GeneratedRegex(@"^https?://\S+$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
	private static partial Regex ClipboardLinkRegex();

	// The patterns that scan the whole page run in linear time, so a page that never closes its tags cannot stall the parsing.
	// A meta tag always matches up to its first '>' outside quotes, or to the end of the page when it never closes, so no part of the page is read twice.
	// Its parts are capped at 1000, far above the few attributes of a real meta tag, so the backtracking stack that the regex keeps between uses stays small.
	[GeneratedRegex(@"<meta\b(?>[^>""']+|""[^""]*""?|'[^']*'?){0,1000}", RegexOptions.IgnoreCase)]
	private static partial Regex ClipboardMetaTagRegex();

	[GeneratedRegex(@"(?<![\w-])(?<name>property|name|content)\s*=\s*(?:""(?<value>[^""]*)""|'(?<value>[^']*)'|(?<value>[^\s""'>]+))", RegexOptions.IgnoreCase)]
	private static partial Regex ClipboardMetaAttributeRegex();

	// The title tag cannot contain '<', so every attempt stops at the next tag.
	[GeneratedRegex(@"<title\b[^<>]*>(?<title>[^<]*)</title>", RegexOptions.IgnoreCase)]
	private static partial Regex ClipboardTitleRegex();

	/// <summary>
	/// Connects link card requests only to public addresses.
	/// </summary>
	private static async ValueTask<Stream> ConnectToPublicAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
	{
		IPAddress[] addresses = Array.FindAll(await Dns.GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken), IsPublicAddress);
		if (addresses.Length == 0)
		{
			throw new HttpRequestException("The link does not lead to a public address.");
		}
		// The returned stream owns the socket, and the socket is disposed here when connecting fails.
#pragma warning disable CA2000
		Socket socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
#pragma warning restore CA2000
		try
		{
			await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, cancellationToken);
			return new NetworkStream(socket, ownsSocket: true);
		}
		catch
		{
			socket.Dispose();
			throw;
		}
	}

	/// <summary>
	/// Returns whether an address belongs to the public internet rather than to this device or a local network.
	/// </summary>
	private static bool IsPublicAddress(IPAddress address)
	{
		if (address.IsIPv4MappedToIPv6)
		{
			address = address.MapToIPv4();
		}
		if (address.AddressFamily == AddressFamily.InterNetwork)
		{
			byte[] bytes = address.GetAddressBytes();
			return bytes[0] is not (0 or 10 or 127) and < 224 &&
				!(bytes[0] == 169 && bytes[1] == 254) &&
				!(bytes[0] == 172 && bytes[1] is >= 16 and <= 31) &&
				!(bytes[0] == 192 && bytes[1] == 168) &&
				!(bytes[0] == 100 && bytes[1] is >= 64 and <= 127);
		}
		return !IPAddress.IsLoopback(address) && !address.Equals(IPAddress.IPv6Any) && !address.IsIPv6LinkLocal &&
			!address.IsIPv6SiteLocal && !address.IsIPv6Multicast && !address.IsIPv6UniqueLocal;
	}

	/// <summary>
	/// Slides the search box open or closed next to the search button. Closing it clears the query, which also removes the
	/// highlight of the current match.
	/// </summary>
	private void SetClipboardSearchOpen(bool open)
	{
		ClipboardSearchToggle.IsChecked = open;

		// The slide continues from the width the box has now, which matters when the button is clicked during a slide.
		double width = ClipboardSearchHost.ActualWidth;
		_clipboardSearchStoryboard.Stop();
		ClipboardSearchHost.Width = width;
		ClipboardSearchHost.Visibility = Visibility.Visible;
		_clipboardSearchAnimation.To = open ? ClipboardSearchWidthDips : 0.0;
		_clipboardSearchAnimation.Duration = _uiSettings.AnimationsEnabled ? TimeSpan.FromMilliseconds(180) : TimeSpan.Zero;
		_clipboardSearchStoryboard.Begin();
		if (open)
		{
			_ = ClipboardSearchBox.Focus(FocusState.Programmatic);
		}
		else
		{
			ClipboardSearchBox.Text = string.Empty;
		}
	}

	private void OnClipboardSearchToggleClick() => SetClipboardSearchOpen(ClipboardSearchToggle.IsChecked == true);

	private void OnClipboardSearchAnimationCompleted(object? sender, object e)
	{
		if (ClipboardSearchToggle.IsChecked != true)
		{
			ClipboardSearchHost.Visibility = Visibility.Collapsed;
		}
	}

	private void OnClipboardSearchTextChanged() => FindClipboardSearchMatch(next: false);

	private void OnClipboardSearchKeyDown(object sender, Microsoft.UI.Xaml.Input.KeyRoutedEventArgs args)
	{
		if (args.Key == VirtualKey.Enter)
		{
			args.Handled = true;
			FindClipboardSearchMatch(next: true);
		}
		else if (args.Key == VirtualKey.Escape)
		{
			args.Handled = true;
			SetClipboardSearchOpen(false);
		}
	}

	/// <summary>
	/// Highlights the first bucket, from the current match onward through every collection, whose title or clips contain the
	/// query, and shows its collection. With <paramref name="next"/> set the search starts after the current match, so
	/// pressing Enter steps through every match in turn.
	/// </summary>
	private void FindClipboardSearchMatch(bool next)
	{
		string query = ClipboardSearchBox.Text.Trim();
		if (query.Length == 0)
		{
			ClearClipboardSearchMatch();
			ClipboardStatusText.Text = _clipboardEnabled ? ClipboardOnStatus : ClipboardOffStatus;
			return;
		}
		TopBarClipboardBucket? previous = _clipboardSearchMatch;
		int collectionStart = Math.Max(0, _clipboardCollections.IndexOf(previous?.Collection ?? _clipboardCollection));
		int bucketStart = previous is null ? 0 : previous.Collection.Buckets.IndexOf(previous) + (next ? 1 : 0);

		// The collection where the search starts is visited twice, so the buckets before the starting bucket are searched last.
		for (int step = 0; step <= _clipboardCollections.Count; step++)
		{
			TopBarClipboardCollection collection = _clipboardCollections[(collectionStart + step) % _clipboardCollections.Count];
			for (int index = step == 0 ? bucketStart : 0; index < collection.Buckets.Count; index++)
			{
				TopBarClipboardBucket bucket = collection.Buckets[index];
				if (!ClipboardBucketMatches(bucket, query))
				{
					continue;
				}
				ClearClipboardSearchMatch();
				_clipboardSearchMatch = bucket;
				bucket.IsHighlighted = true;
				ShowClipboardCollection(collection);
				ScrollClipboardBucketIntoView(bucket);
				ClipboardStatusText.Text = "Found in " + collection.Name + ", " + bucket.Title + ". Press Enter for the next match.";
				return;
			}
		}
		ClearClipboardSearchMatch();
		ClipboardStatusText.Text = "No clips match.";
	}

	private static bool ClipboardBucketMatches(TopBarClipboardBucket bucket, string query) =>
		bucket.Title.Contains(query, StringComparison.OrdinalIgnoreCase) ||
		bucket.Entries.Exists(entry =>
			entry.Text?.Contains(query, StringComparison.OrdinalIgnoreCase) is true ||
			entry.LinkTitle?.Contains(query, StringComparison.OrdinalIgnoreCase) is true ||
			entry.LinkDescription?.Contains(query, StringComparison.OrdinalIgnoreCase) is true ||
			entry.Files.Exists(file => file.Path.Contains(query, StringComparison.OrdinalIgnoreCase)));

	/// <summary>
	/// Builds the unencrypted layout of a payload file: the layout version, then the HTML, RTF and bitmap formats, each
	/// marked as present or absent. The buffer of the returned segment holds the bitmap, so the caller zeroes it when done.
	/// </summary>
	private static ArraySegment<byte> CreateClipboardPayload(string? html, string? rtf, byte[]? bitmap)
	{
		using MemoryStream stream = new();
		using (BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true))
		{
			writer.Write(ClipboardStoreVersion);
			WriteNullableString(writer, html);
			WriteNullableString(writer, rtf);
			writer.Write(bitmap?.Length ?? -1);
			if (bitmap is not null) writer.Write(bitmap);
		}

		// The buffer of a MemoryStream stays readable after the stream is disposed.
		return new ArraySegment<byte>(stream.GetBuffer(), 0, (int)stream.Length);
	}

	private static string GetClipboardBlobFileName(Guid id) => id.ToString("N", CultureInfo.InvariantCulture) + ".dat";

	private static string GetClipboardBlobPath(Guid id) => Path.Join(ClipboardStoreFolder, GetClipboardBlobFileName(id));

	private static Task WriteClipboardBlobAsync(Guid id, ArraySegment<byte> payload, CancellationToken cancellationToken) =>
		Task.Run(() => WriteClipboardBlob(id, payload), cancellationToken);

	/// <summary>
	/// Protects a payload with DPAPI CurrentUser and writes it to its own file.
	/// </summary>
	private static void WriteClipboardBlob(Guid id, ReadOnlySpan<byte> payload)
	{
		_ = Directory.CreateDirectory(ClipboardStoreFolder);
		File.WriteAllBytes(GetClipboardBlobPath(id), ProtectedData.Protect(payload, DataProtectionScope.CurrentUser, ClipboardEntropy));
	}

	/// <summary>
	/// Reads and decrypts the payload file of a clip. A payload file that is missing or damaged leaves the clip with its
	/// text and file references.
	/// </summary>
	private static Task<(string? Html, string? Rtf, byte[]? Bitmap)> ReadClipboardPayloadAsync(Guid id) => Task.Run<(string? Html, string? Rtf, byte[]? Bitmap)>(() =>
	{
		byte[]? plainBytes = null;
		try
		{
			plainBytes = ProtectedData.Unprotect(File.ReadAllBytes(GetClipboardBlobPath(id)), ClipboardEntropy, DataProtectionScope.CurrentUser);
			using MemoryStream stream = new(plainBytes, writable: false);
			using BinaryReader reader = new(stream, Encoding.UTF8, leaveOpen: false);
			_ = ValidateClipboardStoreVersion(reader.ReadInt32());
			string? html = ReadNullableString(reader);
			string? rtf = ReadNullableString(reader);
			int length = reader.ReadInt32();
			return (html, rtf, length < 0 ? null : reader.ReadBytes(ValidateLength(length)));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException)
		{
			return default;
		}
		finally
		{
			CryptographicOperations.ZeroMemory(plainBytes);
		}
	});

	/// <summary>
	/// Loads the index from LocalCacheFolder and decrypts it exclusively with the current user's DPAPI context.
	/// An index protected for another user or machine context is intentionally rejected.
	/// </summary>
	private async Task LoadClipboardStoreAsync(CancellationToken cancellationToken)
	{
		(List<TopBarClipboardCollection> collections, int activeIndex, HashSet<Guid> storedBlobs) = await Task.Run(ReadClipboardStore, cancellationToken);
		if (collections.Count == 0)
		{
			return;
		}
		_clipboardStoredBlobs = storedBlobs;
		ReplaceClipboardCollections(collections, activeIndex);
	}

	/// <summary>
	/// Reads the index and deletes the payload files that it does not refer to. Those are left behind when the app closes
	/// between writing a payload file and saving the index, or between saving the index and deleting the payload files that
	/// it no longer refers to.
	/// </summary>
	private (List<TopBarClipboardCollection> Collections, int ActiveIndex, HashSet<Guid> StoredBlobs) ReadClipboardStore()
	{
		List<TopBarClipboardCollection> collections = new(MaximumClipboardCollections + 1);
		HashSet<Guid> referencedBlobs = [];
		int activeIndex = 0;
		if (!Directory.Exists(ClipboardStoreFolder))
		{
			return (collections, activeIndex, referencedBlobs);
		}
		string indexPath = Path.Join(ClipboardStoreFolder, ClipboardIndexFileName);
		if (File.Exists(indexPath))
		{
			byte[] plainBytes = ProtectedData.Unprotect(File.ReadAllBytes(indexPath), ClipboardEntropy, DataProtectionScope.CurrentUser);
			try
			{
				activeIndex = ReadClipboardIndex(plainBytes, collections, referencedBlobs);
			}
			finally
			{
				CryptographicOperations.ZeroMemory(plainBytes);
			}
		}
		(IEnumerable<string> files, int _) = FileUtility.GetFilesFast(new[] { ClipboardStoreFolder }, null, [".dat"]);
		foreach (string file in files)
		{
			if (Guid.TryParseExact(Path.GetFileNameWithoutExtension(file), "N", out Guid id) && !referencedBlobs.Contains(id))
			{
				DeleteClipboardFile(file);
			}
		}
		return (collections, activeIndex, referencedBlobs);
	}

	/// <summary>
	/// Validates and reconstructs the collections of the index while enforcing collection, bucket and entry invariants.
	/// Returns the index of the collection that was shown.
	/// </summary>
	private int ReadClipboardIndex(byte[] plainBytes, List<TopBarClipboardCollection> collections, HashSet<Guid> referencedBlobs)
	{
		using MemoryStream stream = new(plainBytes, writable: false);
		using BinaryReader reader = new(stream, Encoding.UTF8, leaveOpen: false);
		_ = ValidateClipboardStoreVersion(reader.ReadInt32());
		int activeIndex = reader.ReadInt32();
		int collectionCount = reader.ReadInt32();
		if (collectionCount is < 1 or > MaximumClipboardCollections + 1 || activeIndex < 0 || activeIndex >= collectionCount)
		{
			throw new InvalidDataException("Invalid clipboard collection count.");
		}
		for (int collectionIndex = 0; collectionIndex < collectionCount; collectionIndex++)
		{
			string name = reader.ReadString();
			bool useNewBucket = reader.ReadBoolean();
			int targetIndex = reader.ReadInt32();
			int bucketCount = reader.ReadInt32();
			if (name.Length is 0 or > MaximumClipboardCollectionNameLength || bucketCount is < 0 or > ClipboardCollectionCapacity ||
				targetIndex < -1 || targetIndex >= bucketCount)
			{
				throw new InvalidDataException("Invalid clipboard collection.");
			}

			// The first collection is always the Default collection.
			TopBarClipboardCollection collection = new(name, isDefault: collectionIndex == 0);
			for (int bucketIndex = 0; bucketIndex < bucketCount; bucketIndex++)
			{
				string customName = reader.ReadString();
				int entryCount = reader.ReadInt32();
				if (customName.Length > MaximumClipboardBucketNameLength || entryCount < 1)
				{
					throw new InvalidDataException("Invalid clipboard bucket.");
				}
				TopBarClipboardBucket bucket = CreateClipboardBucket(collection);
				_ = bucket.SetCustomName(customName);
				for (int entryIndex = 0; entryIndex < entryCount; entryIndex++)
				{
					long ticks = reader.ReadInt64();
					string? text = ReadNullableString(reader);
					byte formats = reader.ReadByte();
					Guid? payloadId = ReadNullableGuid(reader, referencedBlobs);
					int fileCount = reader.ReadInt32();

					// Every format is a bit of TopBarClipboardFormats, and an entry holds at most one file because a package
					// of several files is stored as one entry per file.
					if (formats > 7 || fileCount is < 0 or > 1)
					{
						throw new InvalidDataException("Invalid clipboard entry.");
					}
					List<TopBarClipboardFile> files = new(fileCount);
					for (int fileIndex = 0; fileIndex < fileCount; fileIndex++)
					{
						files.Add(new TopBarClipboardFile
						{
							Name = reader.ReadString(),
							Path = reader.ReadString(),
							FileType = reader.ReadString(),
							Size = reader.ReadUInt64()
						});
					}
					bucket.Entries.Add(new TopBarClipboardEntry
					{
						CapturedAt = new DateTimeOffset(ticks, TimeSpan.Zero),
						Text = text,
						Formats = (TopBarClipboardFormats)formats,
						PayloadId = payloadId,
						Files = files,
						Summary = reader.ReadString(),
						LinkTitle = ReadNullableString(reader),
						LinkDescription = ReadNullableString(reader),
						LinkImageId = ReadNullableGuid(reader, referencedBlobs)
					});
				}
				collection.Buckets.Add(bucket);
			}
			collection.Target = targetIndex < 0 ? null : collection.Buckets[targetIndex];
			collection.UseNewBucket = useNewBucket || collection.Target is null;
			collections.Add(collection);
		}
		return activeIndex;
	}

	/// <summary>
	/// Serializes the collections with their clip text and path-only file metadata, protects the index with DPAPI
	/// CurrentUser, and replaces the index file. The plain serialized buffer is zeroed after protection. Payload files that
	/// the new index no longer refers to are deleted afterwards.
	/// </summary>
	private async Task SaveClipboardStoreAsync(CancellationToken cancellationToken)
	{
		if (!_clipboardEnabled)
		{
			return;
		}
		int activeIndex = _clipboardCollections.IndexOf(_clipboardCollection);
		HashSet<Guid> storedBlobs = _clipboardStoredBlobs;

		// Serialization and protection run off the UI thread. The caller holds the serialization gate, which every change to
		// bucket entries and to the collection and bucket lists requires. Only the scalar routing fields and bucket names change
		// outside the gate, and those reference and scalar writes are atomic.
		_clipboardStoredBlobs = await Task.Run(() =>
		{
			HashSet<Guid> referencedBlobs = new(storedBlobs.Count);
			byte[] protectedBytes;
			using (MemoryStream stream = WriteClipboardStore(activeIndex, referencedBlobs))
			{
				byte[] plainBuffer = stream.GetBuffer();
				protectedBytes = ProtectedData.Protect(plainBuffer.AsSpan(0, (int)stream.Length), DataProtectionScope.CurrentUser, ClipboardEntropy);
				CryptographicOperations.ZeroMemory(plainBuffer);
			}
			_ = Directory.CreateDirectory(ClipboardStoreFolder);

			// The new index is written next to the old one and then replaces it, so a failed write never leaves a truncated index.
			string indexPath = Path.Join(ClipboardStoreFolder, ClipboardIndexFileName);
			File.WriteAllBytes(indexPath + ".tmp", protectedBytes);
			File.Move(indexPath + ".tmp", indexPath, overwrite: true);
			foreach (Guid id in storedBlobs)
			{
				if (!referencedBlobs.Contains(id))
				{
					DeleteClipboardFile(GetClipboardBlobPath(id));
				}
			}
			return referencedBlobs;
		}, cancellationToken);
	}

	/// <summary>
	/// Writes the current binary representation of the index and collects the payload files that it refers to.
	/// </summary>
	private MemoryStream WriteClipboardStore(int activeIndex, HashSet<Guid> referencedBlobs)
	{
		MemoryStream stream = new();
		using BinaryWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
		writer.Write(ClipboardStoreVersion);
		writer.Write(activeIndex);
		writer.Write(_clipboardCollections.Count);
		foreach (TopBarClipboardCollection collection in _clipboardCollections)
		{
			writer.Write(collection.Name);
			writer.Write(collection.UseNewBucket);
			writer.Write(collection.Target is { } target ? collection.Buckets.IndexOf(target) : -1);
			writer.Write(collection.Buckets.Count);
			foreach (TopBarClipboardBucket bucket in collection.Buckets)
			{
				writer.Write(bucket.CustomName ?? string.Empty);
				writer.Write(bucket.Entries.Count);
				foreach (TopBarClipboardEntry entry in bucket.Entries)
				{
					writer.Write(entry.CapturedAt.UtcTicks);
					WriteNullableString(writer, entry.Text);
					writer.Write((byte)entry.Formats);
					WriteNullableGuid(writer, entry.PayloadId, referencedBlobs);
					writer.Write(entry.Files.Count);
					foreach (TopBarClipboardFile file in entry.Files)
					{
						writer.Write(file.Name);
						writer.Write(file.Path);
						writer.Write(file.FileType);
						writer.Write(file.Size);
					}
					writer.Write(entry.Summary);
					WriteNullableString(writer, entry.LinkTitle);
					WriteNullableString(writer, entry.LinkDescription);
					WriteNullableGuid(writer, entry.LinkImageId, referencedBlobs);
				}
			}
		}
		writer.Flush();
		return stream;
	}

	private static void DeleteClipboardFile(string path)
	{
		try
		{
			File.Delete(path);
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			// A file that cannot be deleted now is deleted the next time the store is loaded.
		}
	}

	private static int ValidateClipboardStoreVersion(int version) => version is >= 1 and <= ClipboardStoreVersion
		? version
		: throw new InvalidDataException("Unsupported clipboard store version.");

	private static void WriteNullableString(BinaryWriter writer, string? value)
	{
		writer.Write(value is not null);
		if (value is not null) writer.Write(value);
	}

	private static string? ReadNullableString(BinaryReader reader) => reader.ReadBoolean() ? reader.ReadString() : null;

	private static void WriteNullableGuid(BinaryWriter writer, Guid? value, HashSet<Guid> referencedBlobs)
	{
		writer.Write(value.HasValue);
		if (value is Guid id)
		{
			Span<byte> bytes = stackalloc byte[16];
			_ = id.TryWriteBytes(bytes);
			writer.Write(bytes);
			_ = referencedBlobs.Add(id);
		}
	}

	private static Guid? ReadNullableGuid(BinaryReader reader, HashSet<Guid> referencedBlobs)
	{
		if (!reader.ReadBoolean())
		{
			return null;
		}
		Guid id = new(reader.ReadBytes(16));
		_ = referencedBlobs.Add(id);
		return id;
	}

	private static int ValidateLength(int length) => length is >= 0 and <= MaximumClipboardPayloadBytes
		? length
		: throw new InvalidDataException("Invalid clipboard payload length.");

	/// <summary>
	/// Returns whether a clipboard file reference can be reopened later through the filesystem path APIs.
	/// </summary>
	private static bool IsUsableClipboardFilePath(string path) => !string.IsNullOrWhiteSpace(path) && Path.IsPathRooted(path);

	/// <summary>
	/// Opens the explorer window of a bucket, which lists every clip of the bucket.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(DataTemplate))]
	private void OpenClipboardBucketDetails(TopBarClipboardBucket bucket)
	{
		_clipboardExplorer?.Close();
		_clipboardViewerBucket = bucket;
		_clipboardViewerEntries.Clear();
		SyncClipboardViewerEntries();
		TopBarClipboardExplorerWindow explorer = new(RootGrid.ActualTheme);
		explorer.ItemsList.ItemTemplate = (DataTemplate)ClipboardBucketsList.Resources["ClipboardExplorerItemTemplate"];
		explorer.ItemsList.ItemsSource = _clipboardViewerEntries;
		explorer.ItemsList.ContainerContentChanging += OnClipboardViewerContainerContentChanging;
		explorer.ItemsList.DragItemsStarting += OnClipboardViewerDragItemsStarting;
		explorer.ItemsList.DragItemsCompleted += OnClipboardDragItemsCompleted;
		_clipboardExplorer = explorer;
		_openFlyoutCount++;
		_retractionTimer.Stop();
		explorer.Closed += (_, _) => OnClipboardExplorerClosed(explorer);
		explorer.ShowForBucket(
			bucket.Title + "  |  " + bucket.CountText,
			bucket.Entries.Count,
			GetClipboardBucketScreenBounds(bucket),
			new RectInt32(_displayLeft, _displayTop, _displayWidth, _displayHeight),
			_rasterizationScale,
			_dockToBottom);
	}

	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private RectInt32 GetClipboardBucketScreenBounds(TopBarClipboardBucket bucket)
	{
		if (ClipboardBucketsList.ContainerFromItem(bucket) is not FrameworkElement container ||
			!NativeMethods.GetWindowRect(_windowHandle, out RECT windowBounds))
		{
			return new RectInt32(_displayLeft + (_displayWidth / 2), _dockToBottom ? _displayBottom : _displayTop, 1, 1);
		}

		Windows.Foundation.Rect bounds = container.TransformToVisual(RootGrid).TransformBounds(
			new Windows.Foundation.Rect(0.0, 0.0, container.ActualWidth, container.ActualHeight));

		return new RectInt32(
			windowBounds.left + (int)Math.Round(bounds.X * _rasterizationScale),
			windowBounds.top + (int)Math.Round(bounds.Y * _rasterizationScale),
			Math.Max(1, (int)Math.Round(bounds.Width * _rasterizationScale)),
			Math.Max(1, (int)Math.Round(bounds.Height * _rasterizationScale)));
	}

	private void OnClipboardExplorerClosed(TopBarClipboardExplorerWindow explorer)
	{
		// The rows collection outlives the window, so the list of the window stops listening to it.
		explorer.ItemsList.ItemsSource = null;
		if (ReferenceEquals(_clipboardExplorer, explorer))
		{
			_clipboardExplorer = null;
			_clipboardViewerBucket = null;
			_clipboardViewerEntries.Clear();
		}
		if (_openFlyoutCount > 0)
		{
			_openFlyoutCount--;
		}
		if (!_isPinned && !_isClosed && !IsCursorOverBar())
		{
			_retractionTimer.Stop();
			_retractionTimer.Start();
		}
	}

	/// <summary>
	/// Brings the explorer rows in line with the entries of the bucket the explorer shows. Rows of entries that remain in
	/// place keep their previews, so a change only builds previews for the rows it added.
	/// </summary>
	private void SyncClipboardViewerEntries()
	{
		if (_clipboardViewerBucket is not { } bucket)
		{
			return;
		}
		List<TopBarClipboardEntry> entries = bucket.Entries;
		HashSet<TopBarClipboardEntry> liveEntries = [.. entries];
		for (int index = _clipboardViewerEntries.Count - 1; index >= 0; index--)
		{
			if (!liveEntries.Contains(_clipboardViewerEntries[index].Entry))
			{
				_clipboardViewerEntries.RemoveAt(index);
			}
		}
		for (int index = 0; index < entries.Count; index++)
		{
			if (index == _clipboardViewerEntries.Count || !ReferenceEquals(_clipboardViewerEntries[index].Entry, entries[index]))
			{
				_clipboardViewerEntries.Insert(index, CreateClipboardViewerItem(bucket, entries[index]));
			}
		}

		// Rows whose entries moved within the bucket were inserted again at their new positions, which leaves the old rows last.
		while (_clipboardViewerEntries.Count > entries.Count)
		{
			_clipboardViewerEntries.RemoveAt(_clipboardViewerEntries.Count - 1);
		}
	}

	/// <summary>
	/// Replaces the explorer row of an entry whose card changed, or every row when <paramref name="entry"/> is null, so their
	/// text and previews are built again.
	/// </summary>
	private void RefreshClipboardViewerRows(TopBarClipboardEntry? entry)
	{
		if (_clipboardViewerBucket is not { } bucket)
		{
			return;
		}
		for (int index = 0; index < _clipboardViewerEntries.Count; index++)
		{
			TopBarClipboardEntry rowEntry = _clipboardViewerEntries[index].Entry;
			if (entry is null || ReferenceEquals(rowEntry, entry))
			{
				_clipboardViewerEntries[index] = CreateClipboardViewerItem(bucket, rowEntry);
			}
		}
	}

	private TopBarClipboardViewerItem CreateClipboardViewerItem(TopBarClipboardBucket bucket, TopBarClipboardEntry entry) =>
		new(entry, () => DeleteClipboardViewerEntryAsync(bucket, entry));

	/// <summary>
	/// Removes one clipboard item, updates the preview card, removes an empty bucket from its collection, and persists the
	/// encrypted store. Deleting an item never changes the current routing selection unless its bucket becomes empty, and
	/// the selected bucket is published again when the item was deleted from it.
	/// </summary>
	private async void DeleteClipboardViewerEntryAsync(TopBarClipboardBucket bucket, TopBarClipboardEntry entry) => await RunClipboardOperationAsync(async cancellationToken =>
	{
		if (!bucket.Entries.Remove(entry))
		{
			return;
		}
		OnClipboardBucketChanged(bucket);
		if (ReferenceEquals(SelectedClipboardBucket, bucket))
		{
			// Runs after this operation releases the serialization gate.
			_ = PublishSelectedClipboardBucketAsync(announce: false);
		}
		await SaveClipboardStoreAsync(cancellationToken);
	}, "The clipboard item could not be deleted.");

	/// <summary>
	/// Reconstructs the bucket shown as selected as a standard Windows clipboard package so normal paste commands in other
	/// applications use it. The bucket is read once this operation holds the serialization gate, so a selection that changed
	/// while it waited is never published. Every available path-backed file in the bucket is published together. Otherwise
	/// the text, HTML, RTF, and bitmap formats of the newest entry are published. The status line reports a published bucket
	/// only when <paramref name="announce"/> is true, while a busy clipboard and a bucket with nothing left to paste are
	/// always reported.
	/// </summary>
	private async Task ActivateClipboardBucketAsync(bool announce, CancellationToken cancellationToken)
	{
		// Nothing is published while clipboard history is off or the new-bucket card is selected.
		if (!_clipboardEnabled || SelectedClipboardBucket is not { Entries.Count: > 0 } bucket)
		{
			return;
		}
		DataPackage package = new();
		List<IStorageItem> storageItems = await ResolveClipboardStorageItemsAsync(bucket.Entries, cancellationToken);
		if (storageItems.Count > 0)
		{
			package.SetStorageItems(storageItems, readOnly: true);
		}
		else
		{
			TopBarClipboardEntry entry = bucket.Entries[0];
			if (entry.Text is not null) package.SetText(entry.Text);
			if (entry.PayloadId is Guid payloadId)
			{
				(string? html, string? rtf, byte[]? bitmap) = await ReadClipboardPayloadAsync(payloadId);
				try
				{
					if (html is not null) package.SetHtmlFormat(html);
					if (rtf is not null) package.SetRtf(rtf);
					if (bitmap is not null) package.SetBitmap(await CreateClipboardBitmapReferenceAsync(bitmap));
				}
				finally
				{
					CryptographicOperations.ZeroMemory(bitmap);
				}
			}
		}
		ClipboardContentOptions options = new() { IsAllowedInHistory = false, IsRoamable = false };
		if (!await RetryWhileClipboardBusyAsync(() => Clipboard.SetContentWithOptions(package, options), cancellationToken))
		{
			ClipboardStatusText.Text = "Another app is using the clipboard. Click the bucket again to place it on the clipboard.";
			return;
		}

		// Clipboard contention is expected and the package was already published successfully. A failed flush only means the
		// package is not guaranteed to outlive this process, so do not pollute the error log.
		_ = await RetryWhileClipboardBusyAsync(static () =>
		{
			Clipboard.Flush();
			return true;
		}, cancellationToken);

		// Record the final sequence after Flush because Flush can advance the sequence independently of SetContent.
		_clipboardHandledSequence = NativeMethods.GetClipboardSequenceNumber();

		// An empty package still replaces the clipboard, so an older copy is never pasted in place of this bucket.
		if (storageItems.Count == 0 && package.GetView().AvailableFormats.Count == 0)
		{
			ClipboardStatusText.Text = "Nothing in this bucket can be pasted anymore. Its files may have been moved or deleted.";
		}
		else if (announce)
		{
			ClipboardStatusText.Text = storageItems.Count > 0
				? storageItems.Count.ToString(CultureInfo.CurrentCulture) + " files are ready to paste."
				: "Selected content is ready to paste.";
		}
	}

	/// <summary>
	/// Reopens the path-backed files of the given entries without copying their content.
	/// </summary>
	private static async Task<List<IStorageItem>> ResolveClipboardStorageItemsAsync(IReadOnlyList<TopBarClipboardEntry> entries, CancellationToken cancellationToken)
	{
		List<IStorageItem> storageItems = new(entries.Count);
		foreach (TopBarClipboardEntry entry in entries)
		{
			foreach (TopBarClipboardFile file in entry.Files)
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (!IsUsableClipboardFilePath(file.Path))
				{
					continue;
				}
				try
				{
					storageItems.Add(await StorageFile.GetFileFromPathAsync(file.Path));
				}
				catch (Exception)
				{
					// Path-only file references intentionally expire when the original file or its drive is moved, deleted,
					// invalid, unavailable, or inaccessible.
				}
			}
		}
		return storageItems;
	}

	/// <summary>
	/// Runs a clipboard call again after transient clipboard ownership conflicts have had a chance to clear. While another app
	/// holds the clipboard open, setting content returns false or fails with CLIPBRD_E_CANT_OPEN, and a flush fails with
	/// CLIPBRD_E_CANT_CLOSE. Returns false when the clipboard stayed busy through every attempt.
	/// </summary>
	private static async Task<bool> RetryWhileClipboardBusyAsync(Func<bool> call, CancellationToken cancellationToken)
	{
		const int ClipboardCannotOpenHResult = unchecked((int)0x800401D0);
		const int ClipboardCannotCloseHResult = unchecked((int)0x800401D4);
		const int MaximumAttempts = 12;
		const int InitialRetryDelayMilliseconds = 25;
		const int MaximumRetryDelayMilliseconds = 2000;
		for (int attempt = 1; ; attempt++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			try
			{
				if (call())
				{
					return true;
				}
			}
			catch (COMException ex) when (ex.HResult is ClipboardCannotOpenHResult or ClipboardCannotCloseHResult)
			{
				// Another app holds the clipboard open, which is retried below like a call that returned false.
			}
			if (attempt == MaximumAttempts)
			{
				return false;
			}
			int exponentialDelayMilliseconds = InitialRetryDelayMilliseconds << (attempt - 1);
			int delayMilliseconds = Math.Min(exponentialDelayMilliseconds, MaximumRetryDelayMilliseconds);
			await Task.Delay(TimeSpan.FromMilliseconds(delayMilliseconds), cancellationToken);
		}
	}

	private void OnClipboardBucketDragItemsStarting(object sender, DragItemsStartingEventArgs args)
	{
		if (args.Items.Count != 1 || args.Items[0] is not TopBarClipboardBucket bucket || bucket.Entries.Count == 0)
		{
			args.Cancel = true;
			return;
		}
		SetClipboardDragData(args.Data, bucket, null);
	}

	private void OnClipboardViewerDragItemsStarting(object sender, DragItemsStartingEventArgs args)
	{
		if (args.Items.Count != 1 || args.Items[0] is not TopBarClipboardViewerItem item ||
			_clipboardViewerBucket is not { } bucket || !bucket.Entries.Contains(item.Entry))
		{
			args.Cancel = true;
			return;
		}
		SetClipboardDragData(args.Data, bucket, item.Entry);
	}

	/// <summary>
	/// Exposes a bucket, or one clip of a bucket when <paramref name="entry"/> is set, as a standard drag payload. File
	/// entries are resolved from their original paths without copying file content. The text, HTML, RTF, or bitmap of the
	/// newest entry, or of the clip, is provided too, and the formats kept in its payload file are only read when a target
	/// asks for them.
	/// </summary>
	private void SetClipboardDragData(DataPackage data, TopBarClipboardBucket bucket, TopBarClipboardEntry? entry)
	{
		_clipboardDragBucket = bucket;
		_clipboardDragEntry = entry;

		// Mark this as a bucket drag before exposing standard clipboard formats. The root drop target uses the marker
		// to avoid treating file references inside a bucket as files that should be pinned to Apps or Folders.
		data.Properties[ClipboardDragSourceProperty] = true;

		// External targets must only copy path-backed files. Moving clips and merging and reordering buckets are performed internally.
		data.RequestedOperation = DataPackageOperation.Copy;

		// The target requests the files later, so it receives the entries the bucket held when the drag started.
		TopBarClipboardEntry[] entries = entry is null ? [.. bucket.Entries] : [entry];
		if (Array.Exists(entries, static item => item.Files.Count > 0))
		{
			data.SetDataProvider(StandardDataFormats.StorageItems, request => ProvideClipboardBucketFilesAsync(request, entries));
		}

		TopBarClipboardEntry newest = entries[0];
		if (newest.Text is string text) data.SetText(text);
		if (newest.PayloadId is not Guid payloadId)
		{
			return;
		}
		if ((newest.Formats & TopBarClipboardFormats.Html) != 0)
		{
			data.SetDataProvider(StandardDataFormats.Html, request => ProvideClipboardPayloadAsync(request, payloadId));
		}
		if ((newest.Formats & TopBarClipboardFormats.Rtf) != 0)
		{
			data.SetDataProvider(StandardDataFormats.Rtf, request => ProvideClipboardPayloadAsync(request, payloadId));
		}
		if (newest.HasBitmap)
		{
			data.SetDataProvider(StandardDataFormats.Bitmap, request => ProvideClipboardPayloadAsync(request, payloadId));
		}
	}

	/// <summary>
	/// Ends a bucket or clip drag. An explorer whose bucket was emptied by dragging its clips away closes now.
	/// </summary>
	private void OnClipboardDragItemsCompleted(ListViewBase sender, DragItemsCompletedEventArgs args)
	{
		_clipboardDragBucket = null;
		_clipboardDragEntry = null;
		if (_clipboardViewerBucket is { } bucket && !IsLiveClipboardBucket(bucket))
		{
			_clipboardExplorer?.Close();
		}
	}

	/// <summary>
	/// Accepts only another live clipboard bucket as a merge source or a clip from another bucket. External drag targets can
	/// still request the standard formats placed on the data package by <see cref="SetClipboardDragData"/>.
	/// </summary>
	private void OnClipboardBucketDragOver(object sender, DragEventArgs args)
	{
		if (sender is FrameworkElement { DataContext: TopBarClipboardBucket destination } element &&
			TryGetClipboardDrag(args.DataView, out TopBarClipboardBucket? source, out TopBarClipboardEntry? entry) &&
			!ReferenceEquals(source, destination) && source.Entries.Count > 0 && destination.Entries.Count > 0)
		{
			int placement = entry is null ? GetClipboardBucketDropPlacement(element, args) : 0;
			args.AcceptedOperation = DataPackageOperation.Copy;
			args.DragUIOverride.Caption = entry is not null ? $"Move this clip to {destination.Title}" : placement switch
			{
				< 0 => $"Move {source.Title} before {destination.Title}",
				> 0 => $"Move {source.Title} after {destination.Title}",
				_ => $"Merge {source.Title} into {destination.Title}"
			};
			args.DragUIOverride.IsCaptionVisible = true;
			args.DragUIOverride.IsContentVisible = true;
		}
		else
		{
			args.AcceptedOperation = DataPackageOperation.None;
		}
		args.Handled = true;
	}

	private static int GetClipboardBucketDropPlacement(FrameworkElement destinationElement, DragEventArgs args)
	{
		double relativeX = args.GetPosition(destinationElement).X;
		double edgeWidth = destinationElement.ActualWidth * 0.25;
		return relativeX < edgeWidth ? -1 : relativeX > destinationElement.ActualWidth - edgeWidth ? 1 : 0;
	}

	/// <summary>
	/// Moves a dragged clip, or every entry of a dragged bucket, into the target bucket, removes a source bucket that is left
	/// empty, refreshes selection and explorer state, and persists the change as one serialized clipboard-store update.
	/// A bucket dropped near the edge of another bucket of its collection is moved before or after it instead.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(FrameworkElement))]
	private async void OnClipboardBucketDrop(object sender, DragEventArgs args)
	{
		args.AcceptedOperation = DataPackageOperation.None;
		args.Handled = true;
		if (sender is not FrameworkElement { DataContext: TopBarClipboardBucket destination } destinationElement ||
			!TryGetClipboardDrag(args.DataView, out TopBarClipboardBucket? source, out TopBarClipboardEntry? entry) ||
			ReferenceEquals(source, destination))
		{
			return;
		}

		// The pointer position has to be read while the drop event is being dispatched.
		int placement = entry is null ? GetClipboardBucketDropPlacement(destinationElement, args) : 0;
		await RunClipboardOperationAsync(async cancellationToken =>
		{
			// Revalidate after acquiring the gate because capture, deletion, or another drop may have changed either bucket.
			// A live bucket always holds at least one entry.
			if (!IsLiveClipboardBucket(source) || !IsLiveClipboardBucket(destination) ||
				(entry is not null && !source.Entries.Contains(entry)))
			{
				return;
			}
			TopBarClipboardCollection collection = source.Collection;
			if (entry is null && placement != 0 && ReferenceEquals(collection, destination.Collection))
			{
				bool sourceWasSelected = !collection.UseNewBucket && ReferenceEquals(collection.Target, source);
				_ = collection.Buckets.Remove(source);
				int destinationIndex = collection.Buckets.IndexOf(destination);
				int insertionIndex = placement < 0 ? destinationIndex : destinationIndex + 1;
				collection.Buckets.Insert(insertionIndex, source);

				// Removing the selected bucket cleared the ListView selection. Restore it without activating the bucket again.
				if (sourceWasSelected)
				{
					SetSelectedClipboardBucket(collection, source);
				}
				await SaveClipboardStoreAsync(cancellationToken);
				ClipboardBucketsList.ScrollIntoView(source, ScrollIntoViewAlignment.Default);
				ClipboardStatusText.Text = source.Title + " was moved.";
				return;
			}
			string sourceTitle = source.Title;
			string destinationTitle = destination.Title;
			MoveClipboardEntries(source, destination, entry);
			await SaveClipboardStoreAsync(cancellationToken);
			ClipboardStatusText.Text = entry is null
				? sourceTitle + " was merged into " + destinationTitle + "."
				: "The clip was moved to " + destinationTitle + ".";
		}, "The clipboard buckets could not be merged.");
	}

	/// <summary>
	/// Accepts a clip, but not a whole bucket, while the shown collection has room for another bucket.
	/// </summary>
	private void OnClipboardNewBucketDragOver(object sender, DragEventArgs args)
	{
		if (TryGetClipboardDrag(args.DataView, out TopBarClipboardBucket? source, out TopBarClipboardEntry? entry) &&
			entry is not null && source.Entries.Count > 0 && _clipboardCollection.Buckets.Count < ClipboardCollectionCapacity)
		{
			args.AcceptedOperation = DataPackageOperation.Copy;
			args.DragUIOverride.Caption = "Move this clip to a new bucket";
			args.DragUIOverride.IsCaptionVisible = true;
			args.DragUIOverride.IsContentVisible = true;
		}
		else
		{
			args.AcceptedOperation = DataPackageOperation.None;
		}
		args.Handled = true;
	}

	/// <summary>
	/// Moves a dragged clip into a new bucket at the end of the shown collection, which separates it from the clips that
	/// share its bucket.
	/// </summary>
	private async void OnClipboardNewBucketDrop(object sender, DragEventArgs args)
	{
		args.AcceptedOperation = DataPackageOperation.None;
		args.Handled = true;
		if (!TryGetClipboardDrag(args.DataView, out TopBarClipboardBucket? source, out TopBarClipboardEntry? entry) || entry is null)
		{
			return;
		}
		await RunClipboardOperationAsync(async cancellationToken =>
		{
			// Revalidate after acquiring the gate because capture, deletion, or another drop may have changed the buckets.
			TopBarClipboardCollection collection = _clipboardCollection;
			if (!IsLiveClipboardBucket(source) || !source.Entries.Contains(entry) || collection.Buckets.Count >= ClipboardCollectionCapacity)
			{
				return;
			}
			TopBarClipboardBucket destination = CreateClipboardBucket(collection);
			collection.Buckets.Add(destination);
			MoveClipboardEntries(source, destination, entry);
			await SaveClipboardStoreAsync(cancellationToken);
			ScrollClipboardBucketIntoView(destination);

			// The title is read after the move because removing an emptied source bucket renumbers the buckets after it.
			ClipboardStatusText.Text = "The clip was moved to " + destination.Title + ".";
		}, "The clip could not be moved to a new bucket.");
	}

	/// <summary>
	/// Moves a clip, or every entry of a bucket when <paramref name="entry"/> is null, into another bucket that stays newest
	/// first. A source bucket that is left empty is removed, and when it was the selected bucket of the destination's
	/// collection, the destination becomes the selected bucket instead. The selected bucket is published again when its
	/// clips changed.
	/// </summary>
	private void MoveClipboardEntries(TopBarClipboardBucket source, TopBarClipboardBucket destination, TopBarClipboardEntry? entry)
	{
		// The target of a collection is always one of its own buckets, so a source from another collection is never selected here.
		TopBarClipboardCollection collection = destination.Collection;
		bool sourceWasSelected = !collection.UseNewBucket && ReferenceEquals(collection.Target, source);
		if (entry is null)
		{
			destination.Entries.AddRange(source.Entries);
			source.Entries.Clear();
		}
		else
		{
			_ = source.Entries.Remove(entry);
			destination.Entries.Add(entry);
		}

		// Every bucket normally stores newest first, so retain that invariant regardless of which bucket was dragged.
		destination.Entries.Sort(static (left, right) => right.CapturedAt.CompareTo(left.CapturedAt));

		RemoveDuplicateClipboardFiles(destination);
		OnClipboardBucketChanged(source);
		if (sourceWasSelected && source.Entries.Count == 0)
		{
			SetSelectedClipboardBucket(collection, destination);
		}
		OnClipboardBucketChanged(destination);
		if (SelectedClipboardBucket is { } selected && (ReferenceEquals(selected, source) || ReferenceEquals(selected, destination)))
		{
			// Runs after the calling operation releases the serialization gate.
			_ = PublishSelectedClipboardBucketAsync(announce: false);
		}
	}

	/// <summary>
	/// Returns the bucket and the clip of a drag that started in this view. The clip is null while a whole bucket is dragged.
	/// </summary>
	private bool TryGetClipboardDrag(DataPackageView data, [NotNullWhen(true)] out TopBarClipboardBucket? bucket, out TopBarClipboardEntry? entry)
	{
		bucket = _clipboardDragBucket;
		entry = _clipboardDragEntry;
		return bucket is not null && data.Properties.ContainsKey(ClipboardDragSourceProperty);
	}

	private static async void ProvideClipboardBucketFilesAsync(DataProviderRequest request, TopBarClipboardEntry[] entries)
	{
		DataProviderDeferral deferral = request.GetDeferral();
		try
		{
			List<IStorageItem> items = await ResolveClipboardStorageItemsAsync(entries, CancellationToken.None);
			if (items.Count > 0)
			{
				DataPackage package = new();
				package.SetStorageItems(items, readOnly: true);
				request.SetData(await package.GetView().GetDataAsync(StandardDataFormats.StorageItems));
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			deferral.Complete();
		}
	}

	/// <summary>
	/// Provides the HTML, RTF or bitmap format that a drop target asked for from the payload file of a clip.
	/// </summary>
	private static async void ProvideClipboardPayloadAsync(DataProviderRequest request, Guid payloadId)
	{
		DataProviderDeferral deferral = request.GetDeferral();
		byte[]? bitmap = null;
		try
		{
			(string? html, string? rtf, bitmap) = await ReadClipboardPayloadAsync(payloadId);
			object? value = string.Equals(request.FormatId, StandardDataFormats.Html, StringComparison.OrdinalIgnoreCase) ? html
				: string.Equals(request.FormatId, StandardDataFormats.Rtf, StringComparison.OrdinalIgnoreCase) ? rtf
				: bitmap is null ? null
				: await CreateClipboardBitmapReferenceAsync(bitmap);
			if (value is not null)
			{
				request.SetData(value);
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			CryptographicOperations.ZeroMemory(bitmap);
			deferral.Complete();
		}
	}

	/// <summary>
	/// Wraps a bitmap payload in an in-memory stream so it can be handed to the clipboard or a drop target without
	/// writing an unencrypted copy to disk. The stream holds its own copy, so the caller can zero the bitmap afterwards.
	/// </summary>
	private static async Task<RandomAccessStreamReference> CreateClipboardBitmapReferenceAsync(byte[] bitmap)
	{
		// The target reads the stream after it receives the reference, so the stream has to stay open. Disposing it, or a
		// DataWriter over it, would close it before the target reads the bitmap.
		// The stream is reference-counted. The clipboard or drop target holds its own reference until it finishes reading.
		// Our reference is released when garbage collection runs, and the buffer is freed then.
#pragma warning disable CA2000
		InMemoryRandomAccessStream stream = new();
#pragma warning restore CA2000
		_ = await stream.WriteAsync(bitmap.AsBuffer());
		stream.Seek(0);
		return RandomAccessStreamReference.CreateFromStream(stream);
	}

	/// <summary>
	/// Stops native clipboard notifications and cancels outstanding clipboard persistence or activation work.
	/// </summary>
	private void TeardownClipboard()
	{
		_clipboardExplorer?.Close();
		_clipboardExplorer = null;
		_clipboardSearchStoryboard.Stop();
		_clipboardPreviewQueue.Clear();
		UnregisterClipboardListener();
		_clipboardCancellation.Cancel();
		_clipboardCancellation.Dispose();
		_clipboardLinkClient.Dispose();

		// Wait for the current gate owner to leave before disposing the semaphore. Disposing it directly here could
		// race with an outstanding clipboard operation that still has to release the gate in its finally block.
		_clipboardDisposalTask = DisposeClipboardGateAsync();
	}

	private async Task DisposeClipboardGateAsync()
	{
		await _clipboardGate.WaitAsync();
		_clipboardGate.Dispose();
	}
}
