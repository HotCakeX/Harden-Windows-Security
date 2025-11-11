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
using System.Diagnostics;
using System.Numerics;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.WindowComponents;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.Graphics;


#if HARDEN_SYSTEM_SECURITY
using AppControlManager.ViewModels;
namespace HardenSystemSecurity.ViewModels;
#endif
#if APP_CONTROL_MANAGER
namespace AppControlManager.ViewModels;
#endif

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : ViewModelBase
{
	internal object? NavViewSelectedItem { get; set => SP(ref field, value); }

	internal Thickness NavViewMargin { get; } = new Thickness(0);

	/// <summary>
	/// a list of all the NavigationViewItem in the Main NavigationViewItem.
	/// It is populated in the class initializer.
	/// Since the app uses it multiple times, we only populate this list once to reuse it in subsequent calls.
	/// </summary>
	internal List<NavigationViewItem> allNavigationItems = [];

	/// <summary>
	/// Every page in the application must be defined in this dictionary.
	/// It is used by the BreadCrumbBar.
	/// Sub-pages must use the same value as their main page in the dictionary.
	/// </summary>
	internal readonly Dictionary<Type, PageTitleMap> breadCrumbMappingsV2 = [];

	/// <summary>
	/// Values for back drop combo box in the settings page
	/// </summary>
	private enum BackDropComboBoxItems
	{
		MicaAlt = 0,
		Mica = 1,
		Acrylic = 2
	};

	/// <summary>
	/// ItemsSource of the ComboBox in the Settings page
	/// </summary>
	internal IEnumerable<string> BackDropOptions => Enum.GetNames<BackDropComboBoxItems>();

	/// <summary>
	/// Sets the initial value of the back drop. if it's null, Mica Alt will be used.
	/// </summary>
	internal int BackDropComboBoxSelectedIndex
	{
		get;
		set
		{
			// Update the value and the system backdrop
			if (SP(ref field, value))
			{
				UpdateSystemBackDrop();
			}
		}
	} = (int)Enum.Parse<BackDropComboBoxItems>(App.Settings.BackDropBackground);

	/// <summary>
	/// Defines a private property for the system backdrop style, initialized with a MicaBackdrop of kind BaseAlt.
	/// </summary>
	internal SystemBackdrop SystemBackDropStyle
	{
		get; set => SP(ref field, value);
	} = new MicaBackdrop { Kind = MicaKind.BaseAlt };

	/// <summary>
	/// The state of the OpenConfigDirectoryButton button which is on the Sidebar
	/// </summary>
	internal bool OpenConfigDirectoryButtonState { get; set => SP(ref field, value); } = App.IsElevated;

	/// <summary>
	/// Backing field for InfoBadgeOpacity, which controls the visibility of the InfoBadge in the UI.
	/// https://learn.microsoft.com/windows/apps/design/controls/info-badge
	/// Opacity level of the InfoBadge icon in the UI. When set to 1, the badge is visible.
	/// When set to 0, the badge is hidden.
	/// </summary>
	internal double InfoBadgeOpacity { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the sidebar pane is open or closed
	/// </summary>
	internal bool SidebarPaneIsOpen { get; set => SP(ref field, value); }

	/// <summary>
	///  Adjust the elevation of the border to achieve the shadow effect
	/// </summary>
	internal Vector3 BorderTranslation { get; set => SP(ref field, value); } = new(0, 0, 500);

	/// <summary>
	/// Whether the main NavigationView's pane is open or closed
	/// </summary>
	internal bool MainNavigationIsPaneOpen { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// The width of the TitleColumn in the main window's custom title bar
	/// </summary>
	internal GridLength TitleColumnWidth { get; set => SP(ref field, value); } = GridLength.Auto;

	/// <summary>
	/// Event handler for the main Sidebar button click
	/// </summary>
	internal void SidebarButton_Click() => SidebarPaneIsOpen = !SidebarPaneIsOpen;

	/// <summary>
	/// Event handler triggered when the UpdateAvailable event is raised, indicating an update is available.
	/// Updates InfoBadgeOpacity to show the InfoBadge in the UI if an update is available.
	/// </summary>
	/// <param name="sender">Sender of the event, in this case, AppUpdate class.</param>
	/// <param name="e">Boolean indicating whether an update is available.</param>
	private void OnUpdateAvailable(object sender, UpdateAvailableEventArgs e)
	{
		// Marshal back to the UI thread using the dispatcher to safely update UI-bound properties
		_ = Dispatcher.TryEnqueue(() =>
		{
			// Set InfoBadgeOpacity based on update availability: 1 to show, 0 to hide
			InfoBadgeOpacity = e.IsUpdateAvailable ? 1 : 0;
		});
	}

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Event handler for the Sidebar button to open the user config directory
	/// </summary>
	internal void OpenConfigDirectoryButton_Click()
	{
		_ = Process.Start(new ProcessStartInfo
		{
			FileName = GlobalVars.UserConfigDir,
			UseShellExecute = true
		});
	}
#endif

	/// <summary>
	/// Event handler for the hamburger/main menu button click
	/// </summary>
	internal void HamburgerMenuButton_Click() => MainNavigationIsPaneOpen = !MainNavigationIsPaneOpen;

	/// <summary>
	/// Event handler for the Background ComboBox selection change event in the Settings page.
	/// </summary>
	private void UpdateSystemBackDrop()
	{
		// Cast the index to the enum
		BackDropComboBoxItems selection = (BackDropComboBoxItems)BackDropComboBoxSelectedIndex;
		switch (selection)
		{
			case BackDropComboBoxItems.MicaAlt:
				SystemBackDropStyle = new MicaBackdrop { Kind = MicaKind.BaseAlt };
				break;
			case BackDropComboBoxItems.Mica:
				SystemBackDropStyle = new MicaBackdrop { Kind = MicaKind.Base };
				break;
			case BackDropComboBoxItems.Acrylic:
				SystemBackDropStyle = new DesktopAcrylicBackdrop();
				break;
			default:
				break;
		}

		// Save the selected option (using the enum's name)
		App.Settings.BackDropBackground = selection.ToString();
	}

	/// <summary>
	/// Event handler for when the main AppWindow size changes.
	/// Throughout the app the AppWindow's size must be used, nothing else such as frame size, Window size etc.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void MainWindow_SizeChanged(AppWindow sender, AppWindowChangedEventArgs args)
	{
		if (!args.DidSizeChange) return;

		double mainWindowWidth = sender.Size.Width; // Width of the main AppWindow

		// Hide TitleColumn if width is less than certain amount, Restore the TitleColumn if width is more
		TitleColumnWidth = mainWindowWidth < 950 ? new GridLength(0) : GridLength.Auto;

		bool wide = mainWindowWidth >= HeaderThresholdWidth;

		// Update breadcrumb text style based on width threshold
		BreadcrumbItemStyle = (Style)Application.Current.Resources[wide ? "TitleTextBlockStyle" : "SubtitleTextBlockStyle"];

		HeaderInlineVisibility = (wide && HasPageHeader) ? Visibility.Visible : Visibility.Collapsed;
		HeaderFlyoutVisibility = (!wide && HasPageHeader) ? Visibility.Visible : Visibility.Collapsed;
	}

	internal const double HeaderThresholdWidth = 1300;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/winmsg/extended-window-styles
	/// </summary>
	private const int WS_EX_LAYOUTRTL = 0x00400000;

	/// <summary>
	/// https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getwindowlonga
	/// </summary>
	private const int GWL_EXSTYLE = -20;

	/// <summary>
	/// Sets the flow direction of the Main Window's title bar and Close/Minimize/Maximize buttons.
	/// </summary>
	/// <param name="flowD">The Flow Direction to set.</param>
	internal static void SetCaptionButtonsFlowDirection(FlowDirection flowD)
	{
		IntPtr exStyle = NativeMethods.GetWindowLongPtrW(GlobalVars.hWnd, GWL_EXSTYLE);

		if (flowD is FlowDirection.LeftToRight)
		{
			exStyle &= ~WS_EX_LAYOUTRTL;
		}
		else
		{
			exStyle |= WS_EX_LAYOUTRTL;
		}

		_ = NativeMethods.SetWindowLongPtrW(GlobalVars.hWnd, GWL_EXSTYLE, exStyle);
	}

	/// <summary>
	/// Checks if the window has RTL layout applied
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool IsWindowRTL()
	{
		IntPtr exStyle = NativeMethods.GetWindowLongPtrW(GlobalVars.hWnd, GWL_EXSTYLE);
		return (exStyle.ToInt32() & WS_EX_LAYOUTRTL) != 0;
	}

	/// <summary>
	/// Transforms a UIElement's RenderSize to a pixel-based RectInt32.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static RectInt32 CalculatePixelRect(UIElement element, double scale)
	{
		GeneralTransform t = element.TransformToVisual(null);

		// Could cast to FrameworkElement and use ActualHeight and ActualWidth instead.
		Rect bounds = t.TransformBounds(new Rect(0, 0, element.RenderSize.Width, element.RenderSize.Height));

		return new RectInt32(
			_X: (int)Math.Round(bounds.X * scale),
			_Y: (int)Math.Round(bounds.Y * scale),
			_Width: (int)Math.Round(bounds.Width * scale),
			_Height: (int)Math.Round(bounds.Height * scale)
		);
	}

	/// <summary>
	/// Mirror a pixel-space rect horizontally around the given total width.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static RectInt32 FlipHorizontally(RectInt32 rect, double totalWidthPx)
	{
		rect.X = (int)Math.Round(totalWidthPx - (rect.X + rect.Width));
		return rect;
	}

	/// <summary>
	/// Whether the OptimizeMemory button on the Sidebar is enabled or disabled.
	/// </summary>
	internal bool OptimizeMemoryButtonIsEnabled { get; set => SP(ref field, value); } = true;

	internal async void OptimizeMemory()
	{
		OptimizeMemoryButtonIsEnabled = false;

		try
		{
			await Task.Run(() =>
			{

				// Baseline memory snapshot before forcing GC/compaction.
				long beforeHeapBytes = GC.GetGCMemoryInfo().HeapSizeBytes;
				long beforeManagedBytes = GC.GetTotalMemory(false);
				long beforeWorkingSetBytes = Process.GetCurrentProcess().WorkingSet64;
				long beforePrivateBytes = Process.GetCurrentProcess().PrivateMemorySize64;

				// Request a one-time LOH compaction.
				GCSettings.LargeObjectHeapCompactionMode = GCLargeObjectHeapCompactionMode.CompactOnce;

				// First pass: thorough, compacting collection across all generations.
				GC.Collect(
				GC.MaxGeneration,
				GCCollectionMode.Forced,
				blocking: true,
				compacting: true);

				// Ensure all pending finalizers run, releasing references.
				GC.WaitForPendingFinalizers();

				// Second pass: collect anything finalized above.
				GC.Collect(
					GC.MaxGeneration,
					GCCollectionMode.Forced,
					blocking: true,
					compacting: true);

				// Memory snapshot after GC/compaction completes.
				long afterHeapBytes = GC.GetGCMemoryInfo().HeapSizeBytes;
				long afterManagedBytes = GC.GetTotalMemory(false);
				long afterWorkingSetBytes = Process.GetCurrentProcess().WorkingSet64;
				long afterPrivateBytes = Process.GetCurrentProcess().PrivateMemorySize64;

				// Compute deltas
				long heapDelta = beforeHeapBytes - afterHeapBytes;
				long managedDelta = beforeManagedBytes - afterManagedBytes;
				long workingSetDelta = beforeWorkingSetBytes - afterWorkingSetBytes;
				long privateDelta = beforePrivateBytes - afterPrivateBytes;

				Logger.Write(
					$"Memory after compaction:\n" +
					$"GC Heap: ({beforeHeapBytes / 1048576.0:F2} MiB) -> ({afterHeapBytes / 1048576.0:F2} MiB), Δ ({heapDelta / 1048576.0:F2} MiB);\n" +
					$"Managed (GetTotalMemory): ({beforeManagedBytes / 1048576.0:F2} MiB) -> ({afterManagedBytes / 1048576.0:F2} MiB), Δ ({managedDelta / 1048576.0:F2} MiB);\n" +
					$"Working Set: ({beforeWorkingSetBytes / 1048576.0:F2} MiB) -> ({afterWorkingSetBytes / 1048576.0:F2} MiB), Δ ({workingSetDelta / 1048576.0:F2} MiB);\n" +
					$"Private Bytes: ({beforePrivateBytes / 1048576.0:F2} MiB) -> ({afterPrivateBytes / 1048576.0:F2} MiB), Δ ({privateDelta / 1048576.0:F2} MiB)"
				);

			});
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
		finally
		{
			OptimizeMemoryButtonIsEnabled = true;
		}
	}

	// Page header's title
	internal string? PageHeaderTitle { get; set => SP(ref field, value); }
	// Page header's URL
	internal Uri? PageHeaderGuideUri { get; set => SP(ref field, value); }

	// Wether the inline page header is visible.
	internal Visibility HeaderInlineVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	// Wether the flyout page header is visible.
	internal Visibility HeaderFlyoutVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	// Style used by Breadcrumb items
	internal Style? BreadcrumbItemStyle { get; private set => SP(ref field, value); }

	// Whether the current page supplies a header, aka implements the IPageHeaderProvider interface.
	internal bool HasPageHeader { get; set => SP(ref field, value); }

	// Guide button visibility (collapsed when PageHeaderGuideUri is null)
	internal Visibility GuideButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	// Whether the Crumbar is visible
	internal Visibility IsCrumbBarVisible { get; set => SP(ref field, value); }
}
