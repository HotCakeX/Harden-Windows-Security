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
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using AppControlManager.Others;
using AppControlManager.WindowComponents;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.Graphics;

#if HARDEN_WINDOWS_SECURITY
using AppControlManager;
using AppControlManager.ViewModels;
namespace HardenWindowsSecurity.ViewModels;
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
	internal IEnumerable<NavigationViewItem> allNavigationItems = [];

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
	internal bool OpenConfigDirectoryButtonState
	{
		get; set => SP(ref field, value);
	} = App.IsElevated;

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
	internal Vector3 BorderTranslation
	{
		get; set => SP(ref field, value);
	} = new(0, 0, 500);

	/// <summary>
	/// Whether the main NavigationView's pane is open or closed
	/// </summary>
	internal bool MainNavigationIsPaneOpen
	{
		get; set => SP(ref field, value);
	} = true;

	/// <summary>
	/// The width of the TitleColumn in the main window's custom title bar
	/// </summary>
	internal GridLength TitleColumnWidth
	{
		get; set => SP(ref field, value);
	} = GridLength.Auto;

	/// <summary>
	/// Event handler for the main Sidebar button click
	/// </summary>
	internal void SidebarButton_Click()
	{
		SidebarPaneIsOpen = !SidebarPaneIsOpen;
	}

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

	/// <summary>
	/// Event handler for the hamburger/main menu button click
	/// </summary>
	internal void HamburgerMenuButton_Click()
	{
		MainNavigationIsPaneOpen = !MainNavigationIsPaneOpen;
	}

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
	/// Event handler for when the main app window's size changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void MainWindow_SizeChanged(object sender, WindowSizeChangedEventArgs args)
	{
		double mainWindowWidth = args.Size.Width; // Width of the main window

		// Hide TitleColumn if width is less than 200, Restore the TitleColumn if width is 200 or more
		TitleColumnWidth = mainWindowWidth < 750 ? new GridLength(0) : GridLength.Auto;
	}

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
		IntPtr exStyle = NativeMethods.GetWindowLongPtr(GlobalVars.hWnd, GWL_EXSTYLE);

		if (flowD is FlowDirection.LeftToRight)
		{
			exStyle &= ~WS_EX_LAYOUTRTL;
		}
		else
		{
			exStyle |= WS_EX_LAYOUTRTL;
		}

		_ = NativeMethods.SetWindowLongPtr(GlobalVars.hWnd, GWL_EXSTYLE, exStyle);
	}

	/// <summary>
	/// Checks if the window has RTL layout applied
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool IsWindowRTL()
	{
		IntPtr exStyle = NativeMethods.GetWindowLongPtr(GlobalVars.hWnd, GWL_EXSTYLE);
		return (exStyle.ToInt32() & WS_EX_LAYOUTRTL) != 0;
	}

	/// <summary>
	/// Transforms a UIElement’s RenderSize to a pixel-based RectInt32.
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

}
