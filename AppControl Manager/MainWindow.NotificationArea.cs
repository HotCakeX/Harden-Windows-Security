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

using System.IO;
using System.Threading.Tasks;
using CommonCore.Interop;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Windows.ApplicationModel;
using Windows.Graphics.Imaging;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Graphics;

#if APP_CONTROL_MANAGER
using AppControlManager.ViewModels;
namespace AppControlManager;
#endif

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.ViewModels;
namespace HardenSystemSecurity;
#endif

internal sealed partial class MainWindow
{
	private const WinMsg NotificationAreaCallbackMessage = (WinMsg)((int)WinMsg.WM_APP + 1);
	private static readonly uint TaskbarCreatedMessageId = NativeMethods.RegisterWindowMessageW("TaskbarCreated");
	private const uint NotificationAreaIconId = 1;
	private const uint NotificationAreaRestoreCommandId = 1;
	private const uint NotificationAreaCloseCommandId = 2;
	private static readonly string[] NotificationAreaIconRelativePaths =
	[
		"Assets\\Square44x44Logo.targetsize-48.png",
		"Assets\\Square44x44Logo.scale-200.png",
		"Assets\\Square44x44Logo.targetsize-32.png"
	];

	private bool _isMinimizedToNotificationArea;
	private bool _isNotificationAreaIconVisible;

	private async void MinimizeToNotificationAreaButton_Click(object sender, RoutedEventArgs args)
	{
		if (_isMinimizedToNotificationArea)
		{
			return;
		}

		if (!await EnsureNotificationAreaIconVisibleAsync())
		{
			return;
		}

		_isMinimizedToNotificationArea = true;
		AppWindow.Hide();
	}

	internal bool TryHandleNotificationAreaWindowMessage(IntPtr hWnd, WinMsg msg, UIntPtr wParam, IntPtr lParam, out IntPtr result)
	{
		result = IntPtr.Zero;

		if ((uint)msg == TaskbarCreatedMessageId)
		{
			if (_isMinimizedToNotificationArea)
			{
				_isNotificationAreaIconVisible = false;

				_ = Atlas.AppDispatcher.TryEnqueue(async () =>
				{
					_ = await EnsureNotificationAreaIconVisibleAsync();
				});
			}

			result = NativeMethods.DefSubclassProc(hWnd, msg, wParam, lParam);
			return true;
		}

		if (msg == NotificationAreaCallbackMessage)
		{
			int notificationAreaMessage = lParam.ToInt32();
			ushort notificationEvent = (ushort)(notificationAreaMessage & 0xFFFF);
			ushort iconId = (ushort)((notificationAreaMessage >> 16) & 0xFFFF);

			if (iconId == (ushort)NotificationAreaIconId)
			{
				if (notificationEvent == (ushort)WinMsg.WM_LBUTTONUP || notificationEvent == (ushort)WinMsg.WM_LBUTTONDBLCLK)
				{
					_ = Atlas.AppDispatcher.TryEnqueue(RestoreFromNotificationArea);
					result = IntPtr.Zero;
					return true;
				}

				if (notificationEvent == (ushort)WinMsg.WM_CONTEXTMENU || notificationEvent == (ushort)WinMsg.WM_RBUTTONUP)
				{
					int cursorX = unchecked((short)(wParam.ToUInt64() & 0xFFFF));
					int cursorY = unchecked((short)((wParam.ToUInt64() >> 16) & 0xFFFF));

					_ = Atlas.AppDispatcher.TryEnqueue(() =>
					{
						ShowNotificationAreaContextMenu(cursorX, cursorY);
					});

					result = IntPtr.Zero;
					return true;
				}
			}
		}

		return false;
	}

	/// <summary>
	/// Shows the supported shell-style tray menu with the default OS look.
	/// </summary>
	private unsafe void ShowNotificationAreaContextMenu(int cursorX, int cursorY)
	{
		IntPtr popupMenuHandle = NativeMethods.CreatePopupMenu();

		if (popupMenuHandle == IntPtr.Zero)
		{
			return;
		}

		try
		{
			if (!NativeMethods.AppendMenuW(popupMenuHandle, NativeMethods.MF_STRING, NotificationAreaRestoreCommandId, Atlas.GetStr("RestoreTitleBarMenuFlyoutItem/Text")))
			{
				return;
			}

			if (!NativeMethods.AppendMenuW(popupMenuHandle, NativeMethods.MF_STRING, NotificationAreaCloseCommandId, Atlas.GetStr("CloseTitleBarMenuFlyoutItem/Text")))
			{
				return;
			}

			MENUITEMINFOW menuItemInfo = new()
			{
				cbSize = (uint)sizeof(MENUITEMINFOW),
				fMask = NativeMethods.MIIM_BITMAP,
				hbmpItem = NativeMethods.HBMMENU_POPUP_RESTORE
			};

			if (!NativeMethods.SetMenuItemInfoW(popupMenuHandle, NotificationAreaRestoreCommandId, 0, ref menuItemInfo))
			{
				return;
			}

			menuItemInfo.hbmpItem = NativeMethods.HBMMENU_POPUP_CLOSE;

			if (!NativeMethods.SetMenuItemInfoW(popupMenuHandle, NotificationAreaCloseCommandId, 0, ref menuItemInfo))
			{
				return;
			}

			_ = NativeMethods.SetForegroundWindow(Atlas.hWnd);

			uint selectedCommandId = NativeMethods.TrackPopupMenuEx(
				popupMenuHandle,
				NativeMethods.TPM_LEFTALIGN | NativeMethods.TPM_BOTTOMALIGN | NativeMethods.TPM_RIGHTBUTTON | NativeMethods.TPM_NONOTIFY | NativeMethods.TPM_RETURNCMD,
				cursorX,
				cursorY,
				Atlas.hWnd,
				IntPtr.Zero);

			switch (selectedCommandId)
			{
				case NotificationAreaRestoreCommandId:
					RestoreFromNotificationArea();
					break;
				case NotificationAreaCloseCommandId:
					CloseFromNotificationArea();
					break;
				default:
					break;
			}

			_ = NativeMethods.PostMessageW(Atlas.hWnd, WinMsg.WM_NULL, UIntPtr.Zero, IntPtr.Zero);
		}
		finally
		{
			_ = NativeMethods.DestroyMenu(popupMenuHandle);
		}
	}

	private async Task<bool> EnsureNotificationAreaIconVisibleAsync()
	{
		(IntPtr notificationAreaIconHandle, bool shouldDestroyIconHandle) = await GetNotificationAreaIconHandleAsync();

		if (notificationAreaIconHandle == IntPtr.Zero)
		{
			return false;
		}

		unsafe
		{
			try
			{
				NOTIFYICONDATAW notificationIconData = new()
				{
					cbSize = (uint)sizeof(NOTIFYICONDATAW),
					hWnd = Atlas.hWnd,
					uID = NotificationAreaIconId,
					uFlags = NativeMethods.NIF_MESSAGE | NativeMethods.NIF_ICON | NativeMethods.NIF_TIP | NativeMethods.NIF_SHOWTIP,
					uCallbackMessage = (uint)NotificationAreaCallbackMessage,
					hIcon = notificationAreaIconHandle,
					uVersion = NativeMethods.NOTIFYICON_VERSION_4
				};

				SetNotificationAreaToolTip(ref notificationIconData, AppInfo.Current.DisplayInfo.DisplayName);

				uint notificationIconMessage = _isNotificationAreaIconVisible ? NativeMethods.NIM_MODIFY : NativeMethods.NIM_ADD;

				if (!NativeMethods.Shell_NotifyIconW(notificationIconMessage, ref notificationIconData))
				{
					return false;
				}

				if (!NativeMethods.Shell_NotifyIconW(NativeMethods.NIM_SETVERSION, ref notificationIconData))
				{
					if (!_isNotificationAreaIconVisible)
					{
						_ = NativeMethods.Shell_NotifyIconW(NativeMethods.NIM_DELETE, ref notificationIconData);
					}

					return false;
				}

				_isNotificationAreaIconVisible = true;
				return true;
			}
			finally
			{
				if (shouldDestroyIconHandle)
				{
					_ = NativeMethods.DestroyIcon(notificationAreaIconHandle);
				}
			}
		}
	}

	private static async Task<(IntPtr IconHandle, bool DestroyAfterUse)> GetNotificationAreaIconHandleAsync()
	{
		// Resolve the tray icon from the installed package location.
		StorageFolder installedLocation = Package.Current.InstalledLocation;

		foreach (string relativePath in NotificationAreaIconRelativePaths)
		{
			try
			{
				StorageFile logoAssetFile = await installedLocation.GetFileAsync(relativePath);
				IntPtr assetIconHandle = await CreateIconHandleFromAssetAsync(logoAssetFile);

				if (assetIconHandle != IntPtr.Zero)
				{
					return (assetIconHandle, true);
				}
			}
			catch (FileNotFoundException)
			{
				continue;
			}
		}

		IntPtr notificationAreaIconHandle = NativeMethods.SendMessageW(Atlas.hWnd, WinMsg.WM_GETICON, NativeMethods.ICON_SMALL2, IntPtr.Zero);

		if (notificationAreaIconHandle == IntPtr.Zero)
		{
			notificationAreaIconHandle = NativeMethods.SendMessageW(Atlas.hWnd, WinMsg.WM_GETICON, NativeMethods.ICON_SMALL, IntPtr.Zero);
		}

		if (notificationAreaIconHandle == IntPtr.Zero)
		{
			notificationAreaIconHandle = NativeMethods.SendMessageW(Atlas.hWnd, WinMsg.WM_GETICON, NativeMethods.ICON_BIG, IntPtr.Zero);
		}

		if (notificationAreaIconHandle == IntPtr.Zero)
		{
			notificationAreaIconHandle = NativeMethods.GetClassLongPtrW(Atlas.hWnd, NativeMethods.GCLP_HICONSM);
		}

		if (notificationAreaIconHandle == IntPtr.Zero)
		{
			notificationAreaIconHandle = NativeMethods.GetClassLongPtrW(Atlas.hWnd, NativeMethods.GCLP_HICON);
		}

		if (notificationAreaIconHandle != IntPtr.Zero)
		{
			return (notificationAreaIconHandle, false);
		}

		string? processPath = Environment.ProcessPath;

		if (string.IsNullOrWhiteSpace(processPath))
		{
			return (IntPtr.Zero, false);
		}

		unsafe
		{
			SHFILEINFOW shellFileInfo = new();
			uint iconFlags = NativeMethods.SHGFI_ICON | NativeMethods.SHGFI_SMALLICON;
			IntPtr shellResult = NativeMethods.SHGetFileInfoW(processPath, 0, ref shellFileInfo, (uint)sizeof(SHFILEINFOW), iconFlags);

			if (shellResult == IntPtr.Zero || shellFileInfo.hIcon == IntPtr.Zero)
			{
				return (IntPtr.Zero, false);
			}

			return (shellFileInfo.hIcon, true);
		}
	}

	private static async Task<IntPtr> CreateIconHandleFromAssetAsync(StorageFile logoFile)
	{
		using IRandomAccessStream logoStream = await logoFile.OpenAsync(FileAccessMode.Read);

		BitmapDecoder bitmapDecoder = await BitmapDecoder.CreateAsync(logoStream);
		PixelDataProvider pixelDataProvider = await bitmapDecoder.GetPixelDataAsync(
			BitmapPixelFormat.Bgra8,
			BitmapAlphaMode.Premultiplied,
			new BitmapTransform(),
			ExifOrientationMode.IgnoreExifOrientation,
			ColorManagementMode.DoNotColorManage);

		byte[] pixelData = pixelDataProvider.DetachPixelData();
		int pixelWidth = checked((int)bitmapDecoder.PixelWidth);
		int pixelHeight = checked((int)bitmapDecoder.PixelHeight);

		unsafe
		{
			fixed (byte* pixelBuffer = pixelData)
			{
				IntPtr colorBitmapHandle = NativeMethods.CreateBitmap(pixelWidth, pixelHeight, 1, 32, (IntPtr)pixelBuffer);

				if (colorBitmapHandle == IntPtr.Zero)
				{
					return IntPtr.Zero;
				}

				IntPtr maskBitmapHandle = NativeMethods.CreateBitmap(pixelWidth, pixelHeight, 1, 1, IntPtr.Zero);

				if (maskBitmapHandle == IntPtr.Zero)
				{
					_ = NativeMethods.DeleteObject(colorBitmapHandle);
					return IntPtr.Zero;
				}

				try
				{
					ICONINFO iconInfo = new()
					{
						fIcon = 1,
						xHotspot = 0,
						yHotspot = 0,
						hbmMask = maskBitmapHandle,
						hbmColor = colorBitmapHandle
					};

					return NativeMethods.CreateIconIndirect(ref iconInfo);
				}
				finally
				{
					_ = NativeMethods.DeleteObject(maskBitmapHandle);
					_ = NativeMethods.DeleteObject(colorBitmapHandle);
				}
			}
		}
	}

	internal unsafe void RemoveNotificationAreaIcon()
	{
		if (!_isNotificationAreaIconVisible)
		{
			return;
		}

		NOTIFYICONDATAW notificationIconData = new()
		{
			cbSize = (uint)sizeof(NOTIFYICONDATAW),
			hWnd = Atlas.hWnd,
			uID = NotificationAreaIconId
		};

		_ = NativeMethods.Shell_NotifyIconW(NativeMethods.NIM_DELETE, ref notificationIconData);
		_isNotificationAreaIconVisible = false;
	}

	/// <summary>
	/// Restores the hidden window after the user clicks the notification-area icon.
	/// </summary>
	private void RestoreFromNotificationArea()
	{
		if (!_isMinimizedToNotificationArea)
		{
			return;
		}

		AppWindow.Show();

		if (overlappedPresenter.State is OverlappedPresenterState.Minimized)
		{
			overlappedPresenter.Restore();
		}

		Activate();
		_ = NativeMethods.SetForegroundWindow(Atlas.hWnd);
		RemoveNotificationAreaIcon();
		_isMinimizedToNotificationArea = false;
	}

	/// <summary>
	/// Copies the tooltip text into the fixed native buffer and preserves the terminating null.
	/// </summary>
	private static unsafe void SetNotificationAreaToolTip(ref NOTIFYICONDATAW notificationIconData, string toolTip)
	{
		fixed (char* toolTipBuffer = notificationIconData.szTip)
		{
			Span<char> toolTipSpan = new(toolTipBuffer, 128);
			toolTipSpan.Clear();

			int charsToCopy = Math.Min(toolTip.Length, 127);
			toolTip.AsSpan(0, charsToCopy).CopyTo(toolTipSpan);
		}
	}

	private void CloseFromNotificationArea()
	{
		RemoveNotificationAreaIcon();
		Application.Current.Exit();
	}
}
