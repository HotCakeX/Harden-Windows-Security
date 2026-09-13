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
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.Marshalling;
using AppControlManager.SiPolicy;

namespace CipPreviewHandler;

/// <summary>
/// The CIP file preview handler. It renders a rich, read only preview of a Code Integrity policy in the Explorer
/// preview pane. The text is hosted in a RichEdit control so section headers can be shown bold and larger than the
/// content (markdown style), while remaining selectable and copyable.
///
/// Every method reachable from native code is fully guarded so a managed exception can never cross the native
/// boundary (which would terminate the host). On error the method returns a failure HRESULT or degrades gracefully.
/// All handle and coordinate casts are performed unchecked because this project's build enables overflow checking globally.
/// </summary>
[GeneratedComClass]
[Guid(Exports.HandlerClsid)]
internal sealed partial class CipPreviewHandler : IInitializeWithStream, IObjectWithSite, IOleWindow, IPreviewHandler
{
	// Registry root and flags used to read the current app theme (light or dark).
	internal static readonly nint HKEY_CURRENT_USER = unchecked((int)0x80000001);
	internal const uint RRF_RT_REG_DWORD = 0x00000018;

	// Inner padding (in pixels) around the preview text.
	private const int Padding = 12;

	// Dark theme base colors (COLORREF is 0x00BBGGRR): near black background and near white text.
	private const uint DarkBackground = 0x00202020;
	private const uint DarkText = 0x00F0F0F0;

	// Accent (used for the title and section headers) and muted (subtitle) colors, per theme.
	private const uint LightAccent = 0x00CC6600; // RGB(0,102,204)
	private const uint DarkAccent = 0x00FFCD60;  // RGB(96,205,255)
	private const uint MutedColor = 0x008C8C8C;  // RGB(140,140,140)

	// The face used throughout the preview.
	private const string FaceName = "Segoe UI";

	// Font sizes in twips (1/20 of a point). Title 13pt, header 11pt, subtitle/body 10pt.
	private const int TitleTwips = 260;
	private const int HeaderTwips = 220;
	private const int BodyTwips = 200;

	// The single explicit tab stop (in twips) used for every "label:\tvalue" line. RichEdit's default tab grid is a
	// fixed interval, so labels of different lengths land on different multiples of it: a short label like
	// "Version:" ends up almost exactly at a stop (no visible gap), while a long label like "Signing Scenarios:"
	// overshoots into the next one (a large gap). Applying this single explicit stop to the whole document (see
	// ApplyLabelTabStop) makes every value column line up at the same place regardless of label length. The value
	// is sized to comfortably clear the longest label used in BuildPreviewText ("Signing Scenarios:").
	private const int LabelColumnTwips = 2000;

	// RedrawWindow flags used to force an immediate, synchronous repaint of a window and all of its children.
	internal const uint RDW_INVALIDATE = 0x0001;
	internal const uint RDW_ERASE = 0x0004;
	internal const uint RDW_ALLCHILDREN = 0x0080;
	internal const uint RDW_UPDATENOW = 0x0100;

	// System colors.
	internal const int COLOR_WINDOW = 5;
	internal const int COLOR_WINDOWTEXT = 8;

	// ShowWindow commands.
	internal const int SW_SHOWNA = 8;

	// The RichEdit 4.1 window class exposed by Msftedit.dll (MSFTEDIT_CLASS).
	internal const string MSFTEDIT_CLASS = "RICHEDIT50W";

	// Window styles.
	internal const uint WS_CHILD = 0x40000000;
	internal const uint WS_VISIBLE = 0x10000000;
	internal const uint WS_CLIPSIBLINGS = 0x04000000;
	internal const uint WS_CLIPCHILDREN = 0x02000000;
	internal const uint WS_VSCROLL = 0x00200000;

	// Multiline / read only / auto scroll styles
	internal const uint ES_MULTILINE = 0x0004;
	internal const uint ES_AUTOVSCROLL = 0x0040;

	// EM_SETCHARFORMAT wParam: apply to the current selection (or insertion point).
	internal const uint SCF_SELECTION = 0x0001;

	// CHARFORMAT dwMask bits (which fields / effects are valid).
	internal const uint CFM_BOLD = 0x00000001;
	internal const uint CFM_ITALIC = 0x00000002;
	internal const uint CFM_COLOR = 0x40000000;
	internal const uint CFM_FACE = 0x20000000;
	internal const uint CFM_SIZE = 0x80000000;

	// CHARFORMAT dwEffects bits.
	internal const uint CFE_BOLD = 0x0001;

	// PARAFORMAT dwMask bit indicating that cTabCount / rgxTabs are valid. Used to give every "label:\tvalue" line
	// the same explicit tab stop, instead of relying on RichEdit's default tab grid (which produces uneven spacing
	// because labels of different lengths land on different multiples of that grid).
	internal const uint PFM_TABSTOPS = 0x00000010;

	// LOGFONT charset.
	internal const byte DEFAULT_CHARSET = 1;

	// A styled run of text to render in the RichEdit control.
	private enum RunStyle
	{
		Title,
		Subtitle,
		Header,
		Body
	}

	// The policy bytes, provided by the host through IInitializeWithStream.
	private byte[]? _payload;

	// The site (frame) object provided by the host. Held as a raw, reference counted IUnknown pointer.
	private nint _site;

	// The host supplied parent window and the drawing rectangle inside it.
	private nint _parentHwnd;
	private RECT _rect;

	// Our preview child window (container). The GCHandle that ties this window back to this managed instance is a
	// STRONG handle owned by the window itself: passed as the CreateWindowExW lpParam, stored in GWLP_USERDATA during
	// WM_NCCREATE, and freed in the window procedure's WM_NCDESTROY.
	private nint _hwnd;

	// The read only RichEdit control that hosts the formatted, selectable and copyable preview text. It is a child
	// of _hwnd, so it is destroyed automatically with the parent.
	private nint _editHwnd;

	// The styled runs used to render the RichEdit content. Rebuilt on every DoPreview.
	private readonly List<(string Text, RunStyle Style)> _runs = new(32);

	// Colors are driven solely by the current OS light/dark theme.
	private uint _backgroundColor = NativeMethods.GetSysColor(COLOR_WINDOW);
	private uint _textColor = NativeMethods.GetSysColor(COLOR_WINDOWTEXT);
	private uint _accentColor = LightAccent;
	private bool _isLightTheme = true;

	// IInitializeWithStream
	public int Initialize(IStream pstream, uint grfMode)
	{
		try
		{
			if (pstream is null)
				return HResults.E_INVALIDARG;

			byte[] payload = ReadAllFromStream(pstream);
			_payload = payload;
			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	// IObjectWithSite
	public int SetSite(nint pUnkSite)
	{
		try
		{
			if (_site != 0)
			{
				_ = Marshal.Release(_site);
				_site = 0;
			}

			_site = pUnkSite;

			if (_site != 0)
				_ = Marshal.AddRef(_site);

			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int GetSite(in Guid riid, out nint ppvSite)
	{
		ppvSite = 0;
		try
		{
			if (_site == 0)
				return HResults.E_FAIL;

			Guid iid = riid;
			return Marshal.QueryInterface(_site, in iid, out ppvSite);
		}
		catch
		{
			ppvSite = 0;
			return HResults.E_FAIL;
		}
	}

	// IOleWindow
	public int GetWindow(out nint phwnd)
	{
		phwnd = _hwnd;
		return _hwnd != 0 ? HResults.S_OK : HResults.E_FAIL;
	}

	public int ContextSensitiveHelp(int fEnterMode) => HResults.E_NOTIMPL;

	// IPreviewHandler
	public int SetWindow(nint hwnd, in RECT prc)
	{
		try
		{
			_parentHwnd = hwnd;
			_rect = prc;

			if (_hwnd != 0)
			{
				_ = NativeMethods.SetParent(_hwnd, _parentHwnd);
				_ = NativeMethods.MoveWindow(_hwnd, _rect.left, _rect.top, _rect.Width, _rect.Height, true);
			}

			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int SetRect(in RECT prc)
	{
		try
		{
			_rect = prc;

			if (_hwnd != 0)
				_ = NativeMethods.MoveWindow(_hwnd, _rect.left, _rect.top, _rect.Width, _rect.Height, true);

			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int DoPreview()
	{
		try
		{
			if (_parentHwnd == 0)
				return HResults.E_FAIL;

			// Pick up the current light/dark theme so a dark mode pane is never shown with a light background.
			ApplyThemeDefaults();

			// Always rebuild the styled runs for the current payload.
			BuildPreviewText();

			if (_hwnd == 0)
			{
				PreviewWindowClass.EnsureRegistered();

				GCHandle selfHandle = GCHandle.Alloc(this);

				_hwnd = NativeMethods.CreateWindowExW(
					0,
					PreviewWindowClass.ClassName,
					null,
					WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | WS_CLIPCHILDREN,
					_rect.left,
					_rect.top,
					_rect.Width,
					_rect.Height,
					_parentHwnd,
					0,
					PreviewWindowClass.ModuleHandle,
					GCHandle.ToIntPtr(selfHandle));

				if (_hwnd == 0)
				{
					selfHandle.Free();
					return HResults.E_FAIL;
				}

			}
			else
			{
				_ = NativeMethods.MoveWindow(_hwnd, _rect.left, _rect.top, _rect.Width, _rect.Height, true);
			}

			// Create the RichEdit child once; on reuse just re-render the new content into the existing control.
			if (_editHwnd == 0)
			{
				if (!CreateRichEdit())
					return HResults.E_FAIL;
			}
			else
				RenderRichText(_editHwnd);

			// Size the child to the container's live client rectangle, then force a synchronous full tree repaint so
			// the preview is drawn on the first DoPreview every time.
			ResizeChild(_hwnd);
			_ = NativeMethods.ShowWindow(_hwnd, SW_SHOWNA);
			_ = NativeMethods.RedrawWindow(_hwnd, 0, 0, RDW_INVALIDATE | RDW_ERASE | RDW_UPDATENOW | RDW_ALLCHILDREN);

			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int Unload()
	{
		try
		{
			DestroyPreviewWindow();
			_payload = null;
			_runs.Clear();
			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int SetFocus()
	{
		try
		{
			if (_editHwnd != 0)
			{
				_ = NativeMethods.SetFocus(_editHwnd);
				return HResults.S_OK;
			}

			if (_hwnd == 0)
				return HResults.S_FALSE;

			_ = NativeMethods.SetFocus(_hwnd);
			return HResults.S_OK;
		}
		catch
		{
			return HResults.E_FAIL;
		}
	}

	public int QueryFocus(out nint phwnd)
	{
		phwnd = 0;
		try
		{
			phwnd = NativeMethods.GetFocus();
			return HResults.S_OK;
		}
		catch
		{
			phwnd = 0;
			return HResults.E_FAIL;
		}
	}

	// We do not consume any accelerators, so the frame is told to handle them.
	public int TranslateAccelerator(in MSG pmsg) => HResults.S_FALSE;

	// Creates the read only RichEdit control that fills the container and renders the formatted preview. The control
	// is created writable (no ES_READONLY) because building the content uses EM_REPLACESEL, which is ignored on a
	// read-only control; RenderRichText sets it read-only at the end.
	private bool CreateRichEdit()
	{
		_editHwnd = NativeMethods.CreateWindowExW(
			0,
			MSFTEDIT_CLASS,
			null,
			WS_CHILD | WS_VISIBLE | WS_VSCROLL |
			ES_MULTILINE | ES_AUTOVSCROLL,
			Padding,
			Padding,
			Math.Max(0, unchecked(_rect.Width - (2 * Padding))),
			Math.Max(0, unchecked(_rect.Height - (2 * Padding))),
			_hwnd,
			0,
			PreviewWindowClass.ModuleHandle,
			0);

		if (_editHwnd == 0)
			return false;

		ApplyEditTheme();
		RenderRichText(_editHwnd);
		return true;
	}

	// Applies the Explorer light or dark visual style so the scrollbar matches the theme (best effort, cosmetic).
	private void ApplyEditTheme()
	{
		if (_editHwnd == 0)
			return;

		_ = NativeMethods.SetWindowTheme(_editHwnd, _isLightTheme ? "Explorer" : "DarkMode_Explorer", null);
	}

	// Renders the styled runs into the RichEdit control: clears it, sets the theme background, then inserts each run
	// with its own character format (face, size, bold, color). The CHARFORMATW is built as a local variable per run
	// so its inline szFaceName fixed buffer can be written directly (a fixed buffer can only be indexed on a local or
	// otherwise fixed variable, never through a ref parameter). After all runs are inserted, a single explicit tab
	// stop is applied to the whole document so every "label:\tvalue" line aligns to the same column (see
	// ApplyLabelTabStop).
	private unsafe void RenderRichText(nint hwnd)
	{
		try
		{
			// Make writable while we build the content.
			_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETREADONLY, 0, 0);

			// Clear existing text (WM_SETTEXT works regardless of read-only state).
			_ = NativeMethods.SetWindowTextW(hwnd, string.Empty);

			// Theme background for the whole control.
			_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETBKGNDCOLOR, 0, unchecked((nint)_backgroundColor));

			foreach ((string runText, RunStyle style) in _runs)
			{
				// Move the (empty) selection to the end so the format applies to the text inserted next. The nint to
				// int cast is unchecked because this project's build enables overflow checking globally and a checked
				// narrowing cast of a handle sized value could throw.
				int length = unchecked((int)NativeMethods.SendMessageW(hwnd, WinMsg.WM_GETTEXTLENGTH, 0, 0));
				_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETSEL, length, length);

				// Resolve the style attributes. Locals are initialized so definite assignment is unconditional.
				int twips = BodyTwips;
				bool bold = false;
				uint color = _textColor;
				switch (style)
				{
					case RunStyle.Title:
						twips = TitleTwips; bold = true; color = _accentColor;
						break;
					case RunStyle.Subtitle:
						twips = BodyTwips; bold = true; color = MutedColor;
						break;
					case RunStyle.Header:
						twips = HeaderTwips; bold = true; color = _accentColor;
						break;
					case RunStyle.Body:
						break;
					default:
						break;
				}

				// Build the character format as a LOCAL so its fixed buffer can be written directly.
				CHARFORMATW format = default;
				format.cbSize = unchecked((uint)sizeof(CHARFORMATW));
				format.dwMask = CFM_BOLD | CFM_ITALIC | CFM_SIZE | CFM_FACE | CFM_COLOR;
				format.dwEffects = bold ? CFE_BOLD : 0;
				format.yHeight = twips;
				format.yOffset = 0;
				format.crTextColor = color;
				format.bCharSet = DEFAULT_CHARSET;
				format.bPitchAndFamily = 0;

				int faceCount = Math.Min(FaceName.Length, 31);
				for (int i = 0; i < faceCount; i++)
					format.szFaceName[i] = FaceName[i];
				format.szFaceName[faceCount] = '\0';

				_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETCHARFORMAT, unchecked((int)SCF_SELECTION), (nint)(&format));

				fixed (char* textPtr = runText)
					_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_REPLACESEL, 0, (nint)textPtr);
			}

			// Give every paragraph in the document the same explicit tab stop so the "label:\tvalue" columns align.
			ApplyLabelTabStop(hwnd);

			// Move the caret to the top so the control shows the beginning, then make it read-only.
			_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETSEL, 0, 0);
			_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SCROLLCARET, 0, 0);
			_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETREADONLY, 1, 0);
		}
		catch { }
	}

	// Applies a single explicit tab stop (LabelColumnTwips) to every paragraph in the document. RichEdit's paragraph
	// formatting messages apply to every paragraph touched by the current selection, so selecting the entire text
	// range (rather than relying on how new paragraphs might inherit formatting as they are typed) guarantees the
	// alignment is correct regardless of how the content was built.
	private unsafe void ApplyLabelTabStop(nint hwnd)
	{
		int totalLength = unchecked((int)NativeMethods.SendMessageW(hwnd, WinMsg.WM_GETTEXTLENGTH, 0, 0));
		_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETSEL, 0, totalLength);

		PARAFORMAT paraFormat = default;
		paraFormat.cbSize = unchecked((uint)sizeof(PARAFORMAT));
		paraFormat.dwMask = PFM_TABSTOPS;
		paraFormat.cTabCount = 1;
		paraFormat.rgxTabs[0] = LabelColumnTwips;

		_ = NativeMethods.SendMessageW(hwnd, WinMsg.EM_SETPARAFORMAT, 0, (nint)(&paraFormat));
	}

	// Called by the window procedure on WM_SIZE, and by DoPreview, to keep the child control filling the container.
	internal void ResizeChild(nint hwnd)
	{
		try
		{
			if (_editHwnd == 0)
				return;

			_ = NativeMethods.GetClientRect(hwnd, out RECT client);
			_ = NativeMethods.MoveWindow(
				_editHwnd,
				Padding,
				Padding,
				Math.Max(0, unchecked(client.Width - (2 * Padding))),
				Math.Max(0, unchecked(client.Height - (2 * Padding))),
				true);
		}
		catch { }
	}

	// Called from the window procedure's WM_NCDESTROY so the managed window handles always match the OS.
	internal void NotifyWindowDestroyed(nint hwnd)
	{
		if (hwnd == _hwnd)
		{
			_hwnd = 0;
			_editHwnd = 0;
		}
	}

	// Reads the current light/dark app theme from the registry and sets the colors accordingly.
	private void ApplyThemeDefaults()
	{
		_isLightTheme = IsLightTheme();

		if (_isLightTheme)
		{
			_backgroundColor = NativeMethods.GetSysColor(COLOR_WINDOW);
			_textColor = NativeMethods.GetSysColor(COLOR_WINDOWTEXT);
			_accentColor = LightAccent;
		}
		else
		{
			_backgroundColor = DarkBackground;
			_textColor = DarkText;
			_accentColor = DarkAccent;
		}
	}

	private static unsafe bool IsLightTheme()
	{
		// If the registry read fails below we return the light default instead.
		uint data;
		uint size = sizeof(uint);
		int result = NativeMethods.RegGetValueW(
			HKEY_CURRENT_USER,
			"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
			"AppsUseLightTheme",
			RRF_RT_REG_DWORD,
			null,
			&data,
			&size);

		if (result != 0)
			return true;

		return data != 0;
	}

	private void AddRun(string text, RunStyle style) => _runs.Add((text, style));

	// Reads the policy metadata and produces the styled runs to render.
	private void BuildPreviewText()
	{
		_runs.Clear();

		if (_payload is null)
		{
			_runs.Add(("No Code Integrity policy file was provided.", RunStyle.Body));
			return;
		}

		try
		{
			CipPolicyInfo info = CipPolicyInfo.Read(_payload);

			AddRun("This preview was generated by the AppControl Manager.\r\n", RunStyle.Title);
			AddRun("Code Integrity Policy Preview\r\n\r\n", RunStyle.Subtitle);

			AddRun("Policy\r\n", RunStyle.Header);
			AddRun(string.Concat("Name:\t", string.IsNullOrEmpty(info.PolicyName) ? "(not set)" : info.PolicyName, "\r\n"), RunStyle.Body);
			AddRun(string.Concat("Type:\t", CustomSerialization.s_policyTypeLabels[(int)info.PolicyType], "\r\n"), RunStyle.Body);
			AddRun(string.Concat("Version:\t", info.Version, "\r\n"), RunStyle.Body);
			AddRun(string.Concat("Signing:\t", info.SigningStatus, "\r\n"), RunStyle.Body);
			AddRun(string.Concat("HVCI:\t", info.Hvci, "\r\n\r\n"), RunStyle.Body);

			AddRun("Identifiers\r\n", RunStyle.Header);
			AddRun(string.Concat("Policy ID:\t", info.PolicyID, "\r\n"), RunStyle.Body);
			AddRun(string.Concat("Base Policy ID:\t", info.BasePolicyID, "\r\n\r\n"), RunStyle.Body);

			AddRun("Counts\r\n", RunStyle.Header);
			AddRun(string.Concat("Signers:\t", info.SignerCount.ToString(), "\r\n"), RunStyle.Body);
			AddRun(string.Concat("File Rules:\t", info.FileRuleCount.ToString(), "\r\n"), RunStyle.Body);
			AddRun(string.Concat("EKUs:\t", info.EkuCount.ToString(), "\r\n"), RunStyle.Body);
			AddRun(string.Concat("Signing Scenarios:\t", info.ScenarioCount.ToString(), "\r\n\r\n"), RunStyle.Body);

			AddRun("Rule Options\r\n", RunStyle.Header);
			if (info.RuleOptions.Count == 0)
			{
				AddRun("  (none)\r\n", RunStyle.Body);
			}
			else
			{
				foreach (string option in info.RuleOptions)
					AddRun(string.Concat("  \u2022 ", option, "\r\n"), RunStyle.Body);
			}
		}
		catch
		{
			_runs.Clear();
		}
	}

	// Reads all bytes from an IStream provided by the host.
	private static byte[] ReadAllFromStream(IStream stream)
	{
		const int chunkSize = 64 * 1024;
		using MemoryStream memoryStream = new();
		nint nativeBuffer = Marshal.AllocHGlobal(chunkSize);
		try
		{
			byte[] managedBuffer = new byte[chunkSize];
			while (true)
			{
				int hr = stream.Read(nativeBuffer, chunkSize, out uint bytesRead);
				if (bytesRead > 0)
				{
					int count = unchecked((int)bytesRead);
					Marshal.Copy(nativeBuffer, managedBuffer, 0, count);
					memoryStream.Write(managedBuffer, 0, count);
				}

				if (hr != HResults.S_OK || bytesRead == 0)
					break;
			}
		}
		finally
		{
			Marshal.FreeHGlobal(nativeBuffer);
		}

		return memoryStream.ToArray();
	}

	// Destroys the preview window. DestroyWindow synchronously sends WM_NCDESTROY on this same thread, and the window
	// procedure clears the managed handles and frees the strong GCHandle there. Safe to call repeatedly.
	private void DestroyPreviewWindow()
	{
		if (_hwnd != 0)
		{
			_ = NativeMethods.DestroyWindow(_hwnd);
			_hwnd = 0;
		}

		_editHwnd = 0;
	}
}
