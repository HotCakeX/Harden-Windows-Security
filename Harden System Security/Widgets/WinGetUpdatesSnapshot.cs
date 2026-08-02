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
using HardenSystemSecurity.WinGet;

namespace HardenSystemSecurity.Widgets;

/// <summary>
/// The stage that the WinGet update check of the App Updates widget is currently in.
/// </summary>
internal enum WinGetUpdatesState
{
	/// <summary>
	/// No update check has been performed yet, so the card only invites the user to start one.
	/// </summary>
	Idle,

	/// <summary>
	/// An update check is running right now.
	/// </summary>
	Checking,

	/// <summary>
	/// An update check finished and its result is displayed.
	/// </summary>
	Completed,

	/// <summary>
	/// An update check ended with an error, which the card displays instead of a result.
	/// </summary>
	Failed
}

/// <summary>
/// An immutable snapshot of everything that the App Updates widget displays.
///
/// A single snapshot is shared by every pinned instance of the widget because the available updates are a machine wide
/// piece of information that does not differ per widget.
/// </summary>
internal sealed class WinGetUpdatesSnapshot(WinGetUpdatesState state, IReadOnlyList<WinGetAvailableUpdate> updates, string errorMessage, DateTime completedAt)
{
	private static readonly List<WinGetAvailableUpdate> EmptyUpdates = [];
	internal WinGetUpdatesState State => state;

	/// <summary>
	/// The packages that have an update available. Only meaningful when <see cref="State"/> is <see cref="WinGetUpdatesState.Completed"/>.
	/// </summary>
	internal IReadOnlyList<WinGetAvailableUpdate> Updates => updates;

	/// <summary>
	/// The reason of the failure. Only meaningful when <see cref="State"/> is <see cref="WinGetUpdatesState.Failed"/>.
	/// </summary>
	internal string ErrorMessage => errorMessage;

	/// <summary>
	/// The local time at which the update check finished, used for the "Checked at" line of the card.
	/// </summary>
	internal DateTime CompletedAt => completedAt;

	/// <summary>
	/// The state that a freshly pinned widget starts in.
	/// </summary>
	internal static WinGetUpdatesSnapshot Idle { get; } = new(WinGetUpdatesState.Idle, EmptyUpdates, string.Empty, default);

	/// <summary>
	/// The state that the card switches to the moment the user presses the check button.
	/// </summary>
	internal static WinGetUpdatesSnapshot Checking { get; } = new(WinGetUpdatesState.Checking, EmptyUpdates, string.Empty, default);

	internal static WinGetUpdatesSnapshot FromUpdates(IReadOnlyList<WinGetAvailableUpdate> updates) =>
		new(WinGetUpdatesState.Completed, updates, string.Empty, DateTime.Now);

	internal static WinGetUpdatesSnapshot FromFailure(string errorMessage) =>
		new(WinGetUpdatesState.Failed, EmptyUpdates, errorMessage, DateTime.Now);
}
