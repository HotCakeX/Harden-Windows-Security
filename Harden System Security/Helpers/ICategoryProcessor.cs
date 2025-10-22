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
using System.Threading;
using System.Threading.Tasks;
using HardenSystemSecurity.DeviceIntents;
using HardenSystemSecurity.Protect;

namespace HardenSystemSecurity.Helpers;

/// <summary>
/// Interface that all category processors must implement for orchestrated operations.
/// </summary>
internal interface ICategoryProcessor
{
	/// <summary>
	/// Apply security measures for this category with optional sub-category filtering and optional device-intent filtering
	/// </summary>
	/// <param name="selectedSubCategories">Selected sub-categories to include (null or empty means include only MUnits without sub-category)</param>
	/// <param name="selectedIntent">Selected device intent to include (null means ignore intents)</param>
	/// <param name="cancellationToken">Cancellation token</param>
	/// <returns>Task representing the operation</returns>
	Task ApplyAllAsync(
		List<SubCategories>? selectedSubCategories = null,
		Intent? selectedIntent = null,
		CancellationToken? cancellationToken = null);

	/// <summary>
	/// Remove security measures for this category with optional sub-category filtering and optional device-intent filtering
	/// </summary>
	/// <param name="selectedSubCategories">Selected sub-categories to include (null or empty means include only MUnits without sub-category)</param>
	/// <param name="selectedIntent">Selected device intent to include (null means ignore intents)</param>
	/// <param name="cancellationToken">Cancellation token</param>
	/// <returns>Task representing the operation</returns>
	Task RemoveAllAsync(
		List<SubCategories>? selectedSubCategories = null,
		Intent? selectedIntent = null,
		CancellationToken? cancellationToken = null);

	/// <summary>
	/// Verify security measures for this category with optional sub-category filtering and optional device-intent filtering
	/// </summary>
	/// <param name="selectedSubCategories">Selected sub-categories to include (null or empty means include only MUnits without sub-category)</param>
	/// <param name="selectedIntent">Selected device intent to include (null means ignore intents)</param>
	/// <param name="cancellationToken">Cancellation token</param>
	/// <returns>Task representing the operation</returns>
	Task VerifyAllAsync(
		List<SubCategories>? selectedSubCategories = null,
		Intent? selectedIntent = null,
		CancellationToken? cancellationToken = null);

	/// <summary>
	/// The category this processor handles
	/// </summary>
	Categories Category { get; }

	/// <summary>
	/// Display name for this category
	/// </summary>
	string CategoryDisplayName { get; }
}
