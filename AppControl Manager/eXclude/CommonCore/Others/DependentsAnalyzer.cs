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
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel;

namespace CommonCore.Others;

/// <summary>
/// Performs the optional "what depends on this app" analysis.
/// This is intentionally kept out of the normal packaged apps enumeration path so that the apps list keeps loading at the same speed,
/// and it is only executed when the user explicitly asks for it through the UI.
///
/// The result comes from inverting the resolved dependency graph of every package, enumerated across all users of the machine.
/// An empty list means no other package currently resolves to this one. Dependencies taken at run time through the dynamic dependency
/// API are recorded outside package manifests and do not appear here.
/// </summary>
internal static class DependentsAnalyzer
{
	/// <summary>
	/// Runs the analysis and writes the dependents text into every supplied app.
	/// </summary>
	/// <param name="apps">Every app that is currently loaded in the list.</param>
	internal static async Task AnalyzeAsync(List<PackagedAppView> apps)
	{
		string[] composedDependents = new string[apps.Count];

		await Task.Run(() =>
		{
			Dictionary<string, List<string>> dependentsByFullName = BuildDependentsMap();

			for (int i = 0; i < apps.Count; i++)
			{
				composedDependents[i] = ComposeForApp(apps[i], dependentsByFullName);
			}
		});

		await ApplyComposedResultsAsync(apps, composedDependents);
	}

	/// <summary>
	/// Applies the composed results to every app on the UI thread.
	/// </summary>
	private static async Task ApplyComposedResultsAsync(List<PackagedAppView> apps, string[] composedDependents)
	{
		if (Atlas.AppDispatcher.HasThreadAccess)
		{
			ApplyComposedResults(apps, composedDependents);
			return;
		}

		TaskCompletionSource applyCompletionSource = new();

		bool enqueued = Atlas.AppDispatcher.TryEnqueue(() =>
		{
			try
			{
				ApplyComposedResults(apps, composedDependents);
				applyCompletionSource.SetResult();
			}
			catch (Exception ex)
			{
				// The exception is transferred to the awaiting caller so that it surfaces on the InfoBar instead of being swallowed
				// on the dispatcher thread.
				applyCompletionSource.SetException(ex);
			}
		});

		if (!enqueued)
		{
			throw new InvalidOperationException("The dependents analysis results could not be queued on the UI thread because the application dispatcher rejected the work item.");
		}

		await applyCompletionSource.Task;
	}

	/// <summary>
	/// Writes the composed results into every app. This must only ever run on the UI thread.
	/// </summary>
	private static void ApplyComposedResults(List<PackagedAppView> apps, string[] composedDependents)
	{
		for (int i = 0; i < apps.Count; i++)
		{
			apps[i].SetDependents(composedDependents[i]);
		}
	}

	/// <summary>
	/// Walks every package on the system once and inverts the declared dependency graph.
	/// The key is the full name of the package that is depended upon and the value is the display names of the packages that declare it.
	/// </summary>
	private static Dictionary<string, List<string>> BuildDependentsMap()
	{
		Dictionary<string, List<string>> dependentsByFullName = new(StringComparer.OrdinalIgnoreCase);

		IEnumerable<Package> allPackages;

		try
		{
			allPackages = GetAppsList.packageManager.FindPackages();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return dependentsByFullName;
		}

		foreach (Package package in allPackages)
		{
			try
			{
				string dependentDisplayName = GetPackageDisplayName(package);

				foreach (Package dependency in package.Dependencies)
				{
					ref List<string>? currentDependents = ref CollectionsMarshal.GetValueRefOrAddDefault(dependentsByFullName, dependency.Id.FullName, out _);

					currentDependents ??= [];
					currentDependents.Add(dependentDisplayName);
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		return dependentsByFullName;
	}

	/// <summary>
	/// Returns a display ready name for a package, falling back to the family name when the manifest declares no usable display name.
	/// </summary>
	private static string GetPackageDisplayName(Package package)
	{
		try
		{
			string displayName = package.DisplayName;
			if (!string.IsNullOrWhiteSpace(displayName))
			{
				return displayName;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		return package.Id.FamilyName;
	}

	/// <summary>
	/// Builds the dependents text for a single app, which is the list of the packages that declare a dependency on it.
	/// </summary>
	private static string ComposeForApp(PackagedAppView app, Dictionary<string, List<string>> dependentsByFullName)
	{
		if (!dependentsByFullName.TryGetValue(app.FullName, out List<string>? dependentDisplayNames) || dependentDisplayNames.Count == 0)
		{
			return Atlas.GetStr("NAText");
		}

		dependentDisplayNames.Sort(StringComparer.OrdinalIgnoreCase);

		StringBuilder builder = new();
		string previousDisplayName = string.Empty;

		foreach (string dependentDisplayName in CollectionsMarshal.AsSpan(dependentDisplayNames))
		{
			// Several architectures of the same app declare the same dependency, so repeated names are collapsed now that the list is
			// sorted, which keeps the section readable.
			if (string.Equals(previousDisplayName, dependentDisplayName, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			if (builder.Length > 0)
			{
				_ = builder.AppendLine();
			}

			_ = builder.Append(dependentDisplayName);
			previousDisplayName = dependentDisplayName;
		}

		return builder.ToString();
	}
}
