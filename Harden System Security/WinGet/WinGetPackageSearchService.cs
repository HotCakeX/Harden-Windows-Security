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
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Management.Deployment;
using Windows.Foundation;

namespace HardenSystemSecurity.WinGet;

internal enum WinGetPackageSearchField
{
	CatalogDefault,
	PackageId,
	Name,
	Moniker,
	Tag,
	Command
}

internal enum WinGetPackageSearchMatchMode
{
	ContainsCaseInsensitive,
	EqualsCaseInsensitive,
	EqualsCaseSensitive
}

internal static class WinGetPackageSearchService
{
	private const string UnknownExtendedErrorCode = "Unknown";
	internal const string UnavailableValue = "Unavailable";
	private const string DefaultPackageCatalogType = "Microsoft.PreIndexed.Package";
	internal const string MicrosoftStoreSourceName = "msstore";
	internal const string WinGetFontSourceName = "winget-font";
	// WinGet can return this no applicable repairer HRESULT with RepairError status instead of NoApplicableRepairer status.
	private const string NoApplicableRepairerExtendedErrorCode = "0x8A15007C";
	// WinGet can return this HRESULT when no installer matches the current device, source, or package metadata.
	private const string NoApplicableInstallerExtendedErrorCode = "0x8A150010";

	internal const int MaximumResultLimit = 100;

	internal static async Task<List<WinGetPackageSearchResult>> SearchAsync(string query, int resultLimit, WinGetPackageSearchField searchField, string sourceName, WinGetPackageSearchMatchMode searchMatchMode, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(query))
		{
			return [];
		}

		int effectiveResultLimit = Math.Clamp(resultLimit, 1, MaximumResultLimit);
		PackageManager packageManager = new();
		PackageCatalog catalog = await ConnectSearchCatalogAsync(packageManager, cancellationToken, CompositeSearchBehavior.RemotePackagesFromAllCatalogs, sourceName);

		FindPackagesResult findResult = await FindPackagesAsync(catalog, query.Trim(), effectiveResultLimit, searchField, searchMatchMode, cancellationToken);

		if (findResult.Status is not FindPackagesResultStatus.Ok)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "WinGet FindPackages failed with status {0}. Extended error: {1}.", findResult.Status, GetExtendedErrorCode(findResult)));
		}

		List<WinGetPackageSearchResult> results = new(Math.Min(findResult.Matches.Count, effectiveResultLimit));
		int matchCount = Math.Min(findResult.Matches.Count, effectiveResultLimit);
		for (int index = 0; index < matchCount; index++)
		{
			cancellationToken.ThrowIfCancellationRequested();

			MatchResult matchResult = findResult.Matches[index];
			results.Add(CreateSearchResult(matchResult, findResult.WasLimitExceeded));
		}

		return results;
	}

	internal static string GetWinGetEngineVersion()
	{
		try
		{
			PackageManager packageManager = new();
			return SafeString(packageManager.Version);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnavailableValue;
		}
	}

	internal static IAsyncOperationWithProgress<InstallResult, InstallProgress> InstallOrUpdatePackage(WinGetPackageSearchResult packageSearchResult, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, bool force)
	{
		InstallOptions installOptions = CreateInstallOptions(packageInstallMode, packageInstallScope, force);
		PackageManager packageManager = new();
		return packageSearchResult.IsUpdateAvailable
			? packageManager.UpgradePackageAsync(packageSearchResult.Package, installOptions)
			: packageManager.InstallPackageAsync(packageSearchResult.Package, installOptions);
	}

	internal static IAsyncOperationWithProgress<UninstallResult, UninstallProgress> UninstallPackage(WinGetPackageSearchResult packageSearchResult, PackageUninstallMode packageUninstallMode, PackageUninstallScope packageUninstallScope)
	{
		UninstallOptions uninstallOptions = new()
		{
			PackageUninstallMode = packageUninstallMode,
			PackageUninstallScope = packageUninstallScope
		};

		PackageManager packageManager = new();
		return packageManager.UninstallPackageAsync(packageSearchResult.Package, uninstallOptions);
	}

	internal static IAsyncOperationWithProgress<DownloadResult, PackageDownloadProgress> DownloadPackage(WinGetPackageSearchResult packageSearchResult, string downloadDirectory)
	{
		DownloadOptions downloadOptions = new()
		{
			DownloadDirectory = downloadDirectory,
			Scope = PackageInstallScope.Any,
			AcceptPackageAgreements = true
		};

		PackageManager packageManager = new();
		return packageManager.DownloadPackageAsync(packageSearchResult.Package, downloadOptions);
	}

	internal static IAsyncOperationWithProgress<RepairResult, RepairProgress> RepairPackage(WinGetPackageSearchResult packageSearchResult)
	{
		RepairOptions repairOptions = new()
		{
			PackageRepairMode = PackageRepairMode.Silent,
			PackageRepairScope = PackageRepairScope.Any,
			AcceptPackageAgreements = true
		};

		PackageManager packageManager = new();
		return packageManager.RepairPackageAsync(packageSearchResult.Package, repairOptions);
	}

	internal static IReadOnlyList<string> GetPackageAgreements(WinGetPackageSearchResult packageSearchResult)
	{
		PackageVersionInfo? defaultVersion = GetDefaultInstallVersion(packageSearchResult.Package);
		CatalogPackageMetadata? metadata = GetCatalogPackageMetadata(defaultVersion);
		if (metadata is null)
		{
			return [];
		}

		try
		{
			IReadOnlyList<PackageAgreement> agreements = metadata.Agreements;
			List<string> result = new(agreements.Count);
			for (int index = 0; index < agreements.Count; index++)
			{
				PackageAgreement agreement = agreements[index];
				string label = SafeString(agreement.Label);
				string text = SafeString(agreement.Text);
				string url = SafeString(agreement.Url);

				List<string> lines = [];
				if (!string.Equals(label, UnavailableValue, StringComparison.OrdinalIgnoreCase))
				{
					lines.Add(label);
				}

				if (!string.Equals(text, UnavailableValue, StringComparison.OrdinalIgnoreCase))
				{
					lines.Add(text);
				}

				if (!string.Equals(url, UnavailableValue, StringComparison.OrdinalIgnoreCase))
				{
					lines.Add(url);
				}

				if (lines.Count > 0)
				{
					result.Add(string.Join(Environment.NewLine, lines));
				}
			}

			return result;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return [];
		}
	}

	internal static async Task<List<WinGetPackageSearchResult>> GetInstalledProgramsAsync(CancellationToken cancellationToken)
	{
		PackageManager packageManager = new();
		PackageCatalogReference installedCatalogReference = packageManager.GetLocalPackageCatalog(LocalPackageCatalog.InstalledPackages);
		PackageCatalog catalog = await ConnectCatalogAsync(installedCatalogReference, cancellationToken);
		FindPackagesResult findResult = await FindInstalledPackagesAsync(catalog, cancellationToken);

		if (findResult.Status is not FindPackagesResultStatus.Ok)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "WinGet installed program query failed with status {0}. Extended error: {1}.", findResult.Status, GetExtendedErrorCode(findResult)));
		}

		List<WinGetPackageSearchResult> results = new(findResult.Matches.Count);
		for (int index = 0; index < findResult.Matches.Count; index++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			// Items returned by the local installed catalog are known installed even when WinGet cannot report a concrete version.
			results.Add(CreateSearchResult(findResult.Matches[index], findResult.WasLimitExceeded, true));
		}

		return results;
	}

	internal static IReadOnlyList<WinGetSourceInfo> GetSources()
	{
		PackageManager packageManager = new();
		IReadOnlyList<PackageCatalogReference> catalogReferences = packageManager.GetPackageCatalogs();
		List<WinGetSourceInfo> sources = new(catalogReferences.Count);

		for (int index = 0; index < catalogReferences.Count; index++)
		{
			PackageCatalogReference catalogReference = catalogReferences[index];
			sources.Add(CreateSourceInfo(catalogReference));
		}

		return sources;
	}

	internal static IAsyncOperationWithProgress<AddPackageCatalogResult, double> AddSource(string name, string sourceUri, string type, PackageCatalogTrustLevel trustLevel)
	{
		AddPackageCatalogOptions addOptions = new()
		{
			Name = name.Trim(),
			SourceUri = sourceUri.Trim(),
			Type = string.IsNullOrWhiteSpace(type) ? DefaultPackageCatalogType : type.Trim(),
			TrustLevel = trustLevel
		};

		PackageManager packageManager = new();
		return packageManager.AddPackageCatalogAsync(addOptions);
	}

	internal static IAsyncOperationWithProgress<RemovePackageCatalogResult, double> RemoveSource(string name)
	{
		RemovePackageCatalogOptions removeOptions = new()
		{
			Name = name.Trim(),
			PreserveData = false
		};

		PackageManager packageManager = new();
		return packageManager.RemovePackageCatalogAsync(removeOptions);
	}

	internal static IAsyncOperationWithProgress<RefreshPackageCatalogResult, double> UpdateSource(WinGetSourceInfo sourceInfo) => sourceInfo.CatalogReference.RefreshPackageCatalogAsync();

	internal static async Task<WinGetPackageSearchResult?> ResolvePackageByIdAsync(string packageId, string sourceName, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(packageId))
		{
			return null;
		}

		PackageManager packageManager = new();
		string trimmedSourceName = string.IsNullOrWhiteSpace(sourceName) ? string.Empty : sourceName.Trim();
		PackageCatalog catalog = await ConnectSearchCatalogAsync(packageManager, cancellationToken, CompositeSearchBehavior.RemotePackagesFromAllCatalogs, trimmedSourceName);
		return await FindFirstPackageByIdResultAsync(catalog, packageId.Trim(), trimmedSourceName, false, "WinGet FindPackages failed", cancellationToken);
	}

	internal static async Task<WinGetPackageSearchResult?> ResolveInstalledPackageByIdAsync(string packageId, string sourceName, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(packageId))
		{
			return null;
		}

		// Uninstall needs the installed package identity, not the remote source listing, especially for Microsoft Store apps.
		PackageManager packageManager = new();
		string trimmedPackageId = packageId.Trim();
		string trimmedSourceName = string.IsNullOrWhiteSpace(sourceName) ? string.Empty : sourceName.Trim();
		PackageCatalog catalog = await ConnectInstalledPackageCatalogAsync(packageManager, trimmedSourceName, cancellationToken);
		WinGetPackageSearchResult? installedPackageSearchResult = await FindFirstPackageByIdResultAsync(catalog, trimmedPackageId, trimmedSourceName, true, "WinGet installed package lookup failed", cancellationToken);
		if (installedPackageSearchResult is not null || !string.IsNullOrWhiteSpace(trimmedSourceName))
		{
			return installedPackageSearchResult;
		}

		// Some WinGet packages can be correlated to their remote package ID even when the raw installed catalog uses a different local identity.
		// This keeps bundle uninstall from skipping packages after they were installed from a remote WinGet source.
		WinGetPackageSearchResult? remotePackageSearchResult = await ResolvePackageByIdAsync(trimmedPackageId, string.Empty, cancellationToken);
		// The remote resolver also finds packages that are only available to install, so require the installed signal before uninstall can continue.
		return remotePackageSearchResult?.IsInstalled is true ? remotePackageSearchResult : null;
	}

	private static async Task<PackageCatalog> ConnectInstalledPackageCatalogAsync(PackageManager packageManager, string sourceName, CancellationToken cancellationToken)
	{
		if (string.IsNullOrWhiteSpace(sourceName))
		{
			PackageCatalogReference installedCatalogReference = packageManager.GetLocalPackageCatalog(LocalPackageCatalog.InstalledPackages);
			return await ConnectCatalogAsync(installedCatalogReference, cancellationToken);
		}

		// A Microsoft Store product ID only correlates to an installed package through a composite that searches local catalogs against the store source. The installed catalog is implicit here and must not be added explicitly, otherwise FindPackages reports InvalidOptions.
		PackageCatalogReference remoteCatalogReference = GetPackageCatalogReferenceByName(packageManager, sourceName);
		TryAcceptSourceAgreements(remoteCatalogReference);
		CreateCompositePackageCatalogOptions compositeOptions = new() { CompositeSearchBehavior = CompositeSearchBehavior.LocalCatalogs };
		compositeOptions.Catalogs.Add(remoteCatalogReference);
		PackageCatalogReference compositeReference = packageManager.CreateCompositePackageCatalog(compositeOptions);
		cancellationToken.ThrowIfCancellationRequested();
		return await ConnectCatalogAsync(compositeReference, cancellationToken);
	}

	internal static async Task<WinGetPackageSearchResult?> RefreshPackageStatusAsync(WinGetPackageSearchResult packageSearchResult, CancellationToken cancellationToken)
	{
		PackageManager packageManager = new();
		// Preserve the original source only when it still resolves to a configured package catalog. Local, stale, or removed source names must not block refresh.
		string sourceName = GetPackageRefreshSourceName(packageSearchResult);
		PackageCatalog catalog = await ConnectPackageRefreshCatalogAsync(packageManager, sourceName, cancellationToken);
		return await FindFirstPackageByIdResultAsync(catalog, packageSearchResult.Id, sourceName, false, "WinGet FindPackages failed", cancellationToken);
	}

	private static async Task<WinGetPackageSearchResult?> FindFirstPackageByIdResultAsync(PackageCatalog catalog, string packageId, string sourceName, bool isKnownInstalled, string failureMessage, CancellationToken cancellationToken)
	{
		// Keep package ID result handling shared so installed and remote lookups report failures consistently.
		FindPackagesResult findResult = await FindPackageByIdAsync(catalog, packageId, sourceName, cancellationToken);
		if (findResult.Status is not FindPackagesResultStatus.Ok)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "{0} with status {1}. Extended error: {2}.", failureMessage, findResult.Status, GetExtendedErrorCode(findResult)));
		}
		if (findResult.Matches.Count is 0)
		{
			return null;
		}

		cancellationToken.ThrowIfCancellationRequested();
		return CreateSearchResult(findResult.Matches[0], findResult.WasLimitExceeded, isKnownInstalled);
	}

	internal static string GetInstallResultError(InstallResult installResult) => string.Format(CultureInfo.InvariantCulture, "WinGet install returned status {0}. Extended error: {1}. Installer error: {2}.", installResult.Status, GetExtendedErrorCode(installResult), installResult.InstallerErrorCode);
	internal static string GetNoApplicableInstallInstallerMessage() => "WinGet could not find an applicable installer for this package on the current device. This can happen when the installed app is not available from a configured WinGet source, or when no installer matches the current architecture, scope, locale, OS version, or installer type.";
	internal static bool TryGetFriendlyInstallFailureMessage(InstallResult installResult, [NotNullWhen(true)] out string? friendlyMessage)
	{
		string? statusSpecificMessage = installResult.Status switch
		{
			InstallResultStatus.Ok => null,
			InstallResultStatus.BlockedByPolicy => "The installation was blocked by policy. Check Windows Package Manager, Microsoft Store, Intune, or Group Policy settings that might prevent this app from being installed.",
			InstallResultStatus.CatalogError => "WinGet could not access the package catalog for this app. Refresh the WinGet sources and verify that the package source is available.",
			InstallResultStatus.InternalError => string.Equals(GetExtendedErrorCode(installResult), "0x80070652", StringComparison.OrdinalIgnoreCase)
				? "Another installation is already in progress. Finish or cancel the other Windows Installer, Microsoft Store, or Windows Update operation, restart the PC if needed, and then try again."
				: "WinGet encountered an internal error while preparing the installation. Try again, and if the issue persists restart the PC or refresh App Installer and Microsoft Store.",
			InstallResultStatus.InvalidOptions => "The requested install options are not valid for this package. Try a different install mode or scope, or reset the package options and retry.",
			InstallResultStatus.DownloadError => "WinGet could not download the installer or package content. Check the network connection, proxy, firewall, and package source availability, then try again.",
			InstallResultStatus.InstallError => "The installer was downloaded but the installation step failed. Close any setup dialogs, ensure no other installer is running, and then try again.",
			InstallResultStatus.ManifestError => "The package metadata is invalid or incomplete. Refresh the package status or try again after the package manifest is corrected upstream.",
			InstallResultStatus.NoApplicableInstallers => GetNoApplicableInstallInstallerMessage(),
			InstallResultStatus.NoApplicableUpgrade => "No applicable upgrade is available for this package on the current device. The installed version may already be current, or no upgrade matches this device configuration.",
			InstallResultStatus.PackageAgreementsNotAccepted => "The package requires license or agreement acceptance before installation can continue. Accept the package agreements and then try again.",
			_ => null
		};

		if (string.IsNullOrWhiteSpace(statusSpecificMessage))
		{
			friendlyMessage = null;
			return false;
		}

		friendlyMessage = string.Format(CultureInfo.InvariantCulture, "{0} Details: {1}", statusSpecificMessage, GetInstallResultError(installResult));
		return true;
	}

	private static string GetPackageRefreshSourceName(WinGetPackageSearchResult packageSearchResult) =>
		string.IsNullOrWhiteSpace(packageSearchResult.Source) || string.Equals(packageSearchResult.Source, UnavailableValue, StringComparison.OrdinalIgnoreCase)
			? string.Empty
			: packageSearchResult.Source.Trim();

	private static async Task<PackageCatalog> ConnectSearchCatalogAsync(PackageManager packageManager, CancellationToken cancellationToken, CompositeSearchBehavior compositeSearchBehavior = CompositeSearchBehavior.RemotePackagesFromAllCatalogs, string sourceName = "")
	{
		if (!string.IsNullOrWhiteSpace(sourceName))
		{
			PackageCatalogReference sourceCatalogReference = GetPackageCatalogReferenceByName(packageManager, sourceName);
			return await ConnectCatalogAsync(sourceCatalogReference, cancellationToken);
		}

		CreateCompositePackageCatalogOptions compositeOptions = new()
		{
			CompositeSearchBehavior = compositeSearchBehavior
		};

		IReadOnlyList<PackageCatalogReference> catalogReferences = packageManager.GetPackageCatalogs();
		for (int index = 0; index < catalogReferences.Count; index++)
		{
			PackageCatalogReference catalogReference = catalogReferences[index];
			TryAcceptSourceAgreements(catalogReference);
			compositeOptions.Catalogs.Add(catalogReference);
		}

		if (compositeOptions.Catalogs.Count is 0)
		{
			PackageCatalogReference openWindowsCatalogReference = packageManager.GetPredefinedPackageCatalog(PredefinedPackageCatalog.OpenWindowsCatalog);
			PackageCatalogReference microsoftStoreCatalogReference = packageManager.GetPredefinedPackageCatalog(PredefinedPackageCatalog.MicrosoftStore);
			TryAcceptSourceAgreements(openWindowsCatalogReference);
			TryAcceptSourceAgreements(microsoftStoreCatalogReference);
			compositeOptions.Catalogs.Add(openWindowsCatalogReference);
			compositeOptions.Catalogs.Add(microsoftStoreCatalogReference);

			try
			{
				PackageCatalogReference openWindowsCatalogFontReference = packageManager.GetPredefinedPackageCatalog(PredefinedPackageCatalog.OpenWindowsCatalogFont);
				TryAcceptSourceAgreements(openWindowsCatalogFontReference);
				compositeOptions.Catalogs.Add(openWindowsCatalogFontReference);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		PackageCatalogReference compositeReference = packageManager.CreateCompositePackageCatalog(compositeOptions);
		cancellationToken.ThrowIfCancellationRequested();

		return await ConnectCatalogAsync(compositeReference, cancellationToken);
	}

	private static PackageCatalogReference GetPackageCatalogReferenceByName(PackageManager packageManager, string sourceName)
	{
		if (TryGetPackageCatalogReferenceByName(packageManager, sourceName, out PackageCatalogReference? catalogReference))
		{
			return catalogReference;
		}

		if (string.Equals(sourceName.Trim(), WinGetFontSourceName, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "WinGet font source '{0}' was not found. Install or update Windows Package Manager to a version with font source support, then reset or update WinGet sources.", WinGetFontSourceName));
		}

		throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "WinGet source '{0}' was not found.", sourceName));
	}

	private static bool TryGetPackageCatalogReferenceByName(PackageManager packageManager, string sourceName, [NotNullWhen(true)] out PackageCatalogReference? catalogReference)
	{
		catalogReference = null;
		string trimmedSourceName = sourceName.Trim();
		if (string.IsNullOrWhiteSpace(trimmedSourceName))
		{
			return false;
		}

		IReadOnlyList<PackageCatalogReference> catalogReferences = packageManager.GetPackageCatalogs();
		for (int index = 0; index < catalogReferences.Count; index++)
		{
			PackageCatalogReference currentCatalogReference = catalogReferences[index];
			PackageCatalogInfo? catalogInfo = GetCatalogInfo(currentCatalogReference);
			if (string.Equals(catalogInfo?.Name, trimmedSourceName, StringComparison.OrdinalIgnoreCase))
			{
				catalogReference = currentCatalogReference;
				return true;
			}
		}

		return false;
	}

	private static async Task<PackageCatalog> ConnectPackageRefreshCatalogAsync(PackageManager packageManager, string sourceName, CancellationToken cancellationToken)
	{
		if (TryGetPackageCatalogReferenceByName(packageManager, sourceName, out PackageCatalogReference? sourceCatalogReference))
		{
			return await ConnectCatalogAsync(sourceCatalogReference, cancellationToken);
		}

		return await ConnectSearchCatalogAsync(packageManager, cancellationToken, CompositeSearchBehavior.AllCatalogs);
	}

	private static async Task<PackageCatalog> ConnectCatalogAsync(PackageCatalogReference catalogReference, CancellationToken cancellationToken)
	{
		TryAcceptSourceAgreements(catalogReference);

		cancellationToken.ThrowIfCancellationRequested();
		ConnectResult connectResult = await AwaitCancellableOperationAsync(catalogReference.ConnectAsync(), cancellationToken);
		if (connectResult.Status is not ConnectResultStatus.Ok)
		{
			throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, "WinGet source connection failed with status {0}. Extended error: {1}.", connectResult.Status, GetExtendedErrorCode(connectResult)));
		}

		return connectResult.PackageCatalog;
	}

	private static void TryAcceptSourceAgreements(PackageCatalogReference catalogReference)
	{
		try
		{
			if (!catalogReference.IsComposite)
			{
				catalogReference.AcceptSourceAgreements = true;
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static async Task<FindPackagesResult> FindPackagesAsync(PackageCatalog catalog, string query, int resultLimit, WinGetPackageSearchField searchField, WinGetPackageSearchMatchMode searchMatchMode, CancellationToken cancellationToken)
	{
		FindPackagesOptions findOptions = new()
		{
			ResultLimit = (uint)resultLimit
		};

		findOptions.Selectors.Add(new PackageMatchFilter { Field = GetPackageMatchField(searchField), Option = GetPackageMatchOption(searchMatchMode), Value = query });

		cancellationToken.ThrowIfCancellationRequested();
		return await AwaitCancellableOperationAsync(catalog.FindPackagesAsync(findOptions), cancellationToken);
	}

	private static PackageMatchField GetPackageMatchField(WinGetPackageSearchField searchField) => searchField switch
	{
		WinGetPackageSearchField.PackageId => PackageMatchField.Id,
		WinGetPackageSearchField.Name => PackageMatchField.Name,
		WinGetPackageSearchField.Moniker => PackageMatchField.Moniker,
		WinGetPackageSearchField.Tag => PackageMatchField.Tag,
		WinGetPackageSearchField.Command => PackageMatchField.Command,
		_ => PackageMatchField.CatalogDefault
	};

	private static PackageFieldMatchOption GetPackageMatchOption(WinGetPackageSearchMatchMode searchMatchMode) => searchMatchMode switch
	{
		WinGetPackageSearchMatchMode.EqualsCaseInsensitive => PackageFieldMatchOption.EqualsCaseInsensitive,
		WinGetPackageSearchMatchMode.EqualsCaseSensitive => PackageFieldMatchOption.Equals,
		_ => PackageFieldMatchOption.ContainsCaseInsensitive
	};

	private static async Task<FindPackagesResult> FindPackageByIdAsync(PackageCatalog catalog, string packageId, string sourceName, CancellationToken cancellationToken)
	{
		PackageFieldMatchOption matchOption = string.Equals(sourceName, MicrosoftStoreSourceName, StringComparison.OrdinalIgnoreCase)
			? PackageFieldMatchOption.Equals
			: PackageFieldMatchOption.EqualsCaseInsensitive;

		FindPackagesOptions findOptions = new()
		{
			ResultLimit = 1
		};

		findOptions.Selectors.Add(new PackageMatchFilter { Field = PackageMatchField.Id, Option = matchOption, Value = packageId });

		cancellationToken.ThrowIfCancellationRequested();
		return await AwaitCancellableOperationAsync(catalog.FindPackagesAsync(findOptions), cancellationToken);
	}

	private static async Task<FindPackagesResult> FindInstalledPackagesAsync(PackageCatalog catalog, CancellationToken cancellationToken)
	{
		FindPackagesOptions findOptions = new();
		cancellationToken.ThrowIfCancellationRequested();
		return await AwaitCancellableOperationAsync(catalog.FindPackagesAsync(findOptions), cancellationToken);
	}

	private static async Task<TResult> AwaitCancellableOperationAsync<TResult>(IAsyncOperation<TResult> operation, CancellationToken cancellationToken)
	{
		using CancellationTokenRegistration registration = cancellationToken.Register(static state =>
		{
			try
			{
				((IAsyncInfo)state!).Cancel();
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}, operation);

		try
		{
			return await operation;
		}
		catch (Exception ex) when (cancellationToken.IsCancellationRequested)
		{
			throw new OperationCanceledException("The WinGet operation was canceled.", ex, cancellationToken);
		}
	}

	// isKnownInstalled preserves the local catalog signal when InstalledVersion is unavailable.
	private static WinGetPackageSearchResult CreateSearchResult(MatchResult matchResult, bool wasLimitExceeded, bool isKnownInstalled = false)
	{
		CatalogPackage package = matchResult.CatalogPackage;
		PackageVersionInfo? defaultVersion = GetDefaultInstallVersion(package);
		PackageVersionInfo? installedVersion = GetInstalledVersion(package);
		CatalogPackageMetadata? metadata = GetCatalogPackageMetadata(defaultVersion);
		PackageInstallerInfo? installerInfo = GetApplicableInstaller(defaultVersion, PackageInstallMode.Default, PackageInstallScope.Any, false);
		CheckInstalledStatusResult? installedStatusResult = GetInstalledStatus(package);

		return new WinGetPackageSearchResult(package)
		{
			Id = SafeString(package.Id),
			Name = SafeString(package.Name),
			Version = SafeString(defaultVersion?.Version),
			Publisher = SafeString(defaultVersion?.Publisher, metadata?.Publisher),
			Source = SafeString(defaultVersion?.PackageCatalog?.Info?.Name),
			Description = SafeString(metadata?.ShortDescription, metadata?.Description),
			MatchField = SafeString(matchResult.MatchCriteria?.Field.ToString()),
			MatchValue = SafeString(matchResult.MatchCriteria?.Value),
			Tags = JoinStrings(GetTags(metadata)),
			DocumentationUrls = JoinStrings(GetDocumentations(metadata)),
			IconUrls = JoinStrings(GetIcons(metadata)),
			License = SafeOptionalString(metadata?.License),
			LicenseUrl = SafeOptionalString(metadata?.LicenseUrl),
			PrivacyUrl = SafeOptionalString(metadata?.PrivacyUrl),
			PublisherUrl = SafeOptionalString(metadata?.PublisherUrl),
			PublisherSupportUrl = SafeOptionalString(metadata?.PublisherSupportUrl),
			PackageUrl = SafeOptionalString(metadata?.PackageUrl),
			PurchaseUrl = SafeOptionalString(metadata?.PurchaseUrl),
			ReleaseNotes = SafeOptionalString(metadata?.ReleaseNotes),
			ReleaseNotesUrl = SafeOptionalString(metadata?.ReleaseNotesUrl),
			InstallerElevationRequirement = SafeString(installerInfo?.ElevationRequirement.ToString()),
			InstallerArchitecture = SafeString(installerInfo?.Architecture.ToString()),
			InstallerType = SafeString(installerInfo?.InstallerType.ToString()),
			InstallerNestedType = SafeString(installerInfo?.NestedInstallerType.ToString()),
			InstallerScope = SafeString(installerInfo?.Scope.ToString()),
			InstallerLocale = SafeOptionalString(installerInfo?.Locale),
			InstalledLocation = SafeOptionalString(GetMetadata(installedVersion, PackageVersionMetadataField.InstalledLocation)),
			StandardUninstallCommand = SafeOptionalString(GetMetadata(installedVersion, PackageVersionMetadataField.StandardUninstallCommand)),
			SilentUninstallCommand = SafeOptionalString(GetMetadata(installedVersion, PackageVersionMetadataField.SilentUninstallCommand)),
			PackageFamilyNames = JoinStrings(GetPackageFamilyNames(defaultVersion, installedVersion)),
			ProductCodes = JoinStrings(GetProductCodes(defaultVersion, installedVersion)),
			InstalledStatusCheck = SafeString(installedStatusResult?.Status.ToString()),
			InstalledStatusDetails = JoinStrings(GetInstalledStatusDetails(installedStatusResult)),
			WasLimitExceeded = wasLimitExceeded,
			InstallationNotes = SafeOptionalString(metadata?.InstallationNotes),
			InstalledVersion = SafeString(installedVersion?.Version),
			IsUpdateAvailable = GetIsUpdateAvailable(package),
			IsKnownInstalled = isKnownInstalled
		};
	}

	private static PackageVersionInfo? GetDefaultInstallVersion(CatalogPackage package)
	{
		try
		{
			return package.DefaultInstallVersion;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static PackageVersionInfo? GetInstalledVersion(CatalogPackage package)
	{
		try
		{
			return package.InstalledVersion;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static CatalogPackageMetadata? GetCatalogPackageMetadata(PackageVersionInfo? packageVersionInfo)
	{
		if (packageVersionInfo is null)
		{
			return null;
		}

		try
		{
			return packageVersionInfo.GetCatalogPackageMetadata();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	internal static void ApplyApplicableInstallerDetails(WinGetPackageSearchResult packageSearchResult, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, bool force)
	{
		PackageVersionInfo? defaultVersion = GetDefaultInstallVersion(packageSearchResult.Package);
		PackageInstallerInfo? installerInfo = GetApplicableInstaller(defaultVersion, packageInstallMode, packageInstallScope, force);
		packageSearchResult.ApplyInstallerDetails(
			SafeString(installerInfo?.ElevationRequirement.ToString()),
			SafeString(installerInfo?.Architecture.ToString()),
			SafeString(installerInfo?.InstallerType.ToString()),
			SafeString(installerInfo?.NestedInstallerType.ToString()),
			SafeString(installerInfo?.Scope.ToString()),
			SafeOptionalString(installerInfo?.Locale));
	}

	private static PackageInstallerInfo? GetApplicableInstaller(PackageVersionInfo? packageVersionInfo, PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, bool force)
	{
		if (packageVersionInfo is null)
		{
			return null;
		}

		try
		{
			InstallOptions installOptions = CreateInstallOptions(packageInstallMode, packageInstallScope, force);
			return packageVersionInfo.GetApplicableInstaller(installOptions);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static InstallOptions CreateInstallOptions(PackageInstallMode packageInstallMode, PackageInstallScope packageInstallScope, bool force) => new()
	{
		PackageInstallMode = packageInstallMode,
		PackageInstallScope = packageInstallScope,
		Force = force,
		AcceptPackageAgreements = true
	};

	private static CheckInstalledStatusResult? GetInstalledStatus(CatalogPackage package)
	{
		try
		{
			return package.CheckInstalledStatus(InstalledStatusType.AllChecks);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static string? GetMetadata(PackageVersionInfo? packageVersionInfo, PackageVersionMetadataField metadataField)
	{
		if (packageVersionInfo is null)
		{
			return null;
		}

		try
		{
			return packageVersionInfo.GetMetadata(metadataField);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static bool GetIsUpdateAvailable(CatalogPackage package)
	{
		try
		{
			return package.IsUpdateAvailable;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	private static string GetExtendedErrorCode(FindPackagesResult findPackagesResult)
	{
		try
		{
			return $"0x{findPackagesResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(ConnectResult connectResult)
	{
		try
		{
			return $"0x{connectResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(InstallResult installResult)
	{
		try
		{
			return $"0x{installResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	internal static string GetUninstallResultError(UninstallResult uninstallResult) => string.Format(CultureInfo.InvariantCulture, "WinGet uninstall returned status {0}. Extended error: {1}. Uninstaller error: {2}.", uninstallResult.Status, GetExtendedErrorCode(uninstallResult), uninstallResult.UninstallerErrorCode);

	internal static string GetDownloadResultError(DownloadResult downloadResult) => string.Format(CultureInfo.InvariantCulture, "WinGet download returned status {0}. Extended error: {1}.", downloadResult.Status, GetExtendedErrorCode(downloadResult));
	internal static bool IsNoApplicableDownloadInstallerResult(DownloadResult downloadResult) => downloadResult.Status is DownloadResultStatus.NoApplicableInstallers || string.Equals(GetExtendedErrorCode(downloadResult), NoApplicableInstallerExtendedErrorCode, StringComparison.OrdinalIgnoreCase);
	internal static string GetNoApplicableDownloadInstallerMessage() => "WinGet could not find a downloadable installer for this package on the current device. This can happen when the installed app is not available from a configured WinGet source, or when no installer matches the current architecture, scope, locale, OS version, or installer type.";

	internal static string GetRepairResultError(RepairResult repairResult) => string.Format(CultureInfo.InvariantCulture, "WinGet repair returned status {0}. Extended error: {1}. Repairer error: {2}.", repairResult.Status, GetExtendedErrorCode(repairResult), repairResult.RepairerErrorCode);
	internal static bool IsNoApplicableRepairerResult(RepairResult repairResult) => repairResult.Status is RepairResultStatus.NoApplicableRepairer || string.Equals(GetExtendedErrorCode(repairResult), NoApplicableRepairerExtendedErrorCode, StringComparison.OrdinalIgnoreCase);

	internal static string GetAddSourceResultError(AddPackageCatalogResult addResult) => string.Format(CultureInfo.InvariantCulture, "WinGet source add returned status {0}. Extended error: {1}.", addResult.Status, GetExtendedErrorCode(addResult));

	internal static string GetRemoveSourceResultError(RemovePackageCatalogResult removeResult) => string.Format(CultureInfo.InvariantCulture, "WinGet source remove returned status {0}. Extended error: {1}.", removeResult.Status, GetExtendedErrorCode(removeResult));

	internal static string GetUpdateSourceResultError(RefreshPackageCatalogResult refreshResult) => string.Format(CultureInfo.InvariantCulture, "WinGet source update returned status {0}. Extended error: {1}.", refreshResult.Status, GetExtendedErrorCode(refreshResult));

	private static string GetExtendedErrorCode(UninstallResult uninstallResult)
	{
		try
		{
			return $"0x{uninstallResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(DownloadResult downloadResult)
	{
		try
		{
			return $"0x{downloadResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(RepairResult repairResult)
	{
		try
		{
			return $"0x{repairResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(AddPackageCatalogResult addResult)
	{
		try
		{
			return $"0x{addResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(RemovePackageCatalogResult removeResult)
	{
		try
		{
			return $"0x{removeResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(RefreshPackageCatalogResult refreshResult)
	{
		try
		{
			return $"0x{refreshResult.ExtendedErrorCode.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static string GetExtendedErrorCode(Exception? exception)
	{
		if (exception is null)
		{
			return "Ok";
		}

		try
		{
			return $"0x{exception.HResult:X8}";
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return UnknownExtendedErrorCode;
		}
	}

	private static WinGetSourceInfo CreateSourceInfo(PackageCatalogReference catalogReference)
	{
		PackageCatalogInfo? catalogInfo = GetCatalogInfo(catalogReference);
		return new WinGetSourceInfo
		{
			CatalogReference = catalogReference,
			Name = SafeString(catalogInfo?.Name),
			Type = SafeString(catalogInfo?.Type),
			Argument = SafeString(catalogInfo?.Argument),
			Origin = SafeString(catalogInfo?.Origin.ToString()),
			TrustLevel = SafeString(catalogInfo?.TrustLevel.ToString())
		};
	}

	private static PackageCatalogInfo? GetCatalogInfo(PackageCatalogReference catalogReference)
	{
		try
		{
			return catalogReference.Info;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
	}

	private static IReadOnlyList<string> GetTags(CatalogPackageMetadata? metadata)
	{
		if (metadata is null)
		{
			return [];
		}

		try
		{
			return metadata.Tags;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return [];
		}
	}

	private static List<string> GetDocumentations(CatalogPackageMetadata? metadata)
	{
		if (metadata is null)
		{
			return [];
		}

		try
		{
			IReadOnlyList<Documentation> documentations = metadata.Documentations;
			List<string> results = new(documentations.Count);
			for (int index = 0; index < documentations.Count; index++)
			{
				Documentation documentation = documentations[index];
				string documentLabel = SafeOptionalString(documentation.DocumentLabel);
				string documentUrl = SafeOptionalString(documentation.DocumentUrl);
				if (!string.IsNullOrWhiteSpace(documentLabel) && !string.IsNullOrWhiteSpace(documentUrl))
				{
					results.Add($"{documentLabel}: {documentUrl}");
				}
				else if (!string.IsNullOrWhiteSpace(documentUrl))
				{
					results.Add(documentUrl);
				}
				else if (!string.IsNullOrWhiteSpace(documentLabel))
				{
					results.Add(documentLabel);
				}
			}

			return results;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return [];
		}
	}

	private static List<string> GetIcons(CatalogPackageMetadata? metadata)
	{
		if (metadata is null)
		{
			return [];
		}

		try
		{
			IReadOnlyList<Icon> icons = metadata.Icons;
			List<string> results = new(icons.Count);
			for (int index = 0; index < icons.Count; index++)
			{
				Icon icon = icons[index];
				string iconUrl = SafeOptionalString(icon.Url);
				if (string.IsNullOrWhiteSpace(iconUrl))
				{
					continue;
				}

				results.Add(string.Format(CultureInfo.InvariantCulture, "{0} {1} {2}: {3}", icon.FileType, icon.Resolution, icon.Theme, iconUrl));
			}

			return results;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return [];
		}
	}

	private static List<string> GetPackageFamilyNames(PackageVersionInfo? defaultVersion, PackageVersionInfo? installedVersion) => GetDistinctPackageVersionValues(defaultVersion, installedVersion, static packageVersionInfo => packageVersionInfo.PackageFamilyNames);

	private static List<string> GetProductCodes(PackageVersionInfo? defaultVersion, PackageVersionInfo? installedVersion) => GetDistinctPackageVersionValues(defaultVersion, installedVersion, static packageVersionInfo => packageVersionInfo.ProductCodes);

	private static List<string> GetDistinctPackageVersionValues(PackageVersionInfo? defaultVersion, PackageVersionInfo? installedVersion, Func<PackageVersionInfo, IReadOnlyList<string>> valueSelector)
	{
		List<string> results = [];
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
		AddPackageVersionValues(results, seen, installedVersion, valueSelector);
		AddPackageVersionValues(results, seen, defaultVersion, valueSelector);
		return results;
	}

	private static void AddPackageVersionValues(List<string> results, HashSet<string> seen, PackageVersionInfo? packageVersionInfo, Func<PackageVersionInfo, IReadOnlyList<string>> valueSelector)
	{
		if (packageVersionInfo is null)
		{
			return;
		}

		try
		{
			IReadOnlyList<string> values = valueSelector(packageVersionInfo);
			for (int index = 0; index < values.Count; index++)
			{
				string value = values[index];
				if (!string.IsNullOrWhiteSpace(value) && seen.Add(value))
				{
					results.Add(value);
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	private static List<string> GetInstalledStatusDetails(CheckInstalledStatusResult? installedStatusResult)
	{
		if (installedStatusResult is null)
		{
			return [];
		}

		try
		{
			IReadOnlyList<PackageInstallerInstalledStatus> packageInstalledStatuses = installedStatusResult.PackageInstalledStatus;
			List<string> results = [];
			for (int packageStatusIndex = 0; packageStatusIndex < packageInstalledStatuses.Count; packageStatusIndex++)
			{
				PackageInstallerInstalledStatus packageInstalledStatus = packageInstalledStatuses[packageStatusIndex];
				string installerDescription = GetInstallerDescription(packageInstalledStatus.InstallerInfo);
				IReadOnlyList<InstalledStatus> installerInstalledStatuses = packageInstalledStatus.InstallerInstalledStatus;
				for (int statusIndex = 0; statusIndex < installerInstalledStatuses.Count; statusIndex++)
				{
					InstalledStatus installedStatus = installerInstalledStatuses[statusIndex];
					string statusCode = GetExtendedErrorCode(installedStatus.Status);
					string statusPath = SafeOptionalString(installedStatus.Path);
					string detail = string.IsNullOrWhiteSpace(statusPath)
						? string.Format(CultureInfo.InvariantCulture, "{0}: {1}", installedStatus.Type, statusCode)
						: string.Format(CultureInfo.InvariantCulture, "{0}: {1} ({2})", installedStatus.Type, statusPath, statusCode);

					results.Add(string.IsNullOrWhiteSpace(installerDescription) ? detail : $"{installerDescription} - {detail}");
				}
			}

			return results;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return [];
		}
	}

	private static string GetInstallerDescription(PackageInstallerInfo? installerInfo)
	{
		if (installerInfo is null)
		{
			return string.Empty;
		}

		return string.Format(CultureInfo.InvariantCulture, "{0}/{1}/{2}", installerInfo.InstallerType, installerInfo.Scope, installerInfo.Architecture);
	}

	private static string JoinStrings(IReadOnlyList<string> values)
	{
		StringBuilder stringBuilder = new();
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
		for (int index = 0; index < values.Count; index++)
		{
			string value = values[index];
			if (string.IsNullOrWhiteSpace(value) || !seen.Add(value))
			{
				continue;
			}

			if (stringBuilder.Length > 0)
			{
				_ = stringBuilder.Append("; ");
			}

			_ = stringBuilder.Append(value);
		}

		return stringBuilder.ToString();
	}

	private static string SafeString(params string?[] values)
	{
		foreach (string? value in values)
		{
			if (!string.IsNullOrWhiteSpace(value))
			{
				return value;
			}
		}

		return UnavailableValue;
	}

	private static string SafeOptionalString(string? value) => string.IsNullOrWhiteSpace(value) ? string.Empty : value;
}
