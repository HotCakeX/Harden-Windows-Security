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
using Microsoft.Management.Deployment;
using Microsoft.UI.Xaml;
using Windows.Foundation;

namespace HardenSystemSecurity.WinGet;

internal sealed partial class WinGetPackageSearchResult(CatalogPackage package) : ViewModelBase
{
	private const string UnavailableValue = "Unavailable";

	internal CatalogPackage Package { get; set; } = package;

	public string Id { get; set => SP(ref field, value); } = string.Empty;
	public string Name { get; set => SP(ref field, value); } = string.Empty;
	public string Version { get; set => SP(ref field, value); } = string.Empty;
	public string Publisher { get; set => SP(ref field, value); } = string.Empty;
	public string Source { get; set => SP(ref field, value); } = string.Empty;
	public string Description { get; set => SP(ref field, value); } = string.Empty;
	public string MatchField { get; set => SP(ref field, value); } = string.Empty;
	public string MatchValue { get; set => SP(ref field, value); } = string.Empty;
	public string Tags { get; set => SP(ref field, value); } = string.Empty;
	public string DocumentationUrls { get; set => SP(ref field, value); } = string.Empty;
	public string IconUrls { get; set => SP(ref field, value); } = string.Empty;
	public string License { get; set => SP(ref field, value); } = string.Empty;
	public string LicenseUrl { get; set => SP(ref field, value); } = string.Empty;
	public string PrivacyUrl { get; set => SP(ref field, value); } = string.Empty;
	public string PublisherUrl { get; set => SP(ref field, value); } = string.Empty;
	public string PublisherSupportUrl { get; set => SP(ref field, value); } = string.Empty;
	public string PackageUrl { get; set => SP(ref field, value); } = string.Empty;
	public string PurchaseUrl { get; set => SP(ref field, value); } = string.Empty;
	public string ReleaseNotes { get; set => SP(ref field, value); } = string.Empty;
	public string ReleaseNotesUrl { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerElevationRequirement { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerArchitecture { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerType { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerNestedType { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerScope { get; set => SP(ref field, value); } = string.Empty;
	public string InstallerLocale { get; set => SP(ref field, value); } = string.Empty;
	public string InstalledLocation { get; set => SP(ref field, value); } = string.Empty;
	public string StandardUninstallCommand { get; set => SP(ref field, value); } = string.Empty;
	public string SilentUninstallCommand { get; set => SP(ref field, value); } = string.Empty;
	public string PackageFamilyNames { get; set => SP(ref field, value); } = string.Empty;
	public string ProductCodes { get; set => SP(ref field, value); } = string.Empty;
	public string InstalledStatusCheck { get; set => SP(ref field, value); } = string.Empty;
	public string InstalledStatusDetails { get; set => SP(ref field, value); } = string.Empty;
	public bool WasLimitExceeded { get; set => SP(ref field, value); }
	public string InstallationNotes
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(HasInstallationNotes));
			}
		}
	} = string.Empty;

	public string InstalledVersion
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsInstalled));
				OnPropertyChanged(nameof(ActionButtonText));
				OnPropertyChanged(nameof(IsInstalledProgramActionButtonEnabled));
			}
		}
	} = string.Empty;

	// Local installed catalog results can be installed even when InstalledVersion is unavailable.
	public bool IsKnownInstalled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsInstalled));
				OnPropertyChanged(nameof(ActionButtonText));
				OnPropertyChanged(nameof(IsInstalledProgramActionButtonEnabled));
			}
		}
	}

	public bool IsUpdateAvailable
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(UpdateStatus));
				OnPropertyChanged(nameof(ActionButtonText));
				OnPropertyChanged(nameof(InstalledProgramActionButtonText));
			}
		}
	}

	internal bool IsPackageOperationRunning
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(IsPackageActionButtonEnabled));
				OnPropertyChanged(nameof(IsRefreshStatusButtonEnabled));
				OnPropertyChanged(nameof(IsInstalledProgramActionButtonEnabled));
				OnPropertyChanged(nameof(OperationProgressVisibility));
				OnPropertyChanged(nameof(PackageOperationProgressVisibility));
				OnPropertyChanged(nameof(IsPackageOperationCancellationAvailable));
				OnPropertyChanged(nameof(PackageOperationCancelButtonVisibility));
			}
		}
	}

	internal bool IsPackageOperationProgressIndeterminate { get; set => SP(ref field, value); }
	internal double PackageOperationProgress { get; set => SP(ref field, value); }
	private Action? cancelPackageOperationAction;
	internal bool IsPackageOperationCancellationRequested { get; private set; }

	internal string PackageOperationStatus
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(OperationProgressVisibility));
			}
		}
	} = string.Empty;

	// Treat the installed catalog signal as authoritative before falling back to the version string.
	public bool IsInstalled => IsKnownInstalled || (!string.Equals(InstalledVersion, UnavailableValue, StringComparison.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(InstalledVersion));
	public string UpdateStatus => IsUpdateAvailable ? "Update available" : "No update available";
	internal string ActionButtonText => IsInstalled ? (IsUpdateAvailable ? "Update" : "Reinstall") : "Install";
	internal string InstalledProgramActionButtonText => IsUpdateAvailable ? "Update" : "Reinstall";
	internal bool IsPackageActionButtonEnabled => !IsPackageOperationRunning;
	// Installed-program cards already come from the installed catalog, so action enablement should not depend on version metadata.
	internal bool IsInstalledProgramActionButtonEnabled => !IsPackageOperationRunning;
	internal bool IsRefreshStatusButtonEnabled => !IsPackageOperationRunning;
	internal bool IsPackageOperationCancellationAvailable => IsPackageOperationRunning && cancelPackageOperationAction is not null;
	internal bool HasInstallationNotes => !string.IsNullOrWhiteSpace(InstallationNotes);
	internal Visibility OperationProgressVisibility => IsPackageOperationRunning || !string.IsNullOrWhiteSpace(PackageOperationStatus) ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PackageOperationProgressVisibility => IsPackageOperationRunning ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PackageOperationCancelButtonVisibility => IsPackageOperationCancellationAvailable ? Visibility.Visible : Visibility.Collapsed;
	internal IReadOnlyList<WinGetPackageDetailItem> PackageDetails => CreatePackageDetails();

	internal void BeginPackageOperation(IAsyncInfo packageOperation)
	{
		IsPackageOperationCancellationRequested = false;
		cancelPackageOperationAction = packageOperation.Cancel;
		OnPropertyChanged(nameof(IsPackageOperationCancellationAvailable));
		OnPropertyChanged(nameof(PackageOperationCancelButtonVisibility));
	}

	internal void BeginPackageOperation(CancellationTokenSource cancellationTokenSource)
	{
		IsPackageOperationCancellationRequested = false;
		cancelPackageOperationAction = cancellationTokenSource.Cancel;
		OnPropertyChanged(nameof(IsPackageOperationCancellationAvailable));
		OnPropertyChanged(nameof(PackageOperationCancelButtonVisibility));
	}

	internal void CancelPackageOperation()
	{
		Action? cancelAction = cancelPackageOperationAction;
		if (cancelAction is null)
		{
			return;
		}

		IsPackageOperationCancellationRequested = true;
		PackageOperationStatus = "Canceling package operation.";

		try
		{
			cancelAction();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	internal void EndPackageOperation()
	{
		cancelPackageOperationAction = null;
		IsPackageOperationCancellationRequested = false;
		OnPropertyChanged(nameof(IsPackageOperationCancellationAvailable));
		OnPropertyChanged(nameof(PackageOperationCancelButtonVisibility));
	}

	internal void ApplyInstallerDetails(string elevationRequirement, string architecture, string installerType, string nestedInstallerType, string scope, string locale)
	{
		InstallerElevationRequirement = elevationRequirement;
		InstallerArchitecture = architecture;
		InstallerType = installerType;
		InstallerNestedType = nestedInstallerType;
		InstallerScope = scope;
		InstallerLocale = locale;
		OnPropertyChanged(nameof(PackageDetails));
	}

	internal void ApplyRefreshedState(WinGetPackageSearchResult refreshedResult)
	{
		Package = refreshedResult.Package;
		Version = refreshedResult.Version;
		Publisher = refreshedResult.Publisher;
		Source = refreshedResult.Source;
		Description = refreshedResult.Description;
		MatchField = refreshedResult.MatchField;
		MatchValue = refreshedResult.MatchValue;
		Tags = refreshedResult.Tags;
		DocumentationUrls = refreshedResult.DocumentationUrls;
		IconUrls = refreshedResult.IconUrls;
		License = refreshedResult.License;
		LicenseUrl = refreshedResult.LicenseUrl;
		PrivacyUrl = refreshedResult.PrivacyUrl;
		PublisherUrl = refreshedResult.PublisherUrl;
		PublisherSupportUrl = refreshedResult.PublisherSupportUrl;
		PackageUrl = refreshedResult.PackageUrl;
		PurchaseUrl = refreshedResult.PurchaseUrl;
		ReleaseNotes = refreshedResult.ReleaseNotes;
		ReleaseNotesUrl = refreshedResult.ReleaseNotesUrl;
		InstallerElevationRequirement = refreshedResult.InstallerElevationRequirement;
		InstallerArchitecture = refreshedResult.InstallerArchitecture;
		InstallerType = refreshedResult.InstallerType;
		InstallerNestedType = refreshedResult.InstallerNestedType;
		InstallerScope = refreshedResult.InstallerScope;
		InstallerLocale = refreshedResult.InstallerLocale;
		InstalledLocation = refreshedResult.InstalledLocation;
		StandardUninstallCommand = refreshedResult.StandardUninstallCommand;
		SilentUninstallCommand = refreshedResult.SilentUninstallCommand;
		PackageFamilyNames = refreshedResult.PackageFamilyNames;
		ProductCodes = refreshedResult.ProductCodes;
		InstalledStatusCheck = refreshedResult.InstalledStatusCheck;
		InstalledStatusDetails = refreshedResult.InstalledStatusDetails;
		WasLimitExceeded = refreshedResult.WasLimitExceeded;
		InstallationNotes = refreshedResult.InstallationNotes;
		IsKnownInstalled = refreshedResult.IsKnownInstalled;
		InstalledVersion = refreshedResult.InstalledVersion;
		IsUpdateAvailable = refreshedResult.IsUpdateAvailable;
		OnPropertyChanged(nameof(PackageDetails));
	}

	private List<WinGetPackageDetailItem> CreatePackageDetails()
	{
		List<WinGetPackageDetailItem> details = new(27);

		AddDetail(details, "Publisher", Publisher);
		AddDetail(details, "Match", GetMatchDescription());
		AddDetail(details, "Installed status check", InstalledStatusCheck);
		AddDetail(details, "Installed status details", InstalledStatusDetails);
		AddDetail(details, "Installer elevation", InstallerElevationRequirement);
		AddDetail(details, "Installer architecture", InstallerArchitecture);
		AddDetail(details, "Installer type", InstallerType);
		AddDetail(details, "Nested installer", InstallerNestedType);
		AddDetail(details, "Installer scope", InstallerScope);
		AddDetail(details, "Installer locale", InstallerLocale);
		AddDetail(details, "Installed location", InstalledLocation);
		AddDetail(details, "Standard uninstall command", StandardUninstallCommand);
		AddDetail(details, "Silent uninstall command", SilentUninstallCommand);
		AddDetail(details, "Package family names", PackageFamilyNames);
		AddDetail(details, "Product codes", ProductCodes);
		AddDetail(details, "Tags", Tags);
		AddDetail(details, "Documentation", DocumentationUrls);
		AddDetail(details, "Icons", IconUrls);
		AddDetail(details, "License", License);
		AddDetail(details, "License URL", LicenseUrl);
		AddDetail(details, "Privacy URL", PrivacyUrl);
		AddDetail(details, "Publisher URL", PublisherUrl);
		AddDetail(details, "Support URL", PublisherSupportUrl);
		AddDetail(details, "Package URL", PackageUrl);
		AddDetail(details, "Purchase URL", PurchaseUrl);
		AddDetail(details, "Release notes", ReleaseNotes);
		AddDetail(details, "Release notes URL", ReleaseNotesUrl);

		return details;
	}

	private string GetMatchDescription()
	{
		if (string.IsNullOrWhiteSpace(MatchValue) || string.Equals(MatchValue, UnavailableValue, StringComparison.OrdinalIgnoreCase))
		{
			return string.Empty;
		}

		return string.IsNullOrWhiteSpace(MatchField) || string.Equals(MatchField, UnavailableValue, StringComparison.OrdinalIgnoreCase)
			? MatchValue
			: $"{MatchField}: {MatchValue}";
	}

	private static void AddDetail(List<WinGetPackageDetailItem> details, string label, string value)
	{
		if (string.IsNullOrWhiteSpace(value) || string.Equals(value, UnavailableValue, StringComparison.OrdinalIgnoreCase))
		{
			return;
		}

		details.Add(new WinGetPackageDetailItem(label, value));
	}
}

internal sealed class WinGetPackageDetailItem(string label, string value)
{
	public string Label => label;
	public string Value => value;
}
