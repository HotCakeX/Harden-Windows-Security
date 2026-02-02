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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using AnimatedVisuals;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : ViewModelBase, IDisposable
{
	/// <summary>
	/// Semaphore to synchronize access to the Policies Library cache on disk.
	/// Used by startup restoration and encryption toggle operations.
	/// </summary>
	internal readonly SemaphoreSlim PoliciesLibraryCacheLock = new(1, 1);

	public void Dispose()
	{
		PoliciesLibraryCacheLock.Dispose();
	}

	/// <summary>
	/// Collection that is the Master List, containing the policies in the Library.
	/// </summary>
	internal readonly UniquePolicyFileRepresentObservableCollection SidebarPoliciesLibrary = [];

	/// <summary>
	/// Collection bound to the UI, representing the filtered version of <see cref="SidebarPoliciesLibrary"/>.
	/// </summary>
	internal readonly ObservableCollection<PolicyFileRepresent> FilteredSidebarPolicies = [];

	/// <summary>
	/// The text used to filter the sidebar policies library.
	/// </summary>
	internal string? SidebarSearchText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				PerformSidebarSearch();
			}
		}
	}

	/// <summary>
	/// Filters the policies based on the search text.
	/// </summary>
	private void PerformSidebarSearch()
	{
		FilteredSidebarPolicies.Clear();

		if (string.IsNullOrWhiteSpace(SidebarSearchText))
		{
			// If search is empty, add all items
			foreach (PolicyFileRepresent policy in SidebarPoliciesLibrary)
			{
				FilteredSidebarPolicies.Add(policy);
			}
		}
		else
		{
			// Filter items
			foreach (PolicyFileRepresent policy in SidebarPoliciesLibrary)
			{
				if (policy.PolicyIdentifier.Contains(SidebarSearchText, StringComparison.OrdinalIgnoreCase) ||
					(policy.FileName is not null && policy.FileName.Contains(SidebarSearchText, StringComparison.OrdinalIgnoreCase)) ||
					policy.SigningStatus.Contains(SidebarSearchText, StringComparison.OrdinalIgnoreCase)
					)
				{
					FilteredSidebarPolicies.Add(policy);
				}
			}
		}
	}

	/// <summary>
	/// Pages that are allowed to run when running without Administrator privileges
	/// </summary>
	internal List<Type> UnelevatedPages = [
		typeof(Pages.ValidatePolicy),
		typeof(Pages.GitHubDocumentation),
		typeof(Pages.MicrosoftDocumentation),
		typeof(Pages.Logs),
		typeof(Pages.GetCIHashes),
		typeof(Pages.PolicyEditor),
		typeof(Pages.MergePolicies),
		typeof(Pages.Settings),
		typeof(Pages.ConfigurePolicyRuleOptions),
		typeof(Pages.ViewFileCertificates),
		typeof(Pages.Home),
		typeof(Pages.CreatePolicy),
		typeof(Pages.MDEAHPolicyCreation),
		typeof(Pages.MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage),
		typeof(Pages.IntuneDeploymentDetails),
		typeof(Pages.EventLogsPolicyCreation),
		typeof(Pages.CreateDenyPolicy),
		typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults),
		typeof(Pages.CreateSupplementalPolicy),
		typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults),
		typeof(Pages.StrictKernelPolicyScanResults),
		typeof(Pages.Simulation),
		typeof(Pages.GetSecurePolicySettings)
		];


	internal void RebuildBreadcrumbMappings()
	{
		breadCrumbMappingsV2.Clear();

		breadCrumbMappingsV2[typeof(Pages.CreatePolicy)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreatePolicyNavItem/Content")],
			pages: [typeof(Pages.CreatePolicy)]
		);

		breadCrumbMappingsV2[typeof(Pages.GetCIHashes)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("GetCodeIntegrityHashesNavItem/Content")],
			pages: [typeof(Pages.GetCIHashes)]
		);

		breadCrumbMappingsV2[typeof(Pages.GitHubDocumentation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("GitHubDocsNavItem/Content")],
			pages: [typeof(Pages.GitHubDocumentation)]
		);

		breadCrumbMappingsV2[typeof(Pages.MicrosoftDocumentation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MSFTDocsNavItem/Content")],
			pages: [typeof(Pages.MicrosoftDocumentation)]
		);

		breadCrumbMappingsV2[typeof(Pages.GetSecurePolicySettings)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("GetSecurePolicySettingsNavItem/Content")],
			pages: [typeof(Pages.GetSecurePolicySettings)]
		);

		breadCrumbMappingsV2[typeof(Pages.Settings)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("SettingsNavItemContent")],
			pages: [typeof(Pages.Settings)]
		);

		breadCrumbMappingsV2[typeof(Pages.SystemInformation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("SystemInformationNavItem/Content")],
			pages: [typeof(Pages.SystemInformation)]
		);

		breadCrumbMappingsV2[typeof(Pages.ConfigurePolicyRuleOptions)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ConfigurePolicyRuleOptionsNavItem/Content")],
			pages: [typeof(Pages.ConfigurePolicyRuleOptions)]
		);

		breadCrumbMappingsV2[typeof(Pages.Logs)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("LogsNavItem/Content")],
			pages: [typeof(Pages.Logs)]
		);

		breadCrumbMappingsV2[typeof(Pages.Simulation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("SimulationNavItem/Content")],
			pages: [typeof(Pages.Simulation)]
		);

		breadCrumbMappingsV2[typeof(Pages.UpdatePage)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("UpdateNavItem/Content"), GlobalVars.GetStr("UpdatePageCustomMSIXPath")],
			pages: [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		);

		breadCrumbMappingsV2[typeof(Pages.UpdatePageCustomMSIXPath)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("UpdateNavItem/Content"), GlobalVars.GetStr("UpdatePageCustomMSIXPath")],
			pages: [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		);

		breadCrumbMappingsV2[typeof(Pages.DeploymentPage)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("DeploymentNavItem/Content"), GlobalVars.GetStr("IntuneDeploymentDetailsNavItemContent")],
			pages: [typeof(Pages.DeploymentPage), typeof(Pages.IntuneDeploymentDetails)]
		);

		breadCrumbMappingsV2[typeof(Pages.IntuneDeploymentDetails)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("DeploymentNavItem/Content"), GlobalVars.GetStr("IntuneDeploymentDetailsNavItemContent")],
			pages: [typeof(Pages.DeploymentPage), typeof(Pages.IntuneDeploymentDetails)]
		);

		breadCrumbMappingsV2[typeof(Pages.EventLogsPolicyCreation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreatePolicyFromEventLogsNavItem/Content")],
			pages: [typeof(Pages.EventLogsPolicyCreation)]
		);

		breadCrumbMappingsV2[typeof(Pages.MDEAHPolicyCreation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreatePolicyFromMDEAHNavItem/Content")],
			pages: [typeof(Pages.MDEAHPolicyCreation)]
		);

		breadCrumbMappingsV2[typeof(Pages.AllowNewApps)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("AllowNewAppsNavItem/Content")],
			pages: [typeof(Pages.AllowNewApps)]
		);

		breadCrumbMappingsV2[typeof(Pages.BuildNewCertificate)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("BuildNewCertificateNavItem/Content")],
			pages: [typeof(Pages.BuildNewCertificate)]
		);

		breadCrumbMappingsV2[typeof(Pages.MergePolicies)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MergePoliciesNavItem/Content")],
			pages: [typeof(Pages.MergePolicies)]
		);

		breadCrumbMappingsV2[typeof(Pages.CreateSupplementalPolicy)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreateSupplementalPolicyNavItem/Content"), GlobalVars.GetStr("ScanResults")],
			pages: [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		);

		breadCrumbMappingsV2[typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreateSupplementalPolicyNavItem/Content"), GlobalVars.GetStr("ScanResults")],
			pages: [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		);

		breadCrumbMappingsV2[typeof(Pages.StrictKernelPolicyScanResults)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreateSupplementalPolicyNavItem/Content"), GlobalVars.GetStr("ScanResults")],
			pages: [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.StrictKernelPolicyScanResults)]
		);

		breadCrumbMappingsV2[typeof(Pages.CreateDenyPolicy)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreateDenyPolicyNavItem/Content"), GlobalVars.GetStr("ScanResults")],
			pages: [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		);

		breadCrumbMappingsV2[typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CreateDenyPolicyNavItem/Content"), GlobalVars.GetStr("ScanResults")],
			pages: [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		);

		breadCrumbMappingsV2[typeof(Pages.ValidatePolicy)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ValidatePoliciesNavItem/Content")],
			pages: [typeof(Pages.ValidatePolicy)]
		);

		breadCrumbMappingsV2[typeof(Pages.ViewFileCertificates)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ViewFileCertificatesNavItem/Content")],
			pages: [typeof(Pages.ViewFileCertificates)]
		);

		breadCrumbMappingsV2[typeof(Pages.PolicyEditor)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("PolicyEditorNavItem/Content")],
			pages: [typeof(Pages.PolicyEditor)]
		);

		breadCrumbMappingsV2[typeof(Pages.Home)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("HomeNavItem/Content")],
			pages: [typeof(Pages.Home)]
		);
	}

	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	internal readonly ObservableCollection<Crumb> Breadcrumbs = [new Crumb(GlobalVars.GetStr("HomeNavItem/Content"), typeof(Pages.Home))];

	/// <summary>
	/// Dictionary of all the main pages in the app, used for the main navigation.
	/// Keys are the Navigation Item tags (non-localized) and values are the page types.
	/// </summary>
	internal readonly FrozenDictionary<string, Type> NavigationPageToItemContentMap = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
	{
		{ "CreatePolicy", typeof(Pages.CreatePolicy) },
		{ "GetCodeIntegrityHashes", typeof(Pages.GetCIHashes) },
		{ "GitHubDocs", typeof(Pages.GitHubDocumentation) },
		{ "MSFTDocs", typeof(Pages.MicrosoftDocumentation) },
		{ "GetSecurePolicySettings", typeof(Pages.GetSecurePolicySettings) },
		{ "Settings", typeof(Pages.Settings) },
		{ "SystemInformation", typeof(Pages.SystemInformation) },
		{ "ConfigurePolicyRuleOptions", typeof(Pages.ConfigurePolicyRuleOptions) },
		{ "Logs", typeof(Pages.Logs) },
		{ "Simulation", typeof(Pages.Simulation) },
		{ "Deployment", typeof(Pages.DeploymentPage) },
		{ "CreatePolicyFromEventLogs", typeof(Pages.EventLogsPolicyCreation) },
		{ "CreatePolicyFromMDEAH", typeof(Pages.MDEAHPolicyCreation) },
		{ "AllowNewApps", typeof(Pages.AllowNewApps) },
		{ "BuildNewCertificate", typeof(Pages.BuildNewCertificate) },
		{ "CreateSupplementalPolicy", typeof(Pages.CreateSupplementalPolicy) },
		{ "MergePolicies", typeof(Pages.MergePolicies) },
		{ "CreateDenyPolicy", typeof(Pages.CreateDenyPolicy) },
		{ "ValidatePolicies", typeof(Pages.ValidatePolicy) },
		{ "ViewFileCertificates", typeof(Pages.ViewFileCertificates) },
		{ "PolicyEditor", typeof(Pages.PolicyEditor) },
		{ "Update", typeof(Pages.UpdatePage) },
		{ "Home", typeof(Pages.Home) }
	}.ToFrozenDictionary<string, Type>(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Dictionary of all the pages in the app, used for the search bar.
	/// Keys are page header contents which are localized and values are page types.
	/// </summary>
	internal readonly Dictionary<string, Type> NavigationPageToItemContentMapForSearch = [];

	internal void RebuildNavigationPageToItemContentMapForSearch()
	{
		NavigationPageToItemContentMapForSearch.Clear();

		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CreatePolicyNavItem/Content")] = typeof(Pages.CreatePolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CreateSupplementalPolicyNavItem/Content")] = typeof(Pages.CreateSupplementalPolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ScanResults")] = typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ScanResults")] = typeof(Pages.StrictKernelPolicyScanResults);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CreateDenyPolicyNavItem/Content")] = typeof(Pages.CreateDenyPolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ScanResults")] = typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("BuildNewCertificateNavItem/Content")] = typeof(Pages.BuildNewCertificate);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ViewFileCertificatesNavItem/Content")] = typeof(Pages.ViewFileCertificates);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CreatePolicyFromEventLogsNavItem/Content")] = typeof(Pages.EventLogsPolicyCreation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CreatePolicyFromMDEAHNavItem/Content")] = typeof(Pages.MDEAHPolicyCreation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("AllowNewAppsNavItem/Content")] = typeof(Pages.AllowNewApps);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("GetCodeIntegrityHashesNavItem/Content")] = typeof(Pages.GetCIHashes);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("GitHubDocsNavItem/Content")] = typeof(Pages.GitHubDocumentation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("MSFTDocsNavItem/Content")] = typeof(Pages.MicrosoftDocumentation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("GetSecurePolicySettingsNavItem/Content")] = typeof(Pages.GetSecurePolicySettings);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("SettingsNavItemContent")] = typeof(Pages.Settings);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("SystemInformationNavItem/Content")] = typeof(Pages.SystemInformation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ConfigurePolicyRuleOptionsNavItem/Content")] = typeof(Pages.ConfigurePolicyRuleOptions);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("LogsNavItem/Content")] = typeof(Pages.Logs);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("SimulationNavItem/Content")] = typeof(Pages.Simulation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("DeploymentNavItem/Content")] = typeof(Pages.DeploymentPage);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("MergePoliciesNavItem/Content")] = typeof(Pages.MergePolicies);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ValidatePoliciesNavItem/Content")] = typeof(Pages.ValidatePolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("PolicyEditorNavItem/Content")] = typeof(Pages.PolicyEditor);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("UpdateNavItem/Content")] = typeof(Pages.UpdatePage);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("UpdatePageCustomMSIXPath")] = typeof(Pages.UpdatePageCustomMSIXPath);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("HomeNavItem/Content")] = typeof(Pages.Home);
	}

	/// <summary>
	/// Constructor initializes the ViewModel and subscribes to various events, sets initial values of some variables.
	/// </summary>
	internal MainWindowVM()
	{
		RebuildBreadcrumbMappings();
		RebuildNavigationPageToItemContentMapForSearch();

		// Subscribe to the collection changed event to update visibility and maintain the filtered list
		SidebarPoliciesLibrary.CollectionChanged += (s, e) =>
		{
			UpdateSidebarVisibilities();
			PerformSidebarSearch();
		};

		// Initial visibility update
		UpdateSidebarVisibilities();

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		AppUpdate.UpdateAvailable += OnUpdateAvailable!;

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();

		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Subscribe to encryption setting changes
		App.Settings.EncryptPoliciesLibraryChanged += (s, e) => OnEncryptPoliciesLibraryChanged(e);

		// If the App is installed from the Microsoft Store source
		// Then make the update page available for non-elevated usage.
		if (App.PackageSource is 1)
			UnelevatedPages.Add(typeof(Pages.UpdatePage));

		// If Persistent library is enabled, populate the policies library on the Sidebar with the local cache content
		// Fire and forget since this runs at startup and we can't let it slow us down
		if (AppSettings.PersistentPoliciesLibrary)
		{
			_ = Task.Run(async () =>
			{
				await PoliciesLibraryCacheLock.WaitAsync();
				try
				{
					// Get all of the files in the cache first
					IEnumerable<string> currentFiles = Directory.EnumerateFiles(SidebarPoliciesLibraryCache);

					foreach (string file in currentFiles)
					{
						try
						{
							string uniqueID = Path.GetFileNameWithoutExtension(file);

							byte[] fileBytes = await File.ReadAllBytesAsync(file);
							bool isFileEncrypted = false;
							byte[]? decryptedBytes = null;
							byte[]? plainContentForParsing = null;

							// Try to decrypt the file content to check its state
							try
							{
								decryptedBytes = ProtectedData.Unprotect(fileBytes, PoliciesLibraryEntropyBytes, AppSettings.EncryptionScopePoliciesLibrary ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
								isFileEncrypted = true;
							}
							catch (CryptographicException)
							{
								isFileEncrypted = false;
							}

							// Ensure the file on disk matches the 'shouldEncrypt' setting.

							// Setting: Encrypt
							if (AppSettings.EncryptPoliciesLibrary)
							{
								if (isFileEncrypted)
								{
									// Setting: Encrypt
									// File: Encrypted.
									// We use decrypted bytes for parsing.
									plainContentForParsing = decryptedBytes;
								}
								else
								{
									// Setting: Encrypt
									// File: Plain.
									// We must encrypt the file on disk.
									// The current file is plain text, so 'fileBytes' is the policy content.
									try
									{
										byte[] encrypted = ProtectedData.Protect(fileBytes, PoliciesLibraryEntropyBytes, AppSettings.EncryptionScopePoliciesLibrary ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
										await File.WriteAllBytesAsync(file, encrypted);
									}
									catch (Exception ex)
									{
										MainInfoBar.WriteError(ex, $"Failed to enforce encryption on startup for {file}");
									}

									// We use original file bytes for parsing since they were plain text.
									plainContentForParsing = fileBytes;
								}
							}
							else
							{
								// Setting: Decrypt (Plain)
								if (isFileEncrypted)
								{
									// Setting: Plain
									// File: Encrypted.
									// We must decrypt the file on disk.
									try
									{
										await File.WriteAllBytesAsync(file, decryptedBytes!);
									}
									catch (Exception ex)
									{
										MainInfoBar.WriteError(ex, $"Failed to enforce decryption on startup for {file}");
									}

									// Use decrypted bytes for parsing.
									plainContentForParsing = decryptedBytes;
								}
								else
								{
									// Setting: Plain
									// File: Plain.
									// Load directly.
									plainContentForParsing = fileBytes;
								}
							}

							// Create XML doc from the file's bytes
							XmlDocument xmlDocument = new();
							using MemoryStream stream = new(plainContentForParsing!);
							xmlDocument.Load(stream);

							PolicyFileRepresent policyToAdd = new(Management.Initialize(null, xmlDocument))
							{
								UniqueObjID = Guid.Parse(uniqueID)
							};

							_ = Dispatcher.TryEnqueue(() =>
							{
								SidebarPoliciesLibrary.Add(policyToAdd);
							});
						}
						catch (Exception ex)
						{
							MainInfoBar.WriteError(ex);
						}
					}
				}
				catch (Exception ex)
				{
					MainInfoBar.WriteError(ex);
				}
				finally
				{
					_ = PoliciesLibraryCacheLock.Release();
				}
			});
		}
	}

	/// <summary>
	/// Local cache of the Sidebar's policies library where policies are kept for persistence.
	/// </summary>
	internal static readonly string SidebarPoliciesLibraryCache = Directory.CreateDirectory(Path.Combine(Microsoft.Windows.Storage.ApplicationData.GetDefault().LocalCachePath, "PoliciesLibraryCache")).FullName;

	/// <summary>
	/// Visibility for the ItemsRepeater in the sidebar
	/// </summary>
	internal Visibility SidebarRepeaterVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	/// <summary>
	/// Visibility for the Shimmer effect in the sidebar
	/// </summary>
	internal Visibility SidebarShimmerVisibility { get; set => SP(ref field, value); } = Visibility.Visible;

	/// <summary>
	/// Updates the visibility of the sidebar elements based on the number of items in the library.
	/// </summary>
	private void UpdateSidebarVisibilities()
	{
		if (SidebarPoliciesLibrary.Count > 0)
		{
			SidebarRepeaterVisibility = Visibility.Visible;
			SidebarShimmerVisibility = Visibility.Collapsed;
		}
		else
		{
			SidebarRepeaterVisibility = Visibility.Collapsed;
			SidebarShimmerVisibility = Visibility.Visible;
		}
	}

	#region UI-Bound Properties

	/// <summary>
	/// Icon for the Create Policy navigation item.
	/// </summary>
	internal IconElement? CreatePolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Supplemental Policy navigation item.
	/// </summary>
	internal IconElement? CreateSupplementalPolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Deny Policy navigation item.
	/// </summary>
	internal IconElement? CreateDenyPolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Build New Certificate navigation item.
	/// </summary>
	internal IconElement? BuildNewCertificateIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the View File Certificates navigation item.
	/// </summary>
	internal IconElement? ViewFileCertificatesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Policy from Event Logs navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromEventLogsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the MDE Advanced Hunting navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromMDEAHIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Allow New Apps navigation item.
	/// </summary>
	internal IconElement? AllowNewAppsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Policy Editor navigation item.
	/// </summary>
	internal IconElement? PolicyEditorIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Simulation navigation item.
	/// </summary>
	internal IconElement? SimulationIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the System Information navigation item.
	/// </summary>
	internal IconElement? SystemInformationIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Get Code Integrity Hashes navigation item.
	/// </summary>
	internal IconElement? GetCodeIntegrityHashesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Get Secure Policy Settings navigation item.
	/// </summary>
	internal IconElement? GetSecurePolicySettingsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Configure Policy Rule Options navigation item.
	/// </summary>
	internal IconElement? ConfigurePolicyRuleOptionsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Merge Policies navigation item.
	/// </summary>
	internal IconElement? MergePoliciesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Deployment navigation item.
	/// </summary>
	internal IconElement? DeploymentIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Validate Policies navigation item.
	/// </summary>
	internal IconElement? ValidatePoliciesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the GitHub Documentation navigation item.
	/// </summary>
	internal IconElement? GitHubDocsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Microsoft Documentation navigation item.
	/// </summary>
	internal IconElement? MSFTDocsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Logs navigation item.
	/// </summary>
	internal IconElement? LogsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Update navigation item in the footer.
	/// </summary>
	internal IconElement? UpdateIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Home navigation item.
	/// </summary>
	internal IconElement? HomeIcon { get; set => SP(ref field, value); }

	#endregion

	/// <summary>
	/// Additional Entropy used for data encryption/decryption of the Policies Library files.
	/// Must always remain the same.
	/// </summary>
	private static readonly byte[] PoliciesLibraryEntropyBytes = Encoding.UTF8.GetBytes("HotCakeX");

	/// <summary>
	/// The only method used to add new policies to the Sidebar's Policies Library.
	/// </summary>
	/// <param name="policy"></param>
	internal async void AssignToSidebar(SiPolicy.PolicyFileRepresent policy)
	{
		await PoliciesLibraryCacheLock.WaitAsync();
		try
		{
			_ = Dispatcher.TryEnqueue(() =>
			{
				SidebarPoliciesLibrary.Add(policy);
			});

			// If the library should be persistent
			if (AppSettings.PersistentPoliciesLibrary)
			{
				await Task.Run(() =>
				{
					string filePath = Path.Combine(SidebarPoliciesLibraryCache, $"{policy.UniqueObjID}.xml");

					XmlDocument xmlObj = CustomSerialization.CreateXmlFromSiPolicy(policy.PolicyObj);

					using MemoryStream memoryStream = new();

					XmlWriterSettings settings = new()
					{
						Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
						Indent = true
					};

					using (XmlWriter xmlWriter = XmlWriter.Create(memoryStream, settings))
					{
						xmlObj.Save(xmlWriter);
					}

					if (AppSettings.EncryptPoliciesLibrary)
					{
						try
						{
							byte[] enc = ProtectedData.Protect(memoryStream.ToArray(), PoliciesLibraryEntropyBytes, AppSettings.EncryptionScopePoliciesLibrary ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
							File.WriteAllBytes(filePath, enc);
						}
						catch (Exception ex)
						{
							MainInfoBar.WriteError(ex, $"Error encrypting policy {policy.UniqueObjID}");
						}
					}
					else
					{
						File.WriteAllBytes(filePath, memoryStream.ToArray());
					}
				});
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			_ = PoliciesLibraryCacheLock.Release();
		}
	}

	/// <summary>
	/// Handles the change event for the EncryptPoliciesLibrary setting.
	/// Converts existing cache files between encrypted and plain text formats.
	/// </summary>
	/// <param name="shouldEncrypt"></param>
	private async void OnEncryptPoliciesLibraryChanged(bool shouldEncrypt)
	{
		await PoliciesLibraryCacheLock.WaitAsync();
		try
		{
			await Task.Run(() =>
			{
				// Enumerate all files in the cache directory
				IEnumerable<string> files = Directory.EnumerateFiles(SidebarPoliciesLibraryCache);
				foreach (string file in files)
				{
					try
					{
						byte[] currentBytes = File.ReadAllBytes(file);
						byte[] plainBytes;
						bool isEncrypted = false;

						// Determine if the file is currently encrypted by attempting to decrypt it
						try
						{
							plainBytes = ProtectedData.Unprotect(currentBytes, PoliciesLibraryEntropyBytes, AppSettings.EncryptionScopePoliciesLibrary ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
							isEncrypted = true;
						}
						catch (CryptographicException)
						{
							// If decryption fails, assume the file is plain text
							plainBytes = currentBytes;
							isEncrypted = false;
						}

						// Encrypt if requested and currently plain text
						if (shouldEncrypt && !isEncrypted)
						{
							byte[] encrypted = ProtectedData.Protect(plainBytes, PoliciesLibraryEntropyBytes, AppSettings.EncryptionScopePoliciesLibrary ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine);
							File.WriteAllBytes(file, encrypted);
						}
						// Decrypt if requested (toggle off) and currently encrypted
						else if (!shouldEncrypt && isEncrypted)
						{
							File.WriteAllBytes(file, plainBytes);
						}
					}
					catch (Exception ex)
					{
						MainInfoBar.WriteError(ex, $"Error processing file {file} during encryption toggle.");
					}
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, "Error enumerating files during encryption toggle.");
		}
		finally
		{
			_ = PoliciesLibraryCacheLock.Release();
		}
	}

	/// <summary>
	/// Event handler for the global Icons Style change event
	/// </summary>
	/// <param name="style"></param>
	internal void OnIconsStylesChanged(string? style)
	{
		if (MainWindow.RootGridPub is null) throw new InvalidOperationException("RootGrid is null");

		// Get the current theme from the RootGrid or another element.
		ElementTheme currentTheme = MainWindow.RootGridPub.ActualTheme;

		switch (style)
		{
			case "Animated":
				{
					CreatePolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(-10, -35, -35, -35),
						Source = new Blueprint()
					};

					SystemInformationIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new View()
					};

					ConfigurePolicyRuleOptionsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Configure()
					};

					SimulationIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Simulation()
					};

					AllowNewAppsIcon = currentTheme == ElementTheme.Dark
						? new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarYellow()
						}
						: new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarBlack()
						};

					CreatePolicyFromEventLogsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Scan()
					};

					CreatePolicyFromMDEAHIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new MDE()
					};

					GetCodeIntegrityHashesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Hash()
					};

					GetSecurePolicySettingsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Shield()
					};

					LogsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Timeline()
					};

					GitHubDocsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new GitHub()
					};

					MSFTDocsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Document()
					};

					UpdateIcon = currentTheme == ElementTheme.Dark
						? new AnimatedIcon
						{
							Margin = new Thickness(0, -5, -5, -5),
							Source = new Heart()
						}
						: new AnimatedIcon
						{
							Margin = new Thickness(0, -25, -25, -25),
							Source = new HeartPulse()
						};

					BuildNewCertificateIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Certificate()
					};

					DeploymentIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Deployment()
					};

					CreateSupplementalPolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(-5, -28, -28, -28),
						Source = new SupplementalPolicy()
					};

					MergePoliciesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Merge()
					};

					CreateDenyPolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new AnimatedVisuals.Deny()
					};

					ValidatePoliciesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Validate()
					};

					ViewFileCertificatesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new ViewAllCertificates()
					};

					PolicyEditorIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new Honeymoon()
					};

					HomeIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -7, -7, -7),
						Source = new Home()
					};

					break;
				}
			case "Windows Accent":
				{
					// Retrieve the accent brush from the current resources.
					Brush accentBrush = (Brush)Application.Current.Resources["SystemControlHighlightAccentBrush"];

					CreatePolicyIcon = new FontIcon
					{
						Glyph = "\uE83D",
						Foreground = accentBrush
					};

					SystemInformationIcon = new FontIcon
					{
						Glyph = "\uE7C1",
						Foreground = accentBrush
					};

					ConfigurePolicyRuleOptionsIcon = new FontIcon
					{
						Glyph = "\uEEA3",
						Foreground = accentBrush
					};

					SimulationIcon = new FontIcon
					{
						Glyph = "\uE835",
						Foreground = accentBrush
					};

					AllowNewAppsIcon = new FontIcon
					{
						Glyph = "\uED35",
						Foreground = accentBrush
					};

					CreatePolicyFromEventLogsIcon = new FontIcon
					{
						Glyph = "\uEA18",
						Foreground = accentBrush
					};

					CreatePolicyFromMDEAHIcon = new FontIcon
					{
						Glyph = "\uEB44",
						Foreground = accentBrush
					};

					GetCodeIntegrityHashesIcon = new FontIcon
					{
						Glyph = "\uE950",
						Foreground = accentBrush
					};

					GetSecurePolicySettingsIcon = new FontIcon
					{
						Glyph = "\uF404",
						Foreground = accentBrush
					};

					LogsIcon = new FontIcon
					{
						Glyph = "\uF5A0",
						Foreground = accentBrush
					};

					GitHubDocsIcon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					MSFTDocsIcon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					UpdateIcon = new FontIcon
					{
						Glyph = "\uEB52",
						Foreground = accentBrush
					};

					BuildNewCertificateIcon = new FontIcon
					{
						Glyph = "\uEB95",
						Foreground = accentBrush
					};

					DeploymentIcon = new FontIcon
					{
						Glyph = "\uF32A",
						Foreground = accentBrush
					};

					CreateSupplementalPolicyIcon = new FontIcon
					{
						Glyph = "\uE8F9",
						Foreground = accentBrush
					};

					MergePoliciesIcon = new FontIcon
					{
						Glyph = "\uEE49",
						Foreground = accentBrush
					};

					CreateDenyPolicyIcon = new FontIcon
					{
						Glyph = "\uE8D0",
						Foreground = accentBrush
					};

					ValidatePoliciesIcon = new FontIcon
					{
						Glyph = "\uED5E",
						Foreground = accentBrush
					};

					ViewFileCertificatesIcon = new FontIcon
					{
						Glyph = "\uEBD2",
						Foreground = accentBrush
					};

					PolicyEditorIcon = new FontIcon
					{
						Glyph = "\uE70F",
						Foreground = accentBrush
					};

					HomeIcon = new FontIcon
					{
						Glyph = "\uE80F",
						Foreground = accentBrush
					};

					break;
				}
			case "Monochromatic":
			default:
				{
					CreatePolicyIcon = new FontIcon { Glyph = "\uE83D" };
					SystemInformationIcon = new FontIcon { Glyph = "\uE7C1" };
					ConfigurePolicyRuleOptionsIcon = new FontIcon { Glyph = "\uEEA3" };
					SimulationIcon = new FontIcon { Glyph = "\uE835" };
					AllowNewAppsIcon = new FontIcon { Glyph = "\uED35" };
					CreatePolicyFromEventLogsIcon = new FontIcon { Glyph = "\uEA18" };
					CreatePolicyFromMDEAHIcon = new FontIcon { Glyph = "\uEB44" };
					GetCodeIntegrityHashesIcon = new FontIcon { Glyph = "\uE950" };
					GetSecurePolicySettingsIcon = new FontIcon { Glyph = "\uF404" };
					LogsIcon = new FontIcon { Glyph = "\uF5A0" };
					GitHubDocsIcon = new FontIcon { Glyph = "\uE8A5" };
					MSFTDocsIcon = new FontIcon { Glyph = "\uE8A5" };
					UpdateIcon = new FontIcon { Glyph = "\uEB52" };
					BuildNewCertificateIcon = new FontIcon { Glyph = "\uEB95" };
					DeploymentIcon = new FontIcon { Glyph = "\uF32A" };
					CreateSupplementalPolicyIcon = new FontIcon { Glyph = "\uE8F9" };
					MergePoliciesIcon = new FontIcon { Glyph = "\uEE49" };
					CreateDenyPolicyIcon = new FontIcon { Glyph = "\uE8D0" };
					ValidatePoliciesIcon = new FontIcon { Glyph = "\uED5E" };
					ViewFileCertificatesIcon = new FontIcon { Glyph = "\uEBD2" };
					PolicyEditorIcon = new FontIcon { Glyph = "\uE70F" };
					HomeIcon = new FontIcon { Glyph = "\uE80F" };
					break;
				}
		}
	}

	/// <summary>
	/// The main InfoBar for the Sidebar.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

}
