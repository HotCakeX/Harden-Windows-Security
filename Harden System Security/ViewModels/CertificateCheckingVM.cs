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
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using HardenSystemSecurity.Vyre;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class CertificateCheckingVM : ViewModelBase
{

	internal CertificateCheckingVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Calculate initial column widths
		CalculateColumnWidths();
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	#region Certificate Analysis Properties

	/// <summary>
	/// Search keyword for filtering certificates
	/// </summary>
	internal string? SearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				SearchBox_TextChanged();
		}
	}

	/// <summary>
	/// Toggle to include expired certificates in the analysis
	/// </summary>
	internal bool IncludeExpiredCertificates { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Collection of certificates that don't chain to STL roots
	/// </summary>
	internal ObservableCollection<NonStlRootCert> NonStlCertificates = [];

	/// <summary>
	/// Backing field for all certificates
	/// </summary>
	internal readonly List<NonStlRootCert> AllNonStlCertificates = [];

	#endregion

	#region CTL Header Properties

	/// <summary>
	/// CTL Header information for display in the flyout
	/// </summary>
	internal CtlHeader? CurrentCtlHeader
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				// Update all the formatted properties when CTlHeader changes
				UpdateCtlHeaderProperties();
			}
		}
	}

	/// <summary>
	/// Formatted CTL Header properties for UI display
	/// </summary>
	internal string CtlVersion { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlUsageOid { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlUsageFriendlyName { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlSequenceNumber { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlThisUpdate { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlNextUpdate { get; set => SP(ref field, value); } = GlobalVars.GetStr("EmptyValue");
	internal string CtlAlgorithmOid { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlAlgorithmOidFriendlyName { get; set => SP(ref field, value); } = GlobalVars.GetStr("NAText");
	internal string CtlAlgorithmParameters { get; set => SP(ref field, value); } = GlobalVars.GetStr("NoCertificateHash");
	internal string CtlEntryCount { get; set => SP(ref field, value); } = "0";

	/// <summary>
	/// Updates all CTL header display properties when CurrentCtlHeader changes
	/// </summary>
	private void UpdateCtlHeaderProperties()
	{
		if (CurrentCtlHeader is not null)
		{
			CtlVersion = CurrentCtlHeader.Version.ToString(CultureInfo.InvariantCulture);
			CtlUsageOid = CurrentCtlHeader.UsageOid;
			CtlUsageFriendlyName = CurrentCtlHeader.UsageFriendlyName;
			CtlSequenceNumber = CurrentCtlHeader.SequenceNumberHexLower ?? GlobalVars.GetStr("NAText");
			CtlThisUpdate = CurrentCtlHeader.ThisUpdateUtc.ToLocalTime().ToString("MM/dd/yyyy h:mm tt", CultureInfo.InvariantCulture);
			CtlNextUpdate = CurrentCtlHeader.NextUpdateUtc?.ToLocalTime().ToString("MM/dd/yyyy h:mm tt", CultureInfo.InvariantCulture) ?? GlobalVars.GetStr("EmptyValue");
			CtlAlgorithmOid = CurrentCtlHeader.AlgorithmOid;
			CtlAlgorithmOidFriendlyName = CurrentCtlHeader.AlgorithmOidFriendlyName;
			CtlAlgorithmParameters = FormatAlgorithmParameters();
			CtlEntryCount = CurrentCtlHeader.EntryCount.ToString(CultureInfo.InvariantCulture);
		}
		else
		{
			// Reset to default values when no header is available
			CtlVersion = GlobalVars.GetStr("NAText");
			CtlUsageOid = GlobalVars.GetStr("NAText");
			CtlUsageFriendlyName = GlobalVars.GetStr("NAText");
			CtlSequenceNumber = GlobalVars.GetStr("NAText");
			CtlThisUpdate = GlobalVars.GetStr("NAText");
			CtlNextUpdate = GlobalVars.GetStr("EmptyValue");
			CtlAlgorithmOid = GlobalVars.GetStr("NAText");
			CtlAlgorithmOidFriendlyName = GlobalVars.GetStr("NAText");
			CtlAlgorithmParameters = GlobalVars.GetStr("NoCertificateHash");
			CtlEntryCount = "0";
		}
	}

	/// <summary>
	/// Format algorithm parameters for display
	/// </summary>
	private string FormatAlgorithmParameters()
	{
		if (CurrentCtlHeader?.DigestAlgorithmParameters is null || CurrentCtlHeader.DigestAlgorithmParameters.Length == 0)
			return GlobalVars.GetStr("NoCertificateHash");

		StringBuilder sb = new(CurrentCtlHeader.DigestAlgorithmParameters.Length * 3);
		for (int i = 0; i < CurrentCtlHeader.DigestAlgorithmParameters.Length; i++)
		{
			if (i > 0) _ = sb.Append(' ');
			_ = sb.Append(CurrentCtlHeader.DigestAlgorithmParameters.Span[i].ToString("X2", CultureInfo.InvariantCulture));
		}
		return sb.ToString();
	}

	#endregion

	#region ListView Column Widths

	internal GridLength StoreLocationColumnWidth { get; set => SP(ref field, value); }
	internal GridLength StoreNameColumnWidth { get; set => SP(ref field, value); }
	internal GridLength SubjectColumnWidth { get; set => SP(ref field, value); }
	internal GridLength IssuerColumnWidth { get; set => SP(ref field, value); }
	internal GridLength ThumbprintColumnWidth { get; set => SP(ref field, value); }
	internal GridLength RootSubjectColumnWidth { get; set => SP(ref field, value); }
	internal GridLength RootSha256ColumnWidth { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculate optimal column widths based on content
	/// </summary>
	internal void CalculateColumnWidths()
	{
		// Measure header text widths first
		double maxStoreLocationWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("StoreLocationHeader/Text"));
		double maxStoreNameWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("StoreNameHeader/Text"));
		double maxSubjectWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("SubjectHeader/Text"));
		double maxIssuerWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("IssuerHeader/Text"));
		double maxThumbprintWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("ThumbprintHeader/Text"));
		double maxRootSubjectWidth = ListViewHelper.MeasureText(GlobalVars.GetStr("RootSubjectHeader/Text"));
		double maxRootSha256Width = ListViewHelper.MeasureText(GlobalVars.GetStr("RootSha256Header/Text"));

		// Iterate over all items to determine the widest string for each column
		foreach (NonStlRootCert cert in NonStlCertificates)
		{
			maxStoreLocationWidth = ListViewHelper.MeasureText(cert.StoreLocationString, maxStoreLocationWidth);
			maxStoreNameWidth = ListViewHelper.MeasureText(cert.StoreNameString, maxStoreNameWidth);
			maxSubjectWidth = ListViewHelper.MeasureText(cert.Subject, maxSubjectWidth);
			maxIssuerWidth = ListViewHelper.MeasureText(cert.Issuer, maxIssuerWidth);
			maxThumbprintWidth = ListViewHelper.MeasureText(cert.LeafThumbprintSha1, maxThumbprintWidth);
			maxRootSubjectWidth = ListViewHelper.MeasureText(cert.RootSubject, maxRootSubjectWidth);
			maxRootSha256Width = ListViewHelper.MeasureText(cert.RootSha256Hex, maxRootSha256Width);
		}

		// Set the column width properties
		StoreLocationColumnWidth = new GridLength(maxStoreLocationWidth);
		StoreNameColumnWidth = new GridLength(maxStoreNameWidth);
		SubjectColumnWidth = new GridLength(maxSubjectWidth);
		IssuerColumnWidth = new GridLength(maxIssuerWidth);
		ThumbprintColumnWidth = new GridLength(maxThumbprintWidth);
		RootSubjectColumnWidth = new GridLength(maxRootSubjectWidth);
		RootSha256ColumnWidth = new GridLength(maxRootSha256Width);
	}

	#endregion

	#region Search and Filtering

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = SearchKeyword?.Trim();

		if (string.IsNullOrEmpty(searchTerm))
		{
			// If search is empty, show all certificates
			NonStlCertificates.Clear();
			foreach (NonStlRootCert cert in AllNonStlCertificates)
			{
				NonStlCertificates.Add(cert);
			}
		}
		else
		{
			// Filter certificates based on search term
			List<NonStlRootCert> filteredResults = AllNonStlCertificates.Where(cert =>
				cert.StoreLocationString.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.StoreNameString.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.Subject.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.Issuer.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.LeafThumbprintSha1.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.RootSubject.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				cert.RootSha256Hex.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
			).ToList();

			NonStlCertificates.Clear();
			foreach (NonStlRootCert cert in filteredResults)
			{
				NonStlCertificates.Add(cert);
			}
		}

		CalculateColumnWidths();
	}

	#endregion

	#region Sort

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display NonStlRootCert data type
	private static readonly FrozenDictionary<string, (string Label, Func<NonStlRootCert, object?> Getter)> NonStlRootCertPropertyMappings
		= new Dictionary<string, (string Label, Func<NonStlRootCert, object?> Getter)>
		{
			{ "StoreLocation", (GlobalVars.GetStr("StoreLocationHeader/Text"), cert => cert.StoreLocationString) },
			{ "StoreName", (GlobalVars.GetStr("StoreNameHeader/Text"), cert => cert.StoreNameString) },
			{ "Subject", (GlobalVars.GetStr("SubjectHeader/Text"), cert => cert.Subject) },
			{ "Issuer", (GlobalVars.GetStr("IssuerHeader/Text"), cert => cert.Issuer) },
			{ "Thumbprint", (GlobalVars.GetStr("ThumbprintHeader/Text"), cert => cert.LeafThumbprintSha1) },
			{ "RootSubject", (GlobalVars.GetStr("RootSubjectHeader/Text"), cert => cert.RootSubject) },
			{ "RootSha256", (GlobalVars.GetStr("RootSha256Header/Text"), cert => cert.RootSha256Hex) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the property mappings dictionary.
			if (NonStlRootCertPropertyMappings.TryGetValue(key, out (string Label, Func<NonStlRootCert, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchKeyword,
					AllNonStlCertificates,
					NonStlCertificates,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.CertificateChecking_NonStlCerts);
			}
		}
	}

	#endregion

	#region Copy

	/// <summary>
	/// Converts the properties of a NonStlRootCert row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedCertificates_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CertificateChecking_NonStlCerts);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains NonStlRootCert
			ListViewHelper.ConvertRowToText(lv.SelectedItems, NonStlRootCertPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyCertificateProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CertificateChecking_NonStlCerts);

		if (lv is null) return;

		if (NonStlRootCertPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = NonStlRootCert, copy just that one property
			ListViewHelper.CopyToClipboard<NonStlRootCert>(cert => map.Getter(cert)?.ToString(), lv);
		}
	}

	#endregion

	#region Delete Certificate

	/// <summary>
	/// Deletes the selected certificate from the certificate store
	/// </summary>
	internal async void DeleteSelectedCertificate_Click()
	{
		try
		{
			ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CertificateChecking_NonStlCerts);
			if (lv is null) return;

			if (lv.SelectedItem is not NonStlRootCert selectedCert)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("MainInfoBarDeleteCertificateSelectMessage"));
				return;
			}

			// Show confirmation dialog
			using AppControlManager.CustomUIElements.ContentDialogV2 confirmDialog = new()
			{
				Title = GlobalVars.GetStr("DeleteCertificateDialogTitle"),
				Content = string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("DeleteCertificateDialogContent"), selectedCert.Subject, selectedCert.StoreLocationString, selectedCert.StoreNameString, selectedCert.LeafThumbprintSha1),
				PrimaryButtonText = GlobalVars.GetStr("DeleteCertificateDialogPrimaryButton"),
				SecondaryButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Secondary
			};

			ContentDialogResult result = await confirmDialog.ShowAsync();
			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			// Parse store location
			if (!Enum.TryParse(selectedCert.StoreLocationString, out StoreLocation storeLocation))
			{
				MainInfoBar.WriteWarning(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("InvalidStoreLocationWarning"), selectedCert.StoreLocationString));
				return;
			}

			// Delete the certificate from the store
			await DeleteCertificateFromStore(selectedCert.LeafThumbprintSha1, selectedCert.StoreNameString, storeLocation);

			// Remove from both collections
			_ = AllNonStlCertificates.Remove(selectedCert);
			_ = NonStlCertificates.Remove(selectedCert);

			// Recalculate column widths
			CalculateColumnWidths();

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("CertificateDeletedSuccessMessage"), selectedCert.StoreLocationString, selectedCert.StoreNameString));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Deletes a certificate from the specified certificate store
	/// </summary>
	/// <param name="thumbprint">Certificate thumbprint (SHA1)</param>
	/// <param name="storeName">Certificate store name</param>
	/// <param name="storeLocation">Certificate store location</param>
	/// <returns></returns>
	private async Task DeleteCertificateFromStore(string thumbprint, string storeName, StoreLocation storeLocation)
	{
		await Task.Run(async () =>
		{
			using X509Store store = new(storeName, storeLocation);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived | OpenFlags.MaxAllowed);

			// Find the certificate by thumbprint
			X509Certificate2Collection certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

			if (certificates.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("CertificateNotFoundInStoreWarning"));
				return;
			}

			// Remove the certificate from the store
			store.Remove(certificates[0]);
		});
	}

	#endregion

	#region Certificate Analysis

	/// <summary>
	/// Start the certificate analysis process
	/// </summary>
	internal async void StartCertificateAnalysis()
	{
		try
		{
			await StartCertificateAnalysisPrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Path to the Certificate file used as the trust anchor.
	/// </summary>
	private static readonly string CACertFilePath = Path.Combine(AppContext.BaseDirectory, "Resources", "Certificate", "Microsoft Root CA 2010.crt");

	/// <summary>
	/// Private method that performs the actual certificate analysis
	/// </summary>
	private async Task StartCertificateAnalysisPrivate()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			// Clear existing data
			AllNonStlCertificates.Clear();
			NonStlCertificates.Clear();
			CurrentCtlHeader = null;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("StartingCertificateAnalysisMessage"));

			await Task.Run(async () =>
			{
				const string cabURL = @"https://aka.ms/CTLDownload";

				DateTime start = DateTime.UtcNow;

				// Process either CAB or STL file - the method will automatically detect the type
				TrustListParseResult parseResult = AuthRootProcessor.ProcessAuthRoot(cabURL, CACertFilePath);

				DateTime end = DateTime.UtcNow;

				MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("StlFileParsedMessage"), parseResult.Subjects.Count.ToString(CultureInfo.InvariantCulture), (end - start).TotalMilliseconds.ToString("F2", CultureInfo.InvariantCulture)));

				// Build a lookup set of STL root SHA256 fingerprints
				HashSet<string> stlRootSha256 = AuthRootProcessor.BuildStlRootSha256Set(parseResult.Subjects);

				// Find certificates whose root is not in the STL
				List<NonStlRootCert> nonStlRootCerts =
					AuthRootProcessor.FindCertificatesNotChainingToStlRoots(stlRootSha256, IncludeExpiredCertificates);

				// Update UI on the UI thread
				await Dispatcher.EnqueueAsync(() =>
				{
					// Store CTL header for UI display - this will trigger UpdateCtlHeaderProperties()
					CurrentCtlHeader = parseResult.Header;

					foreach (NonStlRootCert cert in nonStlRootCerts)
					{
						AllNonStlCertificates.Add(cert);
						NonStlCertificates.Add(cert);
					}

					CalculateColumnWidths();
				});
			});

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("CertificateAnalysisCompletedMessage"), NonStlCertificates.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Retrieve all certificates from all certificate stores
	/// </summary>
	internal async void RetrieveAllCertificates()
	{
		try
		{
			await RetrieveAllCertificatesPrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Private method that retrieves all certificates from all stores
	/// </summary>
	private async Task RetrieveAllCertificatesPrivate()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			// Clear existing data
			AllNonStlCertificates.Clear();
			NonStlCertificates.Clear();
			CurrentCtlHeader = null;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("RetrievingAllCertificatesMessage"));

			await Task.Run(async () =>
			{
				DateTime start = DateTime.UtcNow;

				List<NonStlRootCert> allCertificates = GetAllCertificatesFromAllStores();

				DateTime end = DateTime.UtcNow;

				// Update UI on the UI thread
				await Dispatcher.EnqueueAsync(() =>
				{
					foreach (NonStlRootCert cert in allCertificates)
					{
						AllNonStlCertificates.Add(cert);
						NonStlCertificates.Add(cert);
					}

					CalculateColumnWidths();
				});

				MainInfoBar.WriteInfo(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("RetrievedCertificatesMessage"), allCertificates.Count.ToString(CultureInfo.InvariantCulture), (end - start).TotalMilliseconds.ToString("F2", CultureInfo.InvariantCulture)));
			});

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.InvariantCulture, GlobalVars.GetStr("CertificateRetrievalCompletedMessage"), NonStlCertificates.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Gets all certificates from all certificate stores (LocalMachine and CurrentUser)
	/// </summary>
	private List<NonStlRootCert> GetAllCertificatesFromAllStores()
	{
		List<NonStlRootCert> results = [];
		DateTime nowUtc = DateTime.UtcNow;

		foreach (StoreLocation loc in AuthRootProcessor.storeLocations)
		{
			foreach (string storeName in AuthRootProcessor.knownStoreNames)
			{
				try
				{
					using X509Store store = new(storeName, loc);
					store.Open(OpenFlags.OpenExistingOnly | OpenFlags.IncludeArchived | OpenFlags.MaxAllowed);

					X509Certificate2Collection certs = store.Certificates;
					for (int i = 0; i < certs.Count; i++)
					{
						X509Certificate2 leaf = certs[i];

						string leafSha1 = leaf.Thumbprint ?? string.Empty;
						if (string.IsNullOrEmpty(leafSha1))
						{
							continue;
						}

						// Time-valid filtering (applies to leaf). When IncludeExpiredCertificates=false,
						// we exclude both expired and not-yet-valid certificates.
						if (!IncludeExpiredCertificates)
						{
							DateTime notBeforeUtc = leaf.NotBefore.Kind == DateTimeKind.Utc ? leaf.NotBefore : leaf.NotBefore.ToUniversalTime();
							DateTime notAfterUtc = leaf.NotAfter.Kind == DateTimeKind.Utc ? leaf.NotAfter : leaf.NotAfter.ToUniversalTime();
							if (nowUtc < notBeforeUtc || nowUtc > notAfterUtc)
							{
								continue;
							}
						}

						// Get root certificate information
						X509Certificate2? rootCert = TryGetChainRoot(leaf);
						string rootSubject = rootCert is null ? GlobalVars.GetStr("NoRootCertificate") : rootCert.Subject;
						string rootSha256Hex = ComputeCertSha256Hex(rootCert);

						NonStlRootCert item = new(
							storeLocationString: loc.ToString(),
							storeNameString: storeName,
							subject: leaf.Subject,
							issuer: leaf.Issuer,
							leafThumbprintSha1: leafSha1,
							rootSubject: rootSubject,
							rootSha256Hex: string.IsNullOrEmpty(rootSha256Hex) ? GlobalVars.GetStr("NoCertificateHash") : rootSha256Hex
						);
						results.Add(item);
					}
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}
			}
		}

		return results;
	}

	/// <summary>
	/// Attempts to build a chain and return the last element (root). Returns null if no chain elements were built.
	/// Uses system trust; allows unknown/expired to still materialize a chain.
	/// </summary>
	private static X509Certificate2? TryGetChainRoot(X509Certificate2 cert)
	{
		using X509Chain chain = new()
		{
			ChainPolicy =
			{
				RevocationMode = X509RevocationMode.NoCheck,
				RevocationFlag = X509RevocationFlag.ExcludeRoot,
				VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.AllowUnknownCertificateAuthority
			}
		};
		chain.ChainPolicy.TrustMode = X509ChainTrustMode.System;

		try
		{
			_ = chain.Build(cert);
		}
		catch
		{
			// Ignore build exceptions; we only care about any ChainElements captured.
		}

		if (chain.ChainElements.Count > 0)
		{
			return chain.ChainElements[^1].Certificate;
		}

		// Treat a self-issued leaf as its own root if subject == issuer.
		if (IsSelfIssued(cert))
		{
			return cert;
		}

		return null;
	}

	/// <summary>
	/// Computes uppercase hex SHA256 of the certificate's raw data. Returns empty string if cert is null.
	/// </summary>
	private static string ComputeCertSha256Hex(X509Certificate2? cert)
	{
		if (cert is null)
		{
			return string.Empty;
		}
		byte[] hash = System.Security.Cryptography.SHA256.HashData(cert.RawData);
		return Convert.ToHexString(hash);
	}

	/// <summary>
	/// Lightweight self-issued check based on Subject/Issuer string equality.
	/// </summary>
	private static bool IsSelfIssued(X509Certificate2 cert)
	{
		string subject = cert.Subject ?? string.Empty;
		string issuer = cert.Issuer ?? string.Empty;
		return subject.Equals(issuer, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Clear all certificate data
	/// </summary>
	internal void ClearCertificateData()
	{
		AllNonStlCertificates.Clear();
		NonStlCertificates.Clear();
		SearchKeyword = null;
		CurrentCtlHeader = null;
		CalculateColumnWidths();
	}

	#endregion

	#region Export

	/// <summary>
	/// Exports the current certificates to a JSON file
	/// </summary>
	internal async void ExportToJson_Click()
	{
		try
		{
			if (NonStlCertificates.Count == 0)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("NoCertificatesAvailableForExport"));
				return;
			}

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string? saveLocation = FileDialogHelper.ShowSaveFileDialog(
					"Certificates|*.JSON",
					"Certificates.JSON");

			if (saveLocation is null)
				return;

			List<NonStlRootCert> certificatesToExport = NonStlCertificates.ToList();

			await Task.Run(() =>
			{
				string jsonString = JsonSerializer.Serialize(certificatesToExport, NonStlRootCertJsonContext.Default.ListNonStlRootCert);

				File.WriteAllText(saveLocation, jsonString, Encoding.UTF8);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedCertificates"), certificatesToExport.Count, saveLocation));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	#endregion
}
