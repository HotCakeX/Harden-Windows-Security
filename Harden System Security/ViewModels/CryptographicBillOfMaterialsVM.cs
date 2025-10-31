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
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using CommunityToolkit.WinUI;
using HardenSystemSecurity.Arcane;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class CryptographicBillOfMaterialsVM : ViewModelBase
{
	internal CryptographicBillOfMaterialsVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Give column widths paddings to look better
		CA_CalculateColumnWidths();
		CNG_CalculateColumnWidths();
		SSL_CalculateColumnWidths();
		TLS_CalculateColumnWidths();
		REG_CalculateColumnWidths();
	}

	// Main InfoBar for this VM
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal bool ElementsAreEnabled { get; set => SP(ref field, value); } = true;

	// ------------------------------------------------------------
	// Crypto Algorithms
	// ------------------------------------------------------------
	#region Crypto Algorithms

	internal ObservableCollection<CryptoAlgorithm> CryptoAlgorithms = [];
	internal readonly List<CryptoAlgorithm> AllCryptoAlgorithms = [];

	internal string? CryptoAlgorithmsSearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				CA_SearchBox_TextChanged();
		}
	}

	internal GridLength CA_ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength CA_ColumnWidth7 { get; set => SP(ref field, value); }

	private ListViewHelper.SortState CA_SortState { get; set; } = new();

	// Property mappings for CA
	private static readonly FrozenDictionary<string, (string Label, Func<CryptoAlgorithm, object?> Getter)> CA_PropertyMappings =
		new Dictionary<string, (string Label, Func<CryptoAlgorithm, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("CA_NameHeader/Text") + ": ", a => a.Name) },
			{ "AlgorithmType", (GlobalVars.GetStr("CA_TypeHeader/Text") + ": ", a => a.AlgorithmType) },
			{ "Flags", (GlobalVars.GetStr("CA_FlagsHeader/Text") + ": ", a => a.Flags) },
			{ "IsOpenable", (GlobalVars.GetStr("CA_IsOpenableHeader/Text") + ": ", a => a.IsOpenable) },
			{ "IsPostQuantum", (GlobalVars.GetStr("CA_IsPQHeader/Text") + ": ", a => a.IsPostQuantum) },
			{ "SupportsKeyGeneration", (GlobalVars.GetStr("CA_KeyGenHeader/Text") + ": ", a => a.SupportsKeyGeneration) },
			{ "SupportedParameterSets", (GlobalVars.GetStr("CA_ParamSetsHeader/Text") + ": ", a => a.SupportedParameterSets is null ? null : string.Join(", ", a.SupportedParameterSets)) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal async void RetrieveCryptoAlgorithms() => await _RetrieveCryptoAlgorithms();

	private async Task _RetrieveCryptoAlgorithms()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			CryptoAlgorithms.Clear();
			AllCryptoAlgorithms.Clear();

			await Task.Run(() =>
			{
				List<CryptoAlgorithm> list = AlgorithmManager.EnumerateAllAlgorithms();

				// Enrich with availability and PQ capability details
				AlgorithmManager.TestAlgorithmAvailability(list);

				_ = Dispatcher.EnqueueAsync(() =>
				{
					foreach (CryptoAlgorithm alg in list)
					{
						CryptoAlgorithms.Add(alg);
						AllCryptoAlgorithms.Add(alg);
					}
				});
			});

			CA_CalculateColumnWidths();
			MainInfoBar.WriteSuccess("Loaded cryptographic algorithms.");
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

	private void CA_SearchBox_TextChanged()
	{
		string? searchTerm = CryptoAlgorithmsSearchKeyword?.Trim();
		if (searchTerm is null)
			return;

		List<CryptoAlgorithm> filtered = AllCryptoAlgorithms.Where(a =>
			(!string.IsNullOrEmpty(a.Name) && a.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(a.AlgorithmType) && a.AlgorithmType.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			a.Flags.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			a.IsOpenable.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			a.IsPostQuantum.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			a.SupportsKeyGeneration.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			(a.SupportedParameterSets.Count > 0 && string.Join(", ", a.SupportedParameterSets).Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
		).ToList();

		CryptoAlgorithms.Clear();

		foreach (CryptoAlgorithm alg in filtered)
			CryptoAlgorithms.Add(alg);
	}

	internal void CA_HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (CA_PropertyMappings.TryGetValue(key, out (string Label, Func<CryptoAlgorithm, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					CryptoAlgorithmsSearchKeyword,
					AllCryptoAlgorithms,
					CryptoAlgorithms,
					CA_SortState,
					key,
					ListViewHelper.ListViewsRegistry.CBOM_CryptoAlgorithms);
			}
		}
	}

	/// <summary>
	/// Copy Row for CryptoAlgorithms
	/// </summary>
	internal void CopySelectedCryptoAlgorithms_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_CryptoAlgorithms);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<CryptoAlgorithm>(lv.SelectedItems, CA_PropertyMappings);
		}
	}

	/// <summary>
	/// Copy single property for CryptoAlgorithms
	/// </summary>
	internal void CopyCryptoAlgorithmProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_CryptoAlgorithms);
		if (lv is null) return;

		if (CA_PropertyMappings.TryGetValue(key, out (string Label, Func<CryptoAlgorithm, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<CryptoAlgorithm>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	private void CA_CalculateColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_NameColumnHeaderBtn/Content"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_TypeColumnHeaderBtn/Content"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_FlagsColumnHeaderBtn/Content"));
		double w4 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_IsOpenableColumnHeaderBtn/Content"));
		double w5 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_IsPQColumnHeaderBtn/Content"));
		double w6 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_KeyGenColumnHeaderBtn/Content"));
		double w7 = ListViewHelper.MeasureText(GlobalVars.GetStr("CA_ParamSetsColumnHeaderBtn/Content"));

		foreach (CryptoAlgorithm a in CryptoAlgorithms)
		{
			w1 = ListViewHelper.MeasureText(a.Name, w1);
			w2 = ListViewHelper.MeasureText(a.AlgorithmType, w2);
			w3 = ListViewHelper.MeasureText(a.Flags.ToString(), w3);
			w4 = ListViewHelper.MeasureText(a.IsOpenable.ToString(), w4);
			w5 = ListViewHelper.MeasureText(a.IsPostQuantum.ToString(), w5);
			w6 = ListViewHelper.MeasureText(a.SupportsKeyGeneration.ToString(), w6);
			w7 = ListViewHelper.MeasureText(a.SupportedParameterSets.Count.ToString(), w7);
		}

		CA_ColumnWidth1 = new GridLength(w1);
		CA_ColumnWidth2 = new GridLength(w2);
		CA_ColumnWidth3 = new GridLength(w3);
		CA_ColumnWidth4 = new GridLength(w4);
		CA_ColumnWidth5 = new GridLength(w5);
		CA_ColumnWidth6 = new GridLength(w6);
		CA_ColumnWidth7 = new GridLength(w7);
	}

	#endregion

	// ------------------------------------------------------------
	// CNG Curves
	// ------------------------------------------------------------
	#region CNG Curves

	internal ObservableCollection<EccCurveCng> CngCurves = [];
	internal readonly List<EccCurveCng> AllCngCurves = [];

	internal string? CngCurvesSearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				CNG_SearchBox_TextChanged();
		}
	}

	internal GridLength CNG_ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength CNG_ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength CNG_ColumnWidth3 { get; set => SP(ref field, value); }

	private ListViewHelper.SortState CNG_SortState { get; set; } = new();

	// Property mappings for CNG Curves
	private static readonly FrozenDictionary<string, (string Label, Func<EccCurveCng, object?> Getter)> CNG_PropertyMappings =
		new Dictionary<string, (string Label, Func<EccCurveCng, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("CNG_NameHeader/Text") + ": ", c => c.Name) },
			{ "Oid", (GlobalVars.GetStr("CNG_OidHeader/Text") + ": ", c => c.Oid) },
			{ "PublicKeyLengthBits", (GlobalVars.GetStr("CNG_LengthHeader/Text") + ": ", c => c.PublicKeyLengthBits) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal async void RetrieveCngCurves() => await _RetrieveCngCurves();

	internal async Task _RetrieveCngCurves()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			CngCurves.Clear();
			AllCngCurves.Clear();

			await Task.Run(() =>
			{
				List<EccCurveCng> list = EccCurveManager.EnumerateCngCurves();

				_ = Dispatcher.EnqueueAsync(() =>
				{
					foreach (EccCurveCng c in list)
					{
						CngCurves.Add(c);
						AllCngCurves.Add(c);
					}
				});
			});

			CNG_CalculateColumnWidths();
			MainInfoBar.WriteSuccess("Loaded CNG curves.");
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

	private void CNG_SearchBox_TextChanged()
	{
		string? searchTerm = CngCurvesSearchKeyword?.Trim();
		if (searchTerm is null)
			return;

		List<EccCurveCng> filtered = AllCngCurves.Where(c =>
			(!string.IsNullOrEmpty(c.Name) && c.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(c.Oid) && c.Oid.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			c.PublicKeyLengthBits.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		CngCurves.Clear();

		foreach (EccCurveCng c in filtered)
			CngCurves.Add(c);
	}

	internal void CNG_HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (CNG_PropertyMappings.TryGetValue(key, out (string Label, Func<EccCurveCng, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					CngCurvesSearchKeyword,
					AllCngCurves,
					CngCurves,
					CNG_SortState,
					key,
					ListViewHelper.ListViewsRegistry.CBOM_CNGCurves);
			}
		}
	}

	/// <summary>
	/// Copy Row for CNG Curves
	/// </summary>
	internal void CopySelectedCngCurves_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_CNGCurves);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<EccCurveCng>(lv.SelectedItems, CNG_PropertyMappings);
		}
	}

	/// <summary>
	/// Copy single property for CNG Curves
	/// </summary>
	internal void CopyCngCurveProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_CNGCurves);
		if (lv is null) return;

		if (CNG_PropertyMappings.TryGetValue(key, out (string Label, Func<EccCurveCng, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<EccCurveCng>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	private void CNG_CalculateColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("CNG_NameColumnHeaderBtn/Content"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("CNG_OidColumnHeaderBtn/Content"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("CNG_LengthColumnHeaderBtn/Content"));

		foreach (EccCurveCng c in CngCurves)
		{
			w1 = ListViewHelper.MeasureText(c.Name, w1);
			w2 = ListViewHelper.MeasureText(c.Oid, w2);
			w3 = ListViewHelper.MeasureText(c.PublicKeyLengthBits.ToString(), w3);
		}

		CNG_ColumnWidth1 = new GridLength(w1);
		CNG_ColumnWidth2 = new GridLength(w2);
		CNG_ColumnWidth3 = new GridLength(w3);
	}

	#endregion

	// ------------------------------------------------------------
	// SSL Provider Curves
	// ------------------------------------------------------------
	#region SSL Provider Curves

	internal ObservableCollection<EccCurveSslProvider> SslProviderCurves = [];
	internal readonly List<EccCurveSslProvider> AllSslProviderCurves = [];

	internal string? SslProviderCurvesSearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				SSL_SearchBox_TextChanged();
		}
	}

	internal GridLength SSL_ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength SSL_ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength SSL_ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength SSL_ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength SSL_ColumnWidth5 { get; set => SP(ref field, value); }

	private ListViewHelper.SortState SSL_SortState { get; set; } = new();

	// Property mappings for SSL Provider Curves
	private static readonly FrozenDictionary<string, (string Label, Func<EccCurveSslProvider, object?> Getter)> SSL_PropertyMappings =
		new Dictionary<string, (string Label, Func<EccCurveSslProvider, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("SSL_NameHeader/Text") + ": ", c => c.Name) },
			{ "Oid", (GlobalVars.GetStr("SSL_OidHeader/Text") + ": ", c => c.Oid) },
			{ "PublicKeyLengthBits", (GlobalVars.GetStr("SSL_LengthHeader/Text") + ": ", c => c.PublicKeyLengthBits) },
			{ "CurveType", (GlobalVars.GetStr("SSL_TypeHeader/Text") + ": ", c => c.CurveType) },
			{ "Flags", (GlobalVars.GetStr("SSL_FlagsHeader/Text") + ": ", c => c.Flags) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal async void RetrieveSslProviderCurves() => await _RetrieveSslProviderCurves();

	internal async Task _RetrieveSslProviderCurves()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			SslProviderCurves.Clear();
			AllSslProviderCurves.Clear();

			await Task.Run(() =>
			{
				List<EccCurveSslProvider> list = EccCurveManager.EnumerateSslProviderCurves();

				_ = Dispatcher.EnqueueAsync(() =>
				{
					foreach (EccCurveSslProvider c in list)
					{
						SslProviderCurves.Add(c);
						AllSslProviderCurves.Add(c);
					}
				});
			});

			SSL_CalculateColumnWidths();
			MainInfoBar.WriteSuccess("Loaded SSL Provider curves.");
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

	private void SSL_SearchBox_TextChanged()
	{
		string? searchTerm = SslProviderCurvesSearchKeyword?.Trim();
		if (searchTerm is null)
			return;

		List<EccCurveSslProvider> filtered = AllSslProviderCurves.Where(c =>
			(!string.IsNullOrEmpty(c.Name) && c.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(c.Oid) && c.Oid.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			c.PublicKeyLengthBits.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			c.CurveType.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			c.Flags.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		SslProviderCurves.Clear();

		foreach (EccCurveSslProvider c in filtered)
			SslProviderCurves.Add(c);
	}

	internal void SSL_HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (SSL_PropertyMappings.TryGetValue(key, out (string Label, Func<EccCurveSslProvider, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SslProviderCurvesSearchKeyword,
					AllSslProviderCurves,
					SslProviderCurves,
					SSL_SortState,
					key,
					ListViewHelper.ListViewsRegistry.CBOM_SSLProviderCurves);
			}
		}
	}

	/// <summary>
	/// Copy Row for SSL Provider Curves
	/// </summary>
	internal void CopySelectedSslProviderCurves_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_SSLProviderCurves);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<EccCurveSslProvider>(lv.SelectedItems, SSL_PropertyMappings);
		}
	}

	/// <summary>
	/// Copy single property for SSL Provider Curves
	/// </summary>
	internal void CopySslProviderCurveProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_SSLProviderCurves);
		if (lv is null) return;

		if (SSL_PropertyMappings.TryGetValue(key, out (string Label, Func<EccCurveSslProvider, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<EccCurveSslProvider>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	private void SSL_CalculateColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("SSL_NameColumnHeaderBtn/Content"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SSL_OidColumnHeaderBtn/Content"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("SSL_LengthColumnHeaderBtn/Content"));
		double w4 = ListViewHelper.MeasureText(GlobalVars.GetStr("SSL_TypeColumnHeaderBtn/Content"));
		double w5 = ListViewHelper.MeasureText(GlobalVars.GetStr("SSL_FlagsColumnHeaderBtn/Content"));

		foreach (EccCurveSslProvider c in SslProviderCurves)
		{
			w1 = ListViewHelper.MeasureText(c.Name, w1);
			w2 = ListViewHelper.MeasureText(c.Oid, w2);
			w3 = ListViewHelper.MeasureText(c.PublicKeyLengthBits.ToString(), w3);
			w4 = ListViewHelper.MeasureText(c.CurveType.ToString(), w4);
			w5 = ListViewHelper.MeasureText(c.Flags.ToString(), w5);
		}

		SSL_ColumnWidth1 = new GridLength(w1);
		SSL_ColumnWidth2 = new GridLength(w2);
		SSL_ColumnWidth3 = new GridLength(w3);
		SSL_ColumnWidth4 = new GridLength(w4);
		SSL_ColumnWidth5 = new GridLength(w5);
	}

	#endregion

	// ------------------------------------------------------------
	// TLS Cipher Suites
	// ------------------------------------------------------------
	#region TLS Cipher Suites

	internal ObservableCollection<TlsCipherSuite> TlsCipherSuites = [];
	internal readonly List<TlsCipherSuite> AllTlsCipherSuites = [];

	internal string? TlsCipherSuitesSearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				TLS_SearchBox_TextChanged();
		}
	}

	internal bool TlsConfiguredOnly { get; set => SP(ref field, value); } = true;

	internal GridLength TLS_ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth8 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth9 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth10 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth11 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth12 { get; set => SP(ref field, value); }
	internal GridLength TLS_ColumnWidth13 { get; set => SP(ref field, value); }

	private ListViewHelper.SortState TLS_SortState { get; set; } = new();

	// Property mappings for TLS Cipher Suites
	private static readonly FrozenDictionary<string, (string Label, Func<TlsCipherSuite, object?> Getter)> TLS_PropertyMappings =
		new Dictionary<string, (string Label, Func<TlsCipherSuite, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("TLS_NameHeader/Text") + ": ", s => s.Name) },
			{ "Cipher", (GlobalVars.GetStr("TLS_CipherHeader/Text") + ": ", s => s.Cipher) },
			{ "CipherSuiteHex", (GlobalVars.GetStr("TLS_CSHeader/Text") + ": ", s => s.CipherSuiteHex) },
			{ "BaseCipherSuiteHex", (GlobalVars.GetStr("TLS_BaseCSHeader/Text") + ": ", s => s.BaseCipherSuiteHex) },
			{ "Hash", (GlobalVars.GetStr("TLS_HashHeader/Text") + ": ", s => s.Hash) },
			{ "Exchange", (GlobalVars.GetStr("TLS_ExchangeHeader/Text") + ": ", s => s.Exchange) },
			{ "Certificate", (GlobalVars.GetStr("TLS_CertHeader/Text") + ": ", s => s.Certificate) },
			{ "CipherLength", (GlobalVars.GetStr("TLS_CLenHeader/Text") + ": ", s => s.CipherLength) },
			{ "CipherBlockLength", (GlobalVars.GetStr("TLS_CBLenHeader/Text") + ": ", s => s.CipherBlockLength) },
			{ "HashLength", (GlobalVars.GetStr("TLS_HLenHeader/Text") + ": ", s => s.HashLength) },
			{ "MinimumExchangeLength", (GlobalVars.GetStr("TLS_MinExHeader/Text") + ": ", s => s.MinimumExchangeLength) },
			{ "MaximumExchangeLength", (GlobalVars.GetStr("TLS_MaxExHeader/Text") + ": ", s => s.MaximumExchangeLength) },
			{ "KeyType", (GlobalVars.GetStr("TLS_KeyTypeHeader/Text") + ": ", s => s.KeyType) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal async void RetrieveTlsCipherSuites() => await _RetrieveTlsCipherSuites();

	internal async Task _RetrieveTlsCipherSuites()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			TlsCipherSuites.Clear();
			AllTlsCipherSuites.Clear();

			bool configuredOnlyLocal = TlsConfiguredOnly;

			await Task.Run(() =>
			{
				List<TlsCipherSuite> cipherSuites = configuredOnlyLocal
					? CipherSuiteManager.EnumerateConfiguredCipherSuites()
					: CipherSuiteManager.EnumerateAllCipherSuites();

				_ = Dispatcher.EnqueueAsync(() =>
				{
					foreach (TlsCipherSuite s in cipherSuites)
					{
						TlsCipherSuites.Add(s);
						AllTlsCipherSuites.Add(s);
					}
				});
			});

			TLS_CalculateColumnWidths();
			MainInfoBar.WriteSuccess(configuredOnlyLocal ? "Loaded configured TLS cipher suites." : "Loaded all TLS cipher suites.");
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

	private void TLS_SearchBox_TextChanged()
	{
		string? searchTerm = TlsCipherSuitesSearchKeyword?.Trim();
		if (searchTerm is null)
			return;

		List<TlsCipherSuite> filtered = AllTlsCipherSuites.Where(s =>
			(!string.IsNullOrEmpty(s.Name) && s.Name.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(s.Cipher) && s.Cipher.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			s.CipherSuiteHex.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.BaseCipherSuiteHex.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			(!string.IsNullOrEmpty(s.Hash) && s.Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(s.Exchange) && s.Exchange.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(!string.IsNullOrEmpty(s.Certificate) && s.Certificate.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			s.CipherLength.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.CipherBlockLength.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.HashLength.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.MinimumExchangeLength.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.MaximumExchangeLength.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			s.KeyType.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		TlsCipherSuites.Clear();

		foreach (TlsCipherSuite s in filtered)
			TlsCipherSuites.Add(s);
	}

	internal void TLS_HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (TLS_PropertyMappings.TryGetValue(key, out (string Label, Func<TlsCipherSuite, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					TlsCipherSuitesSearchKeyword,
					AllTlsCipherSuites,
					TlsCipherSuites,
					TLS_SortState,
					key,
					ListViewHelper.ListViewsRegistry.CBOM_TlsCipherSuites);
			}
		}
	}

	/// <summary>
	/// Copy Row for TLS Cipher Suites
	/// </summary>
	internal void CopySelectedTlsCipherSuites_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_TlsCipherSuites);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<TlsCipherSuite>(lv.SelectedItems, TLS_PropertyMappings);
		}
	}

	/// <summary>
	/// Copy single property for TLS Cipher Suites
	/// </summary>
	internal void CopyTlsCipherSuiteProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_TlsCipherSuites);
		if (lv is null) return;

		if (TLS_PropertyMappings.TryGetValue(key, out (string Label, Func<TlsCipherSuite, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<TlsCipherSuite>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	private void TLS_CalculateColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_NameColumnHeaderBtn/Content"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_CipherColumnHeaderBtn/Content"));
		double w3 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_CSColumnHeaderBtn/Content"));
		double w4 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_BaseCSColumnHeaderBtn/Content"));
		double w5 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_HashColumnHeaderBtn/Content"));
		double w6 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_ExchangeColumnHeaderBtn/Content"));
		double w7 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_CertColumnHeaderBtn/Content"));
		double w8 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_CLenColumnHeaderBtn/Content"));
		double w9 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_CBLenColumnHeaderBtn/Content"));
		double w10 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_HLenColumnHeaderBtn/Content"));
		double w11 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_MinExColumnHeaderBtn/Content"));
		double w12 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_MaxExColumnHeaderBtn/Content"));
		double w13 = ListViewHelper.MeasureText(GlobalVars.GetStr("TLS_KeyTypeColumnHeaderBtn/Content"));

		foreach (TlsCipherSuite s in TlsCipherSuites)
		{
			w1 = ListViewHelper.MeasureText(s.Name, w1);
			w2 = ListViewHelper.MeasureText(s.Cipher, w2);
			w3 = ListViewHelper.MeasureText(s.CipherSuiteHex, w3);
			w4 = ListViewHelper.MeasureText(s.BaseCipherSuiteHex, w4);
			w5 = ListViewHelper.MeasureText(s.Hash, w5);
			w6 = ListViewHelper.MeasureText(s.Exchange, w6);
			w7 = ListViewHelper.MeasureText(s.Certificate, w7);
			w8 = ListViewHelper.MeasureText(s.CipherLength.ToString(), w8);
			w9 = ListViewHelper.MeasureText(s.CipherBlockLength.ToString(), w9);
			w10 = ListViewHelper.MeasureText(s.HashLength.ToString(), w10);
			w11 = ListViewHelper.MeasureText(s.MinimumExchangeLength.ToString(), w11);
			w12 = ListViewHelper.MeasureText(s.MaximumExchangeLength.ToString(), w12);
			w13 = ListViewHelper.MeasureText(s.KeyType.ToString(), w13);
		}

		TLS_ColumnWidth1 = new GridLength(w1);
		TLS_ColumnWidth2 = new GridLength(w2);
		TLS_ColumnWidth3 = new GridLength(w3);
		TLS_ColumnWidth4 = new GridLength(w4);
		TLS_ColumnWidth5 = new GridLength(w5);
		TLS_ColumnWidth6 = new GridLength(w6);
		TLS_ColumnWidth7 = new GridLength(w7);
		TLS_ColumnWidth8 = new GridLength(w8);
		TLS_ColumnWidth9 = new GridLength(w9);
		TLS_ColumnWidth10 = new GridLength(w10);
		TLS_ColumnWidth11 = new GridLength(w11);
		TLS_ColumnWidth12 = new GridLength(w12);
		TLS_ColumnWidth13 = new GridLength(w13);
	}

	#endregion

	// ------------------------------------------------------------
	// Registered Providers
	// ------------------------------------------------------------
	#region Registered Providers

	internal ObservableCollection<string> RegisteredProviders = [];
	internal readonly List<string> AllRegisteredProviders = [];

	internal string? RegisteredProvidersSearchKeyword
	{
		get; set
		{
			if (SPT(ref field, value))
				REG_SearchBox_TextChanged();
		}
	}

	internal GridLength REG_ColumnWidth1 { get; set => SP(ref field, value); }

	private ListViewHelper.SortState REG_SortState { get; set; } = new();

	// Property mappings for Registered Providers
	private static readonly FrozenDictionary<string, (string Label, Func<string, object?> Getter)> REG_PropertyMappings =
		new Dictionary<string, (string Label, Func<string, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Name", (GlobalVars.GetStr("REG_NameHeader/Text") + ": ", s => s) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal async void RetrieveRegisteredProviders() => await _RetrieveRegisteredProviders();

	internal async Task _RetrieveRegisteredProviders()
	{
		try
		{
			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			RegisteredProviders.Clear();
			AllRegisteredProviders.Clear();

			await Task.Run(() =>
			{
				List<string> list = AlgorithmManager.EnumerateRegisteredProviders();

				_ = Dispatcher.EnqueueAsync(() =>
				{
					foreach (string name in list)
					{
						RegisteredProviders.Add(name);
						AllRegisteredProviders.Add(name);
					}
				});
			});

			REG_CalculateColumnWidths();
			MainInfoBar.WriteSuccess("Loaded registered providers.");
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

	private void REG_SearchBox_TextChanged()
	{
		string? searchTerm = RegisteredProvidersSearchKeyword?.Trim();
		if (searchTerm is null)
			return;

		List<string> filtered = AllRegisteredProviders.Where(p =>
			!string.IsNullOrEmpty(p) && p.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
		).ToList();

		RegisteredProviders.Clear();

		foreach (string p in filtered)
			RegisteredProviders.Add(p);
	}

	internal void REG_HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			if (REG_PropertyMappings.TryGetValue(key, out (string Label, Func<string, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					RegisteredProvidersSearchKeyword,
					AllRegisteredProviders,
					RegisteredProviders,
					REG_SortState,
					key,
					ListViewHelper.ListViewsRegistry.CBOM_RegisteredProviders);
			}
		}
	}

	/// <summary>
	/// Copy Row for Registered Providers
	/// </summary>
	internal void CopySelectedRegisteredProviders_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_RegisteredProviders);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText<string>(lv.SelectedItems, REG_PropertyMappings);
		}
	}

	/// <summary>
	/// Copy single property for Registered Providers
	/// </summary>
	internal void CopyRegisteredProviderProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.CBOM_RegisteredProviders);
		if (lv is null) return;

		if (REG_PropertyMappings.TryGetValue(key, out (string Label, Func<string, object?> Getter) map))
		{
			ListViewHelper.CopyToClipboard<string>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	private void REG_CalculateColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("REG_NameColumnHeaderBtn/Content"));

		foreach (string name in RegisteredProviders)
		{
			w1 = ListViewHelper.MeasureText(name, w1);
		}

		REG_ColumnWidth1 = new GridLength(w1);
	}

	#endregion

	/// <summary>
	/// Generates Cryptographic Bill of Material.
	/// </summary>
	internal async void GenerateCBOM()
	{
		try
		{
			// Retrieve the latest data first
			await _RetrieveCryptoAlgorithms();
			await _RetrieveCngCurves();
			await _RetrieveSslProviderCurves();
			await _RetrieveTlsCipherSuites();
			await _RetrieveRegisteredProviders();

			ElementsAreEnabled = false;
			MainInfoBarIsClosable = false;

			string fileName = $"CBOM_{Environment.MachineName}.json";
			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

			if (savePath is null)
				return;

			// Build the CBOM document from the already-populated collections
			CbomDocument doc = new(
				algorithms: new List<CryptoAlgorithm>(AllCryptoAlgorithms),
				cngCurves: new List<EccCurveCng>(AllCngCurves),
				sslProviderCurves: new List<EccCurveSslProvider>(AllSslProviderCurves),
				tlsCipherSuites: new List<TlsCipherSuite>(AllTlsCipherSuites),
				registeredProviders: new List<string>(AllRegisteredProviders)
				);

			// Serialize with a resolver that combines all generated contexts
			await Task.Run(() =>
			{
				string json = JsonSerializer.Serialize(doc, CbomDocumentJsonSerializationContext.Default.CbomDocument);
				File.WriteAllText(savePath, json);
			});

			MainInfoBar.WriteSuccess($"Successfully exported CBOM to: {savePath}");
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
}
