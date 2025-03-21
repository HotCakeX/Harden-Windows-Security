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

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class SimulationVM : INotifyPropertyChanged
{

	public event PropertyChangedEventHandler? PropertyChanged;

	// private static readonly DispatcherQueue Dispatch = DispatcherQueue.GetForCurrentThread();

	internal readonly ObservableCollection<SimulationOutput> SimulationOutputs = [];

	// Store all outputs for searching
	internal readonly List<SimulationOutput> AllSimulationOutputs = [];


	#region UI-Bound Properties


	#endregion


	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	private GridLength _columnWidth1;
	internal GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	internal GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	internal GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	internal GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	internal GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	internal GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	private GridLength _columnWidth7;
	internal GridLength ColumnWidth7
	{
		get => _columnWidth7;
		set { _columnWidth7 = value; OnPropertyChanged(nameof(ColumnWidth7)); }
	}

	private GridLength _columnWidth8;
	internal GridLength ColumnWidth8
	{
		get => _columnWidth8;
		set { _columnWidth8 = value; OnPropertyChanged(nameof(ColumnWidth8)); }
	}

	private GridLength _columnWidth9;
	internal GridLength ColumnWidth9
	{
		get => _columnWidth9;
		set { _columnWidth9 = value; OnPropertyChanged(nameof(ColumnWidth9)); }
	}

	private GridLength _columnWidth10;
	internal GridLength ColumnWidth10
	{
		get => _columnWidth10;
		set { _columnWidth10 = value; OnPropertyChanged(nameof(ColumnWidth10)); }
	}

	private GridLength _columnWidth11;
	internal GridLength ColumnWidth11
	{
		get => _columnWidth11;
		set { _columnWidth11 = value; OnPropertyChanged(nameof(ColumnWidth11)); }
	}

	private GridLength _columnWidth12;
	internal GridLength ColumnWidth12
	{
		get => _columnWidth12;
		set { _columnWidth12 = value; OnPropertyChanged(nameof(ColumnWidth12)); }
	}

	private GridLength _columnWidth13;
	internal GridLength ColumnWidth13
	{
		get => _columnWidth13;
		set { _columnWidth13 = value; OnPropertyChanged(nameof(ColumnWidth13)); }
	}

	private GridLength _columnWidth14;
	internal GridLength ColumnWidth14
	{
		get => _columnWidth14;
		set { _columnWidth14 = value; OnPropertyChanged(nameof(ColumnWidth14)); }
	}

	private GridLength _columnWidth15;
	internal GridLength ColumnWidth15
	{
		get => _columnWidth15;
		set { _columnWidth15 = value; OnPropertyChanged(nameof(ColumnWidth15)); }
	}


	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PathHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SourceHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsAuthorizedHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("MatchCriteriaHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SpecificFileNameLevelMatchCriteriaHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerIDHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerNameHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerCertRootHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerCertPublisherHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerScopeHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertSubjectCNHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertIssuerCNHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertNotAfterHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("CertTBSValueHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (SimulationOutput item in SimulationOutputs)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.Path);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.Source);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.IsAuthorized.ToString());
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.MatchCriteria?.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.SpecificFileNameLevelMatchCriteria);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.SignerID);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.SignerName);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.SignerCertRoot);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.SignerCertPublisher);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.SignerScope);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.CertSubjectCN);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.CertIssuerCN);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.CertNotAfter);
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.CertTBSValue);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w15 > maxWidth15) maxWidth15 = w15;
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
		ColumnWidth6 = new GridLength(maxWidth6);
		ColumnWidth7 = new GridLength(maxWidth7);
		ColumnWidth8 = new GridLength(maxWidth8);
		ColumnWidth9 = new GridLength(maxWidth9);
		ColumnWidth10 = new GridLength(maxWidth10);
		ColumnWidth11 = new GridLength(maxWidth11);
		ColumnWidth12 = new GridLength(maxWidth12);
		ColumnWidth13 = new GridLength(maxWidth13);
		ColumnWidth14 = new GridLength(maxWidth14);
		ColumnWidth15 = new GridLength(maxWidth15);
	}

	#endregion


	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

}
