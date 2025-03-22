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
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class EventLogsPolicyCreationVM : INotifyPropertyChanged
{

	public event PropertyChangedEventHandler? PropertyChanged;

	// private static readonly DispatcherQueue Dispatch = DispatcherQueue.GetForCurrentThread();

	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal readonly ObservableCollection<FileIdentity> FileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> AllFileIdentities = [];


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

	private GridLength _columnWidth16;
	internal GridLength ColumnWidth16
	{
		get => _columnWidth16;
		set { _columnWidth16 = value; OnPropertyChanged(nameof(ColumnWidth16)); }
	}

	private GridLength _columnWidth17;
	internal GridLength ColumnWidth17
	{
		get => _columnWidth17;
		set { _columnWidth17 = value; OnPropertyChanged(nameof(ColumnWidth17)); }
	}

	private GridLength _columnWidth18;
	internal GridLength ColumnWidth18
	{
		get => _columnWidth18;
		set { _columnWidth18 = value; OnPropertyChanged(nameof(ColumnWidth18)); }
	}

	private GridLength _columnWidth19;
	internal GridLength ColumnWidth19
	{
		get => _columnWidth19;
		set { _columnWidth19 = value; OnPropertyChanged(nameof(ColumnWidth19)); }
	}

	private GridLength _columnWidth20;
	internal GridLength ColumnWidth20
	{
		get => _columnWidth20;
		set { _columnWidth20 = value; OnPropertyChanged(nameof(ColumnWidth20)); }
	}

	private GridLength _columnWidth21;
	internal GridLength ColumnWidth21
	{
		get => _columnWidth21;
		set { _columnWidth21 = value; OnPropertyChanged(nameof(ColumnWidth21)); }
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
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1FlatHashHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256FlatHashHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyGUIDHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyNameHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ComputerNameHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FileIdentities)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.FileName);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.TimeCreated.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.SignatureStatus.ToString());
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.Action.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.OriginalFileName);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.InternalName);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.FileDescription);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.ProductName);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.FileVersion?.ToString());
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.PackageFamilyName);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.SHA256Hash);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.SHA1Hash);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.SISigningScenario.ToString());
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewHelper.MeasureTextWidth(item.SHA1FlatHash);
			if (w15 > maxWidth15) maxWidth15 = w15;

			double w16 = ListViewHelper.MeasureTextWidth(item.SHA256FlatHash);
			if (w16 > maxWidth16) maxWidth16 = w16;

			double w17 = ListViewHelper.MeasureTextWidth(item.FilePublishersToDisplay);
			if (w17 > maxWidth17) maxWidth17 = w17;

			double w18 = ListViewHelper.MeasureTextWidth(item.Opus);
			if (w18 > maxWidth18) maxWidth18 = w18;

			double w19 = ListViewHelper.MeasureTextWidth(item.PolicyGUID.ToString());
			if (w19 > maxWidth19) maxWidth19 = w19;

			double w20 = ListViewHelper.MeasureTextWidth(item.PolicyName);
			if (w20 > maxWidth20) maxWidth20 = w20;

			double w21 = ListViewHelper.MeasureTextWidth(item.ComputerName);
			if (w21 > maxWidth21) maxWidth21 = w21;
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
		ColumnWidth16 = new GridLength(maxWidth16);
		ColumnWidth17 = new GridLength(maxWidth17);
		ColumnWidth18 = new GridLength(maxWidth18);
		ColumnWidth19 = new GridLength(maxWidth19);
		ColumnWidth20 = new GridLength(maxWidth20);
		ColumnWidth21 = new GridLength(maxWidth21);
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
