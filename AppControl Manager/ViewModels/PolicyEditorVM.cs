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
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

public partial class PolicyEditorVM : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	private static PolicyEditorVM? _instance;

	private static readonly DispatcherQueue Dispatch = DispatcherQueue.GetForCurrentThread();


	#region Column Widths


	// ------------ File Based ------------

	private GridLength _FileBasedColumnWidth1;
	public GridLength FileBasedColumnWidth1
	{
		get => _FileBasedColumnWidth1;
		set { _FileBasedColumnWidth1 = value; OnPropertyChanged(nameof(FileBasedColumnWidth1)); }
	}

	private GridLength _FileBasedColumnWidth2;
	public GridLength FileBasedColumnWidth2
	{
		get => _FileBasedColumnWidth2;
		set { _FileBasedColumnWidth2 = value; OnPropertyChanged(nameof(FileBasedColumnWidth2)); }
	}

	private GridLength _FileBasedColumnWidth3;
	public GridLength FileBasedColumnWidth3
	{
		get => _FileBasedColumnWidth3;
		set { _FileBasedColumnWidth3 = value; OnPropertyChanged(nameof(FileBasedColumnWidth3)); }
	}

	private GridLength _FileBasedColumnWidth4;
	public GridLength FileBasedColumnWidth4
	{
		get => _FileBasedColumnWidth4;
		set { _FileBasedColumnWidth4 = value; OnPropertyChanged(nameof(FileBasedColumnWidth4)); }
	}

	private GridLength _FileBasedColumnWidth5;
	public GridLength FileBasedColumnWidth5
	{
		get => _FileBasedColumnWidth5;
		set { _FileBasedColumnWidth5 = value; OnPropertyChanged(nameof(FileBasedColumnWidth5)); }
	}

	private GridLength _FileBasedColumnWidth6;
	public GridLength FileBasedColumnWidth6
	{
		get => _FileBasedColumnWidth6;
		set { _FileBasedColumnWidth6 = value; OnPropertyChanged(nameof(FileBasedColumnWidth6)); }
	}

	private GridLength _FileBasedColumnWidth7;
	public GridLength FileBasedColumnWidth7
	{
		get => _FileBasedColumnWidth7;
		set { _FileBasedColumnWidth7 = value; OnPropertyChanged(nameof(FileBasedColumnWidth7)); }
	}

	private GridLength _FileBasedColumnWidth8;
	public GridLength FileBasedColumnWidth8
	{
		get => _FileBasedColumnWidth8;
		set { _FileBasedColumnWidth8 = value; OnPropertyChanged(nameof(FileBasedColumnWidth8)); }
	}

	private GridLength _FileBasedColumnWidth9;
	public GridLength FileBasedColumnWidth9
	{
		get => _FileBasedColumnWidth9;
		set { _FileBasedColumnWidth9 = value; OnPropertyChanged(nameof(FileBasedColumnWidth9)); }
	}

	private GridLength _FileBasedColumnWidth10;
	public GridLength FileBasedColumnWidth10
	{
		get => _FileBasedColumnWidth10;
		set { _FileBasedColumnWidth10 = value; OnPropertyChanged(nameof(FileBasedColumnWidth10)); }
	}

	private GridLength _FileBasedColumnWidth11;
	public GridLength FileBasedColumnWidth11
	{
		get => _FileBasedColumnWidth11;
		set { _FileBasedColumnWidth11 = value; OnPropertyChanged(nameof(FileBasedColumnWidth11)); }
	}

	private GridLength _FileBasedColumnWidth12;
	public GridLength FileBasedColumnWidth12
	{
		get => _FileBasedColumnWidth12;
		set { _FileBasedColumnWidth12 = value; OnPropertyChanged(nameof(FileBasedColumnWidth12)); }
	}

	private GridLength _FileBasedColumnWidth13;
	public GridLength FileBasedColumnWidth13
	{
		get => _FileBasedColumnWidth13;
		set { _FileBasedColumnWidth13 = value; OnPropertyChanged(nameof(FileBasedColumnWidth13)); }
	}

	private GridLength _FileBasedColumnWidth14;
	public GridLength FileBasedColumnWidth14
	{
		get => _FileBasedColumnWidth14;
		set { _FileBasedColumnWidth14 = value; OnPropertyChanged(nameof(FileBasedColumnWidth14)); }
	}



	// ------------ Signature Based ------------

	private GridLength _SignatureBasedColumnWidth1;
	public GridLength SignatureBasedColumnWidth1
	{
		get => _SignatureBasedColumnWidth1;
		set { _SignatureBasedColumnWidth1 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth1)); }
	}

	private GridLength _SignatureBasedColumnWidth2;
	public GridLength SignatureBasedColumnWidth2
	{
		get => _SignatureBasedColumnWidth2;
		set { _SignatureBasedColumnWidth2 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth2)); }
	}

	private GridLength _SignatureBasedColumnWidth3;
	public GridLength SignatureBasedColumnWidth3
	{
		get => _SignatureBasedColumnWidth3;
		set { _SignatureBasedColumnWidth3 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth3)); }
	}

	private GridLength _SignatureBasedColumnWidth4;
	public GridLength SignatureBasedColumnWidth4
	{
		get => _SignatureBasedColumnWidth4;
		set { _SignatureBasedColumnWidth4 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth4)); }
	}

	private GridLength _SignatureBasedColumnWidth5;
	public GridLength SignatureBasedColumnWidth5
	{
		get => _SignatureBasedColumnWidth5;
		set { _SignatureBasedColumnWidth5 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth5)); }
	}

	private GridLength _SignatureBasedColumnWidth6;
	public GridLength SignatureBasedColumnWidth6
	{
		get => _SignatureBasedColumnWidth6;
		set { _SignatureBasedColumnWidth6 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth6)); }
	}

	private GridLength _SignatureBasedColumnWidth7;
	public GridLength SignatureBasedColumnWidth7
	{
		get => _SignatureBasedColumnWidth7;
		set { _SignatureBasedColumnWidth7 = value; OnPropertyChanged(nameof(SignatureBasedColumnWidth7)); }
	}

	#endregion

	// Observable Collections bound to the ListViews in the UI via compiled bindings
	internal readonly ObservableCollection<PolicyEditor.FileBasedRulesForListView> FileRulesCollection = [];
	internal readonly List<PolicyEditor.FileBasedRulesForListView> FileRulesCollectionList = [];

	internal readonly ObservableCollection<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesCollection = [];
	internal readonly List<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesCollectionList = [];

	// Don't need getters/setters via OnPropertyChanged for the collections above since it is an observable collection and we don't replace it completely
	// We just use the .Add(), .Remove() etc. methods

	/*
	private ObservableCollection<PolicyEditor.FileBasedRulesForListView> _fileRulesCollection = [];
	internal ObservableCollection<PolicyEditor.FileBasedRulesForListView> FileRulesCollection
	{
		get => _fileRulesCollection;
		set
		{
			if (_fileRulesCollection != value)
			{
				_fileRulesCollection = value;
				OnPropertyChanged(nameof(FileRulesCollection));
			}
		}
	}


	private ObservableCollection<PolicyEditor.SignatureBasedRulesForListView> _signatureRulesCollection = [];
	internal ObservableCollection<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesCollection
	{
		get => _signatureRulesCollection;
		set
		{
			if (_signatureRulesCollection != value)
			{
				_signatureRulesCollection = value;
				OnPropertyChanged(nameof(SignatureRulesCollection));
			}
		}
	}
	*/


	#region UI-Bound Properties

	private bool _UIElementsEnabledState = true;
	public bool UIElementsEnabledState
	{
		get => _UIElementsEnabledState;
		set => SetProperty(_UIElementsEnabledState, value, newValue => _UIElementsEnabledState = newValue);
	}

	private string? _selectedPolicyFile;
	public string? SelectedPolicyFile
	{
		get => _selectedPolicyFile;
		set => SetProperty(_selectedPolicyFile, value, newValue => _selectedPolicyFile = newValue);
	}

	private bool _TextsAreSelectableToggleState;
	public bool TextsAreSelectableToggleState
	{
		get => _TextsAreSelectableToggleState;
		set => SetProperty(_TextsAreSelectableToggleState, value, newValue => _TextsAreSelectableToggleState = newValue);
	}

	private string _FileBasedCollectionTabItemHeader = "File-based Rules - count: 0";
	public string FileBasedCollectionTabItemHeader
	{
		get => _FileBasedCollectionTabItemHeader;
		set => SetProperty(_FileBasedCollectionTabItemHeader, value, newValue => _FileBasedCollectionTabItemHeader = newValue);
	}

	private string _SignatureBasedCollectionTabItemHeader = "Signature-based Rules - count: 0";
	public string SignatureBasedCollectionTabItemHeader
	{
		get => _SignatureBasedCollectionTabItemHeader;
		set => SetProperty(_SignatureBasedCollectionTabItemHeader, value, newValue => _SignatureBasedCollectionTabItemHeader = newValue);
	}

	private string _PolicyNameTextBox = string.Empty;
	public string PolicyNameTextBox
	{
		get => _PolicyNameTextBox;
		set => SetProperty(_PolicyNameTextBox, value, newValue => _PolicyNameTextBox = newValue);
	}

	private string? _MainTeachingSubTitle;
	public string? MainTeachingSubTitle
	{
		get => _MainTeachingSubTitle;
		set => SetProperty(_MainTeachingSubTitle, value, newValue => _MainTeachingSubTitle = newValue);
	}

	private string? _MainTeachingTitle;
	public string? MainTeachingTitle
	{
		get => _MainTeachingTitle;
		set => SetProperty(_MainTeachingTitle, value, newValue => _MainTeachingTitle = newValue);
	}

	private bool _MainTeachingTipIsOpen;
	public bool MainTeachingTipIsOpen
	{
		get => _MainTeachingTipIsOpen;
		set => SetProperty(_MainTeachingTipIsOpen, value, newValue => _MainTeachingTipIsOpen = newValue);
	}

	private string? _PolicyIDTextBox;
	public string? PolicyIDTextBox
	{
		get => _PolicyIDTextBox;
		set => SetProperty(_PolicyIDTextBox, value, newValue => _PolicyIDTextBox = newValue);
	}

	private string? _PolicyBaseIDTextBox;
	public string? PolicyBaseIDTextBox
	{
		get => _PolicyBaseIDTextBox;
		set => SetProperty(_PolicyBaseIDTextBox, value, newValue => _PolicyBaseIDTextBox = newValue);
	}

	private string? _PolicyVersionTextBox;
	public string? PolicyVersionTextBox
	{
		get => _PolicyVersionTextBox;
		set => SetProperty(_PolicyVersionTextBox, value, newValue => _PolicyVersionTextBox = newValue);
	}

	private string? _PolicyInfoIDTextBox;
	public string? PolicyInfoIDTextBox
	{
		get => _PolicyInfoIDTextBox;
		set => SetProperty(_PolicyInfoIDTextBox, value, newValue => _PolicyInfoIDTextBox = newValue);
	}

	private PolicyType? _PolicyTypeComboBox;
	public PolicyType? PolicyTypeComboBox
	{
		get => _PolicyTypeComboBox;
		set => SetProperty(_PolicyTypeComboBox, value, newValue => _PolicyTypeComboBox = newValue);
	}

	// The valid values for the ItemsSource of the Policy Type ComboBox
	public readonly Array ComboBoxSource = Enum.GetValues<PolicyType>();

	private string? _HVCIOptionComboBox;
	public string? HVCIOptionComboBox
	{
		get => _HVCIOptionComboBox;
		set => SetProperty(_HVCIOptionComboBox, value, newValue => _HVCIOptionComboBox = newValue);
	}

	#region Counting properties

	private string? _AllowRulesCount = "• Allow Rules count: 0";
	public string? AllowRulesCount
	{
		get => _AllowRulesCount;
		set => SetProperty(_AllowRulesCount, value, newValue => _AllowRulesCount = newValue);
	}

	private string? _DenyRulesCount = "• Deny Rules count: 0";
	public string? DenyRulesCount
	{
		get => _DenyRulesCount;
		set => SetProperty(_DenyRulesCount, value, newValue => _DenyRulesCount = newValue);
	}

	private string? _FileRulesCount = "• File Rules count: 0";
	public string? FileRulesCount
	{
		get => _FileRulesCount;
		set => SetProperty(_FileRulesCount, value, newValue => _FileRulesCount = newValue);
	}

	private string? _FilePublishersCount = "  ⚬ File Publisher Rules count: 0";
	public string? FilePublishersCount
	{
		get => _FilePublishersCount;
		set => SetProperty(_FilePublishersCount, value, newValue => _FilePublishersCount = newValue);
	}

	private string? _WHQLFilePublishersCount = "  ⚬ WHQL File Publisher Rules count: 0";
	public string? WHQLFilePublishersCount
	{
		get => _WHQLFilePublishersCount;
		set => SetProperty(_WHQLFilePublishersCount, value, newValue => _WHQLFilePublishersCount = newValue);
	}

	private string? _FileAttributesCount = "• File Attributes count: 0";
	public string? FileAttributesCount
	{
		get => _FileAttributesCount;
		set => SetProperty(_FileAttributesCount, value, newValue => _FileAttributesCount = newValue);
	}

	private string? _WHQLPublishersCount = "• WHQL Publisher Rules count: 0";
	public string? WHQLPublishersCount
	{
		get => _WHQLPublishersCount;
		set => SetProperty(_WHQLPublishersCount, value, newValue => _WHQLPublishersCount = newValue);
	}

	private string? _GenericSignersCount = "• Generic Signer Rules count: 0";
	public string? GenericSignersCount
	{
		get => _GenericSignersCount;
		set => SetProperty(_GenericSignersCount, value, newValue => _GenericSignersCount = newValue);
	}

	private string? _UpdatePolicySignersCount = "• Update Policy Signer Rules count: 0";
	public string? UpdatePolicySignersCount
	{
		get => _UpdatePolicySignersCount;
		set => SetProperty(_UpdatePolicySignersCount, value, newValue => _UpdatePolicySignersCount = newValue);
	}

	private string? _SupplementalPolicySignersCount = "• Supplemental Policy Signer Rules count: 0";
	public string? SupplementalPolicySignersCount
	{
		get => _SupplementalPolicySignersCount;
		set => SetProperty(_SupplementalPolicySignersCount, value, newValue => _SupplementalPolicySignersCount = newValue);
	}

	#endregion

	#endregion


	private static uint GetHVCIOptionValue(string key) =>
		key switch
		{
			"Enabled - Strict" => 2,
			"Enabled" => 1,
			"Debug Mode" => 4,
			"Disable is Allowed" => 8,
			"None" => 0,
			_ => throw new ArgumentException($"Invalid HVCI option key: {key}", nameof(key))
		};


	private static string GetHVCIOptionKey(uint value) =>
	value switch
	{
		2 => "Enabled - Strict",
		1 => "Enabled",
		4 => "Debug Mode",
		8 => "Disable is Allowed",
		0 => "None",
		_ => throw new ArgumentException($"Invalid HVCI option value: {value}", nameof(value))
	};



	// All of these must be nullified/emptied during policy load

	// To store the EKUs, will use them during policy creation
	private static IEnumerable<EKU> ekusToUse = [];

	// To store the user-selected XML policy objectified
	private static SiPolicy.SiPolicy? PolicyObj;

	// To store the signerCollection
	private static SignerCollection? SignerCollectionCol;


	/// <summary>
	/// For File Based rules
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	private void CalculateFileBasedListViewColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth("ID");
		double maxWidth2 = ListViewHelper.MeasureTextWidth("Friendly Name");
		double maxWidth3 = ListViewHelper.MeasureTextWidth("Hash");
		double maxWidth4 = ListViewHelper.MeasureTextWidth("File Name");
		double maxWidth5 = ListViewHelper.MeasureTextWidth("Internal Name");
		double maxWidth6 = ListViewHelper.MeasureTextWidth("File Description");
		double maxWidth7 = ListViewHelper.MeasureTextWidth("Product Name");
		double maxWidth8 = ListViewHelper.MeasureTextWidth("File Path");
		double maxWidth9 = ListViewHelper.MeasureTextWidth("Minimum File Version");
		double maxWidth10 = ListViewHelper.MeasureTextWidth("Maximum File Version");
		double maxWidth11 = ListViewHelper.MeasureTextWidth("Package Family Name");
		double maxWidth12 = ListViewHelper.MeasureTextWidth("Package Version");
		double maxWidth13 = ListViewHelper.MeasureTextWidth("App IDs");
		double maxWidth14 = ListViewHelper.MeasureTextWidth("Type");

		// Iterate over all items to determine the widest string for each column.
		foreach (PolicyEditor.FileBasedRulesForListView item in FileRulesCollection)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.Id);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.FriendlyName);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.Hash);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.FileName);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.InternalName);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.FileDescription);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.ProductName);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.MinimumFileVersion);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.MaximumFileVersion);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.PackageFamilyName);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.PackageVersion);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.AppIDs);
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.Type);
			if (w14 > maxWidth14) maxWidth14 = w14;
		}

		// Set the column width properties.
		FileBasedColumnWidth1 = new GridLength(maxWidth1);
		FileBasedColumnWidth2 = new GridLength(maxWidth2);
		FileBasedColumnWidth3 = new GridLength(maxWidth3);
		FileBasedColumnWidth4 = new GridLength(maxWidth4);
		FileBasedColumnWidth5 = new GridLength(maxWidth5);
		FileBasedColumnWidth6 = new GridLength(maxWidth6);
		FileBasedColumnWidth7 = new GridLength(maxWidth7);
		FileBasedColumnWidth8 = new GridLength(maxWidth8);
		FileBasedColumnWidth9 = new GridLength(maxWidth9);
		FileBasedColumnWidth10 = new GridLength(maxWidth10);
		FileBasedColumnWidth11 = new GridLength(maxWidth11);
		FileBasedColumnWidth12 = new GridLength(maxWidth12);
		FileBasedColumnWidth13 = new GridLength(maxWidth13);
		FileBasedColumnWidth14 = new GridLength(maxWidth14);
	}


	/// <summary>
	/// For Signature Based rules
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	private void CalculateSignatureBasedListViewColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth("ID");
		double maxWidth2 = ListViewHelper.MeasureTextWidth("Name");
		double maxWidth3 = ListViewHelper.MeasureTextWidth("Cert Root");
		double maxWidth4 = ListViewHelper.MeasureTextWidth("Cert Publisher");
		double maxWidth5 = ListViewHelper.MeasureTextWidth("Cert OEM ID");
		double maxWidth6 = ListViewHelper.MeasureTextWidth("Cert EKU");
		double maxWidth7 = ListViewHelper.MeasureTextWidth("Cert Issuer");

		// Iterate over all items to determine the widest string for each column.
		foreach (PolicyEditor.SignatureBasedRulesForListView item in SignatureRulesCollection)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.Id);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.Name);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.CertRoot);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.CertPublisher);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.CertOemID);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.CertificateEKU);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.CertIssuer);
			if (w7 > maxWidth7) maxWidth7 = w7;
		}

		// Set the column width properties.
		SignatureBasedColumnWidth1 = new GridLength(maxWidth1);
		SignatureBasedColumnWidth2 = new GridLength(maxWidth2);
		SignatureBasedColumnWidth3 = new GridLength(maxWidth3);
		SignatureBasedColumnWidth4 = new GridLength(maxWidth4);
		SignatureBasedColumnWidth5 = new GridLength(maxWidth5);
		SignatureBasedColumnWidth6 = new GridLength(maxWidth6);
		SignatureBasedColumnWidth7 = new GridLength(maxWidth7);
	}


	/// <summary>
	/// Extracts the data from the user selected policy XML file and puts them in the UI elements such as the ListViews
	/// </summary>
	internal async void ProcessData()
	{

		try
		{

			MainTeachingTipIsOpen = false;

			UIElementsEnabledState = false;

			if (SelectedPolicyFile is null)
			{
				MainTeachingTitle = "No policy file selected";
				MainTeachingSubTitle = "Please select a policy file to view its contents.";
				MainTeachingTipIsOpen = true;

				return;
			}

			// Clear the class variables
			PolicyObj = null;
			ekusToUse = [];
			SignerCollectionCol = null;

			// Clear the ListView collections and their backing Lists before inserting new data into them
			FileRulesCollection.Clear();
			FileRulesCollectionList.Clear();
			SignatureRulesCollection.Clear();
			SignatureRulesCollectionList.Clear();

			// Collections to deserialize the policy object into
			IEnumerable<object> fileRulesNode = [];
			List<Signer> signers = [];
			IEnumerable<CiSigner> ciSigners = [];
			IEnumerable<AllowedSigner> userModeAllowedSigners = [];
			IEnumerable<DeniedSigner> userModeDeniedSigners = [];
			IEnumerable<AllowedSigner> kernelModeAllowedSigners = [];
			IEnumerable<DeniedSigner> kernelModeDeniedSigners = [];
			IEnumerable<SupplementalPolicySigner> supplementalPolicySignersCol = [];
			IEnumerable<UpdatePolicySigner> updatePolicySignersCol = [];
			HashSet<FileRuleRule> fileRules = [];
			HashSet<DenyRule> denyRules = [];
			HashSet<AllowRule> allowRules = [];
			IEnumerable<FileRuleRef> kernelModeFileRulesRefs = [];
			IEnumerable<FileRuleRef> userModeFileRulesRefs = [];

			await Task.Run(() =>
			{
				// Close the empty rules in the main policy
				CloseEmptyXmlNodesSemantic.Close(SelectedPolicyFile);

				// Instantiate the policy
				PolicyObj = Management.Initialize(SelectedPolicyFile, null);


				#region Extract policy details

				foreach (Setting item in PolicyObj.Settings)
				{
					if (string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
					{

						if (item.Value.Item is not null)

							_ = Dispatch.TryEnqueue(() =>
							{
								PolicyNameTextBox = (string)item.Value.Item;
							});

						break;
					}
				}


				_ = Dispatch.TryEnqueue(() =>
				{
					PolicyIDTextBox = PolicyObj.PolicyID;
					PolicyBaseIDTextBox = PolicyObj.BasePolicyID;
					PolicyVersionTextBox = PolicyObj.VersionEx;
					PolicyTypeComboBox = PolicyObj.PolicyType;
				});


				foreach (Setting item in PolicyObj.Settings)
				{
					if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
					{

						if (item.Value.Item is not null)

							_ = Dispatch.TryEnqueue(() =>
							{
								PolicyInfoIDTextBox = (string)item.Value.Item;
							});

						break;
					}
				}


				if (PolicyObj.HvciOptionsSpecified)
				{
					_ = Dispatch.TryEnqueue(() =>
					{
						HVCIOptionComboBox = GetHVCIOptionKey(PolicyObj.HvciOptions);
					});
				}
				// If policy doesn't have HVCI field then set it to None on the UI ComboBox
				else
				{
					_ = Dispatch.TryEnqueue(() =>
					{
						HVCIOptionComboBox = GetHVCIOptionKey(0);
					});
				}

				#endregion

				// Deserialize the policy and populate the collections
				Merger.PolicyDeserializer(
					[PolicyObj],
					ref ekusToUse,
					ref fileRulesNode,
					ref signers,
					ref ciSigners,
					ref userModeAllowedSigners,
					ref userModeDeniedSigners,
					ref kernelModeAllowedSigners,
					ref kernelModeDeniedSigners,
					ref supplementalPolicySignersCol,
					ref updatePolicySignersCol,
					ref fileRules,
					ref denyRules,
					ref allowRules,
					ref SignerCollectionCol,
					ref kernelModeFileRulesRefs,
					ref userModeFileRulesRefs);
			});

			// Process the Allow rules

			uint _AllowRulesCount = 0;

			foreach (AllowRule allowRule in allowRules)
			{

				_AllowRulesCount++;


				PolicyEditor.FileBasedRulesForListView temp1 = new
				(
					id: allowRule.AllowElement.ID,
					friendlyName: allowRule.AllowElement.FriendlyName,
					fileName: allowRule.AllowElement.FileName,
					internalName: allowRule.AllowElement.InternalName,
					fileDescription: allowRule.AllowElement.FileDescription,
					productName: allowRule.AllowElement.ProductName,
					packageFamilyName: allowRule.AllowElement.PackageFamilyName,
					packageVersion: allowRule.AllowElement.PackageVersion,
					minimumFileVersion: allowRule.AllowElement.MinimumFileVersion,
					maximumFileVersion: allowRule.AllowElement.MaximumFileVersion,
					hash: CustomSerialization.ConvertByteArrayToHex(allowRule.AllowElement.Hash),
					appIDs: allowRule.AllowElement.AppIDs,
					filePath: allowRule.AllowElement.FilePath,
					type: null,
					sourceType: PolicyEditor.FileBasedRuleType.Allow,
					source: allowRule,
					parentViewModel: this
				);


				FileRulesCollection.Add(temp1);
				FileRulesCollectionList.Add(temp1);
			}

			AllowRulesCount = $"• Allow Rules count: {_AllowRulesCount}";

			// Process the Deny rules

			uint _DenyRulesCount = 0;

			foreach (DenyRule denyRule in denyRules)
			{

				_DenyRulesCount++;

				PolicyEditor.FileBasedRulesForListView temp2 = new
				(
					id: denyRule.DenyElement.ID,
					friendlyName: denyRule.DenyElement.FriendlyName,
					fileName: denyRule.DenyElement.FileName,
					internalName: denyRule.DenyElement.InternalName,
					fileDescription: denyRule.DenyElement.FileDescription,
					productName: denyRule.DenyElement.ProductName,
					packageFamilyName: denyRule.DenyElement.PackageFamilyName,
					packageVersion: denyRule.DenyElement.PackageVersion,
					minimumFileVersion: denyRule.DenyElement.MinimumFileVersion,
					maximumFileVersion: denyRule.DenyElement.MaximumFileVersion,
					hash: CustomSerialization.ConvertByteArrayToHex(denyRule.DenyElement.Hash),
					appIDs: denyRule.DenyElement.AppIDs,
					filePath: denyRule.DenyElement.FilePath,
					type: null,
					sourceType: PolicyEditor.FileBasedRuleType.Deny,
					source: denyRule,
					parentViewModel: this
				);


				FileRulesCollection.Add(temp2);
				FileRulesCollectionList.Add(temp2);
			}

			DenyRulesCount = $"• Deny Rules count: {_DenyRulesCount}";

			// Process the File rules

			uint _FileRulesCount = 0;

			foreach (FileRuleRule fileRule in fileRules)
			{

				_FileRulesCount++;

				PolicyEditor.FileBasedRulesForListView temp3 = new
				(
					id: fileRule.FileRuleElement.ID,
					friendlyName: fileRule.FileRuleElement.FriendlyName,
					fileName: fileRule.FileRuleElement.FileName,
					internalName: fileRule.FileRuleElement.InternalName,
					fileDescription: fileRule.FileRuleElement.FileDescription,
					productName: fileRule.FileRuleElement.ProductName,
					packageFamilyName: fileRule.FileRuleElement.PackageFamilyName,
					packageVersion: fileRule.FileRuleElement.PackageVersion,
					minimumFileVersion: fileRule.FileRuleElement.MinimumFileVersion,
					maximumFileVersion: fileRule.FileRuleElement.MaximumFileVersion,
					hash: CustomSerialization.ConvertByteArrayToHex(fileRule.FileRuleElement.Hash),
					appIDs: fileRule.FileRuleElement.AppIDs,
					filePath: fileRule.FileRuleElement.FilePath,
					type: fileRule.FileRuleElement.Type.ToString(),
					sourceType: PolicyEditor.FileBasedRuleType.FileRule,
					source: fileRule,
					parentViewModel: this
				);


				FileRulesCollection.Add(temp3);
				FileRulesCollectionList.Add(temp3);
			}

			FileRulesCount = $"• File Rules count: {_FileRulesCount}";

			#region FileAttribs processing

			// a list of file attributes in the <FileRules> node
			List<FileAttrib> fileAttribs = fileRulesNode.OfType<FileAttrib>().ToList() ?? [];

			FileAttributesCount = $"• File Attributes count: {fileAttribs.Count}";

			// Add each FileAttrib to the ListView
			foreach (FileAttrib item in fileAttribs)
			{
				PolicyEditor.FileBasedRulesForListView temp4 = new
							(
								id: item.ID,
								friendlyName: item.FriendlyName,
								fileName: item.FileName,
								internalName: item.InternalName,
								fileDescription: item.FileDescription,
								productName: item.ProductName,
								packageFamilyName: item.PackageFamilyName,
								packageVersion: item.PackageVersion,
								minimumFileVersion: item.MinimumFileVersion,
								maximumFileVersion: item.MaximumFileVersion,
								hash: CustomSerialization.ConvertByteArrayToHex(item.Hash),
								appIDs: item.AppIDs,
								filePath: item.FilePath,
								type: null,
								sourceType: PolicyEditor.FileBasedRuleType.CompoundPublisher,
								source: item,
								parentViewModel: this
							);

				FileRulesCollection.Add(temp4);
				FileRulesCollectionList.Add(temp4);
			}


			// Count the number of WHQLFilePublisher and FilePublisher signer types
			uint _FilePublisherRulesCount = 0;
			uint _WHQLFilePublisherRulesCount = 0;

			if (SignerCollectionCol is not null)
			{
				_FilePublisherRulesCount = (uint)SignerCollectionCol.FilePublisherSigners.Count;

				FilePublishersCount = $"  ⚬ File Publisher Rules count: {_FilePublisherRulesCount}";

				_WHQLFilePublisherRulesCount = (uint)SignerCollectionCol.WHQLFilePublishers.Count;

				WHQLFilePublishersCount = $"  ⚬ WHQL File Publisher Rules count: {_WHQLFilePublisherRulesCount}";
			}

			#endregion


			// Calculate the column widths for File Based rules after processing them
			CalculateFileBasedListViewColumnWidths();


			if (SignerCollectionCol is not null)
			{

				// Process the Generic signer rules for levels: Publisher, PCA Certificate, Leaf Certificate, Root Certificate

				uint _GenericSignerRulesCount = 0;

				foreach (SignerRule sig in SignerCollectionCol.SignerRules)
				{

					_GenericSignerRulesCount++;


					PolicyEditor.SignatureBasedRulesForListView temp6 = new
						(
						certRoot: CustomSerialization.ConvertByteArrayToHex(sig.SignerElement.CertRoot?.Value),
						certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
						certIssuer: sig.SignerElement.CertIssuer?.Value,
						certPublisher: sig.SignerElement.CertPublisher?.Value,
						certOemID: sig.SignerElement.CertOemID?.Value,
						name: sig.SignerElement.Name,
						id: sig.SignerElement.ID,
						sourceType: PolicyEditor.SignatureBasedRuleType.Signer,
						source: sig,
						parentViewModel: this
						);

					SignatureRulesCollection.Add(temp6);
					SignatureRulesCollectionList.Add(temp6);
				}

				GenericSignersCount = $"• Generic Signer Rules count: {_GenericSignerRulesCount}";

				// Process WHQLPublisher rules

				uint _WHQLPublisherRulesCount = 0;

				foreach (WHQLPublisher sig in SignerCollectionCol.WHQLPublishers)
				{

					_WHQLPublisherRulesCount++;


					PolicyEditor.SignatureBasedRulesForListView temp7 = new
						(
						certRoot: CustomSerialization.ConvertByteArrayToHex(sig.SignerElement.CertRoot?.Value),
						certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
						certIssuer: sig.SignerElement.CertIssuer?.Value,
						certPublisher: sig.SignerElement.CertPublisher?.Value,
						certOemID: sig.SignerElement.CertOemID?.Value,
						name: sig.SignerElement.Name,
						id: sig.SignerElement.ID,
						sourceType: PolicyEditor.SignatureBasedRuleType.WHQLPublisher,
						source: sig,
						parentViewModel: this
						);


					SignatureRulesCollection.Add(temp7);
					SignatureRulesCollectionList.Add(temp7);
				}

				WHQLPublishersCount = $"• WHQL Publisher Rules count: {_WHQLPublisherRulesCount}";

				// Process the UpdatePolicySigner rules

				uint _UpdatePolicySignersCount = 0;

				foreach (UpdatePolicySignerRule sig in SignerCollectionCol.UpdatePolicySigners)
				{

					_UpdatePolicySignersCount++;


					PolicyEditor.SignatureBasedRulesForListView temp8 = new
						(
						certRoot: CustomSerialization.ConvertByteArrayToHex(sig.SignerElement.CertRoot?.Value),
						certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
						certIssuer: sig.SignerElement.CertIssuer?.Value,
						certPublisher: sig.SignerElement.CertPublisher?.Value,
						certOemID: sig.SignerElement.CertOemID?.Value,
						name: sig.SignerElement.Name,
						id: sig.SignerElement.ID,
						sourceType: PolicyEditor.SignatureBasedRuleType.UpdatePolicySigner,
						source: sig,
						parentViewModel: this
						);


					SignatureRulesCollection.Add(temp8);
					SignatureRulesCollectionList.Add(temp8);
				}

				UpdatePolicySignersCount = $"• Update Policy Signer Rules count: {_UpdatePolicySignersCount}";

				// Process the SupplementalPolicySigner rules

				uint _SupplementalPolicySignersCount = 0;

				foreach (SupplementalPolicySignerRule sig in SignerCollectionCol.SupplementalPolicySigners)
				{

					_SupplementalPolicySignersCount++;

					SignatureRulesCollection.Add(new PolicyEditor.SignatureBasedRulesForListView
						(
						certRoot: CustomSerialization.ConvertByteArrayToHex(sig.SignerElement.CertRoot?.Value),
						certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
						certIssuer: sig.SignerElement.CertIssuer?.Value,
						certPublisher: sig.SignerElement.CertPublisher?.Value,
						certOemID: sig.SignerElement.CertOemID?.Value,
						name: sig.SignerElement.Name,
						id: sig.SignerElement.ID,
						sourceType: PolicyEditor.SignatureBasedRuleType.SupplementalPolicySigner,
						source: sig,
						parentViewModel: this
						));
				}

				SupplementalPolicySignersCount = $"• Supplemental Policy Signer Rules count: {_SupplementalPolicySignersCount}";

				// Calculate the column widths for Signature Based rules after processing them
				CalculateSignatureBasedListViewColumnWidths();
			}
		}
		finally
		{
			UIElementsEnabledState = true;

			UpdateFileBasedCollectionsCount();
			UpdateSignatureBasedCollectionsCount();
		}
	}


	/// <summary>
	/// To remove an item from the File rules based ListView
	/// </summary>
	/// <param name="item"></param>
	internal void RemoveFileRuleFromCollection(PolicyEditor.FileBasedRulesForListView item)
	{
		if (!FileRulesCollection.Remove(item))
		{
			Logger.Write($"Could not remove file rule with the ID {item.Id}");
		}

		_ = FileRulesCollectionList.Remove(item);

		UpdateFileBasedCollectionsCount();
	}


	/// <summary>
	/// To remove an item from the Signature based rules ListView
	/// </summary>
	/// <param name="item"></param>
	internal void RemoveSignatureRuleFromCollection(PolicyEditor.SignatureBasedRulesForListView item)
	{
		if (!SignatureRulesCollection.Remove(item))
		{
			Logger.Write($"Could not remove signature rule with the ID {item.Id}");
		}

		_ = SignatureRulesCollectionList.Remove(item);

		UpdateSignatureBasedCollectionsCount();
	}


	/// <summary>
	/// Event handler for browse for policy button
	/// </summary>
	public void BrowseForPolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			SelectedPolicyFile = selectedFile;

			MainTeachingTipIsOpen = false;
		}
	}

	/// <summary>
	/// Event handler for the Clear selected policy button
	/// </summary>
	public void ClearButton_Click()
	{
		SelectedPolicyFile = null;
	}


	/// <summary>
	/// To set the count of File-based rules ListView collection in the TabView's header in real time
	/// </summary>
	internal void UpdateFileBasedCollectionsCount()
	{
		FileBasedCollectionTabItemHeader = $"File-based Rules - count: {FileRulesCollection.Count}";
	}

	/// <summary>
	/// To set the count of Signature-based rules ListView collection in the TabView's header in real time
	/// </summary>
	internal void UpdateSignatureBasedCollectionsCount()
	{
		SignatureBasedCollectionTabItemHeader = $"Signature-based Rules - count: {SignatureRulesCollection.Count}";
	}


	/// <summary>
	/// Event handler for the UI toggle button to enable/disable text selection in the ListViews
	/// </summary>
	internal void ChangeTextSelectionsState()
	{
		TextsAreSelectableToggleState = !TextsAreSelectableToggleState;
	}

	public PolicyEditorVM()
	{
		_instance = this;
	}

	public static PolicyEditorVM Instance => _instance ?? throw new InvalidOperationException("PolicyEditorVM is not initialized.");


	#region Custom HashSet comparers so that when processing FilePublisher and WHQLFilePublisher rules, we don't add duplicate signers to the policy.
	/*
	 
		Because each FileAttrib in the <FileRules> node can be associated with more than 1 signer.

		Longer description of the problem and why the custom HashSet comparers are necessary:

		ProcessData() splits a single FilePublisherSignerRule into multiple FileBasedRulesForListView items (one per FileAttribElement) for UI display, all pointing to the same Source object.
		
		SaveChanges() iterates over FileRulesCollection and naively adds the AllowedSignerElement/DeniedSignerElement for each item, duplicating it if the signer has multiple file attributes.
		
		Example:
		Original FilePublisherSignerRule: 1 DeniedSigner (SignerId = "ID_SIGNER_A_XYZ") with 3 FileAttribElements.
		
		FileRulesCollection: 3 items, each with Source = same FilePublisherSignerRule.
		
		SaveChanges(): Adds the same DeniedSignerElement 3 times to userModeDeniedSigners.
		
		Result: userModeDeniedSigners contains duplicate DeniedSigner objects with the same SignerId.
	*/

	private sealed class SignerComparer : IEqualityComparer<Signer>
	{
		public bool Equals(Signer? x, Signer? y) => x?.ID == y?.ID;
		public int GetHashCode(Signer obj) => obj.ID.GetHashCode();
	}

	private sealed class AllowedSignerComparer : IEqualityComparer<AllowedSigner>
	{
		public bool Equals(AllowedSigner? x, AllowedSigner? y) => x?.SignerId == y?.SignerId;
		public int GetHashCode(AllowedSigner obj) => obj.SignerId.GetHashCode();
	}

	private sealed class DeniedSignerComparer : IEqualityComparer<DeniedSigner>
	{
		public bool Equals(DeniedSigner? x, DeniedSigner? y) => x?.SignerId == y?.SignerId;
		public int GetHashCode(DeniedSigner obj) => obj.SignerId.GetHashCode();
	}

	private sealed class CiSignerComparer : IEqualityComparer<CiSigner>
	{
		public bool Equals(CiSigner? x, CiSigner? y) => x?.SignerId == y?.SignerId;
		public int GetHashCode(CiSigner obj) => obj.SignerId.GetHashCode();
	}

	#endregion


	/// <summary>
	/// Saves the changes made to the policy file.
	/// </summary>
	internal async void SaveChanges()
	{

		try
		{
			MainTeachingTipIsOpen = false;

			UIElementsEnabledState = false;

			if (SelectedPolicyFile is null || PolicyObj is null)
			{
				MainTeachingTitle = "No policy file selected";
				MainTeachingSubTitle = "Please select a policy file first before using the save feature.";
				MainTeachingTipIsOpen = true;

				return;
			}

			await Task.Run(() =>
			{

				// Collections we will populate to be passed to the policy generator method
				List<object> fileRulesNode = [];
				List<FileRuleRef> userModeFileRulesRefs = [];
				List<FileRuleRef> kernelModeFileRulesRefs = [];
				HashSet<Signer> signers = new(new SignerComparer());
				HashSet<CiSigner> ciSigners = new(new CiSignerComparer());
				HashSet<AllowedSigner> userModeAllowedSigners = new(new AllowedSignerComparer());
				HashSet<DeniedSigner> userModeDeniedSigners = new(new DeniedSignerComparer());
				HashSet<AllowedSigner> kernelModeAllowedSigners = new(new AllowedSignerComparer());
				HashSet<DeniedSigner> kernelModeDeniedSigners = new(new DeniedSignerComparer());
				List<SupplementalPolicySigner> supplementalPolicySignersCol = [];
				List<UpdatePolicySigner> updatePolicySignersCol = [];

				// Collecting the data from the FileRulesCollectionList that is the backing list of the ObservableCollection
				// So that the search feature won't affect what will be added to the policy
				// However, removal of data will apply correctly since it's removed from both collections
				foreach (PolicyEditor.FileBasedRulesForListView item in FileRulesCollectionList)
				{
					switch (item.SourceType)
					{
						case PolicyEditor.FileBasedRuleType.Allow:
							{
								AllowRule item2 = (AllowRule)item.Source;

								fileRulesNode.Add(item2.AllowElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									userModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									kernelModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}

								break;
							}

						case PolicyEditor.FileBasedRuleType.Deny:
							{
								DenyRule item2 = (DenyRule)item.Source;

								fileRulesNode.Add(item2.DenyElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									userModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									kernelModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}

								break;
							}

						case PolicyEditor.FileBasedRuleType.FileRule:
							{
								FileRuleRule item2 = (FileRuleRule)item.Source;

								fileRulesNode.Add(item2.FileRuleElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									userModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									kernelModeFileRulesRefs.Add(item2.FileRuleRefElement);
								}

								break;
							}


						case PolicyEditor.FileBasedRuleType.CompoundPublisher:
							{
								// The ListViews list each File Attribute separately
								// Because in a FilePublisher/WHQLFilePublisher rule, the signer itself doesn't matter, only each File Attribute matters.
								// If there are no FileAttribs in the <FileRules> node that references a FilePublisher/WHQLFilePublisher signer's FileAttribRefs then that signer should not be added to the policy.

								if (SignerCollectionCol is null)
									break;

								FileAttrib item2 = (FileAttrib)item.Source;

								// Add the FileAttrib to the <FileRules> Node
								fileRulesNode.Add(item2);

								// Since the same FileAttrib can be used for a FilePublisher and WHQLFilePublisher signer, we loop over both of them

								// Find the FilePublisher signers that belong to this FileAttrib based on ID
								foreach (FilePublisherSignerRule item3 in SignerCollectionCol.FilePublisherSigners)
								{
									// If the signer has at least one FileAttribRef the ID of which matches the current FileAttrib
									// Then keep that signer
									if (item3.SignerElement.FileAttribRef.Any(x => string.Equals(x.RuleID, item2.ID, StringComparison.OrdinalIgnoreCase)))
									{
										_ = signers.Add(item3.SignerElement);

										if (item3.SigningScenario is SSType.UserMode)
										{
											_ = ciSigners.Add(item3.CiSignerElement!);


											if (item3.Auth is Authorization.Allow)
											{
												_ = userModeAllowedSigners.Add(item3.AllowedSignerElement!);
											}
											else if (item3.Auth is Authorization.Deny)
											{
												_ = userModeDeniedSigners.Add(item3.DeniedSignerElement!);
											}
										}
										else if (item3.SigningScenario is SSType.KernelMode)
										{
											if (item3.Auth is Authorization.Allow)
											{
												_ = kernelModeAllowedSigners.Add(item3.AllowedSignerElement!);
											}
											else if (item3.Auth is Authorization.Deny)
											{
												_ = kernelModeDeniedSigners.Add(item3.DeniedSignerElement!);
											}
										}

									}
								}


								// Find the WHQLFilePublisher signers that belong to this FileAttrib based on ID
								foreach (WHQLFilePublisher item3 in SignerCollectionCol.WHQLFilePublishers)
								{
									// If the signer has at least one FileAttribRef the ID of which matches the current FileAttrib
									// Then keep that signer
									if (item3.SignerElement.FileAttribRef.Any(x => string.Equals(x.RuleID, item2.ID, StringComparison.OrdinalIgnoreCase)))
									{
										_ = signers.Add(item3.SignerElement);

										if (item3.SigningScenario is SSType.UserMode)
										{
											_ = ciSigners.Add(item3.CiSignerElement!);


											if (item3.Auth is Authorization.Allow)
											{
												_ = userModeAllowedSigners.Add(item3.AllowedSignerElement!);
											}
											else if (item3.Auth is Authorization.Deny)
											{
												_ = userModeDeniedSigners.Add(item3.DeniedSignerElement!);
											}
										}
										else if (item3.SigningScenario is SSType.KernelMode)
										{
											if (item3.Auth is Authorization.Allow)
											{
												_ = kernelModeAllowedSigners.Add(item3.AllowedSignerElement!);
											}
											else if (item3.Auth is Authorization.Deny)
											{
												_ = kernelModeDeniedSigners.Add(item3.DeniedSignerElement!);
											}
										}

									}
								}

								break;
							}

						default:
							throw new InvalidOperationException("Invalid rule type");
					}
				}


				// Collecting the data from the SignatureBasedRulesForListView
				foreach (PolicyEditor.SignatureBasedRulesForListView item in SignatureRulesCollectionList)
				{
					switch (item.SourceType)
					{
						case PolicyEditor.SignatureBasedRuleType.Signer:
							{
								SignerRule item2 = (SignerRule)item.Source;
								_ = signers.Add(item2.SignerElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									_ = ciSigners.Add(item2.CiSignerElement!);


									if (item2.Auth is Authorization.Allow)
									{
										_ = userModeAllowedSigners.Add(item2.AllowedSignerElement!);
									}
									else if (item2.Auth is Authorization.Deny)
									{
										_ = userModeDeniedSigners.Add(item2.DeniedSignerElement!);
									}
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									if (item2.Auth is Authorization.Allow)
									{
										_ = kernelModeAllowedSigners.Add(item2.AllowedSignerElement!);
									}
									else if (item2.Auth is Authorization.Deny)
									{
										_ = kernelModeDeniedSigners.Add(item2.DeniedSignerElement!);
									}
								}

								break;
							}

						case PolicyEditor.SignatureBasedRuleType.WHQLPublisher:
							{
								WHQLPublisher item2 = (WHQLPublisher)item.Source;
								_ = signers.Add(item2.SignerElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									_ = ciSigners.Add(item2.CiSignerElement!);


									if (item2.Auth is Authorization.Allow)
									{
										_ = userModeAllowedSigners.Add(item2.AllowedSignerElement!);
									}
									else if (item2.Auth is Authorization.Deny)
									{
										_ = userModeDeniedSigners.Add(item2.DeniedSignerElement!);
									}
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									if (item2.Auth is Authorization.Allow)
									{
										_ = kernelModeAllowedSigners.Add(item2.AllowedSignerElement!);
									}
									else if (item2.Auth is Authorization.Deny)
									{
										_ = kernelModeDeniedSigners.Add(item2.DeniedSignerElement!);
									}
								}

								break;
							}

						case PolicyEditor.SignatureBasedRuleType.UpdatePolicySigner:
							{
								UpdatePolicySignerRule item2 = (UpdatePolicySignerRule)item.Source;
								_ = signers.Add(item2.SignerElement);

								updatePolicySignersCol.Add(item2.UpdatePolicySigner);

								break;
							}

						case PolicyEditor.SignatureBasedRuleType.SupplementalPolicySigner:
							{
								SupplementalPolicySignerRule item2 = (SupplementalPolicySignerRule)item.Source;
								_ = signers.Add(item2.SignerElement);

								supplementalPolicySignersCol.Add(item2.SupplementalPolicySigner);

								break;
							}

						default:
							throw new InvalidOperationException("Invalid rule type");
					}
				}


				#region Policy details

				bool nameSettingFound = false;

				// Set the policy name
				foreach (Setting item in PolicyObj.Settings)
				{
					if (string.Equals(item.ValueName, "Name", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
					{
						item.Value.Item = PolicyNameTextBox;

						nameSettingFound = true;

						break;
					}
				}

				// If the Setting node with ValueName="Name" does not exist, create it
				if (!nameSettingFound)
				{
					Setting newNameSetting = new()
					{
						Provider = "PolicyInfo",
						Key = "Information",
						ValueName = "Name",
						Value = new SettingValueType()
						{
							Item = PolicyNameTextBox
						}
					};

					List<Setting> settings = [.. PolicyObj.Settings];
					settings.Add(newNameSetting);
					PolicyObj.Settings = [.. settings];
				}



				// Validate User Inputs

				(bool, string) policyIDCheckResult = SetCiPolicyInfo.ValidatePolicyID(PolicyIDTextBox);

				if (!policyIDCheckResult.Item1)
				{
					_ = Dispatch.TryEnqueue(() =>
					{
						MainTeachingTitle = "Invalid Policy ID";
						MainTeachingSubTitle = $"{policyIDCheckResult.Item2} is not valid for Policy ID";
						MainTeachingTipIsOpen = true;
					});
					return;
				}


				(bool, string) basePolicyIDCheckResult = SetCiPolicyInfo.ValidatePolicyID(PolicyBaseIDTextBox);

				if (!basePolicyIDCheckResult.Item1)
				{
					_ = Dispatch.TryEnqueue(() =>
					{
						MainTeachingTitle = "Invalid Base Policy ID";
						MainTeachingSubTitle = $"{basePolicyIDCheckResult.Item2} is not valid for Base Policy ID";
						MainTeachingTipIsOpen = true;
					});
					return;
				}

				if (string.IsNullOrWhiteSpace(PolicyVersionTextBox))
				{
					_ = Dispatch.TryEnqueue(() =>
					{
						MainTeachingTitle = "Enter policy version";
						MainTeachingSubTitle = "Policy Version cannot be empty";
						MainTeachingTipIsOpen = true;
					});
					return;
				}


				// Other policy details retrieved from the UI elements
				PolicyObj.PolicyID = policyIDCheckResult.Item2;
				PolicyObj.BasePolicyID = basePolicyIDCheckResult.Item2;
				PolicyObj.VersionEx = PolicyVersionTextBox;

				if (PolicyTypeComboBox is not null)
					PolicyObj.PolicyType = (PolicyType)PolicyTypeComboBox;


				bool policyInfoIDSettingFound = false;

				// Set the PolicyInfoID if the setting for it exist
				foreach (Setting item in PolicyObj.Settings)
				{
					if (string.Equals(item.ValueName, "Id", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Provider, "PolicyInfo", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(item.Key, "Information", StringComparison.OrdinalIgnoreCase))
					{
						item.Value.Item = PolicyInfoIDTextBox;

						policyInfoIDSettingFound = true;

						break;
					}
				}

				// If the setting for PolicyInfoID does not exist, create it

				if (!policyInfoIDSettingFound)
				{
					Setting newPolicyInfoIDSetting = new()
					{
						Provider = "PolicyInfo",
						Key = "Information",
						ValueName = "Id",
						Value = new SettingValueType()
						{
							Item = PolicyInfoIDTextBox
						}
					};
					List<Setting> settings = [.. PolicyObj.Settings];
					settings.Add(newPolicyInfoIDSetting);
					PolicyObj.Settings = [.. settings];
				}


				// If the user selected an HVCI option, set it in the policy
				if (!string.IsNullOrEmpty(HVCIOptionComboBox))
				{
					PolicyObj.HvciOptionsSpecified = true;
					PolicyObj.HvciOptions = GetHVCIOptionValue(HVCIOptionComboBox);
				}

				#endregion

				// Generate the policy
				Merger.PolicyGenerator(
				   SelectedPolicyFile, // The user selected XML file path
				   PolicyObj, // The deserialized policy object
				   ekusToUse, // The deserialized EKUs
				   fileRulesNode,
				   [.. signers],
				   ciSigners,
				   userModeAllowedSigners,
				   userModeDeniedSigners,
				   kernelModeAllowedSigners,
				   kernelModeDeniedSigners,
				   supplementalPolicySignersCol,
				   updatePolicySignersCol,
				   kernelModeFileRulesRefs,
				   userModeFileRulesRefs);
			});

		}
		finally
		{
			UIElementsEnabledState = true;
		}
	}


	/// <summary>
	/// Event handler for the button that clears the data
	/// </summary>
	internal void ClearData()
	{
		FileRulesCollection.Clear();
		FileRulesCollectionList.Clear();
		SignatureRulesCollection.Clear();
		SignatureRulesCollectionList.Clear();

		ekusToUse = [];
		PolicyObj = null;
		SignerCollectionCol = null;

		SelectedPolicyFile = null;

		FileBasedCollectionTabItemHeader = "File-based Rules - count: 0";
		SignatureBasedCollectionTabItemHeader = "Signature-based Rules - count: 0";

		PolicyNameTextBox = string.Empty;
		PolicyIDTextBox = null;
		PolicyBaseIDTextBox = null;
		PolicyVersionTextBox = null;
		PolicyInfoIDTextBox = null;
		PolicyTypeComboBox = null;
		HVCIOptionComboBox = null;

		AllowRulesCount = "• Allow Rules count: 0";
		DenyRulesCount = "• Deny Rules count: 0";
		FileRulesCount = "• File Rules count: 0";
		FilePublishersCount = "  ⚬ File Publisher Rules count: 0";
		WHQLFilePublishersCount = "  ⚬ WHQL File Publisher Rules count: 0";
		FileAttributesCount = "• File Attributes count: 0";
		WHQLPublishersCount = "• WHQL Publisher Rules count: 0";
		GenericSignersCount = "• Generic Signer Rules count: 0";
		UpdatePolicySignersCount = "• Update Policy Signer Rules count: 0";
		SupplementalPolicySignersCount = "• Supplemental Policy Signer Rules count: 0";
	}


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
	protected bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	protected void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

}
