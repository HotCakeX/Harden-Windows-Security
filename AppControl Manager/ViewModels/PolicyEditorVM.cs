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
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using CommonCore.ToolKits;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class PolicyEditorVM : ViewModelBase
{

	#region Column Managers

	internal ListViewColumnManager<PolicyEditor.FileBasedRulesForListView> FileRulesColumnManager { get; }
	internal ListViewColumnManager<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesColumnManager { get; }

	// ------------ AppIDTags ------------
	internal GridLength AppIDTagsColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength AppIDTagsColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength AppIDTagsColumnWidth3 { get; set => SP(ref field, value); }


	#endregion

	// Observable Collections bound to the ListViews in the UI via compiled bindings
	internal readonly ObservableCollection<PolicyEditor.FileBasedRulesForListView> FileRulesCollection = [];
	internal readonly List<PolicyEditor.FileBasedRulesForListView> FileRulesCollectionList = [];

	internal readonly ObservableCollection<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesCollection = [];
	internal readonly List<PolicyEditor.SignatureBasedRulesForListView> SignatureRulesCollectionList = [];

	internal readonly ObservableCollection<PolicyEditor.AppIDTagsWithContext> AppIDTagsCollection = [];

	/// <summary>
	/// To store Policy Settings, bound to the UI List View.
	/// </summary>
	internal readonly ObservableCollection<PolicyEditor.PolicySettings> PolicySettingsCollection = [];

	internal Visibility PolicySettingsEmptyStateVisibility =>
		PolicySettingsCollection.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

	internal PolicyEditor.PolicySettings? PolicySettingsSelectedItem { get; set => SP(ref field, value); }

	/// <summary>
	/// array for type mapping - index corresponds to the Type property value and should match the GetValueType method in the PolicySettingsManager method.
	/// </summary>
	internal readonly string[] TypeOptions = ["Binary", "Boolean", "DWord", "String"];

	internal PolicyEditorVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher,
			() => MainInfoBarTitle, value => MainInfoBarTitle = value);


		PolicySettingsCollection.CollectionChanged += (s, e) =>
		{
			OnPropertyChanged(nameof(PolicySettingsEmptyStateVisibility));
		};

		// Initialize preset policy settings
		PresetPolicySettings = [
			new(
			parentViewModel: this,
			provider: "AllHostIds",
			key: "AllKeys",
			value: true,
			valueStr: "true",
			valueName: "EnterpriseDefinedClsId",
			type: 1 // Boolean
		)
		];

		// Initialize File Rules Column Manager
		FileRulesColumnManager = new ListViewColumnManager<PolicyEditor.FileBasedRulesForListView>(
		[
			new("Id", "IDHeader/Text", x => x.Id),
			new("FriendlyName", "FriendlyNameHeader/Text", x => x.FriendlyName),
			new("Hash", "Hash", x => x.Hash, useRawHeader: true),
			new("FileName", "FileNameHeader/Text", x => x.FileName),
			new("InternalName", "InternalNameHeader/Text", x => x.InternalName),
			new("FileDescription", "FileDescriptionHeader/Text", x => x.FileDescription),
			new("ProductName", "ProductNameHeader/Text", x => x.ProductName),
			new("FilePath", "FilePathHeader/Text", x => x.FilePath),
			new("MinimumFileVersion", "MinimumFileVersionHeader/Text", x => x.MinimumFileVersion),
			new("MaximumFileVersion", "MaximumFileVersionHeader/Text", x => x.MaximumFileVersion),
			new("PackageFamilyName", "PackageFamilyNameHeader/Text", x => x.PackageFamilyName),
			new("PackageVersion", "PackageVersionHeader/Text", x => x.PackageVersion),
			new("AppIDs", "App IDs", x => x.AppIDs, useRawHeader: true),
			new("Type", "Type", x => x.Type, useRawHeader: true),
			new("RequireHotpatchID", "RequireHotpatchIDHeader/Text", x => x.RequireHotpatchID, defaultVisibility: Visibility.Collapsed),
			new("MinimumHotpatchSequence", "MinimumHotpatchSequenceHeader/Text", x => x.MinimumHotpatchSequence?.ToString(), defaultVisibility: Visibility.Collapsed),
			new("MaximumHotpatchSequence", "MaximumHotpatchSequenceHeader/Text", x => x.MaximumHotpatchSequence?.ToString(), defaultVisibility: Visibility.Collapsed)
		]);

		// Initialize Signature Rules Column Manager
		SignatureRulesColumnManager = new ListViewColumnManager<PolicyEditor.SignatureBasedRulesForListView>(
		[
			new("Id", "IDHeader/Text", x => x.Id),
			new("Name", "Name", x => x.Name, useRawHeader: true),
			new("CertRoot", "Cert Root", x => x.CertRoot, useRawHeader: true),
			new("CertPublisher", "Cert Publisher", x => x.CertPublisher, useRawHeader: true),
			new("CertOemID", "Cert OEM ID", x => x.CertOemID, useRawHeader: true),
			new("CertificateEKU", "Cert EKU", x => x.CertificateEKU, useRawHeader: true),
			new("CertIssuer", "Cert Issuer", x => x.CertIssuer, useRawHeader: true)
		]);

		// To adjust the initial width of the columns
		FileRulesColumnManager.CalculateColumnWidths(FileRulesCollection);
		SignatureRulesColumnManager.CalculateColumnWidths(SignatureRulesCollection);
	}


	private readonly InfoBarSettings MainInfoBar;

	#region UI-Bound Properties

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal string? MainInfoBarTitle { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); }
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	internal bool UIElementsEnabledState { get; set => SP(ref field, value); } = true;

	internal SiPolicy.PolicyFileRepresent? SelectedPolicy { get; set => SP(ref field, value); }

	/// <summary>
	/// The UI toggle that controls whether text selection in the rows of ListViews are enabled or disabled.
	/// </summary>
	internal bool TextsAreSelectableToggleState { get; set => SP(ref field, value); }

	internal string PolicyNameTextBox { get; set => SP(ref field, value); } = string.Empty;

	internal string? PolicyFriendlyNameTextBox { get; set => SP(ref field, value); }

	internal string? PolicyIDTextBox { get; set => SPT(ref field, value); }

	internal string? PolicyBaseIDTextBox { get; set => SPT(ref field, value); }

	internal string? PolicyVersionTextBox { get; set => SPT(ref field, value); }

	internal string? PolicyInfoIDTextBox { get; set => SPT(ref field, value); }

	internal PolicyType? PolicyTypeComboBox { get; set => SP(ref field, value); }

	// The valid values for the ItemsSource of the Policy Type ComboBox
	internal readonly Array ComboBoxSource = Enum.GetValues<PolicyType>();

	internal string? HVCIOptionComboBox { get; set => SP(ref field, value); }

	internal string? SearchTextBox { get; set => SPT(ref field, value); }

	#region Counting properties

	internal string? AllowRulesCount
	{
		get; set => SP(ref field, value);
	} = "• Allow Rules count: 0";

	internal string? DenyRulesCount
	{
		get; set => SP(ref field, value);
	} = "• Deny Rules count: 0";

	internal string? FileRulesCount
	{
		get; set => SP(ref field, value);
	} = "• File Rules count: 0";

	internal string? FilePublishersCount
	{
		get; set => SP(ref field, value);
	} = "  ⚬ File Publisher Rules count: 0";

	internal string? WHQLFilePublishersCount
	{
		get; set => SP(ref field, value);
	} = "  ⚬ WHQL File Publisher Rules count: 0";

	internal string? FileAttributesCount
	{
		get; set => SP(ref field, value);
	} = "• File Attributes count: 0";

	internal string? WHQLPublishersCount
	{
		get; set => SP(ref field, value);
	} = "• WHQL Publisher Rules count: 0";

	internal string? GenericSignersCount
	{
		get; set => SP(ref field, value);
	} = "• Generic Signer Rules count: 0";

	internal string? UpdatePolicySignersCount
	{
		get; set => SP(ref field, value);
	} = "• Update Policy Signer Rules count: 0";

	internal string? SupplementalPolicySignersCount
	{
		get; set => SP(ref field, value);
	} = "• Supplemental Policy Signer Rules count: 0";

	#endregion

	#endregion


	private static uint GetHVCIOptionValue(string key) => key switch
	{
		"Enabled - Strict" => 2,
		"Enabled" => 1,
		"Debug Mode" => 4,
		"Disable is Allowed" => 8,
		"None" => 0,
		_ => throw new ArgumentException($"Invalid HVCI option key: {key}", nameof(key))
	};

	private static string GetHVCIOptionKey(uint? value) => value switch
	{
		2 => "Enabled - Strict",
		1 => "Enabled",
		4 => "Debug Mode",
		8 => "Disable is Allowed",
		0 or null => "None",
		_ => throw new ArgumentException($"Invalid HVCI option value: {value}", nameof(value))
	};

	// All of these must be nullified/emptied during policy load

	// To store the EKUs, will use them during policy creation
	private static List<EKU> ekusToUse = [];

	// To store the signerCollection
	private static SignerCollection? SignerCollectionCol;

	/// <summary>
	/// For AppIDTags collection and list view.
	/// Calculates the maximum required width for each column (including header text).
	private void CalculateAppIDTagsListViewColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("KeyHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("ValueHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("ContextHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (PolicyEditor.AppIDTagsWithContext item in AppIDTagsCollection)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.AppIDTag.Key, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.AppIDTag.Value, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.Context.ToString(), maxWidth3);
		}

		// Set the column width properties.
		AppIDTagsColumnWidth1 = new(maxWidth1);
		AppIDTagsColumnWidth2 = new(maxWidth2);
		AppIDTagsColumnWidth3 = new(maxWidth3);
	}

	/// <summary>
	/// Extracts the data from the user selected policy XML file and puts them in the UI elements such as the ListViews
	/// </summary>
	internal async void ProcessData()
	{
		if (SelectedPolicy is null)
		{
			MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectAppControlPolicyFirstMessage"));
			return;
		}

		bool error = false;

		try
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				MainInfoBarIsClosable = false;

				ProgressBarVisibility = Visibility.Visible;
				UIElementsEnabledState = false;

				MainInfoBar.WriteInfo(GlobalVars.GetStr("LoadingPolicyMessage"));

				// Clear the class variables
				ekusToUse = [];
				SignerCollectionCol = null;

				// Clear the ListView collections and their backing Lists before inserting new data into them
				FileRulesCollection.Clear();
				FileRulesCollectionList.Clear();
				SignatureRulesCollection.Clear();
				SignatureRulesCollectionList.Clear();
				PolicySettingsCollection.Clear();
				AppIDTagsCollection.Clear();
			});

			// Collections to deserialize the policy object into
			List<object> fileRulesNode = [];
			List<Signer> signers = [];
			IEnumerable<CiSigner> ciSigners = [];
			IEnumerable<AllowedSigner> userModeAllowedSigners = [];
			IEnumerable<DeniedSigner> userModeDeniedSigners = [];
			IEnumerable<AllowedSigner> kernelModeAllowedSigners = [];
			IEnumerable<DeniedSigner> kernelModeDeniedSigners = [];
			List<SupplementalPolicySigner> supplementalPolicySignersCol = [];
			List<UpdatePolicySigner> updatePolicySignersCol = [];
			HashSet<FileRuleRule> fileRules = [];
			HashSet<DenyRule> denyRules = [];
			HashSet<AllowRule> allowRules = [];
			List<FileRuleRef> kernelModeFileRulesRefs = [];
			List<FileRuleRef> userModeFileRulesRefs = [];
			AppIDTags? userModeAppIDTags = null;
			AppIDTags? kernelModeAppIDTags = null;

			await Task.Run(() =>
			{
				#region Extract policy details

				string? policyName = PolicySettingsManager.GetPolicyName(SelectedPolicy.PolicyObj);
				string? policyIDInfo = PolicySettingsManager.GetPolicyIDInfo(SelectedPolicy.PolicyObj);

				PolicyNameTextBox = policyName ?? string.Empty;
				PolicyIDTextBox = SelectedPolicy.PolicyObj.PolicyID;
				PolicyBaseIDTextBox = SelectedPolicy.PolicyObj.BasePolicyID;
				PolicyVersionTextBox = SelectedPolicy.PolicyObj.VersionEx;
				PolicyTypeComboBox = SelectedPolicy.PolicyObj.PolicyType;
				PolicyInfoIDTextBox = policyIDInfo;
				PolicyFriendlyNameTextBox = SelectedPolicy.PolicyObj.FriendlyName;

				// If policy doesn't have HVCI field then set it to None on the UI ComboBox
				HVCIOptionComboBox = SelectedPolicy.PolicyObj.HvciOptions is not null ? GetHVCIOptionKey(SelectedPolicy.PolicyObj.HvciOptions) : GetHVCIOptionKey(0);

				#endregion

				// Deserialize the policy and populate the collections
				Merger.PolicyDeserializer(
					[SelectedPolicy.PolicyObj],
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
					ref userModeFileRulesRefs,
					ref userModeAppIDTags,
					ref kernelModeAppIDTags);
			});

			await Dispatcher.EnqueueAsync(() =>
			{
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
						hash: Convert.ToHexString(allowRule.AllowElement.Hash.Span),
						appIDs: allowRule.AllowElement.AppIDs,
						filePath: allowRule.AllowElement.FilePath,
						type: null,
						sourceType: PolicyEditor.FileBasedRuleType.Allow,
						source: allowRule,
						requireHotpatchID: allowRule.AllowElement.RequireHotpatchID,
						minimumHotpatchSequence: allowRule.AllowElement.MinimumHotpatchSequence,
						maximumHotpatchSequence: allowRule.AllowElement.MaximumHotpatchSequence
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
						hash: Convert.ToHexString(denyRule.DenyElement.Hash.Span),
						appIDs: denyRule.DenyElement.AppIDs,
						filePath: denyRule.DenyElement.FilePath,
						type: null,
						sourceType: PolicyEditor.FileBasedRuleType.Deny,
						source: denyRule,
						requireHotpatchID: null,
						minimumHotpatchSequence: null,
						maximumHotpatchSequence: null
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
						hash: Convert.ToHexString(fileRule.FileRuleElement.Hash.Span),
						appIDs: fileRule.FileRuleElement.AppIDs,
						filePath: fileRule.FileRuleElement.FilePath,
						type: fileRule.FileRuleElement.Type.ToString(),
						sourceType: PolicyEditor.FileBasedRuleType.FileRule,
						source: fileRule,
						requireHotpatchID: null,
						minimumHotpatchSequence: null,
						maximumHotpatchSequence: null
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
				foreach (FileAttrib item in CollectionsMarshal.AsSpan(fileAttribs))
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
						hash: Convert.ToHexString(item.Hash.Span),
						appIDs: item.AppIDs,
						filePath: item.FilePath,
						type: null,
						sourceType: PolicyEditor.FileBasedRuleType.CompoundPublisher,
						source: item,
						requireHotpatchID: null,
						minimumHotpatchSequence: null,
						maximumHotpatchSequence: null
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
				FileRulesColumnManager.CalculateColumnWidths(FileRulesCollection);


				if (SignerCollectionCol is not null)
				{

					// Process the Generic signer rules for levels: Publisher, PCA Certificate, Leaf Certificate, Root Certificate

					uint _GenericSignerRulesCount = 0;

					foreach (SignerRule sig in SignerCollectionCol.SignerRules)
					{

						_GenericSignerRulesCount++;


						PolicyEditor.SignatureBasedRulesForListView temp6 = new
						(
							certRoot: Convert.ToHexString(sig.SignerElement.CertRoot.Value.Span),
							certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
							certIssuer: sig.SignerElement.CertIssuer?.Value,
							certPublisher: sig.SignerElement.CertPublisher?.Value,
							certOemID: sig.SignerElement.CertOemID?.Value,
							name: sig.SignerElement.Name,
							id: sig.SignerElement.ID,
							sourceType: PolicyEditor.SignatureBasedRuleType.Signer,
							source: sig
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
							certRoot: Convert.ToHexString(sig.SignerElement.CertRoot.Value.Span),
							certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
							certIssuer: sig.SignerElement.CertIssuer?.Value,
							certPublisher: sig.SignerElement.CertPublisher?.Value,
							certOemID: sig.SignerElement.CertOemID?.Value,
							name: sig.SignerElement.Name,
							id: sig.SignerElement.ID,
							sourceType: PolicyEditor.SignatureBasedRuleType.WHQLPublisher,
							source: sig
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
							certRoot: Convert.ToHexString(sig.SignerElement.CertRoot.Value.Span),
							certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
							certIssuer: sig.SignerElement.CertIssuer?.Value,
							certPublisher: sig.SignerElement.CertPublisher?.Value,
							certOemID: sig.SignerElement.CertOemID?.Value,
							name: sig.SignerElement.Name,
							id: sig.SignerElement.ID,
							sourceType: PolicyEditor.SignatureBasedRuleType.UpdatePolicySigner,
							source: sig
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
							certRoot: Convert.ToHexString(sig.SignerElement.CertRoot.Value.Span),
							certEKU: string.Join(",", sig.SignerElement.CertEKU?.Select(x => x.ID) ?? []),
							certIssuer: sig.SignerElement.CertIssuer?.Value,
							certPublisher: sig.SignerElement.CertPublisher?.Value,
							certOemID: sig.SignerElement.CertOemID?.Value,
							name: sig.SignerElement.Name,
							id: sig.SignerElement.ID,
							sourceType: PolicyEditor.SignatureBasedRuleType.SupplementalPolicySigner,
							source: sig
						));
					}

					SupplementalPolicySignersCount = $"• Supplemental Policy Signer Rules count: {_SupplementalPolicySignersCount}";

					// Calculate the column widths for Signature Based rules after processing them
					SignatureRulesColumnManager.CalculateColumnWidths(SignatureRulesCollection);
				}

				if (SelectedPolicy.PolicyObj is not null)
				{
					foreach (PolicyEditor.PolicySettings item in CollectionsMarshal.AsSpan(PolicySettingsManager.GetPolicySettings(SelectedPolicy.PolicyObj.Settings, this)))
					{
						PolicySettingsCollection.Add(item);
					}
				}


				// Populate the AppIDTags collection UI-bound collection


				foreach (AppIDTag item in CollectionsMarshal.AsSpan(userModeAppIDTags?.AppIDTag))
				{
					AppIDTagsCollection.Add(new(context: SSType.UserMode, appIDTag: item));
				}

				foreach (AppIDTag item in CollectionsMarshal.AsSpan(kernelModeAppIDTags?.AppIDTag))
				{
					AppIDTagsCollection.Add(new(context: SSType.KernelMode, appIDTag: item));
				}

				CalculateAppIDTagsListViewColumnWidths();

			});

			await Dispatcher.EnqueueAsync(() =>
			{
				try
				{
					if (Pages.PolicyEditor._DiamondButtonFlyout is not null && Pages.PolicyEditor._DiamondButton is not null && Pages.PolicyEditor._DiamondButtonFlyout.XamlRoot is not null)
						Pages.PolicyEditor._DiamondButtonFlyout.ShowAt(Pages.PolicyEditor._DiamondButton);
				}
				catch { }
			});

			if (SelectedPolicy.FilePath is not null)
				await PublishUserActivityAsync(LaunchProtocolActions.PolicyEditor,
					SelectedPolicy.FilePath,
					GlobalVars.GetStr("UserActivityNameForPolicyEditor"));
		}
		catch (Exception ex)
		{
			error = true;
			MainInfoBar.WriteError(ex, GlobalVars.GetStr("ErrorLoadingPolicyFileMessage"));
		}
		finally
		{
			await Dispatcher.EnqueueAsync(() =>
			{
				UIElementsEnabledState = true;
				ProgressBarVisibility = Visibility.Collapsed;

				if (!error)
				{
					MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessLoadedPolicyMessage"));
				}

				MainInfoBarIsClosable = true;
			});
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
			Logger.Write(string.Format(
				GlobalVars.GetStr("CouldNotRemoveFileRuleMessage"),
				item.Id));
		}

		_ = FileRulesCollectionList.Remove(item);
	}

	/// <summary>
	/// To remove an item from the Signature based rules ListView
	/// </summary>
	/// <param name="item"></param>
	internal void RemoveSignatureRuleFromCollection(PolicyEditor.SignatureBasedRulesForListView item)
	{
		if (!SignatureRulesCollection.Remove(item))
		{
			Logger.Write(string.Format(
				GlobalVars.GetStr("CouldNotRemoveSignatureRuleMessage"),
				item.Id));
		}

		_ = SignatureRulesCollectionList.Remove(item);
	}


	/// <summary>
	/// Event handler for browse for policy button
	/// </summary>
	internal void BrowseForPolicyButton_Click()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.MultiAppControlPolicyPickerFilter);

			if (!string.IsNullOrEmpty(selectedFile))
			{
				SelectedPolicy = ParseFilePathAsPolicyRepresent(selectedFile);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Accepts a path to an XML or CIP file and then returns a <see cref="PolicyFileRepresent"/> made from it.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static SiPolicy.PolicyFileRepresent ParseFilePathAsPolicyRepresent(string filePath)
	{
		string fileExt = Path.GetExtension(filePath);

		if (string.Equals(fileExt, ".cip", StringComparison.OrdinalIgnoreCase))
		{
			return new SiPolicy.PolicyFileRepresent(
				policyObj: BinaryOpsReverse.ConvertBinaryToXmlFile(filePath),
				kind: PolicyFileRepresentKind.CIP)
			{
				FileName = Path.GetFileNameWithoutExtension(filePath)
			};
		}
		else if (string.Equals(fileExt, ".xml", StringComparison.OrdinalIgnoreCase))
		{
			return new SiPolicy.PolicyFileRepresent(
				policyObj: Management.Initialize(filePath, null),
				kind: PolicyFileRepresentKind.XML)
			{
				FilePath = filePath, // Only assign the file path if it's XML since we use it to save the policy back to the file in other places in the app.
				FileName = Path.GetFileNameWithoutExtension(filePath)
			};
		}
		else if (string.Equals(fileExt, ".p7b", StringComparison.OrdinalIgnoreCase))
		{
			return new SiPolicy.PolicyFileRepresent(
				policyObj: BinaryOpsReverse.ConvertBinaryToXmlFile(filePath),
				kind: PolicyFileRepresentKind.P7B)
			{
				FileName = Path.GetFileNameWithoutExtension(filePath)
			};
		}
		else if (string.Equals(fileExt, ".bin", StringComparison.OrdinalIgnoreCase))
		{
			return new SiPolicy.PolicyFileRepresent(
				policyObj: BinaryOpsReverse.ConvertBinaryToXmlFile(filePath),
				kind: PolicyFileRepresentKind.BIN)
			{
				FileName = Path.GetFileNameWithoutExtension(filePath)
			};
		}
		else
		{
			throw new InvalidOperationException(GlobalVars.GetStr("OnlyXmlCipSupportedMessage"));
		}
	}

	/// <summary>
	/// Event handler for the Clear selected policy button
	/// </summary>
	internal void ClearButton_Click() => SelectedPolicy = null;

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
		public bool Equals(Signer? x, Signer? y) => string.Equals(x?.ID, y?.ID, StringComparison.Ordinal);
		public int GetHashCode(Signer obj)
		{
			unchecked
			{
				return obj.ID.GetHashCode();
			}
		}
	}

	private sealed class AllowedSignerComparer : IEqualityComparer<AllowedSigner>
	{
		public bool Equals(AllowedSigner? x, AllowedSigner? y) => string.Equals(x?.SignerId, y?.SignerId, StringComparison.Ordinal);
		public int GetHashCode(AllowedSigner obj)
		{
			unchecked // Standard for hash code, protects against overflow
			{
				return obj.SignerId.GetHashCode();
			}
		}
	}

	private sealed class DeniedSignerComparer : IEqualityComparer<DeniedSigner>
	{
		public bool Equals(DeniedSigner? x, DeniedSigner? y) => string.Equals(x?.SignerId, y?.SignerId, StringComparison.Ordinal);
		public int GetHashCode(DeniedSigner obj)
		{
			unchecked // Standard for hash code, protects against overflow
			{
				return obj.SignerId.GetHashCode();
			}
		}
	}

	private sealed class CiSignerComparer : IEqualityComparer<CiSigner>
	{
		public bool Equals(CiSigner? x, CiSigner? y) => string.Equals(x?.SignerId, y?.SignerId, StringComparison.Ordinal);
		public int GetHashCode(CiSigner obj)
		{
			unchecked // Standard for hash code, protects against overflow
			{
				return obj.SignerId.GetHashCode();
			}
		}
	}

	#endregion

	/// <summary>
	/// Saves the changes made to the policy file.
	/// </summary>
	internal async void SaveChanges(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			UIElementsEnabledState = false;

			MainInfoBarIsClosable = false;

			if (SelectedPolicy is null)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("SelectPolicyBeforeLoad"));
				return;
			}

			await Task.Run(async () =>
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
				AppIDTags? userModeAppIDTags = null;
				AppIDTags? kernelModeAppIDTags = null;

				// Collecting the data from the FileRulesCollectionList that is the backing list of the ObservableCollection
				// So that the search feature won't affect what will be added to the policy
				// However, removal of data will apply correctly since it's removed from both collections
				foreach (PolicyEditor.FileBasedRulesForListView item in CollectionsMarshal.AsSpan(FileRulesCollectionList))
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
									if (item3.SignerElement.FileAttribRef is not null &&
										item3.SignerElement.FileAttribRef.Any(x => string.Equals(x.RuleID, item2.ID, StringComparison.OrdinalIgnoreCase)))
									{
										_ = signers.Add(item3.SignerElement);

										if (item3.SigningScenario is SSType.UserMode)
										{
											if (item3.CiSignerElement is not null)
											{
												_ = ciSigners.Add(item3.CiSignerElement);
											}

											if (item3.Auth is Authorization.Allow && item3.AllowedSignerElement is not null)
											{
												_ = userModeAllowedSigners.Add(item3.AllowedSignerElement);
											}
											else if (item3.Auth is Authorization.Deny && item3.DeniedSignerElement is not null)
											{
												_ = userModeDeniedSigners.Add(item3.DeniedSignerElement);
											}
										}
										else if (item3.SigningScenario is SSType.KernelMode)
										{
											if (item3.Auth is Authorization.Allow && item3.AllowedSignerElement is not null)
											{
												_ = kernelModeAllowedSigners.Add(item3.AllowedSignerElement);
											}
											else if (item3.Auth is Authorization.Deny && item3.DeniedSignerElement is not null)
											{
												_ = kernelModeDeniedSigners.Add(item3.DeniedSignerElement);
											}
										}

									}
								}


								// Find the WHQLFilePublisher signers that belong to this FileAttrib based on ID
								foreach (WHQLFilePublisher item3 in SignerCollectionCol.WHQLFilePublishers)
								{
									// If the signer has at least one FileAttribRef the ID of which matches the current FileAttrib
									// Then keep that signer
									if (item3.SignerElement.FileAttribRef is not null &&
										item3.SignerElement.FileAttribRef.Any(x => string.Equals(x.RuleID, item2.ID, StringComparison.OrdinalIgnoreCase)))
									{
										_ = signers.Add(item3.SignerElement);

										if (item3.SigningScenario is SSType.UserMode)
										{
											if (item3.CiSignerElement is not null)
											{
												_ = ciSigners.Add(item3.CiSignerElement);
											}

											if (item3.Auth is Authorization.Allow && item3.AllowedSignerElement is not null)
											{
												_ = userModeAllowedSigners.Add(item3.AllowedSignerElement);
											}
											else if (item3.Auth is Authorization.Deny && item3.DeniedSignerElement is not null)
											{
												_ = userModeDeniedSigners.Add(item3.DeniedSignerElement);
											}
										}
										else if (item3.SigningScenario is SSType.KernelMode)
										{
											if (item3.Auth is Authorization.Allow && item3.AllowedSignerElement is not null)
											{
												_ = kernelModeAllowedSigners.Add(item3.AllowedSignerElement);
											}
											else if (item3.Auth is Authorization.Deny && item3.DeniedSignerElement is not null)
											{
												_ = kernelModeDeniedSigners.Add(item3.DeniedSignerElement);
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
				foreach (PolicyEditor.SignatureBasedRulesForListView item in CollectionsMarshal.AsSpan(SignatureRulesCollectionList))
				{
					switch (item.SourceType)
					{
						case PolicyEditor.SignatureBasedRuleType.Signer:
							{
								SignerRule item2 = (SignerRule)item.Source;
								_ = signers.Add(item2.SignerElement);

								if (item2.SigningScenario is SSType.UserMode)
								{
									if (item2.CiSignerElement is not null)
									{
										_ = ciSigners.Add(item2.CiSignerElement);
									}

									if (item2.Auth is Authorization.Allow && item2.AllowedSignerElement is not null)
									{
										_ = userModeAllowedSigners.Add(item2.AllowedSignerElement);
									}
									else if (item2.Auth is Authorization.Deny && item2.DeniedSignerElement is not null)
									{
										_ = userModeDeniedSigners.Add(item2.DeniedSignerElement);
									}
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									if (item2.Auth is Authorization.Allow && item2.AllowedSignerElement is not null)
									{
										_ = kernelModeAllowedSigners.Add(item2.AllowedSignerElement);
									}
									else if (item2.Auth is Authorization.Deny && item2.DeniedSignerElement is not null)
									{
										_ = kernelModeDeniedSigners.Add(item2.DeniedSignerElement);
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
									if (item2.CiSignerElement is not null)
									{
										_ = ciSigners.Add(item2.CiSignerElement);
									}

									if (item2.Auth is Authorization.Allow && item2.AllowedSignerElement is not null)
									{
										_ = userModeAllowedSigners.Add(item2.AllowedSignerElement);
									}
									else if (item2.Auth is Authorization.Deny && item2.DeniedSignerElement is not null)
									{
										_ = userModeDeniedSigners.Add(item2.DeniedSignerElement);
									}
								}
								else if (item2.SigningScenario is SSType.KernelMode)
								{
									if (item2.Auth is Authorization.Allow && item2.AllowedSignerElement is not null)
									{
										_ = kernelModeAllowedSigners.Add(item2.AllowedSignerElement);
									}
									else if (item2.Auth is Authorization.Deny && item2.DeniedSignerElement is not null)
									{
										_ = kernelModeDeniedSigners.Add(item2.DeniedSignerElement);
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

				// Validate User Inputs

				(bool, string) policyIDCheckResult = SetCiPolicyInfo.ValidatePolicyID(PolicyIDTextBox);

				if (!policyIDCheckResult.Item1)
				{
					MainInfoBar.WriteWarning($"{policyIDCheckResult.Item2} is not valid for Policy ID");
					return;
				}

				(bool, string) basePolicyIDCheckResult = SetCiPolicyInfo.ValidatePolicyID(PolicyBaseIDTextBox);

				if (!basePolicyIDCheckResult.Item1)
				{
					MainInfoBar.WriteWarning($"{basePolicyIDCheckResult.Item2} is not valid for Base Policy ID");
					return;
				}

				if (string.IsNullOrWhiteSpace(PolicyVersionTextBox))
				{
					MainInfoBar.WriteWarning(GlobalVars.GetStr("EnterPolicyVersion"));
					return;
				}

				// Other policy details retrieved from the UI elements
				SelectedPolicy.PolicyObj.PolicyID = policyIDCheckResult.Item2;
				SelectedPolicy.PolicyObj.BasePolicyID = basePolicyIDCheckResult.Item2;

				// Increment the version by 1
				string incrementedVersionString = VersionIncrementer.AddVersion(new(PolicyVersionTextBox)).ToString();

				// Assign the new incremented version both to the new policy and the textbox on the UI.
				SelectedPolicy.PolicyObj.VersionEx = incrementedVersionString;
				PolicyVersionTextBox = incrementedVersionString;

				if (PolicyTypeComboBox is not null)
					SelectedPolicy.PolicyObj.PolicyType = (PolicyType)PolicyTypeComboBox;

				// If the user selected an HVCI option, set it in the policy
				if (!string.IsNullOrEmpty(HVCIOptionComboBox))
				{
					SelectedPolicy.PolicyObj.HvciOptions = GetHVCIOptionValue(HVCIOptionComboBox);
				}

				// Set Friendly Name

				SelectedPolicy.PolicyObj.FriendlyName = PolicyFriendlyNameTextBox;

				#endregion

				string? fileToSaveTheChangesTo = null;

				// Save the non-XML file in a XML file
				if (SelectedPolicy.Kind is not PolicyFileRepresentKind.XML)
				{
					// Save it to User Config dir when elevated
					fileToSaveTheChangesTo = GlobalVars.IsElevated
						? Path.Combine(GlobalVars.UserConfigDir, $"{SelectedPolicy.FileName}.xml")
						// Save it to the same location file is being read from if non-elevated since we already check if we have write permission in that location
						: Path.Combine(Path.GetDirectoryName(SelectedPolicy.FilePath)!, $"{SelectedPolicy.FileName}.xml");
				}
				else
				{
					fileToSaveTheChangesTo = SelectedPolicy.FilePath;
				}

				// Anything that has to do with Settings must be applied by this method because it always overwrites any other changes as it writes the final settings block to the policy.
				List<Setting> _policySettings = PolicySettingsManager.ConvertPolicyEditorSettingToSiPolicySetting(PolicySettingsCollection, PolicyNameTextBox, PolicyInfoIDTextBox);


				// Ensure the signers only have FileAttribRefs that point to existing FileAttribs
				// This is critical because when we remove a FileAttrib from the UI, the Signer in the backend cache still points to it.
				// We must remove these stale references before generating the policy.

				// 1. Collect all IDs of the FileAttribs that will actually be in the policy
				HashSet<string> validFileAttribIDs = new(
					fileRulesNode.OfType<FileAttrib>().Select(fa => fa.ID),
					StringComparer.OrdinalIgnoreCase
				);

				// 2. Iterate through all signers and filter their FileAttribRef lists
				foreach (Signer signer in signers)
				{
					if (signer.FileAttribRef?.Count > 0)
					{
						// Keep only the refs whose RuleID exists in our valid set
						signer.FileAttribRef = signer.FileAttribRef
							.Where(refItem => validFileAttribIDs.Contains(refItem.RuleID))
							.ToList();
					}
				}


				#region AppID Tags gathering from UI collection

				List<AppIDTag> userModeAppIDTagsCollection = [];
				List<AppIDTag> kernelModeAppIDTagsCollection = [];

				HashSet<string> currentTagKeysUserMode = new(StringComparer.Ordinal);

				HashSet<string> currentTagKeysKernelMode = new(StringComparer.Ordinal);

				SigningScenario? umciScenario = SelectedPolicy.PolicyObj.SigningScenarios?.FirstOrDefault(s => s.Value == 12);
				SigningScenario? kmciScenario = SelectedPolicy.PolicyObj.SigningScenarios?.FirstOrDefault(s => s.Value == 131);

				// Collect AppIDTags from the UI collection for each signing scenario
				foreach (PolicyEditor.AppIDTagsWithContext tagPackage in AppIDTagsCollection)
				{
					// User-Mode Signing Scenario
					if (tagPackage.Context is SSType.UserMode)
					{
						// Ensure only Unique keys for User-mode will be in the policy.
						if (currentTagKeysUserMode.Add(tagPackage.AppIDTag.Key))
						{
							userModeAppIDTagsCollection.Add(tagPackage.AppIDTag);
						}
					}

					// kernel-Mode Signing Scenario
					else if (tagPackage.Context is SSType.KernelMode)
					{
						// Ensure only Unique keys for Kernel-mode will be in the policy.
						if (currentTagKeysKernelMode.Add(tagPackage.AppIDTag.Key))
						{
							kernelModeAppIDTagsCollection.Add(tagPackage.AppIDTag);
						}
					}
				}


				if (userModeAppIDTagsCollection.Count > 0)
				{
					// Assign the results to the Ref vars
					userModeAppIDTags = new()
					{
						EnforceDLL = umciScenario?.AppIDTags?.EnforceDLL, // Assign from the loaded policy.
						AppIDTag = userModeAppIDTagsCollection
					};
				}

				if (kernelModeAppIDTagsCollection.Count > 0)
				{
					// Assign the results to the Ref vars
					kernelModeAppIDTags = new()
					{
						EnforceDLL = kmciScenario?.AppIDTags?.EnforceDLL, // Assign from the loaded policy.
						AppIDTag = kernelModeAppIDTagsCollection
					};
				}

				#endregion


				// Generate the policy
				SelectedPolicy.PolicyObj = Merger.PolicyGenerator(
				   SelectedPolicy.PolicyObj, // The deserialized policy object
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
				   userModeFileRulesRefs,
				   _policySettings,
				   userModeAppIDTags,
				   kernelModeAppIDTags
				   );

				// Save the policy to the the user selected XML file path
				if (fileToSaveTheChangesTo is not null)
				{
					Management.SavePolicyToFile(SelectedPolicy.PolicyObj, fileToSaveTheChangesTo);
				}

				// Assign the modified policy to the Sidebar
				ViewModelProvider.MainWindowVM.AssignToSidebar(SelectedPolicy);

				MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

				await Dispatcher.EnqueueAsync(async () =>
				{
					// Update the Policy Settings again to reflect the newest changes when something is removed from their UI-bound collection.
					PolicySettingsCollection.Clear();

					foreach (PolicyEditor.PolicySettings item in PolicySettingsManager.GetPolicySettings(_policySettings, this))
					{
						PolicySettingsCollection.Add(item);
					}

					MainInfoBar.WriteSuccess(GlobalVars.GetStr("PolicyEditorSuccessfulSaveMessage"));

					if (SelectedPolicy.Kind is not PolicyFileRepresentKind.XML)
					{
						using ContentDialogV2 dialog = new()
						{
							Title = GlobalVars.GetStr("DialogTitleSuccess"),
							Content = new WrapPanel
							{
								Orientation = Orientation.Vertical,
								HorizontalAlignment = HorizontalAlignment.Center,
								HorizontalSpacing = 8,
								VerticalSpacing = 8,
								Children =
								{
									new TextBlock
									{
										Text = SelectedPolicy.Kind is PolicyFileRepresentKind.CIP ? GlobalVars.GetStr("DialogContentCIPConvertedToXML") : GlobalVars.GetStr("DialogContentP7BConvertedToXML"),
										HorizontalAlignment = HorizontalAlignment.Center,
										TextWrapping = TextWrapping.WrapWholeWords
									},
									new TextBox
									{
										TextWrapping = TextWrapping.Wrap,
										Text = fileToSaveTheChangesTo,
										IsReadOnly = true,
										HorizontalAlignment = HorizontalAlignment.Center
									}
								}
							},
							CloseButtonText = GlobalVars.GetStr("Ok"),
						};

						_ = await dialog.ShowAsync();
					}

				});
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			UIElementsEnabledState = true;
			MainInfoBarIsClosable = true;
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
		PolicySettingsCollection.Clear();
		AppIDTagsCollection.Clear();

		ekusToUse = [];
		SelectedPolicy = null;
		SignerCollectionCol = null;

		SelectedPolicy = null;

		PolicyNameTextBox = string.Empty;
		PolicyIDTextBox = null;
		PolicyBaseIDTextBox = null;
		PolicyVersionTextBox = null;
		PolicyInfoIDTextBox = null;
		PolicyTypeComboBox = null;
		HVCIOptionComboBox = null;
		PolicyFriendlyNameTextBox = null;

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

		MainInfoBar.WriteInfo(GlobalVars.GetStr("AllDataClearedMsg"));
		MainInfoBarIsClosable = true;

		SignatureRulesColumnManager.CalculateColumnWidths(SignatureRulesCollection);
		FileRulesColumnManager.CalculateColumnWidths(FileRulesCollection);
		CalculateAppIDTagsListViewColumnWidths();
	}


	/// <summary>
	/// Performs search in both collections of the ListView.
	/// Implementing it in the ViewModel via x:Bind would not work properly.
	/// </summary>
	internal async void SearchBox_TextChanged()
	{
		try
		{
			if (SearchTextBox is null)
				return;

			// Get the ListView ScrollViewer info
			ScrollViewer? Sv1 = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.PolicyEditor_FileBasedRules);
			double? savedHorizontal1 = null;
			if (Sv1 != null)
			{
				savedHorizontal1 = Sv1.HorizontalOffset;
			}

			ScrollViewer? Sv2 = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.PolicyEditor_SignatureBasedRules);
			double? savedHorizontal2 = null;
			if (Sv2 != null)
			{
				savedHorizontal2 = Sv2.HorizontalOffset;
			}

			string searchTerm = SearchTextBox.Trim();

			List<PolicyEditor.FileBasedRulesForListView> filteredResults = [];

			await Task.Run(() =>
			{
				// Perform a case-insensitive search in all relevant fields
				filteredResults = FileRulesCollectionList.Where(p =>
				(p.Id?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.FriendlyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.FileDescription?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.FileName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.FilePath?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.InternalName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.PackageFamilyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.ProductName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Hash?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
				).ToList();
			});

			FileRulesCollection.Clear();

			foreach (PolicyEditor.FileBasedRulesForListView item in CollectionsMarshal.AsSpan(filteredResults))
			{
				FileRulesCollection.Add(item);
			}

			if (Sv1 != null && savedHorizontal1.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv1.ChangeView(savedHorizontal1, null, null, disableAnimation: false);
			}


			List<PolicyEditor.SignatureBasedRulesForListView> filteredResults2 = [];

			await Task.Run(() =>
			{
				// Perform a case-insensitive search in all relevant fields
				filteredResults2 = [.. SignatureRulesCollectionList.Where(p =>
				(p.Id?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CertIssuer?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CertificateEKU?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CertOemID?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CertPublisher?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.CertRoot?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.Name?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
				)];
			});

			SignatureRulesCollection.Clear();

			foreach (PolicyEditor.SignatureBasedRulesForListView item in CollectionsMarshal.AsSpan(filteredResults2))
			{
				SignatureRulesCollection.Add(item);
			}

			if (Sv2 != null && savedHorizontal2.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv2.ChangeView(savedHorizontal2, null, null, disableAnimation: false);
			}

			// Adjust the column widths after performing search
			SignatureRulesColumnManager.CalculateColumnWidths(SignatureRulesCollection);
			FileRulesColumnManager.CalculateColumnWidths(FileRulesCollection);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	/// <summary>
	/// Used by various methods internally to open a created/modified policy in the Policy Editor
	/// </summary>
	/// <param name="policyFile">the path to the policy file to open in the Policy Editor</param>
	internal async Task OpenInPolicyEditor(SiPolicy.PolicyFileRepresent? policy)
	{
		try
		{
			// Navigate to the policy editor page
			ViewModelProvider.NavigationService.Navigate(typeof(Pages.PolicyEditor), null);

			// Assign the policy file path to the local variable
			SelectedPolicy = policy;

			await Task.Run(ProcessData);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for deleting selected items from the FileBasedRulesListView's Items Source
	/// </summary>
	internal void FileBasedRulesListView_DeleteItems()
	{
		// Get the ListView ScrollViewer info
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.PolicyEditor_FileBasedRules);

		if (lv is null) return;

		// Collect the selected items to delete - without ToList() or [.. ], only half of the selected items are removed from the collection
		List<PolicyEditor.FileBasedRulesForListView> itemsToDelete = lv.SelectedItems.Cast<PolicyEditor.FileBasedRulesForListView>().ToList();

		// Iterate over the copy to remove each item
		foreach (PolicyEditor.FileBasedRulesForListView item in CollectionsMarshal.AsSpan(itemsToDelete))
		{
			RemoveFileRuleFromCollection(item);
		}
	}

	/// <summary>
	/// Event handler for deleting selected items from the SignatureBasedRulesListView's Items Source
	/// </summary>
	internal void SignatureBasedRulesListView_DeleteItems()
	{
		// Get the ListView ScrollViewer info
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.PolicyEditor_SignatureBasedRules);

		if (lv is null) return;

		// Collect the selected items to delete - without ToList() or [.. ], only half of the selected items are removed from the collection
		List<PolicyEditor.SignatureBasedRulesForListView> itemsToDelete = lv.SelectedItems.Cast<PolicyEditor.SignatureBasedRulesForListView>().ToList();

		// Iterate over the copy to remove each item
		foreach (PolicyEditor.SignatureBasedRulesForListView item in CollectionsMarshal.AsSpan(itemsToDelete))
		{
			RemoveSignatureRuleFromCollection(item);
		}
	}

	/// <summary>
	/// Event handler for deleting selected items from the AppIDTagsCollection's Items Source
	/// </summary>
	internal void AppIDTagsListView_DeleteItems(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyEditor.AppIDTagsWithContext tag })
		{
			_ = AppIDTagsCollection.Remove(tag);
		}
	}

	/// <summary>
	/// Clears all of the Policy Settings in the collection.
	/// </summary>
	internal void ClearAllPolicySettings() => PolicySettingsCollection.Clear();

	/// <summary>
	/// Removes the selected Policy Setting item from the collection.
	/// </summary>
	internal void RemoveSelectedPolicySetting()
	{
		if (PolicySettingsSelectedItem is null)
			return;

		_ = PolicySettingsCollection.Remove(PolicySettingsSelectedItem);
	}

	/// <summary>
	/// Adds a new empty policy setting to the collection.
	/// </summary>
	internal void AddNewPolicySetting()
	{
		PolicyEditor.PolicySettings newSetting = new(
			provider: string.Empty,
			key: string.Empty,
			value: string.Empty,
			valueName: string.Empty,
			valueStr: string.Empty,
			type: 0,
			parentViewModel: this
		);

		PolicySettingsCollection.Add(newSetting);
	}

	/// <summary>
	/// Collection of preset policy settings that users can choose from
	/// </summary>
	internal List<PolicyEditor.PolicySettings> PresetPolicySettings { get; private set; }

	/// <summary>
	/// Adds the selected preset policy setting to the collection
	/// </summary>
	internal void AddPresetPolicySetting()
	{
		if (SelectedPresetPolicySetting is null) return;

		// Create a copy of the setting so that their properties won't be tied to each other
		PolicyEditor.PolicySettings newSetting = new(
			parentViewModel: this,
			provider: SelectedPresetPolicySetting.Provider,
			key: SelectedPresetPolicySetting.Key,
			value: SelectedPresetPolicySetting.Value,
			valueStr: SelectedPresetPolicySetting.ValueStr,
			valueName: SelectedPresetPolicySetting.ValueName,
			type: SelectedPresetPolicySetting.Type
		);

		PolicySettingsCollection.Add(newSetting);
	}

	/// <summary>
	/// Visibility property for the preset setting add button
	/// </summary>
	internal Visibility PresetAddButtonVisibility { get; set => SP(ref field, value); }

	internal PolicyEditor.PolicySettings? SelectedPresetPolicySetting
	{
		get; set
		{
			if (SP(ref field, value))
				PresetAddButtonVisibility = field is null ? Visibility.Collapsed : Visibility.Visible;
		}
	}

	// Texts bound to the UI TextBoxes for adding a new App ID Tag
	internal string? NewAppIDTagKey { get; set => SPT(ref field, value); }
	internal string? NewAppIDTagValue { get; set => SPT(ref field, value); }

	/// <summary>
	/// Adds a new App ID Tag to the collection with the key and value that user entered in the text boxes.
	/// </summary>
	internal void AddNewAppIDTag()
	{
		if (string.IsNullOrWhiteSpace(NewAppIDTagKey) || string.IsNullOrWhiteSpace(NewAppIDTagValue)) return;

		PolicyEditor.AppIDTagsWithContext newTag = new(
			context: SSType.UserMode,
			appIDTag: new(key: NewAppIDTagKey, value: NewAppIDTagValue)
		);

		AppIDTagsCollection.Add(newTag);

		// Update the column widths after adding a new item to the ListView's collection.
		CalculateAppIDTagsListViewColumnWidths();
	}

}
