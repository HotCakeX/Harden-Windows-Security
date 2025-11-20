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
using System.Threading.Tasks;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.ViewModels;

namespace HardenSystemSecurity.Traverse;

internal static class Generator
{

	/// <summary>
	/// Helper to verify all MUnits in a ViewModel and compute score + items for Traverse
	/// </summary>
	/// <param name="viewModel"></param>
	/// <param name="cancellationToken"></param>
	/// <returns></returns>
	internal static async Task<(int Score, List<MUnit> Items)> VerifyAndSnapshotMUnitCategoryAsync(
		IMUnitListViewModel viewModel,
		CancellationToken cancellationToken)
	{
		// Run verification across all MUnits so IsApplied is accurate
		await MUnit.ProcessMUnitsWithBulkOperations(viewModel, viewModel.AllMUnits, MUnitOperation.Verify, cancellationToken);

		// Compute score and return the same list as items
		int score = 0;
		foreach (MUnit m in viewModel.AllMUnits)
		{
			if (m.IsApplied == true)
			{
				score++;
			}
		}

		return (score, viewModel.AllMUnits);
	}


	/// <summary>
	/// The MAIN method that generates the complete system report.
	/// </summary>
	/// <returns></returns>
	internal static async Task GenerateTraverseData(string filePath)
	{
		if (Logger.CliRequested)
			Logger.Write(GlobalVars.GetStr("SystemStateReportGenerationBeginsMsg"));

		// Retrieve the data

		int total = 0;
		int compliant = 0;
		int nonCompliant = 0;

		// Microsoft Security Baseline
		Traverse.MicrosoftSecurityBaseline MSBaselineData = await ViewModelProvider.MicrosoftSecurityBaselineVM.GetTraverseData();
		total += MSBaselineData.Items.Count;
		compliant += MSBaselineData.Score;
		nonCompliant += MSBaselineData.Items.Count - MSBaselineData.Score;

		// Microsoft 365 Apps Security Baseline
		Traverse.Microsoft365AppsSecurityBaseline MS365BaselineData = await ViewModelProvider.Microsoft365AppsSecurityBaselineVM.GetTraverseData();
		total += MS365BaselineData.Items.Count;
		compliant += MS365BaselineData.Score;
		nonCompliant += MS365BaselineData.Items.Count - MS365BaselineData.Score;

		// Attack Surface Reduction Rules
		Traverse.AttackSurfaceReductionRules ASR = await ViewModelProvider.ASRVM.GetTraverseData();
		total += ASR.Items.Count;
		compliant += ASR.Score;
		nonCompliant += ASR.Items.Count - ASR.Score;

		// CBOM
		Arcane.CbomDocument CBOM = await ViewModelProvider.CryptographicBillOfMaterialsVM.GetTraverseData();

		#region MUnit based items

		CancellationToken ct = CancellationToken.None;

		// Microsoft Defender
		(int Score, List<MUnit> Items) = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.MicrosoftDefenderVM, ct);
		HardenSystemSecurity.Traverse.MicrosoftDefender mdTraverse = new(Items) { Score = Score };
		total += Items.Count;
		compliant += Score;
		nonCompliant += Items.Count - Score;

		// BitLocker
		(int Score, List<MUnit> Items) blTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.BitLockerVM, ct);
		HardenSystemSecurity.Traverse.BitLockerSettings blTraverse = new(blTuple.Items) { Score = blTuple.Score };
		total += blTuple.Items.Count;
		compliant += blTuple.Score;
		nonCompliant += blTuple.Items.Count - blTuple.Score;

		// TLS
		(int Score, List<MUnit> Items) tlsTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.TLSVM, ct);
		HardenSystemSecurity.Traverse.TLSSecurity tlsTraverse = new(tlsTuple.Items) { Score = tlsTuple.Score };
		total += tlsTuple.Items.Count;
		compliant += tlsTuple.Score;
		nonCompliant += tlsTuple.Items.Count - tlsTuple.Score;

		// Lock Screen
		(int Score, List<MUnit> Items) lsTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.LockScreenVM, ct);
		HardenSystemSecurity.Traverse.LockScreen lsTraverse = new(lsTuple.Items) { Score = lsTuple.Score };
		total += lsTuple.Items.Count;
		compliant += lsTuple.Score;
		nonCompliant += lsTuple.Items.Count - lsTuple.Score;

		// UAC
		(int Score, List<MUnit> Items) uacTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.UACVM, ct);
		HardenSystemSecurity.Traverse.UserAccountControl uacTraverse = new(uacTuple.Items) { Score = uacTuple.Score };
		total += uacTuple.Items.Count;
		compliant += uacTuple.Score;
		nonCompliant += uacTuple.Items.Count - uacTuple.Score;

		// Device Guard
		(int Score, List<MUnit> Items) dgTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.DeviceGuardVM, ct);
		HardenSystemSecurity.Traverse.DeviceGuard dgTraverse = new(dgTuple.Items) { Score = dgTuple.Score };
		total += dgTuple.Items.Count;
		compliant += dgTuple.Score;
		nonCompliant += dgTuple.Items.Count - dgTuple.Score;

		// Windows Firewall
		(int Score, List<MUnit> Items) wfTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.WindowsFirewallVM, ct);
		HardenSystemSecurity.Traverse.WindowsFirewall wfTraverse = new(wfTuple.Items) { Score = wfTuple.Score };
		total += wfTuple.Items.Count;
		compliant += wfTuple.Score;
		nonCompliant += wfTuple.Items.Count - wfTuple.Score;

		// Windows Networking
		(int Score, List<MUnit> Items) wnTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.WindowsNetworkingVM, ct);
		HardenSystemSecurity.Traverse.WindowsNetworking wnTraverse = new(wnTuple.Items) { Score = wnTuple.Score };
		total += wnTuple.Items.Count;
		compliant += wnTuple.Score;
		nonCompliant += wnTuple.Items.Count - wnTuple.Score;

		// Miscellaneous Configurations
		(int Score, List<MUnit> Items) miscTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.MiscellaneousConfigsVM, ct);
		HardenSystemSecurity.Traverse.MiscellaneousConfigurations miscTraverse = new(miscTuple.Items) { Score = miscTuple.Score };
		total += miscTuple.Items.Count;
		compliant += miscTuple.Score;
		nonCompliant += miscTuple.Items.Count - miscTuple.Score;

		// Windows Update Configurations
		(int Score, List<MUnit> Items) wuTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.WindowsUpdateVM, ct);
		HardenSystemSecurity.Traverse.WindowsUpdateConfigurations wuTraverse = new(wuTuple.Items) { Score = wuTuple.Score };
		total += wuTuple.Items.Count;
		compliant += wuTuple.Score;
		nonCompliant += wuTuple.Items.Count - wuTuple.Score;

		// Edge Browser Configurations
		(int Score, List<MUnit> Items) edgeTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.EdgeVM, ct);
		HardenSystemSecurity.Traverse.EdgeBrowserConfigurations edgeTraverse = new(edgeTuple.Items) { Score = edgeTuple.Score };
		total += edgeTuple.Items.Count;
		compliant += edgeTuple.Score;
		nonCompliant += edgeTuple.Items.Count - edgeTuple.Score;

		// Non-Admin Commands
		(int Score, List<MUnit> Items) naTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.NonAdminVM, ct);
		HardenSystemSecurity.Traverse.NonAdminCommands naTraverse = new(naTuple.Items) { Score = naTuple.Score };
		total += naTuple.Items.Count;
		compliant += naTuple.Score;
		nonCompliant += naTuple.Items.Count - naTuple.Score;

		// MSFT Baselines Optional Overrides
		(int Score, List<MUnit> Items) ovTuple = await VerifyAndSnapshotMUnitCategoryAsync(ViewModelProvider.MicrosoftBaseLinesOverridesVM, ct);
		HardenSystemSecurity.Traverse.MSFTSecBaselines_OptionalOverrides ovTraverse = new(ovTuple.Items) { Score = ovTuple.Score };
		total += ovTuple.Items.Count;
		compliant += ovTuple.Score;
		nonCompliant += ovTuple.Items.Count - ovTuple.Score;

		#endregion

		await Task.Run(() =>
		{
			MContainer container = new(
				total: total,
				compliant: compliant,
				nonCompliant: nonCompliant,
				microsoftSecurityBaseline: MSBaselineData,
				microsoft365AppsSecurityBaseline: MS365BaselineData,
				attackSurfaceReductionRules: ASR,
				microsoftDefender: mdTraverse,
				bitLockerSettings: blTraverse,
				tlsSecurity: tlsTraverse,
				lockScreen: lsTraverse,
				userAccountControl: uacTraverse,
				deviceGuard: dgTraverse,
				windowsFirewall: wfTraverse,
				windowsNetworking: wnTraverse,
				miscellaneousConfigurations: miscTraverse,
				windowsUpdateConfigurations: wuTraverse,
				edgeBrowserConfigurations: edgeTraverse,
				nonAdminCommands: naTraverse,
				msftSecBaselines_OptionalOverrides: ovTraverse,
				cryptographicBillOfMaterial: CBOM
				);

			MContainerJsonContext.SerializeSingle(container, filePath);

			if (Logger.CliRequested)
				Logger.Write(string.Format(GlobalVars.GetStr("SystemStateReportGenerationFinishedMsg"), filePath));
		});
	}

	/// <summary>
	/// Returns an appropriate name for the file that contains the <see cref="MContainer"/>.
	/// </summary>
	/// <returns></returns>
	internal static string GetFileName() => $"HardenSystemSecurity-Report-{DateTime.Now:yyyy-MM-dd_HH-mm-ss}.json";

}
