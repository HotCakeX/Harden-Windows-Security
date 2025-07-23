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
using HardenWindowsSecurity.GroupPolicy;
using HardenWindowsSecurity.ViewModels;
using Microsoft.UI.Xaml;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;

#pragma warning disable CA1812

namespace HardenWindowsSecurity.Protect;

/// <summary>
/// The apply strategy interface.
/// </summary>
internal interface IApplyStrategy
{
	void Apply();
}

/// <summary>
/// A marker + payload strategy for bulk secedit system‐access policy.
/// Only used for specific policies that we use secedit to apply.
/// </summary>
internal interface IApplySecedit : IApplyStrategy
{
	/// <summary>
	/// The per‐unit settings that will be merged into one dictionary.
	/// </summary>
	Dictionary<string, string> Settings { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplySecedit"/> strategy.
/// </summary>
internal sealed class SeceditApply(Dictionary<string, string> settings) : IApplySecedit
{
	public Dictionary<string, string> Settings => settings;

	// This will never be called on its own: we bulk-invoke SetSystemAccessPolicy instead.
	public void Apply() =>
		throw new InvalidOperationException(
			"SystemAccessApply should be bulk‑invoked via SetSystemAccessPolicy");
}

/// <summary>
/// A marker + payload strategy for bulk Group Policy application.
/// </summary>
internal interface IApplyGroupPolicy : IApplyStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be applied for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IApplyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyApply(List<RegistryPolicyEntry> policies) : IApplyGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own: we bulk-invoke ApplyPolicies instead.
	public void Apply() => throw new InvalidOperationException(
			"GroupPolicyApply should be bulk‑invoked via ApplyPolicies");
}

/// <summary>
/// A delegate‑based apply strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultApply(Action action) : IApplyStrategy
{
	public void Apply() => action();
}

/// <summary>
/// The verify strategy interface.
/// </summary>
internal interface IVerifyStrategy
{
	bool Verify();
}

/// <summary>
/// A marker + payload strategy for bulk Group Policy application.
/// </summary>
internal interface IVerifyGroupPolicy : IVerifyStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be verified for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IVerifyGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyVerify(List<RegistryPolicyEntry> policies) : IVerifyGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public bool Verify() =>
		throw new InvalidOperationException("should be bulk‑invoked.");

}

/// <summary>
/// A delegate‐based verify strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultVerify(Func<bool> func) : IVerifyStrategy
{
	public bool Verify() => func();
}


/// <summary>
/// The Remove strategy interface.
/// </summary>
internal interface IRemoveStrategy
{
	void Remove();
}

/// <summary>
/// A delegate‑based remove strategy whose logic is provided at construction time.
/// </summary>
internal sealed class DefaultRemove(Action action) : IRemoveStrategy
{
	public void Remove() => action();
}

/// <summary>
/// A marker + payload strategy for bulk Group Policy removal.
/// </summary>
internal interface IRemoveGroupPolicy : IRemoveStrategy
{
	/// <summary>
	/// One or more Group Policies that need to be removed for one specific protection measure.
	/// </summary>
	List<RegistryPolicyEntry> Policies { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveGroupPolicy"/> strategy.
/// </summary>
/// <param name="policies"></param>
internal sealed class GroupPolicyRemove(List<RegistryPolicyEntry> policies) : IRemoveGroupPolicy
{
	public List<RegistryPolicyEntry> Policies => policies;

	// This will never be called on its own.
	public void Remove() =>
		throw new InvalidOperationException("should be bulk‑invoked.");
}

/// <summary>
/// A marker + payload strategy for bulk secedit system‐access policy removal.
/// Only used for specific policies that we use secedit to remove/change.
/// </summary>
internal interface IRemoveSecedit : IRemoveStrategy
{
	/// <summary>
	/// The per‐unit settings that will be merged into one dictionary.
	/// </summary>
	Dictionary<string, string> Settings { get; }
}

/// <summary>
/// Implementation of the <see cref="IRemoveSecedit"/> strategy.
/// </summary>
internal sealed class SeceditRemove(Dictionary<string, string> settings) : IRemoveSecedit
{
	public Dictionary<string, string> Settings => settings;

	// This will never be called on its own: we bulk-invoke SetSystemAccessPolicy instead.
	public void Remove() =>
		throw new InvalidOperationException(
			"SystemAccessApply should be bulk‑invoked via SetSystemAccessPolicy");
}

/// <summary>
/// Represents a unit that can contain any security measure, how to apply it and how to verify it.
/// </summary>
internal sealed partial class MUnit(
	Categories category,
	string? name,
	IApplyStrategy applyStrategy,
	IVerifyStrategy? verifyStrategy = null,
	IRemoveStrategy? removeStrategy = null,
	MicrosoftDefenderVM? defenderVM = null,
	SubCategories? subCategory = null,
	string? url = null) : ViewModelBase
{

	/// <summary>
	/// The category this unit belongs to.
	/// </summary>
	internal Categories Category => category;

	/// <summary>
	/// The name of this unit.
	/// </summary>
	internal string? Name => name;

	/// <summary>
	/// What runs for applying this unit.
	/// </summary>
	internal IApplyStrategy ApplyStrategy => applyStrategy;

	/// <summary>
	/// What runs for verifying this unit.
	/// Not all strategies need/can have verification.
	/// </summary>
	internal IVerifyStrategy? VerifyStrategy { get; set; } = verifyStrategy;

	/// <summary>
	/// What runs for removing this unit.
	/// Not all strategies need/can have removal.
	/// </summary>
	internal IRemoveStrategy? RemoveStrategy => removeStrategy;

	/// <summary>
	/// To store the result whether this protection measure is applied or not.
	/// </summary>
	internal bool? IsApplied
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				// Force immediate UI update on the correct thread
				_ = Dispatcher.TryEnqueue(() =>
				{
					OnPropertyChanged(nameof(StatusState));
				});
			}
		}
	}

	/// ViewModel references
	internal MicrosoftDefenderVM? DefenderVM => defenderVM;

	/// <summary>
	/// Optional sub-category this unit belongs to.
	/// </summary>
	internal SubCategories? SubCategory => subCategory;

	/// <summary>
	/// Used to point the ListView in the UI to a web location for more info or documentation.
	/// </summary>
	internal string? URL => url;

	// Properties for UI binding
	internal StatusState StatusState => IsApplied switch
	{
		true => StatusState.Applied,
		false => StatusState.NotApplied,
		null => StatusState.Undetermined
	};

	internal bool HasSubCategory => SubCategory.HasValue;

	internal string SubCategoryName => SubCategory?.ToString() ?? string.Empty;

	internal bool HasURL => !string.IsNullOrWhiteSpace(URL);

	internal Visibility SubCategoryVisibility => HasSubCategory ? Visibility.Visible : Visibility.Collapsed;

	internal Visibility URLVisibility => HasURL ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Method to handle Apply button click
	/// </summary>
	internal void ApplyMUnit()
	{
		DefenderVM?.ApplyMUnit(this);
	}

	/// <summary>
	/// Method to handle Remove button click
	/// </summary>
	internal void RemoveMUnit()
	{
		DefenderVM?.RemoveMUnit(this);
	}

	/// <summary>
	/// Method to handle Verify button click
	/// </summary>
	internal void VerifyMUnit()
	{
		DefenderVM?.VerifyMUnit(this);
	}
}
