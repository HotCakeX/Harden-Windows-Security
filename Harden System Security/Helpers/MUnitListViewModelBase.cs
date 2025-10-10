using System.Collections.Generic;
using System.Collections.ObjectModel;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.Helpers;

/// <summary>
/// Viewmodels that utilize the <see cref="AppControlManager.CustomUIElements.MUnitListViewControl"/> must inherit from this base class.
/// </summary>
internal abstract partial class MUnitListViewModelBase : ViewModelBase, IMUnitListViewModel
{
	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	public required InfoBarSettings MainInfoBar { get; init; } // Set in the Ctor of the VM class the inherits from this class.

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	public bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	public List<GroupInfoListForMUnit> ListViewItemsSourceBackingField { get; set; } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	public List<MUnit> ItemsSourceSelectedItems { get; set; } = [];

	/// <summary>
	/// Search keyword for ListView.
	/// </summary>
	public string? SearchKeyword { get; set; }

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	public required AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; init; } // Set in the Ctor of the VM class the inherits from this class.

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	public required AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; init; } // Set in the Ctor of the VM class the inherits from this class.

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	public required AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; init; } // Set in the Ctor of the VM class the inherits from this class.

	/// <summary>
	/// Total number of items loaded (all MUnits)
	/// </summary>
	public int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	public int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	public int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Undetermined status (N/A state)
	/// </summary>
	public int UndeterminedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Applied status
	/// </summary>
	public int AppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with NotApplied status
	/// </summary>
	public int NotAppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Persisted status filter toggles for this ViewModel.
	/// </summary>
	public bool ShowApplied { get; set => SP(ref field, value); } = true;
	public bool ShowNotApplied { get; set => SP(ref field, value); } = true;
	public bool ShowUndetermined { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// Derived classes should override to return the actual list and logic for their category.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	public virtual List<MUnit> CreateAllMUnits() => [];
}
