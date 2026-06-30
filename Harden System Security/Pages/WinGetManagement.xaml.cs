using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace HardenSystemSecurity.Pages;

internal sealed partial class WinGetManagement : Page, CommonCore.UI.IPageHeaderProvider
{
	internal WinGetManagementVM ViewModel => ViewModelProvider.WinGetManagementVM;

	internal WinGetManagement()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
		WinGetSectionSelectorBar.SelectedItem = SearchSectionSelectorBarItem;
	}

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => Atlas.GetStr("WinGetManagementNavItem/ToolTipService/ToolTip");
	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/WinGet-Management");

	private void WinGetSectionSelectorBar_SelectionChanged(SelectorBar sender, SelectorBarSelectionChangedEventArgs args)
	{
		SearchSectionGrid.Visibility = sender.SelectedItem == SearchSectionSelectorBarItem ? Visibility.Visible : Visibility.Collapsed;
		InstalledProgramsSectionGrid.Visibility = sender.SelectedItem == InstalledProgramsSectionSelectorBarItem ? Visibility.Visible : Visibility.Collapsed;
		BundlesSectionGrid.Visibility = sender.SelectedItem == BundlesSectionSelectorBarItem ? Visibility.Visible : Visibility.Collapsed;
		SourcesSectionGrid.Visibility = sender.SelectedItem == SourcesSectionSelectorBarItem ? Visibility.Visible : Visibility.Collapsed;
	}

	internal void BundleGridView_ItemClick(object sender, ItemClickEventArgs args)
	{
		ViewModel.BundleGridView_ItemClick(sender, args);
		BundleTilesGrid.IsHitTestVisible = false;
		BundleOverlayGrid.IsHitTestVisible = true;
		BundleOverlayGrid.Visibility = Visibility.Visible;
		BundleOverlayOpenStoryboard.Begin();
		BundleTilesOutStoryboard.Begin();
	}

	internal void CloseSelectedBundle_Click(object sender, RoutedEventArgs args) => BundleOverlayCloseStoryboard.Begin();

	private void BundleTilesOutStoryboard_Completed(object? sender, object e)
	{
		if (ViewModel.SelectedPackageBundle is not null)
		{
			BundleTilesGrid.Visibility = Visibility.Collapsed;
		}
	}

	private void BundleOverlayCloseStoryboard_Completed(object? sender, object e)
	{
		BundleOverlayGrid.Visibility = Visibility.Collapsed;
		BundleOverlayGrid.IsHitTestVisible = false;
		ViewModel.CloseSelectedBundle_Click();
		BundleTilesGrid.Visibility = Visibility.Visible;
		BundleTilesGrid.IsHitTestVisible = true;
		BundleTilesInStoryboard.Begin();
	}
}
