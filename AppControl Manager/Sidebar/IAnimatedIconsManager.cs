using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.Sidebar;

/// <summary>
/// The interface that all of the pages that host AnimatedIcons in order to be able to accept policy paths from the Sidebar use
/// </summary>
internal interface IAnimatedIconsManager
{
	void SetVisibility(Visibility visibility, string? unsignedBasePolicyPath, Button button1, Button button2, Button button3);
}
