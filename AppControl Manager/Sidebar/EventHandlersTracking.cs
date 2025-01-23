using Microsoft.UI.Xaml;

namespace AppControlManager.Sidebar;

/// <summary>
/// Each page that implements the IAnimatedIconsManager interface assigns local event handlers to the sidebar buttons
/// And after method assignment, sets the same method to one of the static variables defined in this class so the main Window class
/// Will use it for un-subscription
/// </summary>
internal static class EventHandlersTracking
{
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect1EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect2EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect3EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect4EventHandler;
	internal static RoutedEventHandler? SidebarUnsignedBasePolicyConnect5EventHandler;
}
