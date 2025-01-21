using System.Collections.Generic;

namespace AppControlManager.Others;

// GroupInfoListForPackagedAppView class definition
public sealed partial class GroupInfoListForPackagedAppView(IEnumerable<PackagedAppView> items) : List<PackagedAppView>(items)
{
	// string is the type for Key since it's based on DisplayName[..1] and will always be a string
	public required string Key { get; set; }

	public override string ToString()
	{
		return "Group " + Key;
	}
}
