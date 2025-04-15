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


/*

The code in this page is MODIFIED version of the MIT licensed code in the following repository: https://github.com/CommunityToolkit/Windows
Taken from this URL: https://github.com/CommunityToolkit/Windows/tree/321f5ddc8f3bf07865c8f51d992febb25fd7859a/components/Behaviors/src/Headers

It's removed the "ScrollViewer_GotFocus" from the base class to prevent scroll positions from changing when clicking on the header which is an unwanted behavior.

License file: https://github.com/CommunityToolkit/Windows/blob/main/License.md

Windows Community Toolkit
Copyright © .NET Foundation and Contributors

All rights reserved.

MIT License (MIT)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 
 */

using System.Numerics;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Animations.Expressions;
using CommunityToolkit.WinUI.Behaviors;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Base class helper for header behaviors which manipulate an element within a viewport of a <see cref="ListViewBase"/> based control.
/// </summary>
internal abstract class HeaderBehaviorBase : BehaviorBase<FrameworkElement>
{
	// From Doc: https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.canvas.zindex
	private const int CanvasZIndexMax = 1_000_000;

	/// <summary>
	/// The ScrollViewer associated with the ListViewBase control.
	/// </summary>
	private protected ScrollViewer? _scrollViewer;

	/// <summary>
	/// The CompositionPropertySet associated with the ScrollViewer.
	/// </summary>
	private protected CompositionPropertySet? _scrollProperties;

	/// <summary>
	/// The CompositionPropertySet associated with the animation.
	/// </summary>
	private protected CompositionPropertySet? _animationProperties;

	/// <summary>
	/// The Visual associated with the header element.
	/// </summary>
	private protected Visual? _headerVisual;

	/// <summary>
	/// Attaches the behavior to the associated object.
	/// </summary>
	/// <returns>
	///   <c>true</c> if attaching succeeded; otherwise <c>false</c>.
	/// </returns>
	protected override bool Initialize()
	{
		bool result = AssignAnimation();
		return result;
	}

	/// <summary>
	/// Detaches the behavior from the associated object.
	/// </summary>
	/// <returns>
	///   <c>true</c> if detaching succeeded; otherwise <c>false</c>.
	/// </returns>
	protected override bool Uninitialize()
	{
		RemoveAnimation();
		return true;
	}

	/// <summary>
	/// Uses Composition API to get the UIElement and sets an ExpressionAnimation.
	/// </summary>
	/// <remarks>
	/// If this method returns true, you should have access to all protected fields with assigned components to use.
	/// </remarks>
	/// <returns><c>true</c> if the assignment was successful; otherwise, <c>false</c>.</returns>
	protected virtual bool AssignAnimation()
	{
		StopAnimation();

		// Double-check that we have an element associated with us (we should) and that it has size
		if (AssociatedObject == null || AssociatedObject.RenderSize.Height == 0)
		{
			return false;
		}

		if (_scrollViewer == null)
		{
			// TODO: We probably want checks which provide better guidance if we detect we're not attached correctly?
			_scrollViewer = AssociatedObject.FindAscendant<ScrollViewer>();
		}

		if (_scrollViewer == null)
		{
			return false;
		}

		ItemsControl? itemsControl = AssociatedObject.FindAscendant<ItemsControl>();

		if (itemsControl != null && itemsControl.ItemsPanelRoot != null)
		{
			// This appears to be important to force the items within the ScrollViewer of an ItemsControl behind our header element.
			Canvas.SetZIndex(itemsControl.ItemsPanelRoot, -1);
		}
		else
		{
			// If we're not part of a collection panel, then we're probably just in the ScrollViewer,
			// And we should ensure our 'header' element is on top of any other content within the ScrollViewer.
			Canvas.SetZIndex(AssociatedObject, CanvasZIndexMax);
		}

		if (_scrollProperties == null)
		{
			_scrollProperties = ElementCompositionPreview.GetScrollViewerManipulationPropertySet(_scrollViewer);
		}

		if (_scrollProperties == null)
		{
			return false;
		}

		if (_headerVisual == null)
		{
			_headerVisual = ElementCompositionPreview.GetElementVisual(AssociatedObject);
		}

		if (_headerVisual == null)
		{
			return false;
		}

		// TODO: Not sure if we need to provide an option to turn these events off, as FadeHeaderBehavior didn't use these two, unlike QuickReturn/Sticky did...
		AssociatedObject.SizeChanged -= ScrollHeader_SizeChanged;
		AssociatedObject.SizeChanged += ScrollHeader_SizeChanged;

		Compositor compositor = _scrollProperties.Compositor;

		if (_animationProperties == null)
		{
			_animationProperties = compositor.CreatePropertySet();
		}

		return true;
	}

	/// <summary>
	/// Stop the animation of the UIElement.
	/// </summary>
	protected abstract void StopAnimation();

	/// <summary>
	/// Remove the animation from the UIElement.
	/// </summary>
	protected virtual void RemoveAnimation()
	{

		if (AssociatedObject != null)
		{
			AssociatedObject.SizeChanged -= ScrollHeader_SizeChanged;
		}

		StopAnimation();
	}

	private void ScrollHeader_SizeChanged(object sender, SizeChangedEventArgs e)
	{
		_ = AssignAnimation();
	}
}


internal sealed class StickyHeaderBehaviorV2 : HeaderBehaviorBase
{

	/// <summary>
	/// Show the header
	/// </summary>
	public void Show()
	{
		if (_headerVisual != null && _scrollViewer != null)
		{
			_animationProperties?.InsertScalar("OffsetY", 0.0f);
		}
	}

	/// <inheritdoc/>
	protected override bool AssignAnimation()
	{
		if (base.AssignAnimation())
		{
			_animationProperties?.InsertScalar("OffsetY", 0.0f);

			ScalarNode propSetOffset = _animationProperties!.GetReference().GetScalarProperty("OffsetY");
			ManipulationPropertySetReferenceNode scrollPropSet = _scrollProperties!.GetSpecializedReference<ManipulationPropertySetReferenceNode>();
			ScalarNode expressionAnimation = ExpressionFunctions.Max(propSetOffset - scrollPropSet.Translation.Y, 0);

			_headerVisual?.StartAnimation("Offset.Y", expressionAnimation);

			return true;
		}

		return false;
	}

	/// <inheritdoc/>
	protected override void StopAnimation()
	{
		_animationProperties?.InsertScalar("OffsetY", 0.0f);

		if (_headerVisual != null)
		{
			_headerVisual.StopAnimation("Offset.Y");

			Vector3 offset = _headerVisual.Offset;
			offset.Y = 0.0f;
			_headerVisual.Offset = offset;
		}
	}

}
