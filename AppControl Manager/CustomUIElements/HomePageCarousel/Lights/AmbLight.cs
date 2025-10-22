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

// The following code is based on the Microsoft AI Dev Gallery, MIT licensed code.
// It has modifications made by Violet Hansen.
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Repository: https://github.com/microsoft/ai-dev-gallery
// License file: https://github.com/microsoft/ai-dev-gallery/blob/main/LICENSE
//    MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE
//

using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.CustomUIElements.HomePageCarousel.Lights;

internal sealed partial class AmbLight : XamlLight
{
	private static readonly string Id = typeof(AmbLight).FullName!;

	protected override void OnConnected(UIElement newElement)
	{
		Compositor compositor = CompositionTarget.GetCompositorForCurrentThread();

		// Create AmbientLight and set its properties
		AmbientLight ambientLight = compositor.CreateAmbientLight();
		ambientLight.Color = Colors.White;

		// Associate CompositionLight with XamlLight
		CompositionLight = ambientLight;

		// Add UIElement to the Light's Targets
		AddTargetElement(GetId(), newElement);
	}

	protected override void OnDisconnected(UIElement oldElement)
	{
		// Dispose Light when it is removed from the tree
		RemoveTargetElement(GetId(), oldElement);
		CompositionLight.Dispose();
	}

	protected override string GetId() => Id;
}
