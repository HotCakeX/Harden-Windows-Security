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

using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Windows.Media;
using Windows.Media.Audio;
using Windows.Media.Capture;
using Windows.Media.MediaProperties;
using Windows.Media.Render;
using Windows.Media.Transcoding;
using Windows.Storage;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

/// <summary>
/// The lifecycle state of the Acoustic Sentry.
/// </summary>
internal enum TopBarSentryState
{
	/// <summary>
	/// Nothing is captured or monitored. The microphone is not held open.
	/// </summary>
	Idle = 0,

	/// <summary>
	/// The microphone is open and the ambient level is being watched, but no capture is in flight.
	/// </summary>
	Armed = 1,

	/// <summary>
	/// A capture is currently being written to disk.
	/// </summary>
	Recording = 2
}

/// <summary>
/// An immutable snapshot of the Sentry that is raised to the owner whenever the engine changes state.
/// </summary>
internal readonly struct TopBarSentryStatus(TopBarSentryState state, int completedCycles)
{
	internal TopBarSentryState State => state;
	internal int CompletedCycles => completedCycles;
}

/// <summary>
/// The values that arm a Sentry session. They are copied into the engine so that a later settings change does not
/// alter a session that is already running unless it is pushed in explicitly through one of the Update methods.
/// </summary>
internal readonly struct TopBarSentrySettings(double thresholdDecibel, int recordingDurationSeconds, int cooldownSeconds, int maxCycles, string outputDirectory)
{
	internal double ThresholdDecibel => thresholdDecibel;
	internal int RecordingDurationSeconds => recordingDurationSeconds;
	internal int CooldownSeconds => cooldownSeconds;
	internal int MaxCycles => maxCycles;
	internal string OutputDirectory => outputDirectory;
}

/// <summary>
/// The outcome of an arm request. When it fails, <see cref="PermissionDenied"/> tells the view whether the cause was
/// the microphone privacy setting, so that the view can offer to open the relevant Settings page.
/// </summary>
internal readonly struct TopBarSentryArmResult(bool success, string? error, bool permissionDenied)
{
	internal bool Success => success;
	internal string? Error => error;
	internal bool PermissionDenied => permissionDenied;
}

/// <summary>
/// The engine of the Acoustic Sentry view of the Top Bar.
///
/// It opens the default microphone through an <see cref="AudioGraph"/> and watches the ambient loudness continuously.
/// The moment the level crosses the user defined trigger it captures the environment to a high fidelity WAV file for
/// a chosen duration, then it waits out a cooldown before it is allowed to trigger again. The whole session runs in
/// the background independently of which Top Bar view is on display and it keeps capturing while the workstation is
/// locked, because an <see cref="AudioGraph"/> capture is bound to the process rather than to the desktop.
///
/// Everything about the capture is measured natively off the audio thread so that a capture never has to walk any
/// managed process table and so that the level meter of the view can read the very same numbers without any cost.
/// </summary>
internal sealed partial class TopBarSentryEngine : IDisposable
{
	/// <summary>
	/// The IID of Windows.Foundation.IMemoryBufferByteAccess, used to reach the raw float samples of an audio frame.
	/// https://learn.microsoft.com/windows/win32/winrt/imemorybufferbyteaccess
	/// </summary>
	private static readonly Guid IMemoryBufferByteAccessIID = new("5B0D3235-4DBA-4D44-865E-8F1D0E4FD04D");

	/// <summary>
	/// The class identifier of the multimedia device enumerator, and the interface identifiers of the enumerator and
	/// of the endpoint volume, all used only to read the mute state of the default capture endpoint.
	/// https://learn.microsoft.com/windows/win32/coreaudio/mmdevice-api
	/// </summary>
	private static readonly Guid CLSID_MMDeviceEnumerator = new("BCDE0395-E52F-467C-8E3D-C4579291692E");
	private static readonly Guid IID_IMMDeviceEnumerator = new("A95664D2-9614-4F35-A746-DE8DB63617E6");
	private static readonly Guid IID_IAudioEndpointVolume = new("5CDF2C82-841E-4546-9722-0CF74078229A");

	/// <summary>
	/// The floor that a fully silent quantum is reported at, so that the logarithm never has to be taken of zero.
	/// </summary>
	private const double SilenceFloorDecibel = -100.0;

	/// <summary>
	/// The default folder that captures are written to when the user has not chosen one of their own.
	/// </summary>
	internal static string DefaultOutputDirectory => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Harden System Security Sentry");

	private readonly DispatcherQueue _dispatcherQueue;

	private AudioGraph? _graph;
	private AudioDeviceInputNode? _deviceInputNode;
	private AudioFrameOutputNode? _frameOutputNode;
	private AudioFileOutputNode? _fileOutputNode;
	private MediaEncodingProfile? _recordingProfile;
	private CancellationTokenSource? _recordingStopSource;

	// The trigger and the current reading are kept as the raw bits of a double so that a 64-bit value can be shared
	// between the audio thread and the UI thread without ever being read halfway through a write.
	private long _thresholdBits;
	private long _currentDecibelBits = BitConverter.DoubleToInt64Bits(SilenceFloorDecibel);
	private long _cooldownUntilTick;

	// Accessed through Interlocked/Volatile, so these must not carry the volatile modifier.
	private int _state = (int)TopBarSentryState.Idle;
	private int _completedCycles;
	private volatile int _maxCycles;
	private volatile int _recordingDurationSeconds = 30;
	private volatile int _cooldownSeconds = 5;

	// The output directory is a reference and a reference assignment is atomic, so it needs no further guarding.
	private string _outputDirectory = string.Empty;

	private int _shutdownStarted;
	private bool _disposed;

	internal TopBarSentryEngine(DispatcherQueue dispatcherQueue) => _dispatcherQueue = dispatcherQueue;

	/// <summary>
	/// Raised on the UI thread whenever the engine transitions between states or finishes a capture.
	/// </summary>
	internal event EventHandler<TopBarSentryStatus>? StatusChanged;

	/// <summary>
	/// The current lifecycle state of the engine.
	/// </summary>
	internal TopBarSentryState State => (TopBarSentryState)_state;

	/// <summary>
	/// The most recent ambient loudness reading in dBFS. It is refreshed on every audio quantum.
	/// </summary>
	internal double CurrentDecibel => BitConverter.Int64BitsToDouble(Volatile.Read(ref _currentDecibelBits));

	/// <summary>
	/// How many capture cycles have completed since the engine was armed.
	/// </summary>
	internal int CompletedCycles => _completedCycles;

	/// <summary>
	/// Opens the microphone and starts watching the ambient level. The returned result reports why the microphone
	/// could not be opened when that is the case, so that the view can surface it to the user.
	/// </summary>
	internal async Task<TopBarSentryArmResult> ArmAsync(TopBarSentrySettings settings)
	{
		try
		{
			Volatile.Write(ref _thresholdBits, BitConverter.DoubleToInt64Bits(settings.ThresholdDecibel));
			_recordingDurationSeconds = Math.Max(1, settings.RecordingDurationSeconds);
			_cooldownSeconds = Math.Max(0, settings.CooldownSeconds);
			_maxCycles = Math.Max(0, settings.MaxCycles);
			_outputDirectory = settings.OutputDirectory ?? string.Empty;
			_completedCycles = 0;
			Volatile.Write(ref _cooldownUntilTick, 0L);

			// The render category is nominal for a capture only graph, but a category still has to be named.
			AudioGraphSettings graphSettings = new(AudioRenderCategory.Media);
			CreateAudioGraphResult graphResult = await AudioGraph.CreateAsync(graphSettings);
			if (graphResult.Status != AudioGraphCreationStatus.Success || graphResult.Graph is null)
			{
				return new TopBarSentryArmResult(false, "The audio engine could not start (" + graphResult.Status.ToString() + ").", false);
			}

			_graph = graphResult.Graph;

			CreateAudioDeviceInputNodeResult inputResult = await _graph.CreateDeviceInputNodeAsync(MediaCategory.Media);
			if (inputResult.Status != AudioDeviceNodeCreationStatus.Success || inputResult.DeviceInputNode is null)
			{
				await ShutdownGraphAsync();
				bool permissionDenied = inputResult.Status == AudioDeviceNodeCreationStatus.AccessDenied;
				string reason = inputResult.Status switch
				{
					AudioDeviceNodeCreationStatus.AccessDenied => "Microphone access is turned off for this app. Turn it on under Settings, Privacy and security, Microphone, and make sure app access is allowed.",
					AudioDeviceNodeCreationStatus.DeviceNotAvailable => "No microphone was found. Connect a recording device and try again.",
					AudioDeviceNodeCreationStatus.FormatNotSupported => "The microphone does not support a format the recorder can use.",
					_ => "The microphone could not be opened (" + inputResult.Status.ToString() + ")."
				};
				return new TopBarSentryArmResult(false, reason, permissionDenied);
			}

			_deviceInputNode = inputResult.DeviceInputNode;

			// The microphone opened, which confirms that a device is present and that access to it is allowed, but a
			// device that is muted still opens and only ever delivers digital silence, which the availability and the
			// permission checks above cannot see. The mute state of the endpoint is therefore read once here, in the
			// same place, and a muted microphone is refused so that the Sentry is never armed on a device that cannot
			// hear anything. It is a single read at arm time and is never polled afterwards.
			if (IsDefaultCaptureMuted() == true)
			{
				await ShutdownGraphAsync();
				return new TopBarSentryArmResult(false, "The microphone is muted. Unmute it in the Windows sound settings and try again.", false);
			}

			// The frame node carries a copy of every quantum so that its loudness can be measured for the meter and
			// for the trigger. It stays connected for the whole session, recording or not.
			_frameOutputNode = _graph.CreateFrameOutputNode();
			_deviceInputNode.AddOutgoingConnection(_frameOutputNode);

			// The frame output node must be started explicitly, otherwise GetFrame keeps handing back empty buffers and
			// the meter never moves. This is the one step a device-input to frame-output capture graph cannot skip.
			_frameOutputNode.Start();

			// The capture is written exactly at the device sample rate and channel count so that nothing is resampled,
			// at 24 bits per sample which is lossless for practical purposes while remaining universally playable.
			AudioEncodingProperties graphProperties = _graph.EncodingProperties;
			MediaEncodingProfile recordingProfile = MediaEncodingProfile.CreateWav(AudioEncodingQuality.High);
			recordingProfile.Audio = AudioEncodingProperties.CreatePcm(graphProperties.SampleRate, graphProperties.ChannelCount, 24U);
			_recordingProfile = recordingProfile;

			// A device-input node pushes audio on its own, which drives the graph clock, so QuantumStarted fires on a
			// regular cadence for reading the accumulated frame. That is the event Microsoft recommends for GetFrame.
			_graph.QuantumStarted += OnQuantumStarted;
			Volatile.Write(ref _state, (int)TopBarSentryState.Armed);
			_graph.Start();

			RaiseStatus();
			return new TopBarSentryArmResult(true, null, false);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			await ShutdownGraphAsync();
			Volatile.Write(ref _state, (int)TopBarSentryState.Idle);
			return new TopBarSentryArmResult(false, ex.Message, false);
		}
	}

	/// <summary>
	/// Pushes a new trigger level into a session that is already running.
	/// </summary>
	internal void UpdateThreshold(double thresholdDecibel) => Volatile.Write(ref _thresholdBits, BitConverter.DoubleToInt64Bits(thresholdDecibel));

	/// <summary>
	/// Pushes a new capture duration into a session that is already running. It takes effect from the next capture.
	/// </summary>
	internal void UpdateRecordingDuration(int seconds) => _recordingDurationSeconds = Math.Max(1, seconds);

	/// <summary>
	/// Pushes a new cooldown into a session that is already running.
	/// </summary>
	internal void UpdateCooldown(int seconds) => _cooldownSeconds = Math.Max(0, seconds);

	/// <summary>
	/// Pushes a new cycle ceiling into a session that is already running.
	/// </summary>
	internal void UpdateMaxCycles(int cycles) => _maxCycles = Math.Max(0, cycles);

	/// <summary>
	/// Pushes a new output directory into a session that is already running. It takes effect from the next capture.
	/// </summary>
	internal void UpdateOutputDirectory(string outputDirectory) => _outputDirectory = outputDirectory ?? string.Empty;

	/// <summary>
	/// Ends the capture that is currently in flight without waiting for its duration to elapse. It does nothing when
	/// no capture is running.
	/// </summary>
	internal void StopCurrentRecording() => _recordingStopSource?.Cancel();

	/// <summary>
	/// Stops watching, ends any capture that is in flight and releases the microphone. It is safe to call more than
	/// once.
	/// </summary>
	internal async Task DisarmAsync()
	{
		Volatile.Write(ref _state, (int)TopBarSentryState.Idle);
		await ShutdownGraphAsync();
	}

	/// <summary>
	/// Reads a single quantum, measures its loudness for the meter, and triggers a capture when the level has crossed
	/// the trigger and the cooldown has elapsed. This runs on an audio thread, so it never touches the UI and it only
	/// ever hands the actual capture work over to the dispatcher.
	/// </summary>
	private void OnQuantumStarted(AudioGraph sender, object args)
	{
		AudioFrameOutputNode? frameOutputNode = _frameOutputNode;
		if (frameOutputNode is null)
		{
			return;
		}

		double decibel;
		try
		{
			decibel = ComputeDecibels(frameOutputNode.GetFrame());
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return;
		}

		// A quantum that carried no samples yet leaves the previous reading in place, so an empty warm up frame does
		// not momentarily drop the meter to its floor.
		if (double.IsNaN(decibel))
		{
			return;
		}

		Volatile.Write(ref _currentDecibelBits, BitConverter.DoubleToInt64Bits(decibel));

		if (Volatile.Read(ref _state) != (int)TopBarSentryState.Armed)
		{
			return;
		}

		if (Environment.TickCount64 < Volatile.Read(ref _cooldownUntilTick))
		{
			return;
		}

		int maxCycles = _maxCycles;
		if (maxCycles > 0 && _completedCycles >= maxCycles)
		{
			return;
		}

		double threshold = BitConverter.Int64BitsToDouble(Volatile.Read(ref _thresholdBits));
		if (decibel < threshold)
		{
			return;
		}

		// The transition is claimed atomically so that two quanta in a row can never both start a capture.
		if (Interlocked.CompareExchange(ref _state, (int)TopBarSentryState.Recording, (int)TopBarSentryState.Armed) == (int)TopBarSentryState.Armed)
		{
			_ = _dispatcherQueue.TryEnqueue(() => _ = BeginRecordingCycleAsync());
		}
	}

	/// <summary>
	/// Creates the capture file, wires it into the graph, lets it run for the chosen duration or until it is stopped,
	/// and then finalizes it. This runs on the UI thread because that is where the graph was created.
	/// </summary>
	private async Task BeginRecordingCycleAsync()
	{
		try
		{
			if (_graph is null || _deviceInputNode is null || _recordingProfile is null)
			{
				RevertToArmed();
				return;
			}

			StorageFolder folder = await ResolveOutputFolderAsync();
			string fileName = "Sentry-" + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture) + ".wav";
			StorageFile file = await folder.CreateFileAsync(fileName, CreationCollisionOption.GenerateUniqueName);

			CreateAudioFileOutputNodeResult result = await _graph.CreateFileOutputNodeAsync(file, _recordingProfile);
			if (result.Status != AudioFileNodeCreationStatus.Success || result.FileOutputNode is null)
			{
				RevertToArmed();
				return;
			}

			_fileOutputNode = result.FileOutputNode;
			_deviceInputNode.AddOutgoingConnection(_fileOutputNode);

			RaiseStatus();

			_recordingStopSource = new CancellationTokenSource();
			try
			{
				await Task.Delay(TimeSpan.FromSeconds(_recordingDurationSeconds), _recordingStopSource.Token);
			}
			catch (OperationCanceledException)
			{
				// A manual stop ends the wait early and the capture is finalized with whatever it has so far.
			}

			await CompleteRecordingAsync();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			RevertToArmed();
		}
		finally
		{
			_recordingStopSource?.Dispose();
			_recordingStopSource = null;
		}
	}

	/// <summary>
	/// Detaches the capture file from the graph, finalizes it, records the cooldown, and either re-arms for the next
	/// cycle or disarms the session when the cycle ceiling has been reached.
	/// </summary>
	private async Task CompleteRecordingAsync()
	{
		AudioFileOutputNode? fileOutputNode = _fileOutputNode;
		_fileOutputNode = null;

		if (fileOutputNode is not null)
		{
			try
			{
				_deviceInputNode?.RemoveOutgoingConnection(fileOutputNode);
				TranscodeFailureReason reason = await fileOutputNode.FinalizeAsync();
				if (reason != TranscodeFailureReason.None)
				{
					Logger.Write("The Sentry could not finalize a capture: " + reason.ToString(), LogTypeIntel.Error);
				}
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		int completed = Interlocked.Increment(ref _completedCycles);
		Volatile.Write(ref _cooldownUntilTick, Environment.TickCount64 + (_cooldownSeconds * 1000L));

		int maxCycles = _maxCycles;
		if (maxCycles > 0 && completed >= maxCycles)
		{
			// The ceiling has been reached, so the session releases the microphone and reports that it is idle.
			await ShutdownGraphAsync();
			Volatile.Write(ref _state, (int)TopBarSentryState.Idle);
			RaiseStatus();
			return;
		}

		Volatile.Write(ref _state, (int)TopBarSentryState.Armed);
		RaiseStatus();
	}

	/// <summary>
	/// Returns the session to the armed state after a capture could not be started.
	/// </summary>
	private void RevertToArmed()
	{
		// Only step back to armed while the session is still meant to be running.
		if (Volatile.Read(ref _state) == (int)TopBarSentryState.Recording)
		{
			Volatile.Write(ref _state, (int)TopBarSentryState.Armed);
			RaiseStatus();
		}
	}

	/// <summary>
	/// Resolves the folder that captures are written to, creating it when it does not yet exist.
	/// </summary>
	private async Task<StorageFolder> ResolveOutputFolderAsync()
	{
		string directory = _outputDirectory;
		if (string.IsNullOrWhiteSpace(directory))
		{
			directory = DefaultOutputDirectory;
		}

		_ = Directory.CreateDirectory(directory);
		return await StorageFolder.GetFolderFromPathAsync(directory);
	}

	/// <summary>
	/// Reads the mute state of the default audio capture endpoint through Core Audio, without opening a stream on it.
	/// Returns true when the endpoint is muted, false when it is not, and null when the state could not be determined,
	/// in which case the caller must not treat the microphone as muted.
	/// https://learn.microsoft.com/windows/win32/api/endpointvolume/nf-endpointvolume-iaudioendpointvolume-getmute
	/// </summary>
	private static unsafe bool? IsDefaultCaptureMuted()
	{
		IntPtr enumerator = IntPtr.Zero;
		IntPtr device = IntPtr.Zero;
		IntPtr endpointVolume = IntPtr.Zero;
		try
		{
			Guid enumeratorClsid = CLSID_MMDeviceEnumerator;
			Guid enumeratorIid = IID_IMMDeviceEnumerator;
			// CLSCTX_ALL is 0x17.
			if (NativeMethods.CoCreateInstance(in enumeratorClsid, IntPtr.Zero, 0x17U, in enumeratorIid, out enumerator) < 0 || enumerator == IntPtr.Zero)
			{
				return null;
			}

			// IMMDeviceEnumerator::GetDefaultAudioEndpoint is the fifth slot of the vtable, after the three IUnknown
			// methods and EnumAudioEndpoints. The data flow eCapture is 1 and the role eConsole is 0.
			IntPtr deviceLocal;
			int getEndpointResult = ((delegate* unmanaged[Stdcall]<IntPtr, int, int, IntPtr*, int>)(*(*(void***)enumerator + 4)))(enumerator, 1, 0, &deviceLocal);
			if (getEndpointResult < 0 || deviceLocal == IntPtr.Zero)
			{
				return null;
			}

			device = deviceLocal;

			// IMMDevice::Activate is the fourth slot of the vtable. CLSCTX_ALL is 0x17 and no activation parameters are passed.
			Guid endpointVolumeIid = IID_IAudioEndpointVolume;
			IntPtr endpointVolumeLocal;
			int activateResult = ((delegate* unmanaged[Stdcall]<IntPtr, Guid*, uint, IntPtr, IntPtr*, int>)(*(*(void***)device + 3)))(device, &endpointVolumeIid, 0x17U, IntPtr.Zero, &endpointVolumeLocal);
			if (activateResult < 0 || endpointVolumeLocal == IntPtr.Zero)
			{
				return null;
			}

			endpointVolume = endpointVolumeLocal;

			// IAudioEndpointVolume::GetMute is the sixteenth slot of the vtable. A non zero value means the endpoint
			// is muted.
			int mute;
			int getMuteResult = ((delegate* unmanaged[Stdcall]<IntPtr, int*, int>)(*(*(void***)endpointVolume + 15)))(endpointVolume, &mute);
			if (getMuteResult < 0)
			{
				return null;
			}

			return mute != 0;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return null;
		}
		finally
		{
			// IUnknown::Release is the third slot of the vtable. Every interface that was obtained is released.
			if (endpointVolume != IntPtr.Zero)
			{
				_ = ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(*(void***)endpointVolume + 2)))(endpointVolume);
			}

			if (device != IntPtr.Zero)
			{
				_ = ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(*(void***)device + 2)))(device);
			}

			if (enumerator != IntPtr.Zero)
			{
				_ = ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(*(void***)enumerator + 2)))(enumerator);
			}
		}
	}

	/// <summary>
	/// Measures the root mean square loudness of a single audio frame and expresses it in dBFS.
	/// The frame is 32-bit float PCM, so the raw byte buffer is read as floats through IMemoryBufferByteAccess, which
	/// is reached by querying the native object for that classic COM interface and calling it through its vtable.
	/// Returns NaN when the quantum carried no samples, so that a warm up frame leaves the previous reading in place.
	/// </summary>
	private static unsafe double ComputeDecibels(AudioFrame frame)
	{
		using AudioBuffer buffer = frame.LockBuffer(AudioBufferAccessMode.Read);
		using Windows.Foundation.IMemoryBufferReference reference = buffer.CreateReference();

		IntPtr nativeReference = ((IWinRTObject)reference).NativeObject.ThisPtr;
		Guid interfaceId = IMemoryBufferByteAccessIID;
		IntPtr byteAccess;
		// IUnknown::QueryInterface is the first slot of the vtable. Calling it through the vtable keeps this Native AOT
		// safe and free of any built in COM interop.
		int queryResult = ((delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)(*(*(void***)nativeReference + 0)))(nativeReference, &interfaceId, &byteAccess);
		if (queryResult < 0 || byteAccess == IntPtr.Zero)
		{
			return SilenceFloorDecibel;
		}

		try
		{
			byte* dataInBytes;
			uint capacityInBytes;
			// IMemoryBufferByteAccess::GetBuffer is the fourth slot of the vtable, after the three IUnknown methods.
			int getBufferResult = ((delegate* unmanaged[Stdcall]<IntPtr, byte**, uint*, int>)(*(*(void***)byteAccess + 3)))(byteAccess, &dataInBytes, &capacityInBytes);
			if (getBufferResult < 0 || dataInBytes is null)
			{
				return SilenceFloorDecibel;
			}

			// GetFrame hands over everything the node accumulated since the previous read, and the capacity of that
			// buffer is the exact size of it. An empty accumulation means the graph has not delivered a quantum yet.
			int sampleCount = (int)(capacityInBytes / sizeof(float));
			if (sampleCount <= 0)
			{
				// Nothing to measure yet. NaN tells the caller to keep the previous reading rather than drop to floor.
				return double.NaN;
			}

			float* samples = (float*)dataInBytes;
			double sumOfSquares = 0.0;
			for (int index = 0; index < sampleCount; index++)
			{
				double sample = samples[index];
				sumOfSquares += sample * sample;
			}

			double rootMeanSquare = Math.Sqrt(sumOfSquares / sampleCount);
			if (rootMeanSquare <= 0.0)
			{
				return SilenceFloorDecibel;
			}

			return Math.Max(SilenceFloorDecibel, 20.0 * Math.Log10(rootMeanSquare));
		}
		finally
		{
			// IUnknown::Release is the third slot of the vtable.
			_ = ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(*(void***)byteAccess + 2)))(byteAccess);
		}
	}

	/// <summary>
	/// Stops and disposes the graph and every node of it. It is guarded so that the several paths that can lead to a
	/// teardown only ever tear the graph down once.
	/// </summary>
	private async Task ShutdownGraphAsync()
	{
		if (Interlocked.Exchange(ref _shutdownStarted, 1) == 1)
		{
			return;
		}

		AudioGraph? graph = _graph;
		if (graph is null)
		{
			return;
		}

		try
		{
			graph.QuantumStarted -= OnQuantumStarted;

			if (_recordingStopSource is not null)
			{
				await _recordingStopSource.CancelAsync();
			}

			AudioFileOutputNode? fileOutputNode = _fileOutputNode;
			_fileOutputNode = null;
			if (fileOutputNode is not null)
			{
				try
				{
					_deviceInputNode?.RemoveOutgoingConnection(fileOutputNode);
					_ = await fileOutputNode.FinalizeAsync();
				}
				catch (Exception ex)
				{
					Logger.Write(ex);
				}
			}

			graph.Stop();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		try
		{
			_frameOutputNode?.Dispose();
			_deviceInputNode?.Dispose();
			graph.Dispose();
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}

		_frameOutputNode = null;
		_deviceInputNode = null;
		_graph = null;
		_recordingProfile = null;
		Volatile.Write(ref _currentDecibelBits, BitConverter.DoubleToInt64Bits(SilenceFloorDecibel));
	}

	/// <summary>
	/// Raises the status event. Every raise happens on the UI thread already, because the only places that raise are
	/// the arm request and the capture orchestration, both of which run on the dispatcher.
	/// </summary>
	private void RaiseStatus() =>
		StatusChanged?.Invoke(this, new TopBarSentryStatus((TopBarSentryState)_state, _completedCycles));

	/// <summary>
	/// Best effort synchronous teardown for when the window is closing and there is no opportunity to await.
	/// A capture that is in flight is finalized on a fire and forget basis so that it is not left truncated.
	/// </summary>
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		Volatile.Write(ref _state, (int)TopBarSentryState.Idle);
		// The token source is cancelled to end any capture wait, then disposed here so that the only IDisposable field
		// of the engine is released deterministically. Nulling it afterwards keeps the teardown below from touching it.
		_recordingStopSource?.Cancel();
		_recordingStopSource?.Dispose();
		_recordingStopSource = null;
		_ = ShutdownGraphAsync();
	}
}
