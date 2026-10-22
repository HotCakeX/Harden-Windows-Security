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
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using Microsoft.UI.Dispatching;
using Windows.Media;
using Windows.Media.Audio;
using Windows.Media.Capture;
using Windows.Media.MediaProperties;
using Windows.Media.Render;
using Windows.Media.SpeechRecognition;
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
/// The values that arm a Sentry session. They are copied into the engine so that a later settings change does not
/// alter a session that is already running unless it is pushed in explicitly through one of the Update methods.
/// </summary>
internal readonly struct TopBarSentrySettings(double thresholdDecibel, int recordingDurationSeconds, int cooldownSeconds, int maxCycles, string outputDirectory, string triggerPhrase)
{
	internal double ThresholdDecibel => thresholdDecibel;
	internal int RecordingDurationSeconds => recordingDurationSeconds;
	internal int CooldownSeconds => cooldownSeconds;
	internal int MaxCycles => maxCycles;
	internal string OutputDirectory => outputDirectory;
	internal string TriggerPhrase => triggerPhrase;
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
/// Applies the selected DPAPI protection mode to Sentry WAV files in place.
/// </summary>
internal static class TopBarSentryProtection
{
	private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("HotCakeX");

	internal static void ProcessFile(string filePath, int mode)
	{
		byte[] currentBytes = File.ReadAllBytes(filePath);
		// If we should disable encryption
		if (mode == 0)
		{
			// Try to decrypt the file with both scopes and write the plain bytes back to disk.
			if (!TryDecrypt(currentBytes, DataProtectionScope.CurrentUser, out byte[]? plainBytes) &&
				!TryDecrypt(currentBytes, DataProtectionScope.LocalMachine, out plainBytes))
			{
				return;
			}

			File.WriteAllBytes(filePath, plainBytes);
			return;
		}

		// Select the DPAPI scope requested by the mode
		DataProtectionScope targetScope = mode == 1 ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine;

		// Check whether the file is already encrypted using the requested scope.
		if (TryDecrypt(currentBytes, targetScope, out _))
		{
			// No processing is needed because the file is already protected using the requested scope.
			return;
		}

		// Select the opposite DPAPI scope so a file protected with that scope can first be decrypted.
		DataProtectionScope otherScope = mode == 1 ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;

		// Use bytes decrypted with the opposite scope when possible; otherwise treat the current bytes as unencrypted file content.
		byte[] plainBytesToProtect = TryDecrypt(currentBytes, otherScope, out byte[]? decryptedBytes) ? decryptedBytes : currentBytes;

		// Encrypt the plain file content using the requested scope and replace the file with the protected bytes.
		File.WriteAllBytes(filePath, ProtectedData.Protect(plainBytesToProtect, Entropy, targetScope));
	}

	private static bool TryDecrypt(byte[] bytes, DataProtectionScope scope, [NotNullWhen(true)] out byte[]? plainBytes)
	{
		try
		{
			plainBytes = ProtectedData.Unprotect(bytes, Entropy, scope);
			return true;
		}
		catch (CryptographicException)
		{
			plainBytes = null;
			return false;
		}
	}
}

/// <summary>
/// The engine of the Acoustic Sentry view of the Top Bar.
///
/// It only runs the trigger mode that was armed. In decibel mode it opens the default microphone through an
/// <see cref="AudioGraph"/> and watches the ambient loudness continuously. In spoken phrase mode it listens through
/// on-device speech recognition alone and opens a graph only while a capture is being written. The moment the level
/// crosses the user defined trigger, or the configured spoken phrase is confirmed, it captures the environment to a
/// high fidelity WAV file for a chosen duration, then it waits out a cooldown before it is allowed to trigger again.
/// The whole session runs in the background independently of which Top Bar view is on display and it keeps capturing
/// while the workstation is locked, because an <see cref="AudioGraph"/> capture is bound to the process rather than to
/// the desktop.
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
	/// The floor that a fully silent quantum is reported at, because the logarithm of zero is negative infinity.
	/// </summary>
	private const double SilenceFloorDecibel = -100.0;
	private static readonly TimeSpan InitializationTimeout = TimeSpan.FromSeconds(15.0);

	/// <summary>
	/// The default folder that captures are written to when the user has not chosen one of their own.
	/// </summary>
	internal static string DefaultOutputDirectory => Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Harden System Security Sentry");

	private readonly DispatcherQueue _dispatcherQueue;

	private AudioGraph? _graph;
	private AudioDeviceInputNode? _deviceInputNode;
	private AudioFrameOutputNode? _frameOutputNode;
	private AudioFileOutputNode? _fileOutputNode;
	// Cancels the capture in flight. The capture owns and disposes the token source behind it.
	private Action? _stopRecording;

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

	private readonly CancellationTokenSource _sessionCancellation = new();
	private Task<TopBarSentryArmResult>? _armTask;
	private Task? _recordingTask;
	private Task? _shutdownTask;

	// How many back to back sessions may end shortly after starting before the Sentry gives up.
	private const int MaxSpeechRestartFailures = 5;
	private SpeechRecognizer? _speechRecognizer;
	private string? _speechGrammarPath;
	// The only recognition restart. It is only replaced on the UI thread, so two starts never overlap.
	private Task _listenTask = Task.CompletedTask;
	// Raised right before a session starts and cleared before a capture cancels it, so that the Completed handler can
	// tell a session that ended on its own from one that was ended on purpose.
	private volatile bool _isListening;
	private volatile int _speechFailures;
	private long _speechStartTick;
	private string[] _phraseWords = [];
	// Packed matched word range of the trigger phrase: start word index in the high 16 bits, word count in the low 16 bits.
	private int _matchedPhraseWords;
	private long _speechProgressTick;

	internal bool UsesPhraseTrigger => _phraseWords.Length > 0;
	// The UI distinguishes an armed session from cooldown and recognizer initialization.
	internal bool IsCoolingDown => Environment.TickCount64 < Volatile.Read(ref _cooldownUntilTick);
	/// <summary>
	/// Whether an armed session can hear its trigger. Decibel mode always can, phrase mode cannot while recognition is being restarted.
	/// </summary>
	internal bool IsListening => !UsesPhraseTrigger || _isListening;
	/// <summary>
	/// Why the engine ended the session by itself, if it did. The owner shows it once its teardown has finished.
	/// </summary>
	internal string? Error { get; private set; }

	// Silence expires provisional feedback; confirmed feedback stays lit until the recording ends.
	// The value is packed as described on _matchedPhraseWords. UnpackPhraseWords is for reading it.
	internal int MatchedPhraseWords => State == TopBarSentryState.Recording ||
		Environment.TickCount64 - Volatile.Read(ref _speechProgressTick) <= 3000L
			? Volatile.Read(ref _matchedPhraseWords) : 0;

	internal static (int Start, int Count) UnpackPhraseWords(int packed) => (packed >>> 16, packed & 0xFFFF);

	internal TopBarSentryEngine(DispatcherQueue dispatcherQueue) => _dispatcherQueue = dispatcherQueue;

	/// <summary>
	/// Raised on the UI thread whenever the engine transitions between states or finishes a capture. The owner reads
	/// the current values straight from the engine.
	/// </summary>
	internal event EventHandler? StatusChanged;

	/// <summary>
	/// The current lifecycle state of the engine.
	/// </summary>
	internal TopBarSentryState State => (TopBarSentryState)Volatile.Read(ref _state);

	/// <summary>
	/// The most recent ambient loudness reading in dBFS. Decibel mode refreshes it on every audio quantum.
	/// </summary>
	internal double CurrentDecibel => BitConverter.Int64BitsToDouble(Volatile.Read(ref _currentDecibelBits));

	/// <summary>
	/// How many capture cycles have completed since the engine was armed.
	/// </summary>
	internal int CompletedCycles => _completedCycles;

	/// <summary>
	/// Opens the microphone for the selected trigger mode and starts watching for its trigger. The returned result
	/// reports why the microphone could not be opened when that is the case, so that the view can surface it to the user.
	/// </summary>
	internal Task<TopBarSentryArmResult> ArmAsync(TopBarSentrySettings settings) => _armTask ??= ArmCoreAsync(settings);

	private async Task<TopBarSentryArmResult> ArmCoreAsync(TopBarSentrySettings settings)
	{
		try
		{
			_phraseWords = GetPhraseWords(settings.TriggerPhrase).ConvertAll(static word => word.Text).ToArray();
			Volatile.Write(ref _thresholdBits, BitConverter.DoubleToInt64Bits(settings.ThresholdDecibel));
			_recordingDurationSeconds = Math.Max(1, settings.RecordingDurationSeconds);
			_cooldownSeconds = Math.Max(0, settings.CooldownSeconds);
			_maxCycles = Math.Max(0, settings.MaxCycles);
			_outputDirectory = settings.OutputDirectory ?? string.Empty;

			// A device that is muted still opens and only ever delivers digital silence, which neither the availability
			// and permission checks of the graph nor speech recognition can see. The mute state of the endpoint is
			// therefore read once here for both trigger modes, and a muted microphone is refused so that the Sentry is
			// never armed on a device that cannot hear anything. It is a single read at arm time and is never polled.
			if (IsDefaultCaptureMuted() == true)
			{
				return new TopBarSentryArmResult(false, "The microphone is muted. Unmute it in the Windows sound settings and try again.", false);
			}

			// Only the audio path of the armed mode is opened, so the other mode costs nothing while the Sentry is armed.
			if (UsesPhraseTrigger)
			{
				await StartSpeechRecognitionAsync();
			}
			else
			{
				await StartAudioGraphAsync(meter: true);
			}

			// A disarm that arrived during initialization must not be overwritten with an armed transition.
			_sessionCancellation.Token.ThrowIfCancellationRequested();
			Volatile.Write(ref _state, (int)TopBarSentryState.Armed);
			// A session that ended while the arm was finishing is restarted like any other that ended on its own.
			if (UsesPhraseTrigger) EnsureListening();

			RaiseStatus();
			return new TopBarSentryArmResult(true, null, false);
		}
		catch (Exception ex)
		{
			// The owner disarms the engine after a failed arm, which releases whatever was opened before the failure.
			Logger.Write(ex);
			string message = ex is TimeoutException ? "The microphone or the speech engine did not respond within 15 seconds." : ex.Message;
			string reason = UsesPhraseTrigger
				? "Speech recognition could not start. Make sure a speech language is installed under Settings, Time and language, Speech, and allow microphone access. " + message
				: message;
			return new TopBarSentryArmResult(false, reason, ex is UnauthorizedAccessException);
		}
	}

	/// <summary>
	/// Opens the default microphone in a capture only graph and starts it. Only decibel mode meters the graph, through
	/// a frame node that stays connected for the whole session; phrase mode opens a graph for each capture alone.
	/// Failures are thrown, and an <see cref="UnauthorizedAccessException"/> means the privacy setting blocked access.
	/// </summary>
	private async Task StartAudioGraphAsync(bool meter)
	{
		// The render category is nominal for a capture only graph, but a category still has to be named.
		AudioGraphSettings graphSettings = new(AudioRenderCategory.Media);
		CreateAudioGraphResult graphResult = await AudioGraph.CreateAsync(graphSettings).AsTask(_sessionCancellation.Token).WaitAsync(InitializationTimeout);
		if (graphResult.Status != AudioGraphCreationStatus.Success || graphResult.Graph is null)
		{
			throw new InvalidOperationException("The audio engine could not start (" + graphResult.Status.ToString() + ").");
		}

		_graph = graphResult.Graph;

		CreateAudioDeviceInputNodeResult inputResult = await _graph.CreateDeviceInputNodeAsync(MediaCategory.Media).AsTask(_sessionCancellation.Token).WaitAsync(InitializationTimeout);
		_deviceInputNode = inputResult.DeviceInputNode;
		if (inputResult.Status != AudioDeviceNodeCreationStatus.Success || _deviceInputNode is null)
		{
			Exception failure = inputResult.Status switch
			{
				AudioDeviceNodeCreationStatus.AccessDenied => new UnauthorizedAccessException("Microphone access is turned off for this app. Turn it on under Settings, Privacy and security, Microphone, and make sure app access is allowed."),
				AudioDeviceNodeCreationStatus.DeviceNotAvailable => new InvalidOperationException("No microphone was found. Connect a recording device and try again."),
				AudioDeviceNodeCreationStatus.FormatNotSupported => new InvalidOperationException("The microphone does not support a format the recorder can use."),
				_ => new InvalidOperationException("The microphone could not be opened (" + inputResult.Status.ToString() + ").")
			};
			throw failure;
		}

		if (meter)
		{
			// The frame node carries a copy of every quantum so that its loudness can be measured for the meter and
			// for the trigger. It stays connected for the whole session, recording or not.
			_frameOutputNode = _graph.CreateFrameOutputNode();
			_deviceInputNode.AddOutgoingConnection(_frameOutputNode);

			// The frame output node must be started explicitly, otherwise GetFrame keeps handing back empty buffers and
			// the meter never moves. This is the one step a device-input to frame-output capture graph cannot skip.
			_frameOutputNode.Start();

			// A device-input node pushes audio on its own, which drives the graph clock, so QuantumStarted fires on a
			// regular cadence for reading the accumulated frame. That is the event Microsoft recommends for GetFrame.
			_graph.QuantumStarted += OnQuantumStarted;
		}

		_graph.Start();
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
	internal void StopCurrentRecording() => _stopRecording?.Invoke();

	/// <summary>
	/// Stops watching, ends any capture that is in flight and releases the microphone. It is safe to call more than
	/// once.
	/// </summary>
	internal Task DisarmAsync() => _shutdownTask ??= DisarmCoreAsync();

	/// <summary>
	/// Await initialization, any capture in flight and any recognition restart before disposing their resources. An
	/// idle transition is made first so queued callbacks and recording continuations cannot re-arm a stopped session.
	/// </summary>
	private async Task DisarmCoreAsync()
	{
		Volatile.Write(ref _state, (int)TopBarSentryState.Idle);
		await _sessionCancellation.CancelAsync();
		// Initialization owns its graph until it has finished. Waiting prevents close-during-arm resource races.
		if (_armTask is not null) _ = await _armTask;
		// The capture finalizes its own file and can queue a recognition restart, so it is awaited before the restart.
		if (_recordingTask is not null) await _recordingTask;
		await _listenTask;
		ShutdownGraph();
		if (_speechRecognizer is SpeechRecognizer recognizer)
		{
			try
			{
				SpeechContinuousRecognitionSession session = recognizer.ContinuousRecognitionSession;
				recognizer.HypothesisGenerated -= OnSpeechHypothesisGenerated;
				session.ResultGenerated -= OnSpeechResultGenerated;
				session.Completed -= OnSpeechSessionCompleted;
				// Microsoft's continuous recognition sample cancels a running session before it disposes the recognizer.
				if (recognizer.State != SpeechRecognizerState.Idle) await session.CancelAsync();
			}
			catch (Exception ex) { Logger.Write(ex); }
			try
			{
				recognizer.Dispose();
				if (_speechGrammarPath is not null) File.Delete(_speechGrammarPath);
			}
			catch (Exception ex) { Logger.Write(ex); }
		}
		_sessionCancellation.Dispose();
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
			using AudioFrame frame = frameOutputNode.GetFrame();
			decibel = ComputeDecibels(frame);
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

		double threshold = BitConverter.Int64BitsToDouble(Volatile.Read(ref _thresholdBits));
		if (decibel < threshold)
		{
			return;
		}

		TryStartRecordingCycle();
	}

	/// <summary>
	/// Share the atomic claim, cycle ceiling and cooldown between both trigger modes. A queued capture is
	/// rejected if disarm reached the UI thread first; its task is retained and awaited during shutdown.
	/// </summary>
	private void TryStartRecordingCycle()
	{
		// The claim itself only succeeds from the armed state.
		if (IsCoolingDown || (_maxCycles > 0 && _completedCycles >= _maxCycles) ||
			Interlocked.CompareExchange(ref _state, (int)TopBarSentryState.Recording, (int)TopBarSentryState.Armed) != (int)TopBarSentryState.Armed) return;
		if (!_dispatcherQueue.TryEnqueue(() =>
		{
			if (Volatile.Read(ref _state) == (int)TopBarSentryState.Recording)
				_recordingTask = RunRecordingCycleAsync();
		}))
			_ = Interlocked.CompareExchange(ref _state, (int)TopBarSentryState.Armed, (int)TopBarSentryState.Recording);
	}

	/// <summary>
	/// Runs one capture on the UI thread, where the graph is created. Phrase mode first stops recognition and opens a
	/// recording only graph, which it closes again once the capture is finalized. The capture file is wired into the
	/// graph for the chosen duration or until it is stopped, then it is finalized and the cooldown starts. A failure
	/// ends the session with an error instead of retrying in a loop. The status is raised last, so that a disarm it
	/// leads to never overlaps with the work of this cycle.
	/// </summary>
	private async Task RunRecordingCycleAsync()
	{
		using CancellationTokenSource stopSource = CancellationTokenSource.CreateLinkedTokenSource(_sessionCancellation.Token);
		_stopRecording = stopSource.Cancel;
		string? filePath = null;
		string? error = null;
		try
		{
			if (_speechRecognizer is SpeechRecognizer recognizer)
			{
				// The session is canceled rather than paused, because a paused session keeps buffering the microphone and
				// would recognize the speech of this capture once it resumed. It is started again after the cooldown.
				// https://learn.microsoft.com/uwp/api/windows.media.speechrecognition.speechrecognizerstate
				_isListening = false;
				// Hearing the phrase proves that recognition works, so earlier sessions that ended quickly are forgiven.
				_speechFailures = 0;
				try
				{
					await recognizer.ContinuousRecognitionSession.CancelAsync();
				}
				catch (Exception ex)
				{
					// The session may have ended on its own right before, which leaves nothing to cancel.
					Logger.Write(ex);
				}
				await StartAudioGraphAsync(meter: false);
			}

			if (_graph is not AudioGraph graph || _deviceInputNode is not AudioDeviceInputNode deviceInputNode)
			{
				throw new InvalidOperationException("The microphone is not open.");
			}

			// The capture is written exactly at the device sample rate and channel count so that nothing is resampled,
			// at 24 bits per sample which is lossless for practical purposes while remaining universally playable.
			AudioEncodingProperties graphProperties = graph.EncodingProperties;
			MediaEncodingProfile recordingProfile = MediaEncodingProfile.CreateWav(AudioEncodingQuality.High);
			recordingProfile.Audio = AudioEncodingProperties.CreatePcm(graphProperties.SampleRate, graphProperties.ChannelCount, 24U);

			StorageFolder folder = await ResolveOutputFolderAsync();
			// A disarm during the setup above must not leave an empty capture file behind.
			_sessionCancellation.Token.ThrowIfCancellationRequested();
			string fileName = "Sentry-" + DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss-fff", CultureInfo.InvariantCulture) + ".wav";
			StorageFile file = await folder.CreateFileAsync(fileName, CreationCollisionOption.GenerateUniqueName);
			CreateAudioFileOutputNodeResult result = await graph.CreateFileOutputNodeAsync(file, recordingProfile);
			if (result.Status != AudioFileNodeCreationStatus.Success || result.FileOutputNode is null)
			{
				throw new InvalidOperationException("The capture file could not be created (" + result.Status.ToString() + ").");
			}

			filePath = file.Path;
			_fileOutputNode = result.FileOutputNode;
			deviceInputNode.AddOutgoingConnection(_fileOutputNode);

			RaiseStatus();

			// A manual stop or a disarm ends the wait early and the capture is finalized with whatever it has so far.
			await Task.Delay(TimeSpan.FromSeconds(_recordingDurationSeconds), stopSource.Token);
		}
		catch (OperationCanceledException) when (stopSource.IsCancellationRequested) { }
		catch (Exception ex)
		{
			Logger.Write(ex);
			error = "A capture failed. " + ex.Message;
		}
		finally
		{
			_stopRecording = null;
		}

		// The path is only known once the capture is attached, which is exactly when there is a capture to finalize.
		// If finalized and user has selected for recording files to be encrypted
		if (filePath is not null && await FinalizeRecordingNodeAsync() && Atlas.Settings.WindowsTopBarSentryEncryptionMode != 0)
		{
			try
			{
				await Task.Run(() => TopBarSentryProtection.ProcessFile(filePath, Atlas.Settings.WindowsTopBarSentryEncryptionMode));
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}

		// Phrase mode releases the recording graph before speech recognition resumes.
		if (UsesPhraseTrigger) ShutdownGraph();

		// Do not overwrite a disarm that arrived during the capture with a new transition.
		if (Volatile.Read(ref _state) != (int)TopBarSentryState.Recording) return;
		if (error is not null)
		{
			Fail(error);
			return;
		}

		Volatile.Write(ref _matchedPhraseWords, 0);
		int completed = Interlocked.Increment(ref _completedCycles);
		Volatile.Write(ref _cooldownUntilTick, Environment.TickCount64 + (_cooldownSeconds * 1000L));

		// Reaching the cycle ceiling reports Idle, and the owner then disarms the engine, which releases the microphone.
		int maxCycles = _maxCycles;
		Volatile.Write(ref _state, (int)(maxCycles > 0 && completed >= maxCycles ? TopBarSentryState.Idle : TopBarSentryState.Armed));
		if (UsesPhraseTrigger) EnsureListening();
		RaiseStatus();
	}

	/// <summary>
	/// Transfer ownership out of the field before awaiting. Completed finalization closes the node;
	/// explicit disposal also covers failures before finalization can complete.
	/// </summary>
	private async Task<bool> FinalizeRecordingNodeAsync()
	{
		AudioFileOutputNode? node = _fileOutputNode;
		_fileOutputNode = null;
		if (node is null) return false;
		bool finalizationCompleted = false;
		try
		{
			_deviceInputNode?.RemoveOutgoingConnection(node);
			node.Stop();
			TranscodeFailureReason reason = await node.FinalizeAsync();
			// FinalizeAsync closes the node on completion. Never dispose that closed node.
			finalizationCompleted = true;
			if (reason == TranscodeFailureReason.None) return true;
			Logger.Write("The Sentry could not finalize a capture: " + reason.ToString(), LogTypeIntel.Error);
			return false;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
		finally
		{
			// Dispose only when finalization did not complete normally.
			if (!finalizationCompleted)
			{
				try { node.Dispose(); }
				catch (Exception ex) { Logger.Write(ex); }
			}
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

	#region Spoken Phrase Trigger

	/// <summary>
	/// Recognition uses an on-device SRGS grammar in the system speech language, so no audio leaves the device.
	/// Recognition is opened only when the user explicitly arms a nonempty phrase. One recognizer serves the whole
	/// armed session and its grammar is compiled once, here. Like Microsoft's continuous recognition sample, the session
	/// is then only canceled and started again on that same recognizer, around every capture.
	/// https://learn.microsoft.com/windows/apps/develop/input/define-custom-recognition-constraints
	/// https://github.com/microsoft/Windows-universal-samples/blob/main/Samples/SpeechRecognitionAndSynthesis/cs/Scenario_ContinuousRecognitionSRGSGrammar.xaml.cs
	/// </summary>
	private async Task StartSpeechRecognitionAsync()
	{
		SpeechRecognizer recognizer = new(SpeechRecognizer.SystemSpeechLanguage);
		_speechRecognizer = recognizer;
		SpeechContinuousRecognitionSession session = recognizer.ContinuousRecognitionSession;
		recognizer.HypothesisGenerated += OnSpeechHypothesisGenerated;
		session.ResultGenerated += OnSpeechResultGenerated;
		session.Completed += OnSpeechSessionCompleted;

		// A list grammar only describes isolated commands. Allow unrelated speech around the
		// complete phrase without adding competing single-word or partial-phrase commands.
		XNamespace ns = "http://www.w3.org/2001/06/grammar";
		XElement filler = new(ns + "item", new XAttribute("repeat", "0-1"),
			new XElement(ns + "ruleref", new XAttribute("special", "GARBAGE")));
		XElement grammar = new(ns + "grammar", new XAttribute("version", "1.0"),
			new XAttribute(XNamespace.Xml + "lang", recognizer.CurrentLanguage.LanguageTag),
			new XAttribute("root", "Sentry"), new XAttribute("mode", "voice"),
			new XElement(ns + "rule", new XAttribute("id", "Sentry"),
				new XAttribute("scope", "public"), filler,
				new XElement(ns + "item", string.Join(' ', _phraseWords)), new XElement(filler)));
		_speechGrammarPath = Path.Join(Path.GetTempPath(), "HSS-Sentry-" + Guid.CreateVersion7().ToString("N") + ".grxml");
		await File.WriteAllTextAsync(_speechGrammarPath, grammar.ToString(SaveOptions.DisableFormatting), _sessionCancellation.Token);
		StorageFile grammarFile = await StorageFile.GetFileFromPathAsync(_speechGrammarPath);
		recognizer.Constraints.Add(new SpeechRecognitionGrammarFileConstraint(grammarFile, "Sentry"));
		SpeechRecognitionCompilationResult compilation = await recognizer.CompileConstraintsAsync().AsTask(_sessionCancellation.Token).WaitAsync(InitializationTimeout);
		if (compilation.Status != SpeechRecognitionResultStatus.Success)
		{
			throw new InvalidOperationException("Speech grammar compilation failed: " + compilation.Status.ToString());
		}

		// The Sentry waits for its phrase indefinitely, so the session must not end itself after a stretch of silence.
		// https://learn.microsoft.com/uwp/api/windows.media.speechrecognition.speechcontinuousrecognitionsession.autostopsilencetimeout
		session.AutoStopSilenceTimeout = TimeSpan.MaxValue;
		_isListening = true;
		Volatile.Write(ref _speechStartTick, Environment.TickCount64);
		await session.StartAsync().AsTask(_sessionCancellation.Token).WaitAsync(InitializationTimeout);
	}

	/// <summary>
	/// Makes sure that recognition is running again once a capture or a session that ended on its own has stopped it.
	/// It runs on the UI thread only, which keeps a single restart in flight at any time.
	/// </summary>
	private void EnsureListening() => _listenTask = _listenTask.IsCompleted ? ListenAsync() : _listenTask;

	/// <summary>
	/// Starts the session again on the same recognizer once the cooldown has elapsed. Sessions that keep ending right
	/// after they start are retried with a growing delay, and the Sentry gives up with an error once there are too many.
	/// </summary>
	private async Task ListenAsync()
	{
		try
		{
			// The session token is only read while armed, and disarm always leaves the armed state before disposing it.
			while (State == TopBarSentryState.Armed && !_isListening && _speechRecognizer is SpeechRecognizer recognizer)
			{
				if (_speechFailures > MaxSpeechRestartFailures)
				{
					throw new InvalidOperationException("The speech session keeps ending right after it starts.");
				}

				long delay = Math.Max(Volatile.Read(ref _cooldownUntilTick), Volatile.Read(ref _speechStartTick) + (_speechFailures * 1000L)) - Environment.TickCount64;
				// StartAsync is only valid while the recognizer is idle, as checked in Microsoft's sample.
				if (delay > 0L || recognizer.State != SpeechRecognizerState.Idle)
				{
					await Task.Delay(TimeSpan.FromMilliseconds(Math.Max(delay, 100L)), _sessionCancellation.Token);
					continue;
				}

				_isListening = true;
				Volatile.Write(ref _speechStartTick, Environment.TickCount64);
				await recognizer.ContinuousRecognitionSession.StartAsync().AsTask(_sessionCancellation.Token).WaitAsync(InitializationTimeout);
			}
		}
		catch (OperationCanceledException) when (_sessionCancellation.IsCancellationRequested) { }
		catch (Exception ex)
		{
			Logger.Write(ex);
			Fail("Spoken-phrase monitoring stopped. Check the installed speech language and microphone access. " + ex.Message);
		}
	}

	/// <summary>
	/// The session also ends on its own, for example when the microphone becomes unavailable. Such an ending is
	/// restarted from the UI thread, while one that a capture or a disarm caused is ignored.
	/// </summary>
	private void OnSpeechSessionCompleted(SpeechContinuousRecognitionSession sender, SpeechContinuousRecognitionCompletedEventArgs args)
	{
		if (!_isListening) return;
		_isListening = false;
		// A session that stayed up for a while was healthy, so its ending does not count as a failure.
		bool failedQuickly = args.Status is not (SpeechRecognitionResultStatus.Success or SpeechRecognitionResultStatus.TimeoutExceeded) &&
			Environment.TickCount64 - Volatile.Read(ref _speechStartTick) < 10000L;
		_speechFailures = failedQuickly ? _speechFailures + 1 : 0;
		Logger.Write("The Sentry speech session ended on its own: " + args.Status.ToString(), LogTypeIntel.Warning);
		_ = _dispatcherQueue.TryEnqueue(EnsureListening);
	}

	private void OnSpeechHypothesisGenerated(SpeechRecognizer sender, SpeechRecognitionHypothesisGeneratedEventArgs args) =>
		OnPhraseHeard(args.Hypothesis.Text);

	// The engine often rates short utterances Low even when the words are right, and the whole-word match below
	// is the real filter, so only results the engine itself rejected are dropped.
	private void OnSpeechResultGenerated(SpeechContinuousRecognitionSession sender, SpeechContinuousRecognitionResultGeneratedEventArgs args) =>
		OnPhraseHeard(args.Result is { Status: SpeechRecognitionResultStatus.Success, Confidence: not SpeechRecognitionConfidence.Rejected } result ? result.Text : string.Empty);

	/// <summary>
	/// Shows how much of the phrase was heard and starts a capture once all of it was. This runs on a speech thread
	/// and only ever hands the capture over to the dispatcher. A callback that was already queued when a capture
	/// canceled the session finds the engine recording and is dropped.
	/// </summary>
	private void OnPhraseHeard(string text)
	{
		if (State != TopBarSentryState.Armed) return;
		int matched = GetMatchedPhraseWords(text);
		Volatile.Write(ref _matchedPhraseWords, matched);
		Volatile.Write(ref _speechProgressTick, Environment.TickCount64);
		// Results are only finalized after a pause and are frequently rated with a low confidence, so continuous
		// speech would otherwise delay or never deliver the trigger. An exact whole-phrase hypothesis, which is
		// exactly what lights every word up, is sufficient evidence to start a capture.
		if ((matched & 0xFFFF) == _phraseWords.Length) TryStartRecordingCycle();
	}

	/// <summary>
	/// Match the longest contiguous run of target words, starting at any target word, in "one" transcript so that
	/// partial matches such as the end of the phrase are shown too. Hypotheses replace previous hypotheses;
	/// separate utterances are never concatenated. Returns the packed range described on _matchedPhraseWords.
	/// </summary>
	private int GetMatchedPhraseWords(string transcript)
	{
		List<(string Text, int End)> heard = GetPhraseWords(transcript);
		int bestStart = 0;
		int bestCount = 0;
		for (int target = 0; target < _phraseWords.Length && bestCount < _phraseWords.Length - target; target++)
		{
			for (int start = 0; start < heard.Count; start++)
			{
				int count = 0;
				while (target + count < _phraseWords.Length && start + count < heard.Count &&
					string.Equals(_phraseWords[target + count], heard[start + count].Text, StringComparison.OrdinalIgnoreCase)) count++;
				if (count > bestCount)
				{
					bestStart = target;
					bestCount = count;
				}
			}
		}
		return (bestStart << 16) | bestCount;
	}

	/// <summary>
	/// Share token boundaries with the UI. Punctuation separates words; internal apostrophes are retained.
	/// This is exact whole-word matching, not phonetic, fuzzy or substring matching.
	/// </summary>
	internal static List<(string Text, int End)> GetPhraseWords(string text)
	{
		List<(string Text, int End)> words = [];
		int index = 0;
		while (index < text.Length)
		{
			if (!char.IsLetterOrDigit(text[index])) { index++; continue; }
			int start = index++;
			while (index < text.Length)
			{
				char character = text[index];
				UnicodeCategory category = char.GetUnicodeCategory(character);
				bool apostrophe = (character is '\'' or '\u2019') && index + 1 < text.Length && char.IsLetterOrDigit(text[index + 1]);
				if (!char.IsLetterOrDigit(character) && category is not (UnicodeCategory.NonSpacingMark or UnicodeCategory.SpacingCombiningMark) && !apostrophe) break;
				index++;
			}
			words.Add((text[start..index].Replace('\u2019', '\''), index));
		}
		return words;
	}

	#endregion

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
			return Math.Max(SilenceFloorDecibel, 20.0 * Math.Log10(rootMeanSquare));
		}
		finally
		{
			// IUnknown::Release is the third slot of the vtable.
			_ = ((delegate* unmanaged[Stdcall]<IntPtr, uint>)(*(*(void***)byteAccess + 2)))(byteAccess);
		}
	}

	/// <summary>
	/// Stops and disposes the graph and every node of it. A capture is always finalized by its own cycle before the
	/// graph is shut down, and calling this without a graph does nothing.
	/// </summary>
	private void ShutdownGraph()
	{
		AudioGraph? graph = _graph;
		if (graph is null)
		{
			return;
		}

		try
		{
			graph.QuantumStarted -= OnQuantumStarted;
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
	}

	/// <summary>
	/// Ends the session with an error. The owner disarms the engine when it sees the idle state and then shows the
	/// error, so nothing here has to wait on any other part of the engine.
	/// </summary>
	private void Fail(string error)
	{
		// A session that was already disarmed has nothing left to report.
		if (Interlocked.Exchange(ref _state, (int)TopBarSentryState.Idle) == (int)TopBarSentryState.Idle) return;
		Error = error;
		RaiseStatus();
	}

	/// <summary>
	/// Raises the status event. Every raise happens on the UI thread already, because the only places that raise are
	/// the arm request, the recognition restart and capture orchestration, all of which run on the dispatcher.
	/// </summary>
	private void RaiseStatus() => StatusChanged?.Invoke(this, EventArgs.Empty);

	/// <summary>
	/// Starts asynchronous teardown from the synchronous IDisposable entry point during window closure.
	/// A capture in flight is finalized by the tracked teardown task, which the owner awaits through DisarmAsync.
	/// </summary>
	public void Dispose() => _shutdownTask ??= DisarmCoreAsync();
}
