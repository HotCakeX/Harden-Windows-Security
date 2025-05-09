using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RustInterop;

internal sealed class DeviceGuard
{
    [JsonInclude]
    [JsonPropertyOrder(0)]
    [JsonPropertyName("__PATH")]
    internal string? __PATH { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(1)]
    [JsonPropertyName("__NAMESPACE")]
    internal string? __NAMESPACE { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(2)]
    [JsonPropertyName("__SERVER")]
    internal string? __SERVER { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(3)]
    [JsonPropertyName("__DERIVATION")]
    internal string? __DERIVATION { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(4)]
    [JsonPropertyName("__PROPERTY_COUNT")]
    internal int? __PROPERTY_COUNT { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(5)]
    [JsonPropertyName("__RELPATH")]
    internal string? __RELPATH { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(6)]
    [JsonPropertyName("__DYNASTY")]
    internal string? __DYNASTY { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(7)]
    [JsonPropertyName("__SUPERCLASS")]
    internal string? __SUPERCLASS { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(8)]
    [JsonPropertyName("__GENUS")]
    internal int? __GENUS { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(9)]
    [JsonPropertyName("AvailableSecurityProperties")]
    internal List<string>? AvailableSecurityProperties { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(10)]
    [JsonPropertyName("CodeIntegrityPolicyEnforcementStatus")]
    internal int? CodeIntegrityPolicyEnforcementStatus { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(11)]
    [JsonPropertyName("InstanceIdentifier")]
    internal string? InstanceIdentifier { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(12)]
    [JsonPropertyName("RequiredSecurityProperties")]
    internal List<string>? RequiredSecurityProperties { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(13)]
    [JsonPropertyName("SecurityFeaturesEnabled")]
    internal List<string>? SecurityFeaturesEnabled { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(14)]
    [JsonPropertyName("SecurityServicesConfigured")]
    internal List<string>? SecurityServicesConfigured { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(15)]
    [JsonPropertyName("SecurityServicesRunning")]
    internal List<string>? SecurityServicesRunning { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(16)]
    [JsonPropertyName("SmmIsolationLevel")]
    internal byte? SmmIsolationLevel { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(17)]
    [JsonPropertyName("UsermodeCodeIntegrityPolicyEnforcementStatus")]
    internal int? UsermodeCodeIntegrityPolicyEnforcementStatus { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(18)]
    [JsonPropertyName("Version")]
    internal string? Version { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(19)]
    [JsonPropertyName("VirtualizationBasedSecurityStatus")]
    internal int? VirtualizationBasedSecurityStatus { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(20)]
    [JsonPropertyName("VirtualMachineIsolation")]
    internal bool? VirtualMachineIsolation { get; set; }

    [JsonInclude]
    [JsonPropertyOrder(21)]
    [JsonPropertyName("VirtualMachineIsolationProperties")]
    internal List<string>? VirtualMachineIsolationProperties { get; set; }
}

[JsonSourceGenerationOptions(WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(DeviceGuard))]
internal sealed partial class DeviceGuardJsonContext : JsonSerializerContext
{
}

internal sealed partial class Program
{

    [LibraryImport("WMI.dll", EntryPoint = "get_device_guard_json", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr Get_device_guard_json();

    [LibraryImport("WMI.dll", EntryPoint = "free_json_string", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial void Free_json_string(IntPtr s);


    static void Main()
    {

        IntPtr jsonPtr = Get_device_guard_json();
        if (jsonPtr == IntPtr.Zero)
        {
            Console.WriteLine("Failed to get JSON from Rust DLL.");
            return;
        }

        string? json = Marshal.PtrToStringAnsi(jsonPtr) ?? throw new InvalidOperationException("No JSON data were available!");

        Free_json_string(jsonPtr);

        DeviceGuard? deviceGuard = JsonSerializer.Deserialize(json, DeviceGuardJsonContext.Default.DeviceGuard);

        Console.WriteLine(deviceGuard);
    }
}