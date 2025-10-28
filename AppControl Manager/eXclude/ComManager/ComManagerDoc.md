# ComManager

A command-line utility for performing several system management tasks through COM / WMI.

All examples assume the executable is named `ComManager.exe`.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Operation succeeded |
| 1 | Operation failed during execution (runtime error, provider failure, etc.) |
| 2 | Invalid or insufficient arguments / incorrect syntax |
| Other HRESULT-derived statuses may be printed inside error messages but the process still exits with one of the above codes. |

---

## Primary Commands

| Primary Command | Purpose |
|-----------------|---------|
| `Get` | Retrieve a specific WMI property or all properties of a class |
| `Firewall` | Manage Firewall settings and rules |
| `BitLocker` | Manage BitLocker |
| `WMI` | Apply WMI preferences of typed values |
| `SCHEDULEDTASKS` | Manage Scheduled Tasks |
| `GetAvailability` | Check if a WMI class contains a given property (prints true/false) |
| `Do` | Invoke a parameterless WMI class method |
| `VIRTUALIZATION` | Manage Hyper‑V nested virtualization CPU setting |

Minimal invocation pattern:
```
ComManager.exe <primaryCommand> [...]
```

---

## 1. GET

### 1.1 Get All Properties
```
ComManager.exe get <namespace> <className>
```
Example:
```
ComManager.exe get root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard
```

### 1.2 Get Specific Property
```
ComManager.exe get <namespace> <className> <propertyName>
```
Example:
```
ComManager.exe get root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard RequiredSecurityProperties
```

---

## 2. FIREWALL

Manages Windows Firewall.

```
ComManager.exe firewall <displayName> <downloadURL> <true|false>
```

Parameters:
- `<displayName>`: Logical name to associate with the group of rules.
- `<downloadURL>`: HTTP/HTTPS URL returning a plaintext IP/CIDR list (one per line). May be empty when removing.
- `<true|false>`:
  - `true` (or `1`): Add / (re)create rules from the URL.
  - `false` (or `0`): Remove rules created previously using `<displayName>`.

Examples:
```
ComManager.exe firewall "Block NK IPs" "https://raw.githubusercontent.com/example/ips.txt" true
ComManager.exe firewall "Block NK IPs" "" false
```

---

## 3. BITLOCKER

Primary pattern:
```
ComManager.exe bitlocker <action> [parameters]
```

### 3.1 Drive Letter Format
Use a root drive designator like `C:` (capitalization is ignored).

### 3.2 Actions Overview

| Action | Syntax (after `bitlocker`) | Description |
|--------|----------------------------|-------------|
| addpass | `addpass <DriveLetter> <PassPhrase>` | Add a password protector |
| addrecovery | `addrecovery <DriveLetter> <RecoveryPasswordOrDashForAuto>` | Add recovery password (dash `-` to auto-generate) |
| addtpm | `addtpm <DriveLetter>` | Add TPM protector |
| addtpm+pin | `addtpm+pin <DriveLetter> <PIN>` | Add TPM + PIN |
| addtpm+startup | `addtpm+startup <DriveLetter> <StartupKeyPath>` | Add TPM + Startup key (directory path to place .BEK) |
| addtpm+pin+startup | `addtpm+pin+startup <DriveLetter> <StartupKeyPath> <PIN>` | Add TPM + PIN + Startup key |
| addstartupkey | `addstartupkey <DriveLetter> <StartupKeyPath>` | Add Startup Key (or Recovery Key if applicable) |
| addsid | `addsid <DriveLetter> <SID> <ServiceAccount true/false>` | Add SID protector (service account flag) |
| removekp | `removekp <DriveLetter> <KeyProtectorID> <NoErrorIfBound true/false>` | Remove key protector GUID |
| enablekps | `enablekps <DriveLetter>` | Enable/Resume protection (reenables key protectors) |
| enableautounlock | `enableautounlock <DriveLetter>` | Enable Auto-Unlock (non-OS volume) |
| enableos | `enableos <DriveLetter> <normal/enhanced> <PIN> <StartupKeyPathOrDash> <FreePlusUsedSpace true/false> <AllowDowngrade true/false>` | Enable OS volume encryption with composite mode |
| enablefixed | `enablefixed <DriveLetter> <FreePlusUsedSpace true/false>` | Enable encryption for fixed data drive |
| enableremovable | `enableremovable <DriveLetter> <Password> <FreePlusUsedSpace true/false>` | Enable encryption for removable drive with password + recovery |
| disable | `disable <DriveLetter>` | Begin decryption (disable BitLocker) |
| suspend | `suspend <DriveLetter> [RebootCount/-]` | Suspend protectors; optional 0–15 reboot persistence |
| info | `info <DriveLetter>` | Output JSON describing a single volume |
| list | `list [all/nonos/removable]` | JSON array of volumes (filter optional) |

### 3.3 Detailed Notes

- `enableos`:
  - Modes:
    - `normal`: TPM + PIN + Recovery; Startup key path may be `-` to skip.
    - `enhanced`: TPM + PIN + Startup Key + Recovery (StartupKeyPath required).
  - `<StartupKeyPathOrDash>`:
    - Directory path where a `.BEK` key file will be created.
    - Use `-` only for `normal` mode to omit the startup key.
  - `<FreePlusUsedSpace true/false>`:
    - `true` = full disk encryption (used + free space).
    - `false` = used space only (faster initial encryption).
  - `<AllowDowngrade true/false>`:
    - Allows downgrading from enhanced to normal composite set if true.

- `enablefixed` / `enableremovable`:
  - `<FreePlusUsedSpace true/false>` follows the same meaning as above.
  - Removable requires a password; a recovery password will also be added automatically by underlying logic.

- `addrecovery`:
  - Provide dash `-` to auto-generate a 48-digit recovery password.

- `suspend`:
  - Optional `RebootCount` range 0–15; `-` uses provider default (indefinite until resumed or system restart semantics vary by version).

- `info` / `list`:
  - Output is JSON (single object for `info`, array for `list`).
  - `list` filters:
    - `all` (default if omitted)
    - `nonos` (exclude OS volume)
    - `removable` (only removable volumes recognized with drive letters)

### 3.4 Examples

```
ComManager.exe bitlocker addpass C: "My Pass Phrase 123!"
ComManager.exe bitlocker addrecovery C: -
ComManager.exe bitlocker addtpm C:
ComManager.exe bitlocker addtpm+pin C: 123456
ComManager.exe bitlocker addtpm+startup C: D:\Keys
ComManager.exe bitlocker addtpm+pin+startup C: D:\Keys 123456
ComManager.exe bitlocker addstartupkey C: D:\Keys
ComManager.exe bitlocker addsid C: S-1-5-21-1234567890-123456789-123456789-1001 false
ComManager.exe bitlocker removekp C: {GUID-HERE} true
ComManager.exe bitlocker enablekps C:
ComManager.exe bitlocker enableautounlock D:
ComManager.exe bitlocker enableos C: normal 123456 - false true
ComManager.exe bitlocker enableos C: enhanced 123456 D:\Keys false false
ComManager.exe bitlocker enablefixed E: true
ComManager.exe bitlocker enableremovable F: MyRemovablePW false
ComManager.exe bitlocker suspend C:
ComManager.exe bitlocker suspend C: 3
ComManager.exe bitlocker disable C:
ComManager.exe bitlocker info C:
ComManager.exe bitlocker list
ComManager.exe bitlocker list nonos
ComManager.exe bitlocker list removable
```

---

## 4. WMI

Primary pattern:
```
ComManager.exe wmi <type> <namespace> <className> <customMethodName> <preferenceName> <value...>
```

Type tokens:
- `bool`
- `int`
- `string`
- `stringarray`
- `intarray`

### 4.1 Argument Mapping (Indices)

| Index | Description |
|-------|-------------|
| 0 | Program name |
| 1 | `wmi` |
| 2 | Type token (bool/int/string/stringarray/intarray) |
| 3 | WMI Namespace |
| 4 | Class name |
| 5 | Method name |
| 6 | Preference name |
| 7..N | Values (count depends on type) |

### 4.3 Examples

Bool:
```
ComManager.exe wmi bool root\Microsoft\Windows\Defender MSFT_MpPreference Set BruteForceProtectionLocalNetworkBlocking true
```

Int:
```
ComManager.exe wmi int root\Microsoft\Windows\Defender MSFT_MpPreference Set SchedulerRandomizationTime 42
```

String:
```
ComManager.exe wmi string root\Custom\Namespace My_Class Set SomeStringProperty "ValueData"
```

String Array:
```
ComManager.exe wmi stringarray root\Microsoft\Windows\Defender MSFT_MpPreference Add AttackSurfaceReductionOnlyExclusions "C:\Temp" "D:\Work"
```

Int Array:
```
ComManager.exe wmi intarray root\Microsoft\Windows\Defender MSFT_MpPreference Set SomeIntArrayProperty 1 2 3 5 8 13
```

---

## 5. SCHEDULEDTASKS

Manage Windows Scheduled Tasks.

### 5.1 Main Usage Example

```
ComManager.exe scheduledtasks --name <TaskName> --exe <PathToExe> [--arg <Arguments>] [--hidden] [--allowstartifonbatteries] [--dontstopifgoingonbatteries] [--startwhenavailable] [--restartcount <Count>] [--restartinterval <Duration>] [--priority <Priority>] [--runonlyifnetworkavailable] [--folder <TaskFolder>] [--author <Author>] [--description <Description>] [--sid <SID>] [--logon <LogonType>] [--runlevel <RunLevel>] [--password <Password>] [--useunifiedschedulingengine true|false] [--executiontimelimit <Duration>] [--waketorun true|false] [--multipleinstancespolicy <Policy>] [--allowhardterminate true|false] [--allowdemandstart true|false] --trigger <TriggerParams> [--trigger <TriggerParams> ...]
```

### 5.2 Delete Task Example

```
ComManager.exe scheduledtasks --delete --name <TaskName> [--folder <TaskFolder>]
```

### 5.3 Delete Folder Example

```
ComManager.exe scheduledtasks --deletefolder --folder <TaskFolder>
```

### 5.4 Options

| Name | Description |
|-------|-------------|
| `--name` | Name of the scheduled task (required for creation or task deletion) |
| `--exe` | Full path to the executable to run (required for creation) |
| `--arg` | Command-line arguments for the executable (optional) |
 `--hidden`| Register the task as hidden (optional) |
| `--allowstartifonbatteries` | Allow the task to start if the computer is on batteries (optional) |
| `--dontstopifgoingonbatteries` | Do not stop the task if the computer switches to battery power (optional) |
| `--startwhenavailable` | Run the task as soon as possible after a scheduled start is missed (optional) |
| `--restartcount <Count>` | Number of times to restart the task (optional, integer) |
| `--restartinterval <Duration>` | Interval between restarts (optional, ISO8601, e.g., PT5M for 5 minutes) |
| `--priority <Priority>` | Task priority (optional, integer 0-10; 0 is highest, 10 is lowest, default is 7) |
| `--runonlyifnetworkavailable` | Only run if network is available (optional) |
| `--folder` | Folder path in Task Scheduler (optional for creation and deletion, e.g., \\folder1\\folder2) |
| `--author` | Author name for the task (optional, default: CLI Scheduler) |
| `--description` | Description for the task (optional, default: User-defined scheduled task) |
| `--sid` | SID of the account to run the task under (optional, default: S-1-5-18 for SYSTEM) |
| `--logon` | Logon type as integer (optional, default: 5 for TASK_LOGON_SERVICE_ACCOUNT), 0: NONE, 1: PASSWORD, 2: S4U, 3: INTERACTIVE_TOKEN, 4: GROUP, 5: SERVICE_ACCOUNT, 6: UAC |
| `--runlevel` | Run level as integer (0 for LUA, 1 for HIGHEST, optional, default: 1) |
| `--password` | Password for logon types requiring it (optional, use with caution) |
| `--useunifiedschedulingengine true/false` | (optional, advanced; default: system default) |
| `--executiontimelimit <Duration>` | Execution time limit for the whole task (optional, ISO8601, e.g., P3D fodays, PT1H for 1 hour) |
| `--waketorun true/false` | Wake the computer to run this task (optional) |
| `--multipleinstancespolicy <Policy>` | Multiple instances policy: 0=Parallel, 1=Queue, 2=IgnoreN3=StopExisting (optional) |
| `--allowhardterminate true/false` | Allow hard terminate on end/killed (optional) |
| `--allowdemandstart true/false` | Allow demand start (optional) |
| `--delete` | Delete mode: delete all tasks with the given name (in optional folder) |
| `--deletefolder` | Delete the specified folder and all tasks in it (use with --folder) |
| `--trigger` | Trigger definition string; can be specified multiple times for multiple triggers. |

### 5.5 Trigger Definition Syntax

Format: `type=<type>; [key=value; ...]`

| Type | Description |
|-------|-------------|
| boot | At system boot |
| logon | At user logon |
| onetime | One-time, with start=<YYYY-MM-DDTHH:MM:SS>, repeat_interval, repeat_duration, execution_time_limit, stop_at_duration_end |
| daily | Daily, with start, interval=<days>, repeat_interval, repeat_duration, execution_time_limit, stop_at_duration_end |
| weekly | Weekly, with start, interval=<weeks>, days_of_week=<mon,tue,..>, execution_time_limit, stop_at_duration_end |
| monthly | Monthly, with start, months, days_of_month, execution_time_limit, stop_at_duration_end |
| idle | At idle |

### 5.6 Common Keys

| Key | Value |
|-------|-------------|
| `start=<ISO8601>` | (e.g. 2025-04-21T18:00:00) |
| `repeat_interval=<ISO8601>` | (e.g. PT6H for 6 hours) |
| `repeat_duration=<ISO8601>` | (e.g. PT24H for 24 hours) |
| `execution_time_limit=<ISO8601>` | (e.g. PT30M for 30 minutes per run) |
| `stop_at_duration_end=true/false` | (true: stop at repetition duration's end, false: let current run finish) |
| `interval=<int>` | (every X days/weeks) |
| `days_of_week=<mon,tue,..>` | (comma-separated list of days) |
| `days_of_month=<1,15,31>` | (comma-separated list of days) |
| `months=<jan,feb,..>` | (comma-separated list of months) |

### 5.7 Examples

```
--trigger type=logon;

--trigger type=onetime;start=2025-04-21T20:00:00;repeat_interval=PT10M;repeat_duration=PT30M;execution_time_limit=PT5M;stop_at_duration_end=true;

--trigger type=daily;start=2025-04-22T10:00:00;interval=1;repeat_interval=PT6H;repeat_duration=PT12H;execution_time_limit=PT10M;stop_at_duration_end=false;

--trigger type=weekly;start=2025-04-22T10:00:00;interval=1;days_of_week=mon,wed;repeat_interval=PT12H;repeat_duration=PT48H;execution_time_limit=PT30M;stop_at_duration_end=true;

--trigger type=monthly;start=2025-04-22T10:00:00;months=jan,apr,dec;days_of_month=1,15,31;execution_time_limit=PT2H;stop_at_duration_end=false;
```

### 5.8 Delete Examples

```
ComManager.exe scheduledtasks --delete --name \"Task To Delete\" --folder \"\\MyFolder\"
```

(if --folder omitted, will search all folders for tasks with that name)

```
ComManager.exe scheduledtasks --deletefolder --folder \"\\MyFolder\\SubFolder\";
```

---

## 6. GETAVAILABILITY

Check if a WMI class contains a given property (outputs a boolean token).

```
ComManager.exe getavailability <namespace> <className> <propertyName>
```

Behavior:
- Prints `true` to stdout if the property exists on the specified class definition.
- Prints `false` to stdout if the property does not exist.
- Treats invalid namespace or class as errors (see Exit Codes).

Notes:
- Primary command and arguments are case-insensitive.
- All three arguments must be provided and must not be empty or whitespace-only; otherwise exit code `2` is returned.

Examples:
```
ComManager.exe getavailability root\Microsoft\Windows\DeviceGuard Win32_DeviceGuard RequiredSecurityProperties
ComManager.exe getavailability root\cimv2 Win32_OperatingSystem NonExistentProperty
```

---

## 7. VIRTUALIZATION

Manage Hyper‑V VM CPU setting `ExposeVirtualizationExtensions` (nested virtualization).

Primary pattern:
```
ComManager.exe Virtualization <subcommand> [parameters]
```

### 7.1 Subcommands

- list
  - Outputs a JSON array of VMs with their current status and details.
  - Usage:
    ```
    ComManager.exe Virtualization list
    ```

- ExposeVirtualizationExtensions
  - Enable or disable ExposeVirtualizationExtensions for a specific VM by name, or for all VMs.
  - Exactly one of `--VMName` or `--all` must be provided.
  - `--enable` accepts `true/false` or `1/0` (case-insensitive).
  - Usages:
    ```
    ComManager.exe Virtualization ExposeVirtualizationExtensions --VMName "<VM Name>" --enable true|false
    ComManager.exe Virtualization ExposeVirtualizationExtensions --all --enable true|false
    ```

### 7.2 Notes

- VM state requirement: Target VM must be Off (EnabledState = 3) for set operations.
- Name matching uses Ordinal Ignore Case.
- Host support: If the host does not expose the property on `Msvm_ProcessorSettingData`, the operation fails.
- Permissions: Run as Administrator,
- Exit codes follow the global “Exit Codes” section:
  - 0 on success.
  - 1 on runtime/provider errors. For `--all`, exit code is 1 if any VM fails; a summary is printed.
  - 2 on invalid arguments (e.g., missing `--enable`, or both/neither of `--VMName` and `--all`).

### 7.3 Examples

```
ComManager.exe Virtualization list
ComManager.exe Virtualization ExposeVirtualizationExtensions --VMName "Win 11 25H2" --enable true
ComManager.exe Virtualization ExposeVirtualizationExtensions --VMName "Win 11 25H2" --enable false
ComManager.exe Virtualization ExposeVirtualizationExtensions --all --enable true
```

---

## 8. DO

Invoke a parameterless WMI class method.

Primary pattern:
```
ComManager.exe do <namespace> <className> <methodName>
```

Behavior:
- Executes the specified method on the WMI class (static or instance).
- Intended for parameterless methods. If the method requires input parameters, it will fail.
- If the provider returns an output parameter `ReturnValue`, the program logs it. A non-zero `ReturnValue` does not automatically change the process exit code; the call is considered successful if the underlying ExecMethod call succeeds.

Notes:
- Arguments are case-insensitive for the primary command.
- `<namespace>`, `<className>`, and `<methodName>` must be provided and non-empty; otherwise exit code `2` is returned.

### 8.1 Example

```
ComManager.exe do root\cimv2\mdm\dmmap MDM_EnterpriseModernAppManagement_AppManagement01 UpdateScanMethod
```

If the provider supplies a `ReturnValue`, it will be printed to stdout (informational).
