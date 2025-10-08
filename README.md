# ScyllaNinja
Author: **Script-Ware Software**

_Automated ScyllaHide injection and setup/configuration for Binary Ninja's debugger_

## Description

Binary Ninja integration for [ScyllaHide](https://github.com/x64dbg/ScyllaHide) by x64dbg. Automatically injects the ScyllaHide DLL when the debugger hits the initial breakpoint, helping bypass anti-debugging techniques commonly found in packed or protected executables.

ScyllaHide handles PEB manipulation, NT API hooking, and timing protection to hide the debugger from anti-debug checks.

## Installation Instructions

### Windows

1. Install the latest release (of this repository) and copy it to `%APPDATA%\Binary Ninja\plugins\`

2. Download ScyllaHide binaries from https://github.com/x64dbg/ScyllaHide/releases/tag/v1.4

3. Extract the following files to a directory:
   - `InjectorCLIx64.exe`
   - `InjectorCLIx86.exe`
   - `HookLibraryx64.dll`
   - `HookLibraryx86.dll`

4. Configure in `Edit > Settings > Debugger > scyllahide`:
   - Set "ScyllaHide Directory" to the path containing extracted files
   - Enable "Enable Automatic ScyllaHide Injection" (if you want)
   - Select a profile (default: Basic) or make a custom one

5. Open a x64/x86 binary and start debugging

6. ScyllaHide is automatically injected when the debugger hits the initial breakpoint

## Usage

### Automatic Injection

If configured (see Settings), ScyllaHide automatically injects when you start debugging any Windows executable. The status bar shows real-time progress during injection, and console output logs detailed status.

### Manual Injection

You can manually inject ScyllaHide at any time during a debug session via:
- **Plugins > ScyllaNinja > Inject ScyllaHide**

ScyllaNinja prevents accidental double-injection by asking you to confirm if you actually want to inject again.

## Settings

Found in Binary Ninja Settings under `Debugger > scyllahide`:

| Setting | Default | Description |
|---------|---------|-------------|
| Enable Automatic ScyllaHide Injection | false | Automatically inject when debugger hits initial breakpoint |
| Profile | Basic | Pre-configured hook profile (preset profiles use built-in configs) |
| ScyllaHide Directory | plugin folder | Directory containing InjectorCLI and HookLibrary DLLs |
| Individual Hooks | varies | PEB, NT API, and timing hooks (only apply when Profile = Custom) |

**Note:** Remember that the individual hook settings are only used when Profile is set to "Custom". For preset profiles like "Basic" or "VMProtect x86/x64", ScyllaHide uses its already built-in configurations.

## Minimum Version

This plugin (was only tested on but likely) requires the following minimum version of Binary Ninja:

* 5000 (5.0)

## Required Dependencies

The following dependencies are required for this plugin:

* ScyllaHide binaries (InjectorCLI + HookLibrary DLLs) from https://github.com/x64dbg/ScyllaHide/releases

The plugin will alert you if these files don't exist and are not set up in the settings. 

## License

This plugin is released under an MIT license.

Copyright (c) 2025 Script-Ware Software

## Credits

ScyllaHide is developed by the [x64dbg team](https://github.com/x64dbg/ScyllaHide). This plugin provides Binary Ninja integration only. The original ScyllaHide has not been modified at all.

## Metadata Version

2