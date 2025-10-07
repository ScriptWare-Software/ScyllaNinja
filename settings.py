import os
from typing import Dict
from binaryninja import Settings # type: ignore

PLUGIN_DIR: str = os.path.dirname(os.path.abspath(__file__))

SETTING_MAP: Dict[str, str] = {
    "pebBeingDebugged": "PebBeingDebugged",
    "pebHeapFlags": "PebHeapFlags",
    "pebNtGlobalFlag": "PebNtGlobalFlag",
    "pebStartupInfo": "PebStartupInfo",
    "pebOsBuildNumber": "PebOsBuildNumber",
    "ntQueryInformationProcess": "NtQueryInformationProcessHook",
    "ntSetInformationThread": "NtSetInformationThreadHook",
    "ntSetInformationProcess": "NtSetInformationProcessHook",
    "ntQuerySystemInformation": "NtQuerySystemInformationHook",
    "ntQueryObject": "NtQueryObjectHook",
    "ntClose": "NtCloseHook",
    "ntYieldExecution": "NtYieldExecutionHook",
    "outputDebugString": "OutputDebugStringHook",
    "ntCreateThreadEx": "NtCreateThreadExHook",
    "preventThreadCreation": "PreventThreadCreation",
    "ntGetContextThread": "NtGetContextThreadHook",
    "ntSetContextThread": "NtSetContextThreadHook",
    "ntContinue": "NtContinueHook",
    "kiUserExceptionDispatcher": "KiUserExceptionDispatcherHook",
    "ntUserBlockInput": "NtUserBlockInputHook",
    "ntUserQueryWindow": "NtUserQueryWindowHook",
    "ntUserFindWindowEx": "NtUserFindWindowExHook",
    "ntUserBuildHwndList": "NtUserBuildHwndListHook",
    "ntUserGetForegroundWindow": "NtUserGetForegroundWindowHook",
    "ntSetDebugFilterState": "NtSetDebugFilterStateHook",
    "getTickCount": "GetTickCountHook",
    "getTickCount64": "GetTickCount64Hook",
    "getLocalTime": "GetLocalTimeHook",
    "getSystemTime": "GetSystemTimeHook",
    "ntQuerySystemTime": "NtQuerySystemTimeHook",
    "ntQueryPerformanceCounter": "NtQueryPerformanceCounterHook",
}

def register_scyllahide_settings() -> None:
    settings = Settings()

    settings.register_setting("debugger.scyllahide.00_enable", '''{
        "title": "Enable Automatic ScyllaHide Injection",
        "description": "Automatically inject ScyllaHide when debugger hits initial breakpoint",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.01_profile", '''{
        "title": "Profile",
        "description": "Pre-configured hook profiles for common packers. Preset profiles use built-in configurations; individual hook settings below only apply when 'Custom' is selected",
        "type": "string",
        "default": "Basic",
        "enum": ["VMProtect x86/x64", "Themida x86/x64", "Obsidium x86/x64", "Armadillo x86", "Basic", "Custom"],
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    default_dir = PLUGIN_DIR.replace('\\', '\\\\')
    settings.register_setting("debugger.scyllahide.02_directory", f'''{{
        "title": "ScyllaHide Directory",
        "description": "Directory containing InjectorCLI (x86/x64) and HookLibrary DLLs (x86/x64)",
        "type": "string",
        "default": "{default_dir}",
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }}''')

    settings.register_setting("debugger.scyllahide.pebBeingDebugged", '''{
        "title": "PEB.BeingDebugged",
        "description": "Clear PEB.BeingDebugged flag",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.pebHeapFlags", '''{
        "title": "PEB Heap Flags",
        "description": "Hide debugger heap flags",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.pebNtGlobalFlag", '''{
        "title": "PEB.NtGlobalFlag",
        "description": "Clear PEB.NtGlobalFlag",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.pebStartupInfo", '''{
        "title": "PEB StartupInfo",
        "description": "Hide debugger in PEB startup info",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.pebOsBuildNumber", '''{
        "title": "PEB OS Build Number",
        "description": "Protect PEB OS build number",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntQueryInformationProcess", '''{
        "title": "NtQueryInformationProcess",
        "description": "Hook NtQueryInformationProcess",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntSetInformationThread", '''{
        "title": "NtSetInformationThread",
        "description": "Hook NtSetInformationThread",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntSetInformationProcess", '''{
        "title": "NtSetInformationProcess",
        "description": "Hook NtSetInformationProcess",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntQuerySystemInformation", '''{
        "title": "NtQuerySystemInformation",
        "description": "Hook NtQuerySystemInformation",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntQueryObject", '''{
        "title": "NtQueryObject",
        "description": "Hook NtQueryObject",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntClose", '''{
        "title": "NtClose",
        "description": "Hook NtClose",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntYieldExecution", '''{
        "title": "NtYieldExecution",
        "description": "Hook NtYieldExecution",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.outputDebugString", '''{
        "title": "OutputDebugString",
        "description": "Hook OutputDebugStringA/W",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntCreateThreadEx", '''{
        "title": "NtCreateThreadEx",
        "description": "Hook NtCreateThreadEx",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.preventThreadCreation", '''{
        "title": "Prevent Thread Creation",
        "description": "Prevent certain threads from being created",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntGetContextThread", '''{
        "title": "NtGetContextThread",
        "description": "Hook NtGetContextThread",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntSetContextThread", '''{
        "title": "NtSetContextThread",
        "description": "Hook NtSetContextThread",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntContinue", '''{
        "title": "NtContinue",
        "description": "Hook NtContinue",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.kiUserExceptionDispatcher", '''{
        "title": "KiUserExceptionDispatcher",
        "description": "Hook KiUserExceptionDispatcher",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntUserBlockInput", '''{
        "title": "NtUserBlockInput",
        "description": "Hook NtUserBlockInput",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntUserQueryWindow", '''{
        "title": "NtUserQueryWindow",
        "description": "Hook NtUserQueryWindow",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntUserFindWindowEx", '''{
        "title": "NtUserFindWindowEx",
        "description": "Hook NtUserFindWindowEx",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntUserBuildHwndList", '''{
        "title": "NtUserBuildHwndList",
        "description": "Hook NtUserBuildHwndList",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntUserGetForegroundWindow", '''{
        "title": "NtUserGetForegroundWindow",
        "description": "Hook NtUserGetForegroundWindow",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntSetDebugFilterState", '''{
        "title": "NtSetDebugFilterState",
        "description": "Hook NtSetDebugFilterState",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.getTickCount", '''{
        "title": "GetTickCount",
        "description": "Hook GetTickCount",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.getTickCount64", '''{
        "title": "GetTickCount64",
        "description": "Hook GetTickCount64",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.getLocalTime", '''{
        "title": "GetLocalTime",
        "description": "Hook GetLocalTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.getSystemTime", '''{
        "title": "GetSystemTime",
        "description": "Hook GetSystemTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntQuerySystemTime", '''{
        "title": "NtQuerySystemTime",
        "description": "Hook NtQuerySystemTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllahide.ntQueryPerformanceCounter", '''{
        "title": "NtQueryPerformanceCounter",
        "description": "Hook NtQueryPerformanceCounter",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')
