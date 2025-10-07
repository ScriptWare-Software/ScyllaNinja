import os
from binaryninja import Settings

PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))

SETTING_MAP = {
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

def register_scyllahide_settings():
    settings = Settings()

    settings.register_setting("debugger.scyllaHide.00_enable", '''{
        "title": "Enable ScyllaHide",
        "description": "Automatically inject ScyllaHide when debugger hits initial breakpoint",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.01_profile", '''{
        "title": "Profile",
        "description": "Pre-configured hook profiles for common packers. Preset profiles use built-in configurations; individual hook settings below only apply when 'Custom' is selected",
        "type": "string",
        "default": "Basic",
        "enum": ["VMProtect x86/x64", "Themida x86/x64", "Obsidium x86/x64", "Armadillo x86", "Basic", "Custom"],
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    default_dir = PLUGIN_DIR.replace('\\', '\\\\')
    settings.register_setting("debugger.scyllaHide.02_directory", f'''{{
        "title": "ScyllaHide Directory",
        "description": "Directory containing InjectorCLI (x86/x64) and HookLibrary DLLs (x86/x64)",
        "type": "string",
        "default": "{default_dir}",
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }}''')

    settings.register_setting("debugger.scyllaHide.pebBeingDebugged", '''{
        "title": "PEB.BeingDebugged",
        "description": "Clear PEB.BeingDebugged flag",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.pebHeapFlags", '''{
        "title": "PEB Heap Flags",
        "description": "Hide debugger heap flags",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.pebNtGlobalFlag", '''{
        "title": "PEB.NtGlobalFlag",
        "description": "Clear PEB.NtGlobalFlag",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.pebStartupInfo", '''{
        "title": "PEB StartupInfo",
        "description": "Hide debugger in PEB startup info",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.pebOsBuildNumber", '''{
        "title": "PEB OS Build Number",
        "description": "Protect PEB OS build number",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntQueryInformationProcess", '''{
        "title": "NtQueryInformationProcess",
        "description": "Hook NtQueryInformationProcess",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntSetInformationThread", '''{
        "title": "NtSetInformationThread",
        "description": "Hook NtSetInformationThread",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntSetInformationProcess", '''{
        "title": "NtSetInformationProcess",
        "description": "Hook NtSetInformationProcess",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntQuerySystemInformation", '''{
        "title": "NtQuerySystemInformation",
        "description": "Hook NtQuerySystemInformation",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntQueryObject", '''{
        "title": "NtQueryObject",
        "description": "Hook NtQueryObject",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntClose", '''{
        "title": "NtClose",
        "description": "Hook NtClose",
        "type": "boolean",
        "default": true,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntYieldExecution", '''{
        "title": "NtYieldExecution",
        "description": "Hook NtYieldExecution",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.outputDebugString", '''{
        "title": "OutputDebugString",
        "description": "Hook OutputDebugStringA/W",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntCreateThreadEx", '''{
        "title": "NtCreateThreadEx",
        "description": "Hook NtCreateThreadEx",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.preventThreadCreation", '''{
        "title": "Prevent Thread Creation",
        "description": "Prevent certain threads from being created",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntGetContextThread", '''{
        "title": "NtGetContextThread",
        "description": "Hook NtGetContextThread",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntSetContextThread", '''{
        "title": "NtSetContextThread",
        "description": "Hook NtSetContextThread",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntContinue", '''{
        "title": "NtContinue",
        "description": "Hook NtContinue",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.kiUserExceptionDispatcher", '''{
        "title": "KiUserExceptionDispatcher",
        "description": "Hook KiUserExceptionDispatcher",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntUserBlockInput", '''{
        "title": "NtUserBlockInput",
        "description": "Hook NtUserBlockInput",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntUserQueryWindow", '''{
        "title": "NtUserQueryWindow",
        "description": "Hook NtUserQueryWindow",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntUserFindWindowEx", '''{
        "title": "NtUserFindWindowEx",
        "description": "Hook NtUserFindWindowEx",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntUserBuildHwndList", '''{
        "title": "NtUserBuildHwndList",
        "description": "Hook NtUserBuildHwndList",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntUserGetForegroundWindow", '''{
        "title": "NtUserGetForegroundWindow",
        "description": "Hook NtUserGetForegroundWindow",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntSetDebugFilterState", '''{
        "title": "NtSetDebugFilterState",
        "description": "Hook NtSetDebugFilterState",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.getTickCount", '''{
        "title": "GetTickCount",
        "description": "Hook GetTickCount",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.getTickCount64", '''{
        "title": "GetTickCount64",
        "description": "Hook GetTickCount64",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.getLocalTime", '''{
        "title": "GetLocalTime",
        "description": "Hook GetLocalTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.getSystemTime", '''{
        "title": "GetSystemTime",
        "description": "Hook GetSystemTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntQuerySystemTime", '''{
        "title": "NtQuerySystemTime",
        "description": "Hook NtQuerySystemTime",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')

    settings.register_setting("debugger.scyllaHide.ntQueryPerformanceCounter", '''{
        "title": "NtQueryPerformanceCounter",
        "description": "Hook NtQueryPerformanceCounter",
        "type": "boolean",
        "default": false,
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }''')
