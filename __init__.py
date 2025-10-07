import os
import configparser
import subprocess
import traceback
from binaryninja import Settings, log_info, log_error, BinaryViewType # type: ignore
from binaryninja.debugger import DebuggerEventType # type: ignore

from .settings import SETTING_MAP, register_scyllahide_settings

g_controller = None
g_callback_id = None
handled_initial_stop = False
registered_views = set()

SCYLLAHIDE_DEFAULTS = {
    "DLLNormal": "1",
    "DLLStealth": "0",
    "DLLUnload": "0",
    "RemoveDebugPrivileges": "0",
    "KillAntiAttach": "0",
    "AutostartServer": "0",
    "ServerPort": "1337"
}

def get_scylla_dir():
    return Settings().get_string("debugger.scyllaHide.02_directory")

def validate_scyllahide_directory():
    try:
        scylla_dir = get_scylla_dir()

        if not scylla_dir or not os.path.exists(scylla_dir):
            log_error(f"[ScyllaNinja] Invalid directory: {scylla_dir}")
            return False

        required_files = [
            "InjectorCLIx64.exe",
            "InjectorCLIx86.exe",
            "HookLibraryx64.dll",
            "HookLibraryx86.dll"
        ]

        missing = []
        for filename in required_files:
            if not os.path.exists(os.path.join(scylla_dir, filename)):
                missing.append(filename)

        if missing:
            log_error(f"[ScyllaNinja] Missing files in directory '{scylla_dir}':")
            for filename in missing:
                log_error(f"  - {filename}")
            return False

        return True
    except Exception as e:
        log_error(f"[ScyllaNinja] Directory validation failed: {e}")
        return False

def write_scylla_ini():
    try:
        settings = Settings()
        profile_name = settings.get_string("debugger.scyllaHide.01_profile")
        scylla_dir = get_scylla_dir()
        ini_path = os.path.join(scylla_dir, "scylla_hide.ini")

        config = configparser.ConfigParser()

        if os.path.exists(ini_path):
            config.read(ini_path)

        if not config.has_section("SETTINGS"):
            config.add_section("SETTINGS")

        if profile_name and profile_name != "Custom":
            config.set("SETTINGS", "CurrentProfile", profile_name)
        else:
            section_name = "BinaryNinja Custom"
            config.set("SETTINGS", "CurrentProfile", section_name)

            if not config.has_section(section_name):
                config.add_section(section_name)

            for bn_key, ini_key in SETTING_MAP.items():
                full_key = f"debugger.scyllaHide.{bn_key}"
                try:
                    value = settings.get_bool(full_key)
                    config.set(section_name, ini_key, "1" if value else "0")
                except Exception:
                    config.set(section_name, ini_key, "0")

            for key, value in SCYLLAHIDE_DEFAULTS.items():
                config.set(section_name, key, value)

        with open(ini_path, 'w') as f:
            config.write(f)

        return True

    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to write INI: {e}")
        log_error(traceback.format_exc())
        return False

def get_target_pid(controller):
    try:
        modules = controller.modules
        if not modules:
            return None

        main_module_name = modules[0].short_name.lower()
        processes = controller.processes

        for proc in processes:
            proc_name_lower = proc.name.lower()
            if main_module_name in proc_name_lower or proc_name_lower in main_module_name:
                return proc.pid

        return None

    except Exception as e:
        log_error(f"[ScyllaNinja] Error getting PID: {e}")
        log_error(traceback.format_exc())
        return None

def get_target_architecture(controller):
    try:
        if hasattr(controller, 'data') and controller.data:
            arch_name = controller.data.arch.name

            if 'x86_64' in arch_name or 'amd64' in arch_name:
                return "x64"
            elif 'x86' in arch_name:
                return "x86"
        
        return None

    except Exception as e:
        log_error(f"[ScyllaNinja] Error detecting architecture: {e}")
        log_error(traceback.format_exc())
        return None

def is_scyllahide_enabled():
    try:
        settings = Settings()
        return settings.get_bool("debugger.scyllaHide.00_enable")
    except Exception:
        return False

def on_debug_event(event):
    global handled_initial_stop, g_controller

    if event.type == DebuggerEventType.TargetStoppedEventType: #14
        if not handled_initial_stop:
            if not is_scyllahide_enabled():
                log_info("[ScyllaNinja] Disabled - skipping ScyllaHide injection")
                handled_initial_stop = True
                return

            if not g_controller:
                log_error("[ScyllaNinja] No controller reference")
                return

            pid = get_target_pid(g_controller)
            if not pid:
                log_error("[ScyllaNinja] Failed to detect PID")
                return

            arch = get_target_architecture(g_controller)
            if not arch:
                log_error("[ScyllaNinja] Failed to detect architecture")
                return

            if not write_scylla_ini():
                log_error("[ScyllaNinja] Failed to write INI file")
                return

            if not validate_scyllahide_directory():
                log_error("[ScyllaNinja] Directory validation failed")
                return

            scylla_dir = get_scylla_dir()

            injector_exe = f"InjectorCLI{arch}.exe"
            dll_name = f"HookLibrary{arch}.dll"
            injector_path = os.path.join(scylla_dir, injector_exe)
            dll_path = os.path.join(scylla_dir, dll_name)

            log_info(f"[ScyllaNinja] Injecting into PID {pid} ({arch})...")

            try:
                result = subprocess.run(
                    [injector_path, f"pid:{pid}", dll_path, "nowait"],
                    capture_output=True,
                    text=True,
                    cwd=scylla_dir,
                    timeout=10
                )

                if result.stdout:
                    for line in result.stdout.splitlines():
                        log_info(f"[InjectorCLI] {line}")

                if result.stderr:
                    for line in result.stderr.splitlines():
                        log_error(f"[InjectorCLI] {line}")

                if result.returncode == 0:
                    log_info("[ScyllaNinja] Injection successful")
                else:
                    log_error(f"[ScyllaNinja] Injection failed (code {result.returncode})")

            except subprocess.TimeoutExpired:
                log_error("[ScyllaNinja] Injection timeout")
            except Exception as e:
                log_error(f"[ScyllaNinja] Injection error: {e}")
                log_error(traceback.format_exc())

            handled_initial_stop = True

def register_debug_callback(bv):
    global g_controller, g_callback_id, handled_initial_stop, registered_views

    file_path = bv.file.filename
    if file_path in registered_views:
        return True

    try:
        from binaryninja.debugger import DebuggerController # type: ignore

        handled_initial_stop = False
        controller = DebuggerController(bv)
        g_controller = controller
        g_callback_id = controller.register_event_callback(on_debug_event, "ScyllaHide Injection")
        registered_views.add(file_path)

        return True

    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to register callback: {e}")
        return False

def on_view_open(bv):
    register_debug_callback(bv)

def on_directory_changed(setting_name):
    if setting_name == "debugger.scyllaHide.02_directory":
        validate_scyllahide_directory()

def init_plugin():
    try:
        register_scyllahide_settings()
    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to register settings: {e}")

    validate_scyllahide_directory()

    try:
        Settings().add_property_changed_callback(on_directory_changed)
    except Exception:
        pass

    BinaryViewType.add_binaryview_finalized_event(on_view_open)

init_plugin()