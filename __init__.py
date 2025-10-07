import os
import configparser
import subprocess
import traceback
import threading
import webbrowser
from typing import Optional, Dict
from binaryninja import Settings, log_info, log_error, log_warn, BinaryViewType, interaction, PluginCommand, BackgroundTask # type: ignore
from binaryninja.binaryview import BinaryView # type: ignore
from binaryninja.debugger import DebuggerEventType, DebuggerController, DebuggerEvent # type: ignore
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult # type: ignore

from .settings import SETTING_MAP, register_scyllahide_settings

g_binary_states: Dict[str, 'BinaryDebugState'] = {}
g_state_lock: threading.Lock = threading.Lock()

SCYLLAHIDE_DEFAULTS: Dict[str, str] = {
    "DLLNormal": "1",
    "DLLStealth": "0",
    "DLLUnload": "0",
    "RemoveDebugPrivileges": "0",
    "KillAntiAttach": "0",
    "AutostartServer": "0",
    "ServerPort": "1337"
}

class BinaryDebugState:
    def __init__(self, bv: BinaryView, controller: DebuggerController) -> None:
        self.file_path: str = bv.file.filename
        self.controller: DebuggerController = controller
        self.callback_id: Optional[int] = None
        self.handled_initial_stop: bool = False
        self.injected: bool = False
        self.lock: threading.Lock = threading.Lock()

    def on_debug_event(self, event: DebuggerEvent) -> None:
        if event.type == DebuggerEventType.LaunchEventType:
            with self.lock:
                self.handled_initial_stop = False
                self.injected = False

        elif event.type == DebuggerEventType.TargetStoppedEventType:
            with self.lock:
                if self.handled_initial_stop:
                    return
                self.handled_initial_stop = True

            if not is_scyllahide_enabled():
                log_info("[ScyllaNinja] Disabled - skipping ScyllaHide injection")
                return

            if perform_injection(self.controller):
                with self.lock:
                    self.injected = True

def get_scylla_dir() -> str:
    return Settings().get_string("debugger.scyllahide.02_directory")

def validate_scyllahide_directory() -> bool:
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

def write_scylla_ini() -> bool:
    try:
        settings = Settings()
        profile_name = settings.get_string("debugger.scyllahide.01_profile")
        scylla_dir = get_scylla_dir()
        ini_path = os.path.join(scylla_dir, "scylla_hide.ini")

        config = configparser.ConfigParser()

        if os.path.exists(ini_path):
            try:
                config.read(ini_path)
            except configparser.Error as e:
                log_warn(f"[ScyllaNinja] Could not parse existing INI: {e}, creating new")
            except Exception as e:
                log_warn(f"[ScyllaNinja] Error reading INI file: {e}, creating new")

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
                full_key = f"debugger.scyllahide.{bn_key}"
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

    except (IOError, PermissionError) as e:
        log_error(f"[ScyllaNinja] Cannot write to INI file: {e}")
        return False
    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to write INI: {e}")
        log_error(traceback.format_exc())
        return False

# binja's debugger doesn't have a way to get the process id of the target program currently, will be changed when this is added
def get_target_pid(controller: DebuggerController) -> Optional[int]:
    try:
        if not controller.connected:
            return None

        modules = controller.modules
        if not modules:
            return None

        main_module_name = modules[0].short_name
        if not main_module_name:
            log_error("[ScyllaNinja] Main module has no name")
            return None

        main_module_name = main_module_name.lower()
        main_module_base = os.path.splitext(main_module_name)[0]
        processes = controller.processes

        if not processes:
            log_error("[ScyllaNinja] No processes available")
            return None

        for proc in processes:
            proc_name_lower = proc.name.lower()
            proc_name_base = os.path.splitext(proc_name_lower)[0]

            if proc_name_lower == main_module_name or proc_name_base == main_module_base:
                log_info(f"[ScyllaNinja] Detected target PID {proc.pid} (exact match: {proc.name})")
                return proc.pid

        fuzzy_match = None
        for proc in processes:
            proc_name_lower = proc.name.lower()
            if main_module_name in proc_name_lower or proc_name_lower in main_module_name:
                fuzzy_match = proc
                break

        if fuzzy_match:
            log_warn(f"[ScyllaNinja] Fuzzy match found: {fuzzy_match.name} (PID: {fuzzy_match.pid})")
            result = interaction.show_message_box(
                "ScyllaHide - Confirm Target Process",
                f"Fuzzy match detected:\n\nProcess: {fuzzy_match.name}\nPID: {fuzzy_match.pid}\n\nInject into this process?",
                MessageBoxButtonSet.YesNoButtonSet,
                MessageBoxIcon.QuestionIcon
            )
            if result == MessageBoxButtonResult.YesButton:
                return fuzzy_match.pid

        process_choices = [f"{proc.name} (PID: {proc.pid})" for proc in processes]
        choice_index = interaction.get_choice_input(
            "ScyllaHide - Select Target Process",
            "Please select the target process:",
            process_choices
        )

        if choice_index is None:
            log_info("[ScyllaNinja] User cancelled process selection")
            return None

        selected_pid = processes[choice_index].pid
        log_info(f"[ScyllaNinja] User selected PID {selected_pid} ({processes[choice_index].name})")
        return selected_pid

    except Exception as e:
        log_error(f"[ScyllaNinja] Error getting PID: {e}")
        log_error(traceback.format_exc())
        return None

def get_target_architecture(controller: DebuggerController) -> Optional[str]:
    try:
        if hasattr(controller, 'data') and controller.data:
            arch = controller.data.arch

            if arch.address_size == 8:
                return "x64"
            elif arch.address_size == 4:
                return "x86"
            else:
                log_warn(f"[ScyllaNinja] Unknown architecture: address_size={arch.address_size}")
                return None

        return None

    except Exception as e:
        log_error(f"[ScyllaNinja] Error detecting architecture: {e}")
        log_error(traceback.format_exc())
        return None

def is_scyllahide_enabled() -> bool:
    try:
        settings = Settings()
        return settings.get_bool("debugger.scyllahide.00_enable")
    except Exception:
        return False

def perform_injection(controller: DebuggerController) -> bool:
    task = BackgroundTask("ScyllaNinja: Validating...")
    try:
        if not validate_scyllahide_directory():
            log_error("[ScyllaNinja] Directory validation failed")
            task.finish()
            return False

        task.progress = "ScyllaNinja: Detecting process..."
        pid = get_target_pid(controller)
        if not pid or not isinstance(pid, int) or pid <= 0:
            log_error("[ScyllaNinja] Failed to detect valid PID")
            task.finish()
            return False

        task.progress = "ScyllaNinja: Detecting architecture..."
        arch = get_target_architecture(controller)
        if not arch:
            log_error("[ScyllaNinja] Failed to detect architecture")
            task.finish()
            return False

        task.progress = "ScyllaNinja: Writing configuration..."
        if not write_scylla_ini():
            log_error("[ScyllaNinja] Failed to write INI file")
            task.finish()
            return False

        scylla_dir = get_scylla_dir()

        injector_exe = f"InjectorCLI{arch}.exe"
        dll_name = f"HookLibrary{arch}.dll"
        injector_path = os.path.join(scylla_dir, injector_exe)
        dll_path = os.path.join(scylla_dir, dll_name)

        task.progress = f"ScyllaNinja: Injecting into PID {pid} ({arch})..."
        log_info(f"[ScyllaNinja] Injecting into PID {pid} ({arch})...")

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
            task.progress = "ScyllaNinja: Injection successful"
            log_info("[ScyllaNinja] Injection successful")
            task.finish()
            return True
        else:
            log_error(f"[ScyllaNinja] Injection failed (code {result.returncode})")
            task.finish()
            return False

    except subprocess.TimeoutExpired:
        log_error("[ScyllaNinja] Injection timeout")
        task.finish()
        return False
    except Exception as e:
        log_error(f"[ScyllaNinja] Injection error: {e}")
        log_error(traceback.format_exc())
        task.finish()
        return False


def register_debug_callback(bv: BinaryView) -> bool:
    file_path: str = bv.file.filename

    old_state = None
    with g_state_lock:
        if file_path in g_binary_states:
            old_state = g_binary_states[file_path]
            del g_binary_states[file_path]

    if old_state:
        try:
            if old_state.callback_id is not None:
                old_state.controller.remove_event_callback(old_state.callback_id)
                log_info(f"[ScyllaNinja] Cleaned up stale callback for {file_path}")
        except Exception as e:
            log_warn(f"[ScyllaNinja] Failed to clean up old callback: {e}")

    try:
        controller = DebuggerController(bv)
        state = BinaryDebugState(bv, controller)
        state.callback_id = controller.register_event_callback(state.on_debug_event, "ScyllaNinja - ScyllaHide Injection")

        with g_state_lock:
            g_binary_states[file_path] = state

        return True

    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to register callback: {e}")
        return False

def on_view_open(bv: BinaryView) -> None:
    success = register_debug_callback(bv)
    if not success:
        log_error(f"[ScyllaNinja] Failed to register debug callback for {bv.file.filename}")

def on_directory_changed(setting_name: str) -> None:
    if setting_name == "debugger.scyllahide.02_directory":
        valid = validate_scyllahide_directory()
        if valid:
            log_info("[ScyllaNinja] ScyllaHide directory validated successfully")
        else:
            log_error("[ScyllaNinja] ScyllaHide directory validation failed - check settings")

def manual_inject_handler(bv: BinaryView) -> None:
    try:
        controller = DebuggerController(bv)

        if not controller.connected:
            interaction.show_message_box(
                "ScyllaNinja - Not Debugging",
                "No active debug session. Start debugging first.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
            return

        file_path = bv.file.filename

        state = None
        with g_state_lock:
            state = g_binary_states.get(file_path)

        if not state:
            success = register_debug_callback(bv)
            if not success:
                log_error("[ScyllaNinja] Failed to register debug state")
                interaction.show_message_box(
                    "ScyllaNinja - Error",
                    "Failed to initialize debug state. Cannot inject.",
                    MessageBoxButtonSet.OKButtonSet,
                    MessageBoxIcon.ErrorIcon
                )
                return
            with g_state_lock:
                state = g_binary_states.get(file_path)

        already_injected = False
        if state:
            with state.lock:
                already_injected = state.injected

        if already_injected:
            result = interaction.show_message_box(
                "ScyllaHide - Already Injected",
                "ScyllaHide has already been injected into this process.\n\nInject again anyway?",
                MessageBoxButtonSet.YesNoButtonSet,
                MessageBoxIcon.WarningIcon
            )
            if result != MessageBoxButtonResult.YesButton:
                return

        log_info("[ScyllaNinja] Manual injection requested")
        success = perform_injection(controller)

        if success:
            with g_state_lock:
                state = g_binary_states.get(file_path)
                if state:
                    with state.lock:
                        state.injected = True
        else:
            interaction.show_message_box(
                "ScyllaHide - Injection Failed",
                "Failed to inject ScyllaHide. Check the log for details.",
                MessageBoxButtonSet.OKButtonSet,
                MessageBoxIcon.ErrorIcon
            )
    except Exception as e:
        log_error(f"[ScyllaNinja] Manual injection error: {e}")
        log_error(traceback.format_exc())
        interaction.show_message_box(
            "ScyllaNinja - Error",
            f"Error during injection: {e}",
            MessageBoxButtonSet.OKButtonSet,
            MessageBoxIcon.ErrorIcon
        )

def is_debugging(bv: BinaryView) -> bool:
    try:
        controller = DebuggerController(bv)
        return controller.connected
    except Exception:
        return False

def init_plugin() -> None:
    try:
        register_scyllahide_settings()
    except Exception as e:
        log_error(f"[ScyllaNinja] Failed to register settings: {e}")

    if not validate_scyllahide_directory():
        result = interaction.show_message_box(
            "ScyllaNinja - Setup Required",
            "ScyllaHide directory is not configured or is missing required files.\n\n"
            "Would you like to download ScyllaHide now?\n\n"
            "The required files are:\n"
            "- InjectorCLIx64.exe\n"
            "- InjectorCLIx86.exe\n"
            "- HookLibraryx64.dll\n"
            "- HookLibraryx86.dll\n\n"
            "After downloading, extract the files and configure the directory in:\n"
            "Edit > Preferences > Settings > Debugger > scyllahide",
            MessageBoxButtonSet.YesNoButtonSet,
            MessageBoxIcon.QuestionIcon
        )
        if result == MessageBoxButtonResult.YesButton:
            webbrowser.open("https://github.com/x64dbg/ScyllaHide/releases/tag/v1.4")

    try:
        Settings().add_property_changed_callback(on_directory_changed)
    except Exception as e:
        log_warn(f"[ScyllaNinja] Failed to register settings callback: {e}")

    BinaryViewType.add_binaryview_finalized_event(on_view_open)

    PluginCommand.register(
        "ScyllaNinja\\Inject ScyllaHide",
        "Manually inject ScyllaHide into the debugged process",
        manual_inject_handler,
        is_debugging
    )

init_plugin()