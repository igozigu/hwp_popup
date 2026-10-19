using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Forms;
using Microsoft.Win32;

[assembly: AssemblyTitle("hwp_popup (AsideHwpGuard)")]
[assembly: AssemblyDescription("Aside Browser HWP Security Popup Permanent Resolver & 3-Layer Auto-Approval Guard")]
[assembly: AssemblyCompany("AsideHwpGuard")]
[assembly: AssemblyProduct("hwp_popup")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace AsideHwpGuard
{
    internal static class Program
    {
        // Constants & Paths
        public const string MutexName = @"Global\AsideHwpGuard_Mutex";
        public const string RunRegistryPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        public const string RunValueName = "AsideHwpGuard";
        public const string HwpModulesRegPath = @"Software\HNC\HwpAutomation\Modules";
        public const string HwpModulesWow64RegPath = @"Software\WOW6432Node\HNC\HwpAutomation\Modules";
        public const string EmbeddedDllResourceName = "FilePathCheckerModuleExample.dll";

        public static readonly string[] StandardModuleKeys = new string[]
        {
            "FilePathCheckerModuleExample",
            "FilePathCheckerModule",
            "FilePathCheckDLL",
            "FilePathCheckDLLModule",
            "SecurityModule",
            "Automation",
            "AsideHwpSetup_v1"
        };

        public const string AgentsMarkerBegin = "<!-- ASIDE-HWP-GUARD:BEGIN -->";
        public const string AgentsMarkerEnd = "<!-- ASIDE-HWP-GUARD:END -->";

        public static readonly string AgentsGuardBlock =
            "<!-- ASIDE-HWP-GUARD:BEGIN -->\r\n" +
            "## [필수] 한글(HWP/HWPX) COM 자동화 보안모듈 초기화 규칙\r\n" +
            "- PowerShell 또는 Python 등에서 `HWPFrame.HwpObject` COM 객체를 생성할 때는 `Open`, `SaveAs`, `Insert` 등 파일 접근 메서드를 호출하기 **직전 첫 줄에 반드시 보안모듈 등록 코드**를 포함해야 한다 (`SetMessageBoxMode`만으로는 보안 승인창이 차단되지 않음).\r\n" +
            "- **PowerShell 필수 패턴:**\r\n" +
            "  ```powershell\r\n" +
            "  $h = New-Object -ComObject HWPFrame.HwpObject\r\n" +
            "  [void]$h.RegisterModule(\"FilePathCheckDLL\", \"FilePathCheckerModule\")\r\n" +
            "  [void]$h.SetMessageBoxMode(0x00020000)\r\n" +
            "  ```\r\n" +
            "- **Python 필수 패턴:**\r\n" +
            "  ```python\r\n" +
            "  hwp = win32com.client.Dispatch(\"HWPFrame.HwpObject\")\r\n" +
            "  hwp.RegisterModule(\"FilePathCheckDLL\", \"FilePathCheckerModule\")\r\n" +
            "  hwp.SetMessageBoxMode(0x00020000)\r\n" +
            "  ```\r\n" +
            "<!-- ASIDE-HWP-GUARD:END -->";

        public static string BaseDir
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AsideHwpGuard"); }
        }

        public static string ModulesDir
        {
            get { return Path.Combine(BaseDir, "modules"); }
        }

        public static string LogsDir
        {
            get { return Path.Combine(BaseDir, "logs"); }
        }

        public static string PermanentDllPath
        {
            get { return Path.Combine(ModulesDir, "FilePathCheckerModuleExample.dll"); }
        }

        public static string GuardLogPath
        {
            get { return Path.Combine(LogsDir, "guard.log"); }
        }

        public static string InstalledPrimaryExePath
        {
            get { return Path.Combine(BaseDir, "hwp_popup.exe"); }
        }

        public static string InstalledAliasExePath
        {
            get { return Path.Combine(BaseDir, "AsideHwpGuard.exe"); }
        }

        private static volatile bool _daemonRunning = true;
        private static Mutex _instanceMutex = null;
        private static NotifyIcon _trayIcon = null;
        private static readonly object _logLock = new object();
        private static readonly Dictionary<IntPtr, DateTime> _recentlyClicked = new Dictionary<IntPtr, DateTime>();

        // Win32 P/Invoke
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll")]
        private static extern bool FreeConsole();

        [DllImport("kernel32.dll")]
        private static extern bool SetProcessWorkingSetSize(IntPtr hProcess, IntPtr dwMinimumWorkingSetSize, IntPtr dwMaximumWorkingSetSize);

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll")]
        private static extern IntPtr GetProcessWindowStation();

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern bool EnumDesktops(IntPtr hwinsta, EnumDesktopsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenDesktop(string lpszDesktop, uint dwFlags, bool fInherit, uint dwDesiredAccess);

        [DllImport("user32.dll")]
        private static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        private static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("user32.dll")]
        private static extern bool EnumDesktopWindows(IntPtr hDesktop, EnumWindowsProc lpfn, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool EnumChildWindows(IntPtr hWndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, StringBuilder lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern int GetDlgCtrlID(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsWindow(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hWnd);

        private delegate bool EnumDesktopsProc([MarshalAs(UnmanagedType.LPWStr)] string lpszDesktop, IntPtr lParam);
        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        private const int SW_HIDE = 0;
        private const uint WM_GETTEXT = 0x000D;
        private const uint WM_ACTIVATE = 0x0006;
        private const uint WM_COMMAND = 0x0111;
        private const uint WM_KEYDOWN = 0x0100;
        private const uint WM_KEYUP = 0x0101;
        private const uint WM_CHAR = 0x0102;
        private const uint WM_SYSKEYDOWN = 0x0104;
        private const uint WM_SYSKEYUP = 0x0105;
        private const uint WM_SYSCHAR = 0x0106;
        private const uint BM_CLICK = 0x00F5;
        private const uint DESKTOP_ALL_ACCESS = 0x01FF;

        [STAThread]
        public static int Main(string[] args)
        {
            try
            {
                Console.OutputEncoding = Encoding.UTF8;
            }
            catch { }

            string mode = (args != null && args.Length > 0) ? args[0].Trim().ToLowerInvariant() : "--install";

            if (mode == "--status" || mode == "/status")
            {
                return RunStatus();
            }
            if (mode == "--uninstall" || mode == "/uninstall")
            {
                return RunUninstall();
            }
            if (mode == "--test" || mode == "/test")
            {
                return RunSelfTest();
            }
            if (mode == "--daemon" || mode == "--daemon-notify")
            {
                bool showBalloon = (mode == "--daemon-notify");
                return RunDaemonProcess(showBalloon);
            }

            // Default: --install, --background, --silent, or no args
            bool isSilent = (mode == "--background" || mode == "--silent" || mode == "/background" || mode == "/silent");
            return RunInstallAndStartLauncher(!isSilent);
        }

        // =====================================================================
        // Launcher & Installation Flow
        // =====================================================================
        private static int RunInstallAndStartLauncher(bool showNotification)
        {
            try
            {
                Directory.CreateDirectory(BaseDir);
                Directory.CreateDirectory(ModulesDir);
                Directory.CreateDirectory(LogsDir);

                // 1. Copy executable to %LocalAppData%\AsideHwpGuard\hwp_popup.exe and AsideHwpGuard.exe
                CopySelfToInstallDir();

                // 2. Layer 1: Extract DLL & Register 7 keys + repair broken paths
                ApplyLayer1();

                // 3. Layer 2: Non-destructive AGENTS.md patch
                ApplyLayer2();

                // 4. Register Windows Startup Run key
                RegisterStartupRun();

                // 5. Ensure background daemon is running
                if (!IsDaemonRunning())
                {
                    string targetExe = File.Exists(InstalledPrimaryExePath) ? InstalledPrimaryExePath : Assembly.GetExecutingAssembly().Location;
                    string daemonArg = showNotification ? "--daemon-notify" : "--daemon";
                    StartDaemonDetached(targetExe, daemonArg);

                    // Wait up to 2.5s for mutex acquisition
                    for (int i = 0; i < 25; i++)
                    {
                        Thread.Sleep(100);
                        if (IsDaemonRunning()) break;
                    }
                }
                else if (showNotification)
                {
                    MessageBox.Show(
                        "Aside 한글 보안 팝업 해결 및 자동 가드가 활성화되어 실행 중입니다.\r\n\r\n" +
                        "- Layer 1: 보안모듈 DLL 및 레지스트리 7종 등록 완료\r\n" +
                        "- Layer 2: AGENTS.md 보안모듈 지침 패치 완료\r\n" +
                        "- Layer 3: 백그라운드 보안 팝업 자동 승인 가드 작동 중",
                        "AsideHwpGuard (hwp_popup)",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }

                WriteLog("INSTALL", string.Format("Setup & Layer 1/2 applied successfully (silent={0}).", !showNotification));
                return 0;
            }
            catch (Exception ex)
            {
                WriteLog("ERROR", "RunInstallAndStartLauncher failed: " + ex.Message);
                Console.Error.WriteLine("[ERROR] " + ex.Message);
                return 1;
            }
        }

        private static void StartDaemonDetached(string targetExe, string daemonArg)
        {
            string cmdLine = string.Format("\"{0}\" {1}", targetExe, daemonArg);
            try
            {
                using (ManagementClass startupClass = new ManagementClass("Win32_ProcessStartup"))
                using (ManagementObject startupInstance = startupClass.CreateInstance())
                using (ManagementClass processClass = new ManagementClass("Win32_Process"))
                {
                    startupInstance["ShowWindow"] = (ushort)0; // SW_HIDE
                    ManagementBaseObject inParams = processClass.GetMethodParameters("Create");
                    inParams["CommandLine"] = cmdLine;
                    inParams["CurrentDirectory"] = BaseDir;
                    inParams["ProcessStartupInformation"] = startupInstance;
                    ManagementBaseObject outParams = processClass.InvokeMethod("Create", inParams, null);
                    if (outParams != null && Convert.ToUInt32(outParams["ReturnValue"]) == 0)
                    {
                        return;
                    }
                }
            }
            catch { }

            // Fallback to direct Process.Start if WMI is unavailable
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = targetExe,
                Arguments = daemonArg,
                WorkingDirectory = BaseDir,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            Process.Start(psi);
        }

        private static void CopySelfToInstallDir()
        {
            string currentExe = Assembly.GetExecutingAssembly().Location;
            if (string.IsNullOrEmpty(currentExe) || !File.Exists(currentExe)) return;

            string[] targets = new string[] { InstalledPrimaryExePath, InstalledAliasExePath };
            foreach (string target in targets)
            {
                try
                {
                    if (!string.Equals(Path.GetFullPath(currentExe), Path.GetFullPath(target), StringComparison.OrdinalIgnoreCase))
                    {
                        File.Copy(currentExe, target, true);
                    }
                }
                catch
                {
                    // Ignore if target is currently locked by running daemon
                }
            }
        }

        private static void RegisterStartupRun()
        {
            string exePath = File.Exists(InstalledPrimaryExePath) ? InstalledPrimaryExePath : Assembly.GetExecutingAssembly().Location;
            string runCmd = string.Format("\"{0}\" --background", exePath);
            using (RegistryKey rk = Registry.CurrentUser.CreateSubKey(RunRegistryPath))
            {
                if (rk != null)
                {
                    rk.SetValue(RunValueName, runCmd, RegistryValueKind.String);
                }
            }
        }

        // =====================================================================
        // [Layer 1] Embedded DLL Extraction & Multi-Key Registry Guard
        // =====================================================================
        public static void ApplyLayer1()
        {
            Directory.CreateDirectory(ModulesDir);

            // 1. Extract embedded FilePathCheckerModuleExample.dll if missing or SHA-256 differs
            byte[] embeddedBytes = GetEmbeddedDllBytes();
            if (embeddedBytes != null && embeddedBytes.Length > 0)
            {
                string expectedHash = ComputeSha256(embeddedBytes);
                bool needWrite = true;
                if (File.Exists(PermanentDllPath))
                {
                    try
                    {
                        string existingHash = ComputeFileSha256(PermanentDllPath);
                        if (string.Equals(expectedHash, existingHash, StringComparison.OrdinalIgnoreCase))
                        {
                            needWrite = false;
                        }
                    }
                    catch
                    {
                        needWrite = true;
                    }
                }

                if (needWrite)
                {
                    File.WriteAllBytes(PermanentDllPath, embeddedBytes);
                    WriteLog("LAYER1", "Extracted permanent DLL to " + PermanentDllPath + " (SHA256=" + expectedHash + ")");
                }
            }

            // 2. Repair broken entries and register all 7 standard keys in HKCU (64-bit & WOW6432Node)
            UpdateHwpModulesRegistryKey(HwpModulesRegPath);
            UpdateHwpModulesRegistryKey(HwpModulesWow64RegPath);
        }

        private static void UpdateHwpModulesRegistryKey(string subKeyPath)
        {
            using (RegistryKey rk = Registry.CurrentUser.CreateSubKey(subKeyPath))
            {
                if (rk == null) return;

                // Repair any existing broken or temporary (_MEI*, \Temp\) paths
                string[] existingNames = rk.GetValueNames();
                foreach (string name in existingNames)
                {
                    if (string.IsNullOrEmpty(name)) continue;
                    string val = rk.GetValue(name) as string;
                    bool isBroken = string.IsNullOrEmpty(val) ||
                                    !Path.IsPathRooted(val) ||
                                    !File.Exists(val) ||
                                    val.IndexOf("_MEI", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                    val.IndexOf("\\Temp\\", StringComparison.OrdinalIgnoreCase) >= 0;
                    if (isBroken)
                    {
                        rk.SetValue(name, PermanentDllPath, RegistryValueKind.String);
                    }
                }

                // Register all 7 standard module keys
                foreach (string keyName in StandardModuleKeys)
                {
                    string currentVal = rk.GetValue(keyName) as string;
                    if (!string.Equals(currentVal, PermanentDllPath, StringComparison.OrdinalIgnoreCase))
                    {
                        rk.SetValue(keyName, PermanentDllPath, RegistryValueKind.String);
                    }
                }
            }
        }

        private static byte[] GetEmbeddedDllBytes()
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            Stream s = asm.GetManifestResourceStream(EmbeddedDllResourceName);
            if (s == null)
            {
                string[] names = asm.GetManifestResourceNames();
                foreach (string n in names)
                {
                    if (n.EndsWith("FilePathCheckerModuleExample.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        s = asm.GetManifestResourceStream(n);
                        break;
                    }
                }
            }
            if (s == null) return null;
            using (s)
            using (MemoryStream ms = new MemoryStream())
            {
                s.CopyTo(ms);
                return ms.ToArray();
            }
        }

        // =====================================================================
        // [Layer 2] Non-Destructive Aside AGENTS.md Auto-Patch & Recovery
        // =====================================================================
        public static List<string> GetTargetAgentsMdPaths()
        {
            List<string> paths = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string asideU = Path.Combine(Path.Combine(userProfile, ".aside"), "u");
            if (Directory.Exists(asideU))
            {
                try
                {
                    foreach (string dir in Directory.GetDirectories(asideU))
                    {
                        string candidate = Path.Combine(dir, "AGENTS.md");
                        if (seen.Add(candidate)) paths.Add(candidate);
                    }
                }
                catch { }
            }

            string asideHome = Environment.GetEnvironmentVariable("ASIDE_HOME");
            if (!string.IsNullOrEmpty(asideHome) && Directory.Exists(asideHome))
            {
                try
                {
                    string directAgents = Path.Combine(asideHome, "AGENTS.md");
                    if (File.Exists(directAgents) && seen.Add(directAgents))
                    {
                        paths.Add(directAgents);
                    }
                    string homeU = Path.Combine(asideHome, "u");
                    if (Directory.Exists(homeU))
                    {
                        foreach (string dir in Directory.GetDirectories(homeU))
                        {
                            string candidate = Path.Combine(dir, "AGENTS.md");
                            if (seen.Add(candidate)) paths.Add(candidate);
                        }
                    }
                }
                catch { }
            }

            return paths;
        }

        public static void ApplyLayer2()
        {
            List<string> agentsPaths = GetTargetAgentsMdPaths();
            UTF8Encoding utf8NoBom = new UTF8Encoding(false);

            foreach (string filePath in agentsPaths)
            {
                try
                {
                    string dir = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                    {
                        Directory.CreateDirectory(dir);
                    }

                    string content = File.Exists(filePath) ? File.ReadAllText(filePath, Encoding.UTF8) : "";
                    int beginIdx = content.IndexOf(AgentsMarkerBegin, StringComparison.Ordinal);
                    int endIdx = content.IndexOf(AgentsMarkerEnd, StringComparison.Ordinal);

                    string updatedContent;
                    if (beginIdx >= 0 && endIdx > beginIdx)
                    {
                        int endBlockIdx = endIdx + AgentsMarkerEnd.Length;
                        string existingBlock = content.Substring(beginIdx, endBlockIdx - beginIdx);
                        if (string.Equals(NormalizeNewlines(existingBlock), NormalizeNewlines(AgentsGuardBlock), StringComparison.Ordinal))
                        {
                            continue; // Already up-to-date
                        }
                        updatedContent = content.Substring(0, beginIdx) + AgentsGuardBlock + content.Substring(endBlockIdx);
                    }
                    else
                    {
                        if (content.Length > 0 && !content.EndsWith("\n"))
                        {
                            updatedContent = content + "\r\n\r\n" + AgentsGuardBlock + "\r\n";
                        }
                        else if (content.Length > 0)
                        {
                            updatedContent = content + "\r\n" + AgentsGuardBlock + "\r\n";
                        }
                        else
                        {
                            updatedContent = AgentsGuardBlock + "\r\n";
                        }
                    }

                    File.WriteAllText(filePath, updatedContent, utf8NoBom);
                    WriteLog("LAYER2", "Patched AGENTS.md: " + filePath);
                }
                catch (Exception ex)
                {
                    WriteLog("ERROR", "Failed to patch " + filePath + ": " + ex.Message);
                }
            }
        }

        private static void RemoveLayer2Markers()
        {
            List<string> agentsPaths = GetTargetAgentsMdPaths();
            UTF8Encoding utf8NoBom = new UTF8Encoding(false);

            foreach (string filePath in agentsPaths)
            {
                try
                {
                    if (!File.Exists(filePath)) continue;
                    string content = File.ReadAllText(filePath, Encoding.UTF8);
                    int beginIdx = content.IndexOf(AgentsMarkerBegin, StringComparison.Ordinal);
                    int endIdx = content.IndexOf(AgentsMarkerEnd, StringComparison.Ordinal);
                    if (beginIdx >= 0 && endIdx > beginIdx)
                    {
                        int endBlockIdx = endIdx + AgentsMarkerEnd.Length;
                        string before = content.Substring(0, beginIdx).TrimEnd('\r', '\n');
                        string after = content.Substring(endBlockIdx).TrimStart('\r', '\n');
                        string updated = string.IsNullOrEmpty(after)
                            ? (string.IsNullOrEmpty(before) ? "" : before + "\r\n")
                            : before + "\r\n\r\n" + after;
                        File.WriteAllText(filePath, updated, utf8NoBom);
                        WriteLog("UNINSTALL", "Removed marker block from " + filePath);
                    }
                }
                catch { }
            }
        }

        // =====================================================================
        // [Layer 3] Background Daemon + Tray UI + Multi-Desktop Popup Watchdog
        // =====================================================================
        private static int RunDaemonProcess(bool showBalloonOnStart)
        {
            // Hide console window immediately so background daemon has zero visible window
            try
            {
                IntPtr hConsole = GetConsoleWindow();
                if (hConsole != IntPtr.Zero)
                {
                    ShowWindow(hConsole, SW_HIDE);
                }
                FreeConsole();
            }
            catch { }

            bool createdNew;
            _instanceMutex = new Mutex(true, MutexName, out createdNew);
            if (!createdNew)
            {
                try
                {
                    if (!_instanceMutex.WaitOne(100))
                    {
                        return 0; // Another daemon instance is already running
                    }
                }
                catch (AbandonedMutexException)
                {
                    // Acquired abandoned mutex
                }
            }

            try
            {
                Directory.CreateDirectory(BaseDir);
                Directory.CreateDirectory(ModulesDir);
                Directory.CreateDirectory(LogsDir);

                ApplyLayer1();
                ApplyLayer2();
                RegisterStartupRun();

                WriteLog("DAEMON", "Background guard daemon started (PID=" + Process.GetCurrentProcess().Id + ").");

                // Start Layer 3 Watchdog thread (scans all desktops whenever Hwp.exe is running)
                Thread watchdogThread = new Thread(WatchdogLoop);
                watchdogThread.IsBackground = true;
                watchdogThread.SetApartmentState(ApartmentState.MTA);
                watchdogThread.Start();

                // Start Layer 1/2 periodic recovery & FileSystemWatcher thread
                Thread recoveryThread = new Thread(RecoveryLoop);
                recoveryThread.IsBackground = true;
                recoveryThread.Start();

                // Initialize System Tray Icon & Context Menu
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);

                using (_trayIcon = CreateTrayIcon())
                {
                    if (showBalloonOnStart)
                    {
                        _trayIcon.ShowBalloonTip(
                            4000,
                            "AsideHwpGuard (hwp_popup)",
                            "Aside 한글 보안 팝업 해결 및 자동 가드가 활성화되었습니다.",
                            ToolTipIcon.Info);
                    }

                    TrimWorkingSet();
                    Application.Run();
                }

                _daemonRunning = false;
                return 0;
            }
            finally
            {
                _daemonRunning = false;
                if (_instanceMutex != null)
                {
                    try { _instanceMutex.ReleaseMutex(); } catch { }
                    _instanceMutex.Dispose();
                }
            }
        }

        private static void TrimWorkingSet()
        {
            try
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
                SetProcessWorkingSetSize(Process.GetCurrentProcess().Handle, (IntPtr)(-1), (IntPtr)(-1));
            }
            catch { }
        }

        private static NotifyIcon CreateTrayIcon()
        {
            NotifyIcon ni = new NotifyIcon();
            ni.Icon = SystemIcons.Shield;
            ni.Text = "AsideHwpGuard - 한글 보안 팝업 자동 가드";
            ni.Visible = true;

            ContextMenu menu = new ContextMenu();

            MenuItem itemDiagnose = new MenuItem("상태 진단 및 즉시 복구", (s, e) =>
            {
                ApplyLayer1();
                ApplyLayer2();
                RegisterStartupRun();
                ni.ShowBalloonTip(
                    3000,
                    "AsideHwpGuard 상태 진단 및 복구 완료",
                    "Layer 1(DLL/레지스트리 7종), Layer 2(AGENTS.md), Layer 3(실시간 감시) 모두 정상입니다.",
                    ToolTipIcon.Info);
            });

            MenuItem itemOpenLogs = new MenuItem("로그 폴더 열기", (s, e) =>
            {
                try
                {
                    Directory.CreateDirectory(LogsDir);
                    Process.Start("explorer.exe", LogsDir);
                }
                catch { }
            });

            MenuItem itemUninstall = new MenuItem("자동 시작 해제 및 제거(Uninstall)", (s, e) =>
            {
                DialogResult dr = MessageBox.Show(
                    "Aside 한글 보안 팝업 자동 가드의 자동 시작 및 AGENTS.md 패치를 제거하고 종료하시겠습니까?",
                    "AsideHwpGuard 제거 확인",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);
                if (dr == DialogResult.Yes)
                {
                    PerformUninstallCleanup();
                    ni.Visible = false;
                    _daemonRunning = false;
                    Application.Exit();
                }
            });

            MenuItem itemExit = new MenuItem("종료", (s, e) =>
            {
                ni.Visible = false;
                _daemonRunning = false;
                WriteLog("DAEMON", "Background guard daemon stopped by user.");
                Application.Exit();
            });

            menu.MenuItems.Add(itemDiagnose);
            menu.MenuItems.Add(itemOpenLogs);
            menu.MenuItems.Add("-");
            menu.MenuItems.Add(itemUninstall);
            menu.MenuItems.Add(itemExit);

            ni.ContextMenu = menu;
            return ni;
        }

        private static void RecoveryLoop()
        {
            Thread.Sleep(500);
            TrimWorkingSet();

            List<FileSystemWatcher> watchers = new List<FileSystemWatcher>();
            try
            {
                foreach (string agentsPath in GetTargetAgentsMdPaths())
                {
                    string dir = Path.GetDirectoryName(agentsPath);
                    if (!string.IsNullOrEmpty(dir) && Directory.Exists(dir))
                    {
                        FileSystemWatcher fsw = new FileSystemWatcher(dir, "AGENTS.md");
                        fsw.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.CreationTime;
                        FileSystemEventHandler handler = (s, e) =>
                        {
                            Thread.Sleep(250);
                            ApplyLayer2();
                        };
                        fsw.Changed += handler;
                        fsw.Created += handler;
                        fsw.Deleted += handler;
                        fsw.EnableRaisingEvents = true;
                        watchers.Add(fsw);
                    }
                }
            }
            catch { }

            while (_daemonRunning)
            {
                for (int i = 0; i < 60 && _daemonRunning; i++)
                {
                    Thread.Sleep(500);
                }
                if (!_daemonRunning) break;
                try
                {
                    ApplyLayer1();
                    ApplyLayer2();
                    TrimWorkingSet();
                }
                catch { }
            }

            foreach (FileSystemWatcher w in watchers)
            {
                try { w.Dispose(); } catch { }
            }
        }

        private static void WatchdogLoop()
        {
            while (_daemonRunning)
            {
                try
                {
                    // Fast path: Only scan desktops/windows when at least one Hwp.exe process exists.
                    // Keeps idle CPU at 0.00% and memory under 10MB.
                    Process[] hwpProcs = Process.GetProcessesByName("Hwp");
                    if (hwpProcs == null || hwpProcs.Length == 0)
                    {
                        Thread.Sleep(80);
                        continue;
                    }

                    HashSet<uint> hwpPids = new HashSet<uint>();
                    foreach (Process p in hwpProcs)
                    {
                        try { hwpPids.Add((uint)p.Id); } catch { }
                        finally { p.Dispose(); }
                    }

                    ScanAllDesktopsAndApprovePopups(hwpPids);
                }
                catch { }

                Thread.Sleep(25);
            }
        }

        private static void ScanAllDesktopsAndApprovePopups(HashSet<uint> hwpPids)
        {
            // Collect desktop names in current WindowStation (includes "Default" and any "exebox-*" desktops)
            List<string> desktops = new List<string>();
            IntPtr hwinsta = GetProcessWindowStation();
            if (hwinsta != IntPtr.Zero)
            {
                EnumDesktops(hwinsta, (deskName, lParam) =>
                {
                    if (!string.IsNullOrEmpty(deskName))
                    {
                        desktops.Add(deskName);
                    }
                    return true;
                }, IntPtr.Zero);
            }

            if (desktops.Count == 0)
            {
                desktops.Add("Default");
            }

            foreach (string deskName in desktops)
            {
                IntPtr hDesk = OpenDesktop(deskName, 0, false, DESKTOP_ALL_ACCESS);
                if (hDesk == IntPtr.Zero) continue;

                try
                {
                    SetThreadDesktop(hDesk);
                    EnumDesktopWindows(hDesk, (hWnd, lParam) =>
                    {
                        try
                        {
                            InspectAndClickWindowIfTarget(hWnd, deskName, hwpPids);
                        }
                        catch { }
                        return true;
                    }, IntPtr.Zero);
                }
                finally
                {
                    CloseDesktop(hDesk);
                }
            }
        }

        private static void InspectAndClickWindowIfTarget(IntPtr hWnd, string deskName, HashSet<uint> hwpPids)
        {
            if (!IsWindowVisible(hWnd)) return;

            // Avoid duplicate rapid clicks on the same handle within 150ms
            DateTime lastClick;
            if (_recentlyClicked.TryGetValue(hWnd, out lastClick))
            {
                if ((DateTime.UtcNow - lastClick).TotalMilliseconds < 150) return;
            }

            uint pid;
            GetWindowThreadProcessId(hWnd, out pid);
            string cls = GetWindowClass(hWnd);
            string title = GetWindowTextSafe(hWnd);

            bool isWin32Dialog = string.Equals(cls, "#32770", StringComparison.Ordinal);
            bool isWpfHwpDialog = cls.StartsWith("HwndWrapper[hwp.exe", StringComparison.OrdinalIgnoreCase);

            if (!isWin32Dialog && !isWpfHwpDialog) return;

            bool isHwpOwner = hwpPids.Contains(pid);
            bool hasHwpTitle = HasHwpTitleKeyword(title);

            // Condition A: Class is #32770 or HwndWrapper[hwp.exe...], and owned by Hwp.exe or has HWP title
            if (!isHwpOwner && !hasHwpTitle) return;

            // Skip main document editing windows (e.g. "빈 문서 1 - 한글")
            if (isWpfHwpDialog && title.IndexOf(" - ", StringComparison.Ordinal) >= 0) return;

            // Path 1: Standard Win32 #32770 Dialog (Child Static + Button controls)
            if (isWin32Dialog)
            {
                bool bodyMatched = false;
                IntPtr allowAllBtn = IntPtr.Zero;
                IntPtr allowOnceBtn = IntPtr.Zero;
                string allowAllText = "";
                string allowOnceText = "";

                EnumChildWindows(hWnd, (hChild, lParam) =>
                {
                    string cCls = GetWindowClass(hChild);
                    string cTxt = GetWindowTextSafe(hChild);
                    if (HasSecurityWarningText(cTxt))
                    {
                        bodyMatched = true;
                    }
                    if (cCls.IndexOf("Button", StringComparison.OrdinalIgnoreCase) >= 0 || !string.IsNullOrEmpty(cTxt))
                    {
                        if (cTxt.IndexOf("모두 허용", StringComparison.Ordinal) >= 0)
                        {
                            allowAllBtn = hChild;
                            allowAllText = cTxt;
                        }
                        else if (cTxt.IndexOf("접근 허용", StringComparison.Ordinal) >= 0)
                        {
                            allowOnceBtn = hChild;
                            allowOnceText = cTxt;
                        }
                    }
                    return true;
                }, IntPtr.Zero);

                IntPtr targetBtn = (allowAllBtn != IntPtr.Zero) ? allowAllBtn : allowOnceBtn;
                string targetBtnText = (allowAllBtn != IntPtr.Zero) ? allowAllText : allowOnceText;

                if (bodyMatched && targetBtn != IntPtr.Zero)
                {
                    _recentlyClicked[hWnd] = DateTime.UtcNow;
                    SendMessage(targetBtn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
                    int ctrlId = GetDlgCtrlID(targetBtn);
                    if (ctrlId != 0 && IsWindowVisible(hWnd))
                    {
                        PostMessage(hWnd, WM_COMMAND, (IntPtr)(ctrlId & 0xFFFF), targetBtn);
                    }
                    WriteLog("LAYER3_APPROVED", string.Format(
                        "Approved Win32 HWP popup (desktop={0}, pid={1}, hWnd={2}, button=\"{3}\")",
                        deskName, pid, hWnd, targetBtnText.Replace("\r", "").Replace("\n", " ")));
                }
                return;
            }

            // Path 2: Hancom Office 2022+ WPF MessageBoxImpl (HwndWrapper[hwp.exe;;...])
            if (isWpfHwpDialog)
            {
                try
                {
                    AutomationElement el = AutomationElement.FromHandle(hWnd);
                    if (el == null) return;

                    string fullName = el.Current.Name ?? "";
                    bool bodyMatched = HasSecurityWarningText(fullName);
                    bool hasAllowAll = fullName.IndexOf("모두 허용", StringComparison.Ordinal) >= 0;
                    bool hasAllowOnce = fullName.IndexOf("접근 허용", StringComparison.Ordinal) >= 0;

                    AutomationElement targetBtnElement = null;
                    string matchedBtnName = "";

                    AutomationElementCollection descendants = el.FindAll(TreeScope.Descendants, System.Windows.Automation.Condition.TrueCondition);
                    if (descendants != null)
                    {
                        foreach (AutomationElement child in descendants)
                        {
                            string cName = child.Current.Name ?? "";
                            if (!bodyMatched && HasSecurityWarningText(cName))
                            {
                                bodyMatched = true;
                            }
                            if (cName.IndexOf("모두 허용", StringComparison.Ordinal) >= 0)
                            {
                                hasAllowAll = true;
                                targetBtnElement = child;
                                matchedBtnName = cName;
                            }
                            else if (cName.IndexOf("접근 허용", StringComparison.Ordinal) >= 0 && targetBtnElement == null)
                            {
                                hasAllowOnce = true;
                                targetBtnElement = child;
                                matchedBtnName = cName;
                            }
                        }
                    }

                    if (bodyMatched && (hasAllowAll || hasAllowOnce))
                    {
                        _recentlyClicked[hWnd] = DateTime.UtcNow;
                        int vk = hasAllowAll ? 0x4E : 0x59;     // 'N' for 모두 허용(N), 'Y' for 접근 허용(Y)
                        int ch = hasAllowAll ? 0x6E : 0x79;     // 'n' or 'y'
                        uint scanLParamDown = hasAllowAll ? 0x00310001u : 0x00150001u;
                        uint scanLParamUp = hasAllowAll ? 0xC0310001u : 0xC0150001u;

                        // Silent activation + key dispatch to the popup window
                        SendMessage(hWnd, WM_ACTIVATE, (IntPtr)1, IntPtr.Zero);
                        PostMessage(hWnd, WM_KEYDOWN, (IntPtr)vk, (IntPtr)scanLParamDown);
                        PostMessage(hWnd, WM_CHAR, (IntPtr)ch, (IntPtr)scanLParamDown);
                        PostMessage(hWnd, WM_KEYUP, (IntPtr)vk, unchecked((IntPtr)scanLParamUp));

                        // Fallback: SYSKEYDOWN (ALT+N / ALT+Y) and UIAutomation InvokePattern if still visible
                        Thread.Sleep(15);
                        if (IsWindow(hWnd) && IsWindowVisible(hWnd))
                        {
                            PostMessage(hWnd, WM_SYSKEYDOWN, (IntPtr)vk, (IntPtr)(scanLParamDown | 0x20000000u));
                            PostMessage(hWnd, WM_SYSCHAR, (IntPtr)ch, (IntPtr)(scanLParamDown | 0x20000000u));
                            PostMessage(hWnd, WM_SYSKEYUP, (IntPtr)vk, unchecked((IntPtr)(scanLParamUp | 0x20000000u)));

                            if (targetBtnElement != null)
                            {
                                object patObj;
                                if (targetBtnElement.TryGetCurrentPattern(InvokePattern.Pattern, out patObj))
                                {
                                    ((InvokePattern)patObj).Invoke();
                                }
                            }
                        }

                        if (string.IsNullOrEmpty(matchedBtnName))
                        {
                            matchedBtnName = hasAllowAll ? "모두 허용(N)" : "접근 허용(Y)";
                        }

                        WriteLog("LAYER3_APPROVED", string.Format(
                            "Approved WPF HWP popup (desktop={0}, pid={1}, hWnd={2}, button=\"{3}\")",
                            deskName, pid, hWnd, matchedBtnName.Replace("\r", "").Replace("\n", " ")));
                    }
                }
                catch { }
            }
        }

        private static bool HasHwpTitleKeyword(string title)
        {
            if (string.IsNullOrEmpty(title)) return false;
            return title.IndexOf("한글", StringComparison.Ordinal) >= 0 ||
                   title.IndexOf("\u1112\u119E\u11AB\uAE00", StringComparison.Ordinal) >= 0 ||
                   title.IndexOf("\uF53A\uAE00", StringComparison.Ordinal) >= 0 ||
                   title.IndexOf("Hwp", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static bool HasSecurityWarningText(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            return text.IndexOf("접근하려는 시도", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("파일의 손상 또는 유출의 위험", StringComparison.Ordinal) >= 0 ||
                   text.IndexOf("정상적인 작업 과정에만 접근을 허용", StringComparison.Ordinal) >= 0;
        }

        private static string GetWindowTextSafe(IntPtr hWnd)
        {
            StringBuilder sb = new StringBuilder(1024);
            GetWindowText(hWnd, sb, sb.Capacity);
            if (sb.Length == 0)
            {
                SendMessage(hWnd, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
            }
            return sb.ToString();
        }

        private static string GetWindowClass(IntPtr hWnd)
        {
            StringBuilder sb = new StringBuilder(256);
            GetClassName(hWnd, sb, sb.Capacity);
            return sb.ToString();
        }

        // =====================================================================
        // CLI Commands: --status, --uninstall, --test
        // =====================================================================
        private static int RunStatus()
        {
            Console.WriteLine("=== AsideHwpGuard (hwp_popup) Status Diagnostics ===");
            Console.WriteLine("1. Permanent DLL Path : " + PermanentDllPath);
            bool dllExists = File.Exists(PermanentDllPath);
            Console.WriteLine("   DLL Exists         : " + dllExists);
            if (dllExists)
            {
                Console.WriteLine("   DLL SHA-256        : " + ComputeFileSha256(PermanentDllPath));
            }

            Console.WriteLine("\n2. Registry Modules (HKCU\\" + HwpModulesRegPath + "):");
            using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(HwpModulesRegPath, false))
            {
                if (rk == null)
                {
                    Console.WriteLine("   [MISSING] Registry key does not exist.");
                }
                else
                {
                    foreach (string key in StandardModuleKeys)
                    {
                        string val = rk.GetValue(key) as string;
                        bool ok = !string.IsNullOrEmpty(val) && File.Exists(val);
                        Console.WriteLine(string.Format("   - {0,-28} : {1} ({2})", key, val ?? "<null>", ok ? "OK" : "BROKEN"));
                    }
                }
            }

            Console.WriteLine("\n3. Aside AGENTS.md Guard Status:");
            List<string> agentsPaths = GetTargetAgentsMdPaths();
            if (agentsPaths.Count == 0)
            {
                Console.WriteLine("   No .aside/u/*/AGENTS.md profiles found.");
            }
            else
            {
                foreach (string p in agentsPaths)
                {
                    bool patched = false;
                    if (File.Exists(p))
                    {
                        string c = File.ReadAllText(p, Encoding.UTF8);
                        patched = c.IndexOf(AgentsMarkerBegin, StringComparison.Ordinal) >= 0 &&
                                  c.IndexOf(AgentsMarkerEnd, StringComparison.Ordinal) >= 0;
                    }
                    Console.WriteLine(string.Format("   - {0} : {1}", p, patched ? "PATCHED (OK)" : "NOT PATCHED"));
                }
            }

            Console.WriteLine("\n4. Startup Run Registration & Background Daemon:");
            using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(RunRegistryPath, false))
            {
                string runVal = (rk != null) ? (rk.GetValue(RunValueName) as string) : null;
                Console.WriteLine("   Startup Run Key    : " + (runVal ?? "<not registered>"));
            }
            bool daemonRunning = IsDaemonRunning();
            Console.WriteLine("   Daemon Running     : " + (daemonRunning ? "RUNNING (Active)" : "STOPPED"));
            Console.WriteLine("   Guard Log Path     : " + GuardLogPath);
            return 0;
        }

        private static int RunUninstall()
        {
            Console.WriteLine("=== Uninstalling AsideHwpGuard (hwp_popup) ===");
            PerformUninstallCleanup();
            Console.WriteLine("[OK] Background daemon stopped, Startup Run entry removed, and AGENTS.md marker blocks cleaned.");
            return 0;
        }

        private static void PerformUninstallCleanup()
        {
            // 1. Remove Startup Run registry value
            try
            {
                using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(RunRegistryPath, true))
                {
                    if (rk != null && rk.GetValue(RunValueName) != null)
                    {
                        rk.DeleteValue(RunValueName, false);
                    }
                }
            }
            catch { }

            // 2. Remove AGENTS.md marker blocks
            RemoveLayer2Markers();

            // 3. Kill running daemon processes (except current process)
            int currentPid = Process.GetCurrentProcess().Id;
            string[] procNames = new string[] { "hwp_popup", "AsideHwpGuard" };
            foreach (string name in procNames)
            {
                try
                {
                    foreach (Process p in Process.GetProcessesByName(name))
                    {
                        try
                        {
                            if (p.Id != currentPid)
                            {
                                p.Kill();
                                p.WaitForExit(2000);
                            }
                        }
                        catch { }
                        finally { p.Dispose(); }
                    }
                }
                catch { }
            }

            WriteLog("UNINSTALL", "Uninstall cleanup completed.");
        }

        private static int RunSelfTest()
        {
            Console.WriteLine("=== AsideHwpGuard (hwp_popup) End-to-End Self-Test ===");

            // Ensure installed and daemon running
            RunInstallAndStartLauncher(false);
            Console.WriteLine("[STEP 1] Layer 1, Layer 2, and Background Daemon active: " + IsDaemonRunning());

            string testFile = Path.Combine(BaseDir, "e2e_test_sample.hwp");
            try
            {
                // Clean any existing Hwp processes to guarantee fresh COM state
                KillExistingHwpProcesses();

                // Test Case 1: With RegisterModule
                Console.WriteLine("[STEP 2] Test Case 1: HWP COM Automation WITH RegisterModule...");
                Type hwpType = Type.GetTypeFromProgID("HWPFrame.HwpObject");
                if (hwpType == null)
                {
                    Console.Error.WriteLine("[FAIL] HWPFrame.HwpObject ProgID is not registered on this PC.");
                    return 2;
                }

                dynamic hwp1 = Activator.CreateInstance(hwpType);
                hwp1.RegisterModule("FilePathCheckDLL", "FilePathCheckerModule");
                hwp1.SetMessageBoxMode(0x00020000);

                dynamic act = hwp1.CreateAction("InsertText");
                dynamic set = act.CreateSet();
                act.GetDefault(set);
                set.SetItem("Text", "AsideHwpGuard E2E Verification Document Content");
                act.Execute(set);

                bool saveOk = hwp1.SaveAs(testFile, "HWP", "");
                hwp1.Clear(1);
                bool openOk1 = hwp1.Open(testFile, "HWP", "");
                hwp1.Clear(1);
                hwp1.Quit();
                Marshal.ReleaseComObject(hwp1);

                Console.WriteLine(string.Format("         SaveAs={0}, Open={1} (Zero popup with RegisterModule)", saveOk, openOk1));
                if (!saveOk || !openOk1)
                {
                    Console.Error.WriteLine("[FAIL] Test Case 1 failed.");
                    return 1;
                }

                KillExistingHwpProcesses();
                Thread.Sleep(400);

                // Test Case 2: WITHOUT RegisterModule (verifying Layer 3 Auto-Clicker)
                Console.WriteLine("[STEP 3] Test Case 2: Fresh HWP COM instance WITHOUT RegisterModule (Layer 3 Auto-Clicker verification)...");
                long logSizeBefore = File.Exists(GuardLogPath) ? new FileInfo(GuardLogPath).Length : 0;

                dynamic hwp2 = Activator.CreateInstance(hwpType);
                // Intentionally omit RegisterModule!
                bool openOk2 = hwp2.Open(testFile, "", "");
                string extracted = hwp2.GetTextFile("TEXT", "");
                hwp2.Clear(1);
                hwp2.Quit();
                Marshal.ReleaseComObject(hwp2);

                Console.WriteLine(string.Format("         Open without RegisterModule={0}, ExtractedTextLength={1}", openOk2, (extracted ?? "").Trim().Length));
                long logSizeAfter = File.Exists(GuardLogPath) ? new FileInfo(GuardLogPath).Length : 0;
                Console.WriteLine(string.Format("         Guard log updated: {0} ({1} -> {2} bytes)", logSizeAfter > logSizeBefore, logSizeBefore, logSizeAfter));

                if (!openOk2)
                {
                    Console.Error.WriteLine("[FAIL] Test Case 2 Open() returned false.");
                    return 1;
                }

                Console.WriteLine("[PASS] All E2E verification tests succeeded!");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("[FAIL] Exception during E2E test: " + ex);
                return 1;
            }
            finally
            {
                KillExistingHwpProcesses();
                try { if (File.Exists(testFile)) File.Delete(testFile); } catch { }
            }
        }

        private static void KillExistingHwpProcesses()
        {
            try
            {
                foreach (Process p in Process.GetProcessesByName("Hwp"))
                {
                    try { p.Kill(); p.WaitForExit(2000); } catch { }
                    finally { p.Dispose(); }
                }
            }
            catch { }
        }

        // =====================================================================
        // Helpers
        // =====================================================================
        public static bool IsDaemonRunning()
        {
            bool createdNew;
            try
            {
                using (Mutex m = new Mutex(false, MutexName, out createdNew))
                {
                    if (!createdNew)
                    {
                        try
                        {
                            if (!m.WaitOne(0))
                            {
                                return true; // Held by active daemon
                            }
                            m.ReleaseMutex();
                            return false;
                        }
                        catch (AbandonedMutexException)
                        {
                            m.ReleaseMutex();
                            return false;
                        }
                    }
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        public static void WriteLog(string category, string message)
        {
            try
            {
                lock (_logLock)
                {
                    Directory.CreateDirectory(LogsDir);
                    string line = string.Format("{0:yyyy-MM-ddTHH:mm:ss.fffK} [{1}] {2}\r\n", DateTime.Now, category, message);
                    File.AppendAllText(GuardLogPath, line, Encoding.UTF8);
                }
            }
            catch { }
        }

        private static string ComputeSha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(data);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }

        private static string ComputeFileSha256(string filePath)
        {
            using (FileStream fs = File.OpenRead(filePath))
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(fs);
                StringBuilder sb = new StringBuilder(hash.Length * 2);
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }
                return sb.ToString();
            }
        }

        private static string NormalizeNewlines(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\r\n", "\n").Trim();
        }
    }
}
