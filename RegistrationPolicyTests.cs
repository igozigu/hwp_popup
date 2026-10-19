using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Win32;

namespace AsideHwpGuard
{
    // Safe tests: only a random HKCU test branch and temporary files are changed.
    // No install, real HWP module keys, daemon, AGENTS.md or COM calls are used.
    internal static class RegistrationPolicyTests
    {
        private static int _assertions;

        public static int Main()
        {
            string runId = Guid.NewGuid().ToString("N");
            string testBranch = @"Software\AsideHwpGuard\RegressionTests\" + runId;
            string tempDirectory = Path.Combine(Path.GetTempPath(), "AsideHwpGuard-tests-" + runId);
            Directory.CreateDirectory(tempDirectory);
            string modulePath = Path.Combine(tempDirectory, "guard.dll");
            string foreignPath = Path.Combine(tempDirectory, "foreign.dll");
            File.WriteAllBytes(modulePath, new byte[] { 1, 2, 3 });
            File.WriteAllBytes(foreignPath, new byte[] { 4, 5, 6 });
            RegistryView[] views = Environment.Is64BitOperatingSystem
                ? new RegistryView[] { RegistryView.Registry64, RegistryView.Registry32 }
                : new RegistryView[] { RegistryView.Registry32 };
            try
            {
                foreach (RegistryView view in views)
                {
                    using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                    using (RegistryKey key = root.CreateSubKey(testBranch))
                    {
                        TestFreshInstall(key, modulePath);
                        TestPreserveOtherTools(key, modulePath, foreignPath);
                        TestOwnedRepairAndRelocation(key, modulePath, tempDirectory);
                    }
                    Console.WriteLine("PASS registry ownership and relocation: " + view);
                }
                Assert(Program.ShouldScanDesktop("Default"), "default desktop is supported");
                Assert(Program.ShouldScanDesktop("exebox-example"), "existing sandbox desktop is supported");
                Assert(!Program.ShouldScanDesktop("AutoPdf-" + runId), "auto_pdf desktop is excluded");
                Assert(!Program.ShouldScanDesktop("autopdf-" + runId), "auto_pdf exclusion ignores case");
                Assert(!Program.ShouldScanDesktop(null) && !Program.ShouldScanDesktop(""), "unnamed desktops are excluded");
                Assert(Program.AgentsGuardBlock.Contains("RegisterModule(\"FilePathCheckDLL\", \"" + Program.GuardModuleKey + "\")"), "agent instructions use guard-owned registration");
                Assert(Program.IsManagedExecutablePath(Program.InstalledPrimaryExePath), "owned primary executable is recognized");
                Assert(Program.IsManagedExecutablePath(Program.InstalledAliasExePath), "owned alias executable is recognized");
                Assert(!Program.IsManagedExecutablePath(Path.Combine(tempDirectory, "hwp_popup.exe")), "same filename outside install directory is excluded");
                Assert(!Program.IsManagedExecutablePath(Program.InstalledPrimaryExePath + ".other.exe"), "path prefix is not executable identity");
                Assert(!Program.IsManagedExecutablePath("hwp_popup.exe"), "relative process identity is rejected");
                Assert(Program.IsDaemonCommandLine("\"C:\\a b\\hwp_popup.exe\" --daemon"), "quoted daemon command is recognized");
                Assert(Program.IsDaemonCommandLine("\"C:\\a b\\hwp_popup.exe\" --daemon-notify"), "notify daemon command is recognized");
                Assert(!Program.IsDaemonCommandLine("\"C:\\ --daemon\\hwp_popup.exe\" --status"), "daemon text inside path is not a daemon argument");
                Assert(!Program.IsDaemonCommandLine("hwp_popup.exe --daemon-other"), "mode prefix is not daemon identity");
                Assert(!Program.IsDaemonCommandLine("hwp_popup.exe --background"), "installer process is not stopped as daemon");
                Assert(!Program.IsDaemonCommandLine("hwp_popup.exe") && !Program.IsDaemonCommandLine(null), "absent daemon mode is rejected");
                Console.WriteLine("PASS " + _assertions + " assertions; no HWP/COM/production registry or daemon operations.");
                return 0;
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine("FAIL " + exception);
                return 1;
            }
            finally
            {
                foreach (RegistryView view in views)
                {
                    using (RegistryKey root = RegistryKey.OpenBaseKey(RegistryHive.CurrentUser, view))
                        root.DeleteSubKeyTree(testBranch, false);
                }
                // Delete only the exact files created by this test; no recursive
                // filesystem deletion is needed, even if an unexpected file appears.
                File.Delete(modulePath);
                File.Delete(foreignPath);
                File.Delete(Path.Combine(tempDirectory, "relocated-guard.dll"));
                Directory.Delete(tempDirectory, false);
            }
        }

        private static void TestFreshInstall(RegistryKey key, string modulePath)
        {
            foreach (string name in key.GetValueNames()) key.DeleteValue(name);
            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 7, "fresh install creates one owned key and six absent aliases");
            AssertEqual(key.GetValue(Program.GuardModuleKey), modulePath, "fresh guard-owned key");
            foreach (string alias in Program.CompatibilityModuleKeys)
                AssertEqual(key.GetValue(alias), modulePath, "fresh compatibility alias " + alias);
            Assert(key.GetValue("AsideHwpSetup_v1") == null, "auto_pdf legacy alias is never created");
            Assert(key.GetValue("AutoPdf_FilePathChecker_v1") == null, "auto_pdf dedicated key is never created");
            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 0, "repeated healthy recovery is idempotent");
        }

        private static void TestPreserveOtherTools(RegistryKey key, string modulePath, string foreignPath)
        {
            Dictionary<string, object> preserved = new Dictionary<string, object>();
            preserved.Add("AsideHwpSetup_v1", foreignPath);
            preserved.Add("AutoPdf_FilePathChecker_v1", foreignPath);
            preserved.Add("UnknownToolBroken", @"C:\missing\foreign.dll");
            preserved.Add("UnknownToolTemp", @"C:\Temp\_MEIexample\foreign.dll");
            preserved.Add("UnknownToolNumeric", 42);
            preserved.Add("FilePathCheckerModuleExample", foreignPath);
            preserved.Add("FilePathCheckerModule", @"C:\missing\shared.dll");
            preserved.Add("FilePathCheckDLL", @"relative\module.dll");
            preserved.Add("FilePathCheckDLLModule", "");
            preserved.Add("SecurityModule", 43);
            preserved.Add("Automation", @"%LOCALAPPDATA%\another-tool\module.dll");
            foreach (KeyValuePair<string, object> pair in preserved)
                key.SetValue(pair.Key, pair.Value, pair.Value is int ? RegistryValueKind.DWord : RegistryValueKind.String);
            key.SetValue("Automation", preserved["Automation"], RegistryValueKind.ExpandString);

            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 0, "recovery preserves every foreign/shared value");
            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 0, "periodic recovery preserves them again");
            foreach (KeyValuePair<string, object> pair in preserved)
                AssertEqual(key.GetValue(pair.Key, null, RegistryValueOptions.DoNotExpandEnvironmentNames), pair.Value, "preserve " + pair.Key);
            Assert(key.GetValueKind("SecurityModule") == RegistryValueKind.DWord, "preserve malformed foreign value kind");
            Assert(key.GetValueKind("Automation") == RegistryValueKind.ExpandString, "preserve expandable foreign value kind");

            // Another application loses its DLL after installation: do not steal its key.
            File.Delete(foreignPath);
            Program.ApplyModuleRegistrations(key, modulePath);
            AssertEqual(key.GetValue("AsideHwpSetup_v1"), foreignPath, "preserve missing legacy owner DLL");
            AssertEqual(key.GetValue("AutoPdf_FilePathChecker_v1"), foreignPath, "preserve missing dedicated owner DLL");
            File.WriteAllBytes(foreignPath, new byte[] { 4, 5, 6 });
        }

        private static void TestOwnedRepairAndRelocation(RegistryKey key, string modulePath, string tempDirectory)
        {
            key.SetValue(Program.GuardModuleKey, @"C:\old-pc\module.dll");
            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 1, "stale owned path is repaired");
            AssertEqual(key.GetValue(Program.GuardModuleKey), modulePath, "repaired owned path");
            key.SetValue(Program.GuardModuleKey, 44, RegistryValueKind.DWord);
            Assert(Program.ApplyModuleRegistrations(key, modulePath) == 1, "wrong owned value kind is repaired");
            Assert(key.GetValueKind(Program.GuardModuleKey) == RegistryValueKind.String, "owned value is REG_SZ");

            string movedPath = Path.Combine(tempDirectory, "relocated-guard.dll");
            File.Copy(modulePath, movedPath, true);
            Assert(Program.ApplyModuleRegistrations(key, movedPath) == 1, "guard relocation changes only owned key");
            AssertEqual(key.GetValue(Program.GuardModuleKey), movedPath, "owned key follows new PC/path");
            AssertEqual(key.GetValue("FilePathCheckerModule"), @"C:\missing\shared.dll", "relocation preserves broken shared alias");

            bool rejected = false;
            try { Program.ApplyModuleRegistrations(key, Path.Combine(tempDirectory, "nonexistent.dll")); }
            catch (FileNotFoundException) { rejected = true; }
            Assert(rejected, "missing guard DLL is rejected");
            AssertEqual(key.GetValue(Program.GuardModuleKey), movedPath, "failed validation makes no registration changes");
        }

        private static void AssertEqual(object actual, object expected, string message)
        {
            Assert(object.Equals(actual, expected), message + "; expected=" + expected + "; actual=" + actual);
        }

        private static void Assert(bool condition, string message)
        {
            _assertions++;
            if (!condition) throw new InvalidOperationException(message);
        }
    }
}
