using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Confuser.Runtime {
	internal static class KiAntiDebug {
		[DllImport("kernel32.dll", EntryPoint = "CloseHandle", ExactSpelling = true)]
		static extern int CloseHandleInternal(IntPtr handle);

		[DllImport("kernel32.dll", EntryPoint = "OpenProcess", ExactSpelling = true)]
		static extern IntPtr OpenProcessInternal(uint access, int inherit, uint pid);

		[DllImport("kernel32.dll", EntryPoint = "GetCurrentProcessId", ExactSpelling = true)]
		static extern uint GetCurrentPidInternal();

		[DllImport("kernel32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress", ExactSpelling = true)]
		static extern IsDebuggerPresentDelegate GetIsDebuggerPresent(IntPtr module, string name);

		[DllImport("kernel32.dll", CharSet = CharSet.Auto, EntryPoint = "LoadLibrary", SetLastError = true)]
		static extern IntPtr LoadLibraryInternal(string name);

		[DllImport("kernel32.dll", CharSet = CharSet.Ansi, EntryPoint = "GetProcAddress", ExactSpelling = true)]
		static extern CheckRemoteDebuggerDelegate GetCheckRemoteDebugger(IntPtr module, string name);

		static void Initialize() {
			if (Detected()) {
				Environment.FailFast("Debugger detected");
			}
		}

		static bool Detected() {
			try {
				if (Debugger.IsAttached) return true;

				IntPtr kernel32 = LoadLibraryInternal("kernel32.dll");
				IsDebuggerPresentDelegate isDbg = GetIsDebuggerPresent(kernel32, "IsDebuggerPresent");
				if (isDbg != null && isDbg() != 0) return true;

				uint pid = GetCurrentPidInternal();
				IntPtr hProcess = OpenProcessInternal(1024u, 0, pid);

				if (hProcess != IntPtr.Zero) {
					try {
						CheckRemoteDebuggerDelegate checkRemote = GetCheckRemoteDebugger(kernel32, "CheckRemoteDebuggerPresent");
						if (checkRemote != null) {
							int debuggerPresent = 0;
							if (checkRemote(hProcess, ref debuggerPresent) != 0 && debuggerPresent != 0)
								return true;
						}
					}
					finally {
						CloseHandleInternal(hProcess);
					}
				}

				try {
					CloseHandleInternal(new IntPtr(0x12345678));
				}
				catch {
					return true;
				}
			}
			catch { }
			return false;
		}

		delegate int IsDebuggerPresentDelegate();
		delegate int CheckRemoteDebuggerDelegate(IntPtr hProcess, ref int debuggerPresent);
	}
}
