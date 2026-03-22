using System;
using System.Diagnostics;

namespace Confuser.Runtime {
	internal static class AntiDnspy {
		static void Initialize() {
			string[] dnSpyNames = new string[] { "dnSpy", "dnspy" };
			Process[] procs = Process.GetProcesses();
			for (int i = 0; i < procs.Length; i++) {
				try {
					string name = procs[i].ProcessName;
					for (int j = 0; j < dnSpyNames.Length; j++) {
						if (name == dnSpyNames[j]) {
							Environment.FailFast(null);
						}
					}
				}
				catch { }
			}
		}
	}
}
