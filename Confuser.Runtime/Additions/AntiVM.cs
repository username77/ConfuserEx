using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace Confuser.Runtime {
	internal static class AntiVM {
		[DllImport("kernel32.dll", EntryPoint = "GetModuleHandle")]
		static extern IntPtr GetModuleHandleInternal(string x);
		[DllImport("kernel32.dll", EntryPoint = "GetProcAddress")]
		static extern IntPtr GetProcAddressInternal(IntPtr a, string b);
		[DllImport("kernel32.dll", CharSet = CharSet.Auto, EntryPoint = "GetFileAttributes", SetLastError = true)]
		static extern uint GetFileAttributesInternal(string d);

		static void Initialize() {
			if (DetectVM()) {
				Environment.FailFast("Virtual machine detected");
			}
		}

		static bool DetectVM() {
			// VirtualBox checks
			if (ReadReg("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VBOX"))
				return true;
			if (ReadReg("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("VBOX"))
				return true;
			if (ReadReg("HARDWARE\\Description\\System", "VideoBiosVersion").ToUpper().Contains("VIRTUALBOX"))
				return true;
			if (ReadReg("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "") == "noValueButYesKey")
				return true;
			if (GetFileAttributesInternal("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") != 0xFFFFFFFFu)
				return true;

			// VMware checks
			if (ReadReg("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("VMWARE"))
				return true;
			if (ReadReg("SOFTWARE\\VMware, Inc.\\VMware Tools", "") == "noValueButYesKey")
				return true;
			if (ReadReg("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0").ToUpper().Contains("VMWARE"))
				return true;
			if (GetFileAttributesInternal("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") != 0xFFFFFFFFu)
				return true;
			if (GetFileAttributesInternal("C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") != 0xFFFFFFFFu)
				return true;

			// Wine check
			if (GetProcAddressInternal(GetModuleHandleInternal("kernel32.dll"), "wine_get_unix_file_name") != IntPtr.Zero)
				return true;

			// QEMU checks
			if (ReadReg("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("QEMU"))
				return true;
			if (ReadReg("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("QEMU"))
				return true;

			return false;
		}

		static string ReadReg(string path, string valueName) {
			try {
				RegistryKey key = Registry.LocalMachine.OpenSubKey(path, false);
				if (key == null) return "noKey";
				object value = key.GetValue(valueName, "noValueButYesKey");
				if (value == null) return "noValueButYesKey";
				return value.ToString();
			}
			catch {
				return "noKey";
			}
		}
	}
}
