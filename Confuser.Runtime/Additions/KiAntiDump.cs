using System;
using System.Runtime.InteropServices;

namespace Confuser.Runtime {
	internal static class KiAntiDump {
		[DllImport("kernel32.dll")]
		static extern unsafe bool VirtualProtect(byte* lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

		static unsafe void Initialize() {
			uint old;

			var module = typeof(KiAntiDump).Module;
			var bas = (byte*)Marshal.GetHINSTANCE(module);

			var ptr = bas + 0x3c;
			byte* ptr2;
			ptr = ptr2 = bas + *(uint*)ptr;
			ptr += 0x6;

			var sectNum = *(ushort*)ptr;
			ptr += 14;

			var optSize = *(ushort*)ptr;
			ptr = ptr2 = ptr + 0x4 + optSize;

			// Prevents dumping by tools like MegaDumper
			VirtualProtect(ptr - 16, 8, 0x40, out old);
			*(uint*)(ptr - 12) = 0;
			var mdDir = bas + *(uint*)(ptr - 16);
			*(uint*)(ptr - 16) = 0;

			// Erase MetaData DataDir
			VirtualProtect(mdDir, 0x48, 0x40, out old);
			var mdHdr = bas + *(uint*)(mdDir + 8);
			*(uint*)mdDir = 0;
			*((uint*)mdDir + 1) = 0;
			*((uint*)mdDir + 2) = 0;
			*((uint*)mdDir + 3) = 0;

			// Erase BSJB signature
			VirtualProtect(mdHdr, 4, 0x40, out old);
			*(uint*)mdHdr = 0;

			// Erase section names
			for (int i = 0; i < sectNum; i++) {
				VirtualProtect(ptr, 8, 0x40, out old);
				Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
				ptr += 0x28;
			}
		}
	}
}
