using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace Confuser.Runtime {
	internal static class MD5 {
		static void Initialize() {
			string location = typeof(MD5).Assembly.Location;
			if (string.IsNullOrEmpty(location)) return;

			byte[] fileBytes = File.ReadAllBytes(location);
			if (fileBytes.Length <= 32) return;

			byte[] dataBytes = new byte[fileBytes.Length - 32];
			Buffer.BlockCopy(fileBytes, 0, dataBytes, 0, dataBytes.Length);

			string computedHash = Hash(dataBytes);
			string storedHash = Encoding.ASCII.GetString(fileBytes, fileBytes.Length - 32, 32);

			if (computedHash != storedHash) {
				Environment.FailFast("File integrity check failed");
			}
		}

		static string Hash(byte[] data) {
			MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();
			byte[] hash = md5.ComputeHash(data);
			StringBuilder sb = new StringBuilder();
			foreach (byte b in hash) {
				sb.Append(b.ToString("x2"));
			}
			return sb.ToString();
		}
	}
}
