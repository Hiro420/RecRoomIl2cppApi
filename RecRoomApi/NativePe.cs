using System;
using System.IO;
using System.Runtime.InteropServices;

namespace RecRoomApi
{
	internal static class NativePe
	{
		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_DOS_HEADER
		{
			public ushort e_magic;      // 'MZ' = 0x5A4D
			public ushort e_cblp; public ushort e_cp; public ushort e_crlc; public ushort e_cparhdr;
			public ushort e_minalloc; public ushort e_maxalloc; public ushort e_ss; public ushort e_sp;
			public ushort e_csum; public ushort e_ip; public ushort e_cs; public ushort e_lfarlc;
			public ushort e_ovno;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public ushort[] e_res1;
			public ushort e_oemid; public ushort e_oeminfo;
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public ushort[] e_res2;
			public int e_lfanew;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_FILE_HEADER
		{
			public ushort Machine;
			public ushort NumberOfSections;
			public uint TimeDateStamp;
			public uint PointerToSymbolTable;
			public uint NumberOfSymbols;
			public ushort SizeOfOptionalHeader;
			public ushort Characteristics;
		}

		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_DATA_DIRECTORY
		{
			public uint VirtualAddress;
			public uint Size;
		}

		// PE32+
		[StructLayout(LayoutKind.Sequential)]
		private struct IMAGE_OPTIONAL_HEADER64
		{
			public ushort Magic;                 // 0x20B
			public byte MajorLinkerVersion;
			public byte MinorLinkerVersion;
			public uint SizeOfCode;
			public uint SizeOfInitializedData;
			public uint SizeOfUninitializedData;
			public uint AddressOfEntryPoint;
			public uint BaseOfCode;
			public ulong ImageBase;
			public uint SectionAlignment;
			public uint FileAlignment;
			public ushort MajorOperatingSystemVersion;
			public ushort MinorOperatingSystemVersion;
			public ushort MajorImageVersion;
			public ushort MinorImageVersion;
			public ushort MajorSubsystemVersion;
			public ushort MinorSubsystemVersion;
			public uint Win32VersionValue;
			public uint SizeOfImage;
			public uint SizeOfHeaders;
			public uint CheckSum;
			public ushort Subsystem;
			public ushort DllCharacteristics;
			public ulong SizeOfStackReserve;
			public ulong SizeOfStackCommit;
			public ulong SizeOfHeapReserve;
			public ulong SizeOfHeapCommit;
			public uint LoaderFlags;
			public uint NumberOfRvaAndSizes;

			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
			public IMAGE_DATA_DIRECTORY[] DataDirectory;
		}

		[StructLayout(LayoutKind.Sequential, Pack = 1)]
		private struct IMAGE_SECTION_HEADER
		{
			[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
			public byte[] Name;
			public uint VirtualSize;
			public uint VirtualAddress;
			public uint SizeOfRawData;
			public uint PointerToRawData;
			public uint PointerToRelocations;
			public uint PointerToLinenumbers;
			public ushort NumberOfRelocations;
			public ushort NumberOfLinenumbers;
			public uint Characteristics;
		}

		private static T PtrToStruct<T>(IntPtr p) where T : struct
			=> Marshal.PtrToStructure<T>(p)!;

		private static IntPtr Add(IntPtr p, int offset)
			=> IntPtr.Add(p, offset);

		/// <summary>
		/// Rebuilds a mapped image in memory into file layout bytes and (optionally) writes them to disk.
		/// </summary>
		public static byte[] DumpMappedImageToFileBytes(IntPtr moduleBase, string? outPath = null)
		{
			if (moduleBase == IntPtr.Zero) throw new ArgumentNullException(nameof(moduleBase));

			var dos = PtrToStruct<IMAGE_DOS_HEADER>(moduleBase);
			if (dos.e_magic != 0x5A4D) throw new InvalidDataException("Not an MZ image.");

			var nt = Add(moduleBase, dos.e_lfanew);
			uint peSig = (uint)Marshal.ReadInt32(nt);
			if (peSig != 0x4550) throw new InvalidDataException("Bad PE signature.");

			var fileHdrPtr = Add(nt, 4);
			var fileHdr = PtrToStruct<IMAGE_FILE_HEADER>(fileHdrPtr);

			var optHdrPtr = Add(fileHdrPtr, Marshal.SizeOf<IMAGE_FILE_HEADER>());
			var optHdr = PtrToStruct<IMAGE_OPTIONAL_HEADER64>(optHdrPtr);
			if (optHdr.Magic != 0x20B) throw new NotSupportedException("Only PE32+ (x64) supported.");

			// Section table pointer
			var secPtr = Add(optHdrPtr, fileHdr.SizeOfOptionalHeader);

			// Read sections, compute final file size
			uint fileSize = optHdr.SizeOfHeaders;
			int secSize = Marshal.SizeOf<IMAGE_SECTION_HEADER>();
			var sections = new IMAGE_SECTION_HEADER[fileHdr.NumberOfSections];

			for (int i = 0; i < sections.Length; i++)
			{
				sections[i] = PtrToStruct<IMAGE_SECTION_HEADER>(Add(secPtr, i * secSize));
				uint end = sections[i].PointerToRawData + Math.Max(sections[i].SizeOfRawData, sections[i].VirtualSize);
				if (end > fileSize) fileSize = end;
			}

			// Build file image
			var fileImage = new byte[fileSize];

			// Copy headers
			Marshal.Copy(moduleBase, fileImage, 0, (int)optHdr.SizeOfHeaders);

			// Copy each section from VA -> file raw
			for (int i = 0; i < sections.Length; i++)
			{
				ref var sh = ref sections[i];

				if (sh.SizeOfRawData == 0 && sh.VirtualSize == 0) continue;

				int toCopy = (int)Math.Min(sh.SizeOfRawData != 0 ? sh.SizeOfRawData : sh.VirtualSize, sh.VirtualSize);
				if (toCopy <= 0) continue;

				IntPtr src = Add(moduleBase, (int)sh.VirtualAddress);
				int dst = (int)sh.PointerToRawData;

				// Clamp if something is weird
				if (dst < 0 || dst + toCopy > fileImage.Length) toCopy = Math.Max(0, fileImage.Length - dst);
				if (toCopy <= 0) continue;

				var tmp = new byte[toCopy];
				Marshal.Copy(src, tmp, 0, toCopy);
				Buffer.BlockCopy(tmp, 0, fileImage, dst, toCopy);
			}

			if (!string.IsNullOrEmpty(outPath))
			{
				File.WriteAllBytes(outPath, fileImage);
			}

			return fileImage;
		}
	}
}
