using Iced.Intel;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static RecRoomApi.Win32Api;
using static RecRoomApi.PatternFinder;
using System.Text;
using System.Transactions;

namespace RecRoomApi;

public class MainApp
{
	public static IntPtr ModuleHandle = IntPtr.Zero;
	public static IntPtr UnityPlayerHandle = IntPtr.Zero;
	public static byte[] moduleBytes = [];
	public static byte[] UnityPlayerBytes = [];
	public static readonly string Pattern = "48 83 EC ?? E8 ?? ?? ?? ?? 48 89 05";
	public static ulong BaseAddress = 0x0;
	public static List<PEHeader.SectionTable> sectionTables = new List<PEHeader.SectionTable>();

	private static uint RunThread()
	{
		Run();
		return 0;
	}

	private static unsafe void Run()
	{
		GCSettings.LatencyMode = GCLatencyMode.Batch;
		AllocConsole();
		while (ModuleHandle == IntPtr.Zero)
		{
			if (GetModuleHandle("GameAssembly.dll") != IntPtr.Zero)
			{
				ModuleHandle = GetModuleHandle("GameAssembly.dll");
				break;
			}

			Console.WriteLine("Waiting for GameAssembly.dll to load...");

			Thread.Sleep(2000);
		}
		Console.WriteLine($"GameAssembly loaded!");

		while (UnityPlayerHandle == IntPtr.Zero)
		{
			if (GetModuleHandle("UnityPlayer.dll") != IntPtr.Zero)
			{
				UnityPlayerHandle = GetModuleHandle("UnityPlayer.dll");
				break;
			}

			Console.WriteLine("Waiting for UnityPlayer.dll to load...");

			Thread.Sleep(2000);
		}
		Console.WriteLine($"UnityPlayer loaded!");

		string exepath = Process.GetCurrentProcess().MainModule!.FileName;

		//string unityOut = Path.Combine(Path.GetDirectoryName(exepath)!, "UnityPlayer_memdump.dll");
		UnityPlayerBytes = NativePe.DumpMappedImageToFileBytes(UnityPlayerHandle); // can also add unityOut argument to output the dll
		//Console.WriteLine($"[OK] UnityPlayer memory dump -> {unityOut} ({UnityPlayerBytes.Length:N0} bytes)");

		string dllpath = Path.Combine(Path.GetDirectoryName(exepath)!, "GameAssembly.dll");
		moduleBytes = File.ReadAllBytes(dllpath);

		//string upPath = Path.Combine(Path.GetDirectoryName(exepath)!, "UnityPlayer_dump.dll");
		//UnityPlayerBytes = File.ReadAllBytes(upPath);

		BinaryReader reader = new BinaryReader(new MemoryStream(UnityPlayerBytes));

		PEHeader.DosHeader dosHeader = Misc.GetDosHeader(reader);
		BaseAddress = Misc.GetOptionalHeader(dosHeader);
		reader.BaseStream.Position = 0;
		sectionTables = Misc.GetSections(dosHeader);

		uint initExportsOffset = ScanPattern(UnityPlayerBytes, Pattern); //Convert.ToUInt32(args[0], 16);
		uint RVA = Offset2RVA(initExportsOffset);
		//Console.WriteLine(RVA);
		var codeReader = new ByteArrayCodeReader(UnityPlayerBytes);
		List<Instruction> instructions = InstructionParser.GetInstructions(
			new Il2cppFunctionAddressData(RVA),
			new ByteArrayCodeReader(UnityPlayerBytes),
			false
		);

		StringBuilder sb = new StringBuilder();
		StringBuilder sb_frida = new StringBuilder();

		var hits = PatternFinder.Find(instructions);
		foreach (var h in hits)
		{
			var stringRVA = h.LeaRdxAddr;
			var qwordRVA = h.MovStoreAddr;

			ulong stringOffset = RVA2Offset(stringRVA);
			reader.BaseStream.Seek((long)stringOffset, SeekOrigin.Begin);
			string apiName = PEHeader.ReadCString(reader);

			//Console.WriteLine($"{apiName} at UnityPlayer + 0x{qwordRVA:X}");

			IntPtr apiVA = Marshal.ReadIntPtr(UnityPlayerHandle + (nint)qwordRVA);
			IntPtr apiRVA = (apiVA - ModuleHandle);

			string toLog = $"{apiName} -> 0x{apiRVA:X}";

			Console.WriteLine(toLog);
			sb.AppendLine(toLog);

			//Console.WriteLine(
			//	$"@{h.StartIndex:D6}: mov rcx,[{h.MovRcxAddr:X}] ; lea rdx,[{h.LeaRdxAddr:X}] ; call {h.CallTarget:X} ; mov [{h.MovStoreAddr:X}], rax");
		}

		File.WriteAllText("Il2CppApi.txt", sb.ToString());
	}

	static (byte[] patternBytes, bool[] mask) ParseX64dbgPattern(string pattern)
	{
		var parts = pattern.Split(' ', StringSplitOptions.RemoveEmptyEntries);
		var bytes = new byte[parts.Length];
		var mask = new bool[parts.Length]; // true = exact match, false = wildcard

		for (int i = 0; i < parts.Length; i++)
		{
			if (parts[i] == "?" || parts[i] == "??")
			{
				bytes[i] = 0;
				mask[i] = false;
			}
			else
			{
				bytes[i] = Convert.ToByte(parts[i], 16);
				mask[i] = true;
			}
		}

		return (bytes, mask);
	}

	static uint ScanPattern(byte[] code, string pattern)
	{
		var (patternBytes, mask) = ParseX64dbgPattern(pattern);

		for (int i = 0; i <= code.Length - patternBytes.Length; i++)
		{
			bool matched = true;
			for (int j = 0; j < patternBytes.Length; j++)
			{
				if (mask[j] && code[i + j] != patternBytes[j])
				{
					matched = false;
					break;
				}
			}

			if (matched)
				return (uint)i; // Return RVA
		}

		return 0; // Not found
	}

	public static uint Offset2RVA(uint fileOffset)
	{
		foreach (var section in MainApp.sectionTables)
		{
			uint sectionRawStart = section.ptrToRawData;
			uint sectionRawEnd = sectionRawStart + section.sizeOfRawData;

			if (fileOffset >= sectionRawStart && fileOffset < sectionRawEnd)
			{
				uint offsetInSection = fileOffset - section.ptrToRawData;
				return section.virtualAddr + offsetInSection;
			}
		}

		Console.WriteLine($"Could not find section for offset 0x{fileOffset:X}");
		Environment.Exit(1);
		return 0; // unreachable
	}

	public static ulong RVA2Offset(ulong rva)
	{
		foreach (var section in MainApp.sectionTables)
		{
			uint start = section.virtualAddr, end = start + section.virtualSize;
			if (rva >= start && rva < end)
				return section.ptrToRawData + (rva - section.virtualAddr);
		}
		return 0;
	}

	[UnmanagedCallersOnly(EntryPoint = "DllMain", CallConvs = [typeof(CallConvStdcall)])]
	public static bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved)
	{
		switch (fdwReason)
		{
			case 1:
				{
					IntPtr threadHandle = Win32Api.CreateThread(IntPtr.Zero, 0, RunThread, IntPtr.Zero, 0, out _);
					if (threadHandle != IntPtr.Zero)
						Win32Api.CloseHandle(threadHandle);
					break;
				}
		}

		return true;
	}
}