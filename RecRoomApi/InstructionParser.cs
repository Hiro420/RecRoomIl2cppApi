using Iced.Intel;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace RecRoomApi;

internal class InstructionParser
{
	public static List<Instruction> GetInstructions(Il2cppFunctionAddressData address, ByteArrayCodeReader codeReader, bool? isDebug = false)
	{
		codeReader.Position = int.Parse(address.Offset, System.Globalization.NumberStyles.HexNumber);
		Iced.Intel.Decoder decoder = Iced.Intel.Decoder.Create(IntPtr.Size * 8, codeReader);
		decoder.IP = ulong.Parse(address.RVA, System.Globalization.NumberStyles.HexNumber);

		List<Instruction> instructions = new List<Instruction>();
		bool debug = isDebug ?? false;
		bool restarted = false;

		if (debug) Console.WriteLine("/*");

		while (true)
		{
			Instruction instruction = decoder.Decode();
			string instructionStr = instruction.ToString();

			if (debug && restarted)
				Console.WriteLine($"\t{instruction.IP32:X} | {instructionStr}");

			// If we encounter `jne` and haven't restarted yet
			if (!restarted && instruction.Mnemonic == Mnemonic.Jne)
			{
				restarted = true;
				ulong targetRva = instruction.NearBranchTarget;

				PEHeader.SectionTable? il2cpp_section = null;
				foreach (PEHeader.SectionTable section in MainApp.sectionTables)
				{
					uint sectionStart = section.virtualAddr;
					uint sectionEnd = sectionStart + section.virtualSize;

					if (targetRva >= sectionStart && targetRva < sectionEnd)
					{
						il2cpp_section = section;
					}
				}

				// Update decoder and code reader to the new RVA
				int newOffset = (int)(il2cpp_section!.Value.ptrToRawData + (targetRva - il2cpp_section.Value.virtualAddr));
				codeReader.Position = newOffset;

				decoder = Iced.Intel.Decoder.Create(IntPtr.Size * 8, codeReader);
				decoder.IP = targetRva;

				instructions.Clear();
				continue;
			}

			instructions.Add(instruction);

			if (instruction.Mnemonic == Mnemonic.Ret)
				break;
		}

		if (debug) Console.WriteLine("*/");

		return instructions;
	}

	public static List<uint> ParseCalls(List<Instruction> instructions)
	{
		List<uint> ret = new List<uint>();
		ulong firstCall = 0;
		ulong RDXValue = 0;

		// get the RVA of the first Call instruction
		foreach (Instruction instruction in instructions)
		{
			if (instruction.Mnemonic == Mnemonic.Call)
			{
				switch (instruction.Op0Kind)
				{
					case OpKind.NearBranch32:
					case OpKind.NearBranch64:
						firstCall = instruction.NearBranchTarget;
						break;
					case OpKind.FarBranch32:
						firstCall = instruction.FarBranch32;
						break;
				}
			}
			if (firstCall != 0)
				break;
		}

		// now we can finally track the rdx register (2nd param)
		foreach (Instruction instruction in instructions)
		{
			switch (instruction.Mnemonic)
			{
				case Mnemonic.Lea:
				case Mnemonic.Mov:
					if (instruction.Op0Kind == OpKind.Register && instruction.Op1Kind == OpKind.Memory)
					{
						if (instruction.Op0Register == Register.RDX)
						{
							RDXValue = instruction.MemoryDisplacement64;
						}
					}
					break;
				case Mnemonic.Call:
					ulong callAddr = instruction.NearBranchTarget;
					if (callAddr != firstCall)
						continue;
					ret.Add(Convert.ToUInt32(RDXValue));
					//Console.WriteLine(RDXValue.ToString("X"));
					RDXValue = 0; // clear for safety
					break;

			}
		}

		return ret;
	}
}

public class Il2cppFunctionAddressData
{
	public string RVA { get; set; } = "";
	public string Offset { get; set; } = "";
	public string VA { get; set; } = "";

	public Il2cppFunctionAddressData(uint _RVA)
	{
		PEHeader.SectionTable? il2cpp_section = null;
		foreach (PEHeader.SectionTable section in MainApp.sectionTables)
		{
			uint sectionStart = section.virtualAddr;
			uint sectionEnd = sectionStart + section.virtualSize;

			if (_RVA >= sectionStart && _RVA < sectionEnd)
			{
				il2cpp_section = section;
			}
		}
		if (il2cpp_section == null)
		{
			Console.WriteLine($"Couldnt find section for method at RVA 0x{_RVA:X}");
			Environment.Exit(0);
			return;
		}
		RVA = _RVA.ToString("X");
		Offset = (il2cpp_section.Value.ptrToRawData + (_RVA - il2cpp_section.Value.virtualAddr)).ToString("X");
		VA = (MainApp.BaseAddress + _RVA).ToString("X");
	}
}
