using System;
using System.Collections.Generic;
using System.Linq;
using Iced.Intel;

namespace RecRoomApi;

public static class PatternFinder
{
	public sealed record Hit(ulong LeaRdxAddr, ulong MovStoreAddr);

	public static List<Hit> Find(List<Instruction> ins)
	{
		var hits = new List<Hit>();

		// hopefully wont need to uncomment this
		var firstLea = ins.First(i => i.Mnemonic == Mnemonic.Lea).MemoryDisplacement32;
		var il2cppInit = ins
			.SkipWhile(i => i.Mnemonic != Mnemonic.Call)
			.Skip(1)
			.First(i => i.Mnemonic == Mnemonic.Mov)
			.MemoryDisplacement32;
		hits.Add(new Hit(firstLea, il2cppInit));

		// Main pattern scan
		for (int i = 0; i < ins.Count; i++)
		{
			ulong leaRdxAddr;

			// Two supported entry patterns:
			// 1) lea rdx, [...]
			// 2) mov rcx, [...] ; lea rdx, [...]
			int k; // index of candidate instruction after LEA

			if (IsLeaRdxFromMem(ins[i], out leaRdxAddr))
			{
				// Pattern: lea rdx, [...]
				k = i + 1;
			}
			else if (i + 1 < ins.Count &&
					 IsMovRcxFromMem(ins[i], out _) &&
					 IsLeaRdxFromMem(ins[i + 1], out leaRdxAddr))
			{
				// Pattern: mov rcx, [...] ; lea rdx, [...]
				k = i + 2;
			}
			else
			{
				continue;
			}

			if (k >= ins.Count)
				continue;

			// Optional instruction(s) between LEA and CALL
			if (IsOptionalBetweenLeaAndCall(ins[k]))
				k++;

			if (k + 1 >= ins.Count)
				continue;

			if (!IsCall(ins[k], out var _))
				continue;

			if (!IsMovStoreFromRax(ins[k + 1], out var movStoreAddr))
				continue;

			hits.Add(new Hit(leaRdxAddr, movStoreAddr));
		}

		return hits;
	}

	private static bool IsMovRcxFromMem(in Instruction instr, out ulong absAddr)
	{
		absAddr = 0;
		if (instr.Mnemonic != Mnemonic.Mov) return false;
		if (instr.Op0Kind != OpKind.Register || instr.Op0Register != Register.RCX) return false;
		if (instr.Op1Kind != OpKind.Memory) return false;
		return TryResolveMemAbsolute(instr, out absAddr);
	}

	private static bool IsLeaRdxFromMem(in Instruction instr, out ulong absAddr)
	{
		absAddr = 0;
		if (instr.Mnemonic != Mnemonic.Lea) return false;
		if (instr.Op0Kind != OpKind.Register || instr.Op0Register != Register.RDX) return false;
		if (instr.Op1Kind != OpKind.Memory) return false;
		return TryResolveMemAbsolute(instr, out absAddr);
	}

	private static bool IsOptionalBetweenLeaAndCall(in Instruction instr)
	{
		if (instr.Mnemonic == Mnemonic.Xor &&
			instr.Op0Kind == OpKind.Register && instr.Op0Register == Register.R8D &&
			instr.Op1Kind == OpKind.Register && instr.Op1Register == Register.R8D)
			return true;

		return instr.FlowControl == FlowControl.Next;
	}

	private static bool IsCall(in Instruction instr, out ulong target)
	{
		target = 0;
		if (instr.Mnemonic != Mnemonic.Call) return false;

		switch (instr.Op0Kind)
		{
			case OpKind.NearBranch16:
			case OpKind.NearBranch32:
			case OpKind.NearBranch64:
				target = instr.NearBranchTarget;
				return true;

			case OpKind.FarBranch16:
			case OpKind.FarBranch32:
			case OpKind.Memory:
			case OpKind.Register:
				return true;

			default:
				return false;
		}
	}

	private static bool IsMovStoreFromRax(in Instruction instr, out ulong absAddr)
	{
		absAddr = 0;
		if (instr.Mnemonic != Mnemonic.Mov) return false;
		if (instr.Op0Kind != OpKind.Memory) return false;
		if (instr.Op1Kind != OpKind.Register || instr.Op1Register != Register.RAX) return false;
		return TryResolveMemAbsolute(instr, out absAddr);
	}

	private static bool TryResolveMemAbsolute(in Instruction instr, out ulong absAddr)
	{
		absAddr = 0;

		bool hasMem =
			instr.Op0Kind == OpKind.Memory ||
			instr.Op1Kind == OpKind.Memory ||
			(instr.OpCount > 2 && instr.GetOpKind(2) == OpKind.Memory);

		if (!hasMem) return false;

		if (instr.IsIPRelativeMemoryOperand)
		{
			absAddr = instr.IPRelativeMemoryAddress;
			return true;
		}

		if (instr.MemoryBase == Register.None && instr.MemoryIndex == Register.None)
		{
			absAddr = instr.MemoryDisplacement64;
			return true;
		}

		return false;
	}
}
