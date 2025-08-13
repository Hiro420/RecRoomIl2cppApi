using System.Runtime.InteropServices;

namespace RecRoomApi;

public static class Win32Api
{
	[UnmanagedFunctionPointer(CallingConvention.StdCall)]
	public delegate uint ThreadStartRoutine();

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern IntPtr CreateThread(
		IntPtr lpThreadAttributes,
		uint dwStackSize,
		ThreadStartRoutine lpStartAddress,
		IntPtr lpParameter,
		uint dwCreationFlags,
		out uint lpThreadId
	);

	[DllImport("kernel32.dll", SetLastError = true)]
	public static extern bool CloseHandle(IntPtr hObject);

	[DllImport("kernel32.dll")]
	public static extern bool AllocConsole();

	[DllImport("kernel32.dll")]
	public static extern IntPtr GetModuleHandle(string lpModuleName);

	[StructLayout(LayoutKind.Sequential)]
	public struct MEMORY_BASIC_INFORMATION
	{
		public IntPtr BaseAddress;
		public IntPtr AllocationBase;
		public uint AllocationProtect;
		public IntPtr RegionSize;
		public uint State;
		public uint Protect;
		public uint Type;
	}

	[DllImport("kernel32.dll")]
	public static extern int VirtualQuery(
		IntPtr lpAddress,
		out MEMORY_BASIC_INFORMATION lpBuffer,
		int dwLength
	);
}