using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace NanocoreDecoder.Utilities
{
    class ResourceHelper
    {
        
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string fileName);

        [DllImport("kernel32.dll")]
        public static extern IntPtr FindResourceEx(IntPtr intptr_0, int int_0, int int_1, short short_0);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadResource(IntPtr intptr_0, IntPtr intptr_1);

        [DllImport("kernel32.dll")]
        public static extern IntPtr LockResource(IntPtr intptr_0);

        [DllImport("kernel32.dll")]
        public static extern int SizeofResource(IntPtr intptr_0, IntPtr intptr_1);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool FreeLibrary([In] IntPtr hModule);

        /// <summary>
        /// Read unmanaged resource 
        /// </summary>
        /// <param name="fname"></param>
        /// <returns></returns>
        public  static byte[] ReadWin32Res(string fname)
        {
            IntPtr a1 = LoadLibrary(fname);

            IntPtr ptr = FindResourceEx(a1, 10, 1, 0);
            if (ptr == IntPtr.Zero)
            {
                FreeLibrary(a1);
                return null;
            }
            IntPtr ptr2 = LoadResource(a1, ptr);
            if (ptr2 == IntPtr.Zero)
            {
                FreeLibrary(a1);
                return null;
            }
            int num = SizeofResource(a1, ptr);
            if (num == 0)
            {
                FreeLibrary(a1);
                return null;
            }
            IntPtr source = LockResource(ptr2);
            if (source == IntPtr.Zero)
            {
                FreeLibrary(a1);
                return null;
            }
            byte[] destination = new byte[(num - 1) + 1];
            Marshal.Copy(source, destination, 0, destination.Length);
            FreeLibrary(a1);
            return destination;
        }


        /// <summary>
        /// Read Managed resource  
        /// </summary>
        /// <param name="assm"></param>
        /// <param name="name"></param>
        /// <returns></returns>
        public static byte[] GetDotnetResourceFromAssembly(Assembly assm, string name)
        {
            Stream manifestResourceStream = assm.GetManifestResourceStream(name);
            if (manifestResourceStream == null)
            {
                return null;
            }
            byte[] buffer = new byte[(((int)manifestResourceStream.Length) - 1) + 1];
            manifestResourceStream.Read(buffer, 0, buffer.Length);
            manifestResourceStream.Dispose();
            return buffer;
        }

    }
}
