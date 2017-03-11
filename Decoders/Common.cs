using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.IO.Compression;

namespace NanocoreDecoder.Decoders
{
    class Common
    {



 


        private static ICryptoTransform DESDecryptor;


        private static List<object> objectlist = new List<object>();

        public static Dictionary<string, object> dictionary_1 = new Dictionary<string, object>(); //Dictionary holding the malware config


        public static Assembly SampleAssembly;//Our Nanocore sample
        public static Guid guid; //Guid of the Binary sample : used as KEY to decrypt the config
        private static string fname; //Sample full path




        [StructLayout(LayoutKind.Sequential)]
        public struct NanoStruct
        {
            public byte byte_0;
            public byte byte_1;
            public Guid guid_0;
            public object[] object_0;
        }


        public static Boolean Decoder(string filename)
        {

            fname = filename;

            //Load the assembly as reflection only, for security reasons
            SampleAssembly = Assembly.ReflectionOnlyLoadFrom(filename);

            //1) Try to read the config as an unmanaged resource (old Nanocore variants)
            byte[] buffer = Utilities.ResourceHelper.ReadWin32Res(filename);

            if (buffer == null)
            {
                //Otherwise read the managed resource "Data.bin"
                buffer = Utilities.ResourceHelper.GetDotnetResourceFromAssembly(SampleAssembly, "Data.bin");
            }
            

            if (buffer != null)
            {
                return decodefinal(buffer);
            }

            return false;
        }


        /// <summary>
        /// Perform the actual config decryption
        /// </summary>
        /// <param name="buf"></param>
        /// <returns></returns>
        private static Boolean decodefinal(byte[] buf)
        {
            bool ret = false;
            byte[] decrypted_buffer;
            
            try
            {

                int num = 0;
                MemoryStream input = new MemoryStream(buf);
                BinaryReader reader = new BinaryReader(input);
                byte[] buffer2 = reader.ReadBytes(reader.ReadInt32());

                guid = GetGuid(SampleAssembly);


                decrypted_buffer = AESDecrypt(buffer2, guid);
                DESInit(decrypted_buffer);

                object[] sourceArray = smethod_2(reader.ReadBytes(reader.ReadInt32()));
                object[] destinationArray = new object[(((int)sourceArray[num]) - 1) + 1];
                num++;
                Array.Copy(sourceArray, num, destinationArray, 0, destinationArray.Length);

                for (int i = 0; i < destinationArray.Length; i++)
                {
                    //Write to disk binary files included in the config (most likely Nanocore assemblies "plugins")
                    if (destinationArray[i] is Byte[])
                    {
                        string f = fname + "-" + i + ".bin";
                        File.Delete(f);
                        File.WriteAllBytes(f, (Byte[])destinationArray[i]);
                    }
                }


                num += destinationArray.Length;
                object[] objArray3 = new object[(((int)sourceArray[num]) - 1) + 1];
                num++;
                Array.Copy(sourceArray, num, objArray3, 0, objArray3.Length);
                filldict(objArray3);

                ret = true;
            }
            catch (Exception)
            {

                ret = false;
            }
            
            return ret;

        }

        /// <summary>
        /// Get Assembly GUID
        /// </summary>
        /// <param name="asm">Assembly</param>
        /// <returns></returns>
        private static Guid GetGuid(Assembly asm)
        {
            guid = new Guid();
            var attributes = CustomAttributeData.GetCustomAttributes(asm);

            foreach (CustomAttributeData cad in attributes)
            {

                if (cad.AttributeType.Name == "GuidAttribute")
                {
                    foreach (CustomAttributeTypedArgument cata in cad.ConstructorArguments)
                    {
                        guid = new Guid((String)cata.Value);
                        break;
                    }

                }
            }
            return guid;
        }

       
        /// <summary>
        /// Decrypt the byte array using the GUID ask key
        /// </summary>
        /// <param name="byte_3"></param>
        /// <param name="guid_0"></param>
        /// <returns></returns>
        private static byte[] AESDecrypt(byte[] byte_3, Guid guid_0)
        {
            Rfc2898DeriveBytes bytes = new Rfc2898DeriveBytes(guid_0.ToByteArray(), guid_0.ToByteArray(), 8);
            RijndaelManaged managed = new RijndaelManaged
            {
                IV = bytes.GetBytes(0x10),
                Key = bytes.GetBytes(0x10)
            };
            return managed.CreateDecryptor().TransformFinalBlock(byte_3, 0, byte_3.Length);
        }
        

        /// <summary>
        /// Fill our dictionary using the object list
        /// </summary>
        /// <param name="object_0"></param>
        private static void filldict(object[] object_0)
        {
            int num2 = object_0.Length - 1;
            for (int i = 0; i <= num2; i += 2)
            {
                string key = (string)object_0[i];
                object objectValue = RuntimeHelpers.GetObjectValue(object_0[i + 1]);
                if (dictionary_1.ContainsKey(key))
                {
                    dictionary_1[key] = RuntimeHelpers.GetObjectValue(objectValue);
                }
                else
                {
                    dictionary_1.Add(key, RuntimeHelpers.GetObjectValue(objectValue));
                }
            }
        }



        private static void DESInit(byte[] byte_0)
        {
            DESCryptoServiceProvider provider = new DESCryptoServiceProvider
            {
                BlockSize = 0x40,
                Key = byte_0,
                IV = byte_0
            };

            DESDecryptor = provider.CreateDecryptor();
        }
        

        private static object[] smethod_2(byte[] byte_0)
        {
            return DESdecodestruct(byte_0).object_0;
        }

        private static NanoStruct DESdecodestruct(byte[] byte_0)
        {
            NanoStruct struct3;
            MemoryStream memoryStream_0 = new MemoryStream();
            MemoryStream memoryStream_1 = new MemoryStream();

           BinaryReader binaryReader_0 = new BinaryReader(memoryStream_0);
           BinaryWriter binaryWriter_0 = new BinaryWriter(memoryStream_1);



            byte_0 = DESDecryptor.TransformFinalBlock(byte_0, 0, byte_0.Length);
            memoryStream_0 = new MemoryStream(byte_0);
            binaryReader_0 = new BinaryReader(memoryStream_0);
            if (binaryReader_0.ReadBoolean())
            {
                int num = binaryReader_0.ReadInt32();
                DeflateStream stream = new DeflateStream(memoryStream_0, CompressionMode.Decompress, false);
                byte[] array = new byte[(num - 1) + 1];
                stream.Read(array, 0, array.Length);
                stream.Close();
                memoryStream_0 = new MemoryStream(array);
                binaryReader_0 = new BinaryReader(memoryStream_0);
            }
            NanoStruct struct2 = new NanoStruct
            {
                byte_0 = binaryReader_0.ReadByte(),
                byte_1 = binaryReader_0.ReadByte()
            };
            if (binaryReader_0.ReadBoolean())
            {
                struct2.guid_0 = new Guid(binaryReader_0.ReadBytes(0x10));
            }
            while (memoryStream_0.Position != memoryStream_0.Length)
            {
                string[] strArray;
                int num3;
                int num4;
                switch (binaryReader_0.ReadByte())
                {
                    case 0:
                        {
                            objectlist.Add(binaryReader_0.ReadBoolean());
                            continue;
                        }
                    case 1:
                        {
                            objectlist.Add(binaryReader_0.ReadByte());
                            continue;
                        }
                    case 2:
                        {
                            objectlist.Add(binaryReader_0.ReadBytes(binaryReader_0.ReadInt32()));
                            continue;
                        }
                    case 3:
                        {
                            objectlist.Add(binaryReader_0.ReadChar());
                            continue;
                        }
                    case 4:
                        {
                            objectlist.Add(binaryReader_0.ReadString().ToCharArray());
                            continue;
                        }
                    case 5:
                        {
                            objectlist.Add(binaryReader_0.ReadDecimal());
                            continue;
                        }
                    case 6:
                        {
                            objectlist.Add(binaryReader_0.ReadDouble());
                            continue;
                        }
                    case 7:
                        {
                            objectlist.Add(binaryReader_0.ReadInt32());
                            continue;
                        }
                    case 8:
                        {
                            objectlist.Add(binaryReader_0.ReadInt64());
                            continue;
                        }
                    case 9:
                        {
                            objectlist.Add(binaryReader_0.ReadSByte());
                            continue;
                        }
                    case 10:
                        {
                            objectlist.Add(binaryReader_0.ReadInt16());
                            continue;
                        }
                    case 11:
                        {
                            objectlist.Add(binaryReader_0.ReadSingle());
                            continue;
                        }
                    case 12:
                        {
                            objectlist.Add(binaryReader_0.ReadString());
                            continue;
                        }
                    case 13:
                        {
                            objectlist.Add(binaryReader_0.ReadUInt32());
                            continue;
                        }
                    case 14:
                        {
                            objectlist.Add(binaryReader_0.ReadUInt64());
                            continue;
                        }
                    case 15:
                        {
                            objectlist.Add(binaryReader_0.ReadUInt16());
                            continue;
                        }
                    case 0x10:
                        {
                            objectlist.Add(DateTime.FromBinary(binaryReader_0.ReadInt64()));
                            continue;
                        }
                    case 0x11:
                        strArray = new string[(binaryReader_0.ReadInt32() - 1) + 1];
                        num3 = strArray.Length - 1;
                        num4 = 0;
                        goto Label_039A;

                    case 0x12:
                        {
                            Guid item = new Guid(binaryReader_0.ReadBytes(0x10));
                            objectlist.Add(item);
                            continue;
                        }
                    case 0x13:
                        {
                            Size size = new Size(binaryReader_0.ReadInt32(), binaryReader_0.ReadInt32());
                            objectlist.Add(size);
                            continue;
                        }
                    case 20:
                        {
                            Rectangle rectangle = new Rectangle(binaryReader_0.ReadInt32(), binaryReader_0.ReadInt32(), binaryReader_0.ReadInt32(), binaryReader_0.ReadInt32());
                            objectlist.Add(rectangle);
                            continue;
                        }
                    case 0x15:
                        {
                            objectlist.Add(new Version(binaryReader_0.ReadString()));
                            continue;
                        }
                    default:
                        {
                            continue;
                        }
                }
            Label_0385:
                strArray[num4] = binaryReader_0.ReadString();
                num4++;
            Label_039A:
                if (num4 <= num3)
                {
                    goto Label_0385;
                }
                objectlist.Add(strArray);
            }
            struct2.object_0 = objectlist.ToArray();
            struct3 = struct2;
            objectlist.Clear();
            binaryReader_0.Close();

            return struct3;
        }











    }

}

