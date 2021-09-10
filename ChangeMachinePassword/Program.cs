using System;
using System.DirectoryServices;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

namespace ChangeMachinePassword
{
	// Token: 0x02000085 RID: 133
	//[Cmdlet("Reset", "ComputerMachinePassword", SupportsShouldProcess = true, HelpUri = "https://go.microsoft.com/fwlink/?LinkID=135252")]
	class Program
	{
		static void Main(string[] args)
		{
            //string target = "1";   // 0 represent change all; 1 represent change local ; 2 represent change remote ;default is change local; 
            string domain = "", localMachineName = "", username = "", password = "", NewMachinePassword = "";
            byte[] NewMachinePasswordHex;

            //SAMAPI.LSA_UNICODE_STRING lsa_UNICODE_STRINGtest = new SAMAPI.LSA_UNICODE_STRING
            //{
            //    Buffer = IntPtr.Zero
            //};
            //byte[] decBytes = System.Text.Encoding.Unicode.GetBytes("abcde");
            ////SAMAPI.InitLsaString("123qwe", ref lsa_UNICODE_STRINGtest);
            //byte[] temp = new byte[] { 0x21, 0x22, 0x23, 0x34 };
            //SAMAPI.InitLsaHexString(temp, ref lsa_UNICODE_STRINGtest);
            ////Marshal.Copy(temp, 0, lsa_UNICODE_STRINGtest.Buffer, temp.Length);
            //Console.WriteLine(Marshal.PtrToStringAnsi(lsa_UNICODE_STRINGtest.Buffer));
            //// Console.WriteLine(Marshal.StringToHGlobalUni(s));
            //Console.ReadLine();

            if (args.Length == 0)
			{
                //Console.WriteLine("target 0 represent change all; 1 represent change local ; 2 represent change remote ;default is change all\r\n");
                Console.WriteLine("Example: xxx.exe allplain test.local win10 admin 123456 aaaaaaaaaaaaa  //don't need $\r\n");
                Console.WriteLine("Example: xxx.exe allhex test.local win10 admin 123456 3f6263646b  //don't need $\r\n");
                Console.WriteLine("Example: xxx.exe localplain aaaaaaaaa  //runas administrator\r\n");
                Console.WriteLine("Example: xxx.exe localhex 6e6a636566  //runas administrator\r\n");
                Console.WriteLine("Example: xxx.exe remoteplain test.local win10 admin 123456 aaaaaaaaaaaaaaa  //don't need $\r\n");
                Console.WriteLine("Example: xxx.exe remotehex test.local win10 admin 123456 3f6263646b  //don't need $\r\n");
                return;
			}
            else
            {
                if (args[0] == "allplain")
                {
                    domain = args[1];
                    localMachineName = args[2];
                    username = args[3];
                    password = args[4];
                    NewMachinePassword = args[5];
                    NewMachinePasswordHex = System.Text.Encoding.Unicode.GetBytes(NewMachinePassword);
                    ChangeRemotePass(domain, localMachineName, username, password, NewMachinePasswordHex);
                    ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
                if (args[0] == "allhex")
                {
                    domain = args[1];
                    localMachineName = args[2];
                    username = args[3];
                    password = args[4];
                    //NewMachinePassword = args[5];
                    NewMachinePasswordHex = ConvertHexStringToBytes(args[5]);
                    ChangeRemotePass(domain, localMachineName, username, password, NewMachinePasswordHex);
                    ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
                if (args[0] == "localplain")
                {
                    NewMachinePassword = args[1];
                    NewMachinePasswordHex = System.Text.Encoding.Unicode.GetBytes(NewMachinePassword);
                    ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
                if (args[0] == "localhex")
                {
                    NewMachinePasswordHex = ConvertHexStringToBytes(args[1]); 
                    ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
                if (args[0] == "remoteplain")
                {
                    domain = args[1];
                    localMachineName = args[2];
                    username = args[3];
                    password = args[4];
                    NewMachinePassword = args[5];
                    NewMachinePasswordHex = System.Text.Encoding.Unicode.GetBytes(NewMachinePassword);
                    ChangeRemotePass(domain, localMachineName, username, password, NewMachinePasswordHex);
                    //ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
                if (args[0] == "remotehex")
                {
                    domain = args[1];
                    localMachineName = args[2];
                    username = args[3];
                    password = args[4];
                    NewMachinePasswordHex = ConvertHexStringToBytes(args[5]);
                    //NewMachinePasswordHex = System.Text.Encoding.Unicode.GetBytes(NewMachinePassword);
                    ChangeRemotePass(domain, localMachineName, username, password, NewMachinePasswordHex);
                    //ChangeLocalPass(NewMachinePasswordHex);
                    return;
                }
            }
        }
		static void ChangeRemotePass(string domain, string localMachineName, string username, string password, byte[] NewMachinePasswordHex)
        {
			//string domain = args[0];
			//string localMachineName = args[1];
			//string username = args[2];
			//string password = args[3];
			//string NewMachinePassword = args[4];
			//string text = null;
			try
			{
				//string username = (credential != null) ? credential.UserName : null;
				//string password = (credential != null) ? Utils.GetStringFromSecureString(credential.Password) : null;
				using (DirectoryEntry directoryEntry = new DirectoryEntry("LDAP://" + domain, username, password, AuthenticationTypes.Secure))
				{
					using (DirectorySearcher directorySearcher = new DirectorySearcher(directoryEntry))
					{
						directorySearcher.Filter = string.Concat(new string[]
						{
							"(&(objectClass=computer)(|(cn=",
							localMachineName,
							")(dn=",
							localMachineName,
							")))"
						});
						SearchResult searchResult = directorySearcher.FindOne();
						if (searchResult == null)
						{
							Console.WriteLine("directorySearcher error\r\n");
							return;
						}
						else
						{
							using (DirectoryEntry directoryEntry2 = searchResult.GetDirectoryEntry())
							{
								//text = ComputerWMIHelper.GetRandomPassword(120);
								//text = NewMachinePassword;
								directoryEntry2.Invoke("SetPassword", new object[]
								{
									NewMachinePasswordHex
                                    //new byte[]{ 0x31,0x00,0x32,0x00,0x33,0x00,0x34, 0x00, 0x35, 0x00, 0x36, 0x00 }
								});
								directoryEntry2.Properties["LockOutTime"].Value = 0;
								Console.WriteLine("Change Machine Password in DC successfully!");
							}
						}
					}
				}
			}
			catch (Exception ex)
			{
				Console.WriteLine(ex.ToString());
			}
		}
		static void ChangeLocalPass(byte[] NewMachinePasswordHex)
        {
            SAMAPI.LSA_OBJECT_ATTRIBUTES lsa_OBJECT_ATTRIBUTES = default(SAMAPI.LSA_OBJECT_ATTRIBUTES);
            lsa_OBJECT_ATTRIBUTES.RootDirectory = IntPtr.Zero;
            lsa_OBJECT_ATTRIBUTES.ObjectName = IntPtr.Zero;
            lsa_OBJECT_ATTRIBUTES.Attributes = 0;
            lsa_OBJECT_ATTRIBUTES.SecurityDescriptor = IntPtr.Zero;
            lsa_OBJECT_ATTRIBUTES.SecurityQualityOfService = IntPtr.Zero;
            lsa_OBJECT_ATTRIBUTES.Length = Marshal.SizeOf(typeof(SAMAPI.LSA_OBJECT_ATTRIBUTES));
            IntPtr zero = IntPtr.Zero;
            IntPtr zero2 = IntPtr.Zero;
            IntPtr zero3 = IntPtr.Zero;
            SAMAPI.LSA_UNICODE_STRING lsa_UNICODE_STRING = new SAMAPI.LSA_UNICODE_STRING
            {
                Buffer = IntPtr.Zero
            };
            SAMAPI.LSA_UNICODE_STRING lsa_UNICODE_STRING2 = new SAMAPI.LSA_UNICODE_STRING
            {
                Buffer = IntPtr.Zero
            };
            SAMAPI.LSA_UNICODE_STRING lsa_UNICODE_STRING3 = default(SAMAPI.LSA_UNICODE_STRING);
            lsa_UNICODE_STRING3.Buffer = IntPtr.Zero;
            lsa_UNICODE_STRING3.Length = 0;
            lsa_UNICODE_STRING3.MaximumLength = 0;
            try
            {
                uint num = SAMAPI.LsaOpenPolicy(ref lsa_UNICODE_STRING3, ref lsa_OBJECT_ATTRIBUTES, 987135U, out zero);
                if (num == 3221225506U)
                {
                    Console.WriteLine("LsaOpenPolicy Error!  Run as administrator or system\r\n");
                    return;
                }
                if (num != 0U)
                {
                    Console.WriteLine("LsaOpenPolicy Error1!");
                    return;
                }
                SAMAPI.InitLsaString("$MACHINE.ACC", ref lsa_UNICODE_STRING);
                SAMAPI.InitLsaHexString(NewMachinePasswordHex, ref lsa_UNICODE_STRING2);
                //Marshal.Copy(NewMachinePasswordHex,0,lsa_UNICODE_STRING2.Buffer,NewMachinePasswordHex.Length);
                //lsa_UNICODE_STRING2.MaximumLength = (ushort)(NewMachinePasswordHex.Length + 2);
                //lsa_UNICODE_STRING2.Length = (ushort)(NewMachinePasswordHex.Length);
                bool flag = false;
                num = SAMAPI.LsaOpenSecret(zero, ref lsa_UNICODE_STRING, 3U, out zero2);
                if (num == 3221225524U)
                {
                    num = SAMAPI.LsaCreateSecret(zero, ref lsa_UNICODE_STRING, 1U, out zero2);
                    flag = true;
                    return;
                }
                if (num != 0U)
                {
                    Console.WriteLine("LsaCreateSecret Error1!");
                    return;
                }
                SAMAPI.LSA_UNICODE_STRING lsa_UNICODE_STRING4;
                if (flag)
                {
                    lsa_UNICODE_STRING4 = lsa_UNICODE_STRING2;
                }
                else
                {
                    num = SAMAPI.LsaQuerySecret(zero2, out zero3, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    if (num != 0U)
                    {
                        Console.WriteLine("LsaQuerySecret Error1!");
                        return;
                    }
                    lsa_UNICODE_STRING4 = (SAMAPI.LSA_UNICODE_STRING)Marshal.PtrToStructure(zero3, typeof(SAMAPI.LSA_UNICODE_STRING));
                }
                num = SAMAPI.LsaSetSecret(zero2, ref lsa_UNICODE_STRING2, ref lsa_UNICODE_STRING4);
                if (num != 0U)
                {
                    Console.WriteLine("LsaSetSecret Error1!");
                    return;
                }
                else
                {
                    Console.WriteLine("Change local Machine Password Successfully!");
                }
            }
            finally
            {
                if (zero3 != IntPtr.Zero)
                {
                    SAMAPI.LsaFreeMemory(zero3);
                }
                if (zero != IntPtr.Zero)
                {
                    SAMAPI.LsaClose(zero);
                }
                if (zero2 != IntPtr.Zero)
                {
                    SAMAPI.LsaClose(zero2);
                }
                SAMAPI.FreeLsaString(ref lsa_UNICODE_STRING);
                SAMAPI.FreeLsaString(ref lsa_UNICODE_STRING2);
            }
        }
        public static byte[] ConvertHexStringToBytes(string hexString)        //"616263"  to byte[]{0x61,0x62,0x63}
        {
            hexString = hexString.Replace(" ", "");
            if (hexString.Length % 2 != 0)
            {
                throw new ArgumentException("the length of param is incorrect!");
            }

            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
            {
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            }

            return returnBytes;
        }
    }
}

