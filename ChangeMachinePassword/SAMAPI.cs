using System;
using System.Runtime.InteropServices;

namespace ChangeMachinePassword
{
	static class SAMAPI
	{
		// Token: 0x060006B6 RID: 1718
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern uint LsaOpenPolicy(ref SAMAPI.LSA_UNICODE_STRING systemName, ref SAMAPI.LSA_OBJECT_ATTRIBUTES objectAttributes, uint desiredAccess, out IntPtr policyHandle);

		// Token: 0x060006B7 RID: 1719
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern uint LsaOpenSecret(IntPtr policyHandle, ref SAMAPI.LSA_UNICODE_STRING secretName, uint accessMask, out IntPtr secretHandle);

		// Token: 0x060006B8 RID: 1720
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern uint LsaCreateSecret(IntPtr policyHandle, ref SAMAPI.LSA_UNICODE_STRING secretName, uint desiredAccess, out IntPtr secretHandle);

		// Token: 0x060006B9 RID: 1721
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern uint LsaQuerySecret(IntPtr secretHandle, out IntPtr currentValue, IntPtr currentValueSetTime, IntPtr oldValue, IntPtr oldValueSetTime);

		// Token: 0x060006BA RID: 1722
		[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern uint LsaSetSecret(IntPtr secretHandle, ref SAMAPI.LSA_UNICODE_STRING currentValue, ref SAMAPI.LSA_UNICODE_STRING oldValue);

		// Token: 0x060006BB RID: 1723
		[DllImport("advapi32")]
		internal static extern int LsaNtStatusToWinError(int ntStatus);

		// Token: 0x060006BC RID: 1724
		[DllImport("advapi32")]
		internal static extern int LsaClose(IntPtr policyHandle);

		// Token: 0x060006BD RID: 1725
		[DllImport("advapi32")]
		internal static extern int LsaFreeMemory(IntPtr buffer);

		// Token: 0x060006BE RID: 1726 RVA: 0x0001B418 File Offset: 0x00019618
		internal static void InitLsaString(string s, ref SAMAPI.LSA_UNICODE_STRING lus)
		{
			ushort num = 32766;
			if (s.Length > (int)num)
			{
				throw new ArgumentException("String too long");
			}
			lus.Buffer = Marshal.StringToHGlobalUni(s);
			lus.Length = (ushort)(s.Length * 2);
			lus.MaximumLength = (ushort)((s.Length + 1) * 2);
		}
		internal static void InitLsaHexString(byte[] s, ref SAMAPI.LSA_UNICODE_STRING lus)
		{
			ushort num = 32766;
			if (s.Length > (int)num)
			{
				throw new ArgumentException("String too long");
			}
			//lus.Buffer = Marshal.StringToHGlobalUni(s);
			lus.Buffer = Marshal.StringToHGlobalUni("a");
			Marshal.Copy(s, 0, lus.Buffer, s.Length);
			lus.Length = (ushort)(s.Length);
			lus.MaximumLength = (ushort)((s.Length + 2));
		}
		// Token: 0x060006BF RID: 1727 RVA: 0x0001B46B File Offset: 0x0001966B
		internal static void FreeLsaString(ref SAMAPI.LSA_UNICODE_STRING s)
		{
			if (s.Buffer == IntPtr.Zero)
			{
				return;
			}
			Marshal.FreeHGlobal(s.Buffer);
			s.Buffer = IntPtr.Zero;
		}

		// Token: 0x060006C0 RID: 1728
		[DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
		internal static extern int I_NetLogonControl2([In] string lpServerName, uint lpFunctionCode, uint lpQueryLevel, ref IntPtr lpInputData, out IntPtr queryInformation);

		// Token: 0x060006C1 RID: 1729
		[DllImport("Netapi32.dll", SetLastError = true)]
		internal static extern int NetApiBufferFree(IntPtr Buffer);

		// Token: 0x04000224 RID: 548
		internal const int WorkrGroupMachine = 2692;

		// Token: 0x04000225 RID: 549
		internal const int MaxMachineNameLength = 15;

		// Token: 0x02000139 RID: 313
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
		internal struct LSA_UNICODE_STRING
		{
			// Token: 0x040007BB RID: 1979
			internal ushort Length;

			// Token: 0x040007BC RID: 1980
			internal ushort MaximumLength;

			// Token: 0x040007BD RID: 1981
			internal IntPtr Buffer;
		}

		// Token: 0x0200013A RID: 314
		internal struct LSA_OBJECT_ATTRIBUTES
		{
			// Token: 0x040007BE RID: 1982
			internal int Length;

			// Token: 0x040007BF RID: 1983
			internal IntPtr RootDirectory;

			// Token: 0x040007C0 RID: 1984
			internal IntPtr ObjectName;

			// Token: 0x040007C1 RID: 1985
			internal int Attributes;

			// Token: 0x040007C2 RID: 1986
			internal IntPtr SecurityDescriptor;

			// Token: 0x040007C3 RID: 1987
			internal IntPtr SecurityQualityOfService;
		}

		// Token: 0x0200013B RID: 315
		internal enum LSA_ACCESS
		{
			// Token: 0x040007C5 RID: 1989
			Read = 131078,
			// Token: 0x040007C6 RID: 1990
			AllAccess = 987135,
			// Token: 0x040007C7 RID: 1991
			Execute = 133121,
			// Token: 0x040007C8 RID: 1992
			Write = 133112
		}

		// Token: 0x0200013C RID: 316
		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
		internal struct NetLogonInfo2
		{
			// Token: 0x040007C9 RID: 1993
			internal uint Flags;

			// Token: 0x040007CA RID: 1994
			internal uint PdcConnectionStatus;

			// Token: 0x040007CB RID: 1995
			internal string TrustedDcName;

			// Token: 0x040007CC RID: 1996
			internal uint TdcConnectionStatus;
		}
	}
}
