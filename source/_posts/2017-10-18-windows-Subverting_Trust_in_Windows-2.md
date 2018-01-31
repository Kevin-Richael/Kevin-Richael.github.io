---
layout: post
category: "Win"
title:  "[翻译]颠覆windows的信任体系(2)"
date: 2017/10/18 21:24:24
tags: [Win,Trust,certificate]
---
## 什么文件可以被签名呢

怎么知道一个可执行文件是否被签名呢？一个最简单直接的方法就是右键查看文件属性，然后切换到数字签名选项卡。

![“数字签名”选项卡显示是否存在嵌入的认证签名](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-1.png)
*“数字签名”选项卡显示是否存在嵌入的认证签名*

虽然这种方法可以用来确认某些文件类型是否被签名，如上图所示的ise.psm1（[PowerShell脚本模块][1]文件）的情况，但这远远不是枚举可签名文件类型的系统方法。对文件类型的签名支持只是SIP(负责数字签名的创建、检索和哈希计算、验证的体系结构)的部分实现。 

以下是ise.psm1中嵌入签名的一部分：
```
# SIG # Begin signature block
# MIIXXAYJKoZIhvcNAQcCoIIXTTCCF0kCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUv0M9fHFPOaghmrZBoun/tqPG
# zE6gghIxMIIEYDCCA0ygAwIBAgIKLqsR3FD/XJ3LwDAJBgUrDgMCHQUAMHAxKzAp
# BgNVBAsTIkNvcHlyaWdodCAoYykgMTk5NyBNaWNyb3NvZnQgQ29ycC4xHjAcBgNV
# BAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEhMB8GA1UEAxMYTWljcm9zb2Z0IFJv
# b3QgQXV0aG9yaXR5MB4XDTA3MDgyMjIyMzEwMloXDTEyMDgyNTA3MDAwMFoweTEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWlj
# cm9zb2Z0IENvZGUgU2lnbmluZyBQQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
# ggEKAoIBAQC3eX3WXbNFOag0rDHa+SU1SXfA+x+ex0Vx79FG6NSMw2tMUmL0mQLD
# TdhJbC8kPmW/ziO3C0i3f3XdRb2qjw5QxSUr8qDnDSMf0UEk+mKZzxlFpZNKH5nN
# sy8iw0otfG/ZFR47jDkQOd29KfRmOy0BMv/+J0imtWwBh5z7urJjf4L5XKCBhIWO
# sPK4lKPPOKZQhRcnh07dMPYAPfTG+T2BvobtbDmnLjT2tC6vCn1ikXhmnJhzDYav
...
# HNHPPQanI9HpDNBxWrVzcH6zIV1vBHSeB/tFtZpOI+beHjx7X3d1cyCg5lfERzyQ
# 3jJyjSbMMbz8Pj/1meM0rlWQ/ZnYYiQAtJYqUN3ctT21Uu3ZVVnw46A8voTnSRMd
# 5mVFLFMeFyJkWgsyqLroBTm4U/G+gZ2BB0ImzSbSfIo=
# SIG # End signature block
```

这就是PowerShell代码中的签名如何存储的（MOF文件是一个例外）。 为了使问题复杂化，可以签名的每种文件类型都以独特的方式存储其签名。 例如，[PE签名认证规范](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)解释了如何在PE文件（如EXE、DLL、SYS等）中存储和验证签名。

位于crypt32.dll（常通过[WinVerifyTrust][2]间接调用）中的一个函数[CryptSIPRetrieveSubjectGuid][3]，用于发现与特定文件类型相关联的SIP的功能。 给定文件名和可选句柄，CryptSIPRetrieveSubjectGuid返回一个GUID，表示可以处理检索嵌入认证签名的SIP。 功能大致如下：
1. 根据文件魔数，尝试确定该文件是PE，编录文件，CTL还是cabinet文件。如果是任何这些文件类型，它将返回以下相应的SIP GUID：
  - C689AAB8-8E78-11D0-8C47-00C04FC295EE  -PE
  - DE351A43-8E59-11D0-8C47-00C04FC295EE  -Catalog
  - 9BA61D3F-E73A-11D0-8CD2-00C04FC295EE  -CTL
  - C689AABA-8E78-11D0-8C47-00C04FC295EE  -Cabinet
2. 如果文件不匹配任何以前的文件类型，它将调用[CryptEnumOIDFunction][4]函数，传递它的功能名称为“CryptSIPDllIsMyFileType”和“CryptSIPDllIsMyFileType2”。 这些功能分别对应于以下注册表项的查找：
  - HKLM\\SOFTWARE\\[WOW6432Node]\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType\\<All sub-GUIDs>
  - HKLM\\SOFTWARE\\[WOW6432Node]\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllIsMyFileType2\\<All sub-GUIDs>
    随着CryptEnumOIDFunction枚举每个SIP GUID注册表子项，它将从“FuncName”和“Dll”列出的注册表键值中调用DLL导出函数。

“CryptSIPDllIsMyFileType”的功能原型文档[戳我][5]，“CryptSIPDllIsMyFileType2”的功能原型文档[戳我][6]。 如果有实现，“CryptSIPDllIsMyFileType”
函数首先被调用，如果其中一个函数返回“TRUE”，则返回处理签名的SIP GUID。 在实践中（至少在Windows 10上），没有SIP实现“CryptSIPDllIsMyFileType”，所以随后调用“CryptSIPDllIsMyFileType2”函数来尝试解决处理SIP。 例如，PowerShell（SIP GUID：603BCC1F-4B59-4E08-B724-D2C6297EF351）将CryptSIPDllIsMyFileType2实现为pwrshsip！PsIsMyFileType。 经过反汇编、反编译及整理输出，这里是`PsIsMyFileType`函数的C语言版的原型：

```c

#define CRYPT_SUBJTYPE_POWERSHELL_IMAGE \
{ 0x603BCC1F, \
0x4B59, \
0x4E08, \
{ 0xB7, 0x24, 0xD2, 0xC6, 0x29, 0x7E, 0xF3, 0x51 } \
}
BOOL WINAPI PsIsMyFileType(IN WCHAR *pwszFileName, OUT GUID *pgSubject) {
	BOOL bResult;
	WCHAR *SupportedExtensions[7];
	WCHAR *Extension;
	GUID PowerShellSIPGUID = CRYPT_SUBJTYPE_POWERSHELL_IMAGE;
	SupportedExtensions[0] = L"ps1";
	SupportedExtensions[1] = L"ps1xml";
	SupportedExtensions[2] = L"psc1";
	SupportedExtensions[3] = L"psd1";
	SupportedExtensions[4] = L"psm1";
	SupportedExtensions[5] = L"cdxml";
	SupportedExtensions[6] = L"mof";
	bResult = FALSE;
	if (pwszFileName && pgSubject) {
		Extension = wcsrchr(pwszFileName, '.');
		if (Extension) {
			Extension++;
			for (int i = 0; i < 7; i++) {
				if (!_wcsicmp(Extension, SupportedExtensions[i])) {
					bResult = TRUE;
					memcpy(pgSubject, &PowerShellSIPGUID, sizeof(GUID));
					break;
				}
			}
		}
	}
	else
	{
		SetLastError(
			ERROR_INVALID_PARAMETER
		);
	}
	return
		bResult;
}
```
从C代码中可以看出，如果任何文件有任何上述扩展名，那么PowerShell SIP将是用作代码签名的SIP。 “CryptSIPDllIsMyFileType2”不一定要检查文件扩展名，SIP还可以选择打开文件句柄并检查文件中的魔数值，以确定正确的文件/blob SIP处理顺序。

其他支持的SIP文件类型处理函数如下（非详尽列表）：
1.  000C10F1-0000-0000-C000-000000000046
  C:\Windows\System32\MSISIP.DLL
  MsiSIPIsMyTypeOfFile
2.  06C9E010-38CE-11D4-A2A3-00104BD35090
  C:\Windows\System32\wshext.dll
  IsFileSupportedName
3.  0AC5DF4B-CE07-4DE2-B76E-23C839A09FD1
  C:\Windows\System32\AppxSip.dll
  AppxSipIsFileSupportedName
4.  0F5F58B3-AADE-4B9A-A434-95742D92ECEB
  C:\Windows\System32\AppxSip.dll
  AppxBundleSipIsFileSupportedName
5.  1629F04E-2799-4DB5-8FE5-ACE10F17EBAB
  C:\Windows\System32\wshext.dll
  IsFileSupportedName
6.  1A610570-38CE-11D4-A2A3-00104BD35090
  C:\Windows\System32\wshext.dll
  IsFileSupportedName
7.  5598CFF1-68DB-4340-B57F-1CACF88C9A51
  C:\Windows\System32\AppxSip.dll
  P7xSipIsFileSupportedName
8.  603BCC1F-4B59-4E08-B724-D2C6297EF351
  C:\Windows\System32\WindowsPowerShell\v1.0\pwrshsip.dll
  PsIsMyFileType
9.  9F3053C5-439D-4BF7-8A77-04F0450A1D9F
  C:\Windows\System32\EsdSip.dll
  EsdSipIsMyFileType
10.  CF78C6DE-64A2-4799-B506-89ADFF5D16D6
  C:\Windows\System32\AppxSip.dll
  EappxSipIsFileSupportedName
11.  D1D04F0C-9ABA-430D-B0E4-D7E96ACCE66C
   C:\Windows\System32\AppxSip.dll
   EappxBundleSipIsFileSupportedName

对于读者来说, 逆向上面的某些函数来查看Windows所支持代码签名的文件或二进制blob的类型，这将是一个很有价值的练习。

一旦需要检索签名的软件获得该 SIP 的 GUID, 那它就可以继续提取该证书。

## 文件签名检索和哈希验证
一旦负责处理特定文件/二进制Blob格式的签名的SIP通过其各自的GUID标识符被识别，WinVerifyTrust 就会知道如何从该文件中获取数字签名并验证其计算出的哈希对嵌入在数字中的签名哈希签名。为实现这一点, WinVerifyTrust 在注册表中调用以下函数:

SIP 签名检索功能位置：
  - HKLM\\SOFTWARE\\[WOW6432Node]\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllGetSignedDataMsg\\{SIP Guid}
  - Dll
  - FuncName

SIP 哈希验证函数：
  - HKLM\\SOFTWARE\\[WOW6432Node]\\Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{SIP Guid}
     - Dll
     - FuncName

[CryptSIPDllGetSignedDataMsg][7]和[CryptSIPDllVerifyIndirectData][8]的函数原型在MSDN有文档，同样也存在于Windows SDK中的mssip.h头文件中。

SIP签名检索功能原型：
```c
BOOL WINAPI CryptSIPGetSignedDataMsg(
	IN SIP_SUBJECTINFO *pSubjectInfo,
	OUT DWORD *pdwEncodingType,
	IN DWORD dwIndex,
	IN OUT DWORD *pcbSignedDataMsg,
	OUT BYTE *pbSignedDataMsg);
```
SIP 哈希验证函数原型：
```c
BOOL WINAPI CryptSIPVerifyIndirectData(
	IN SIP_SUBJECTINFO *pSubjectInfo,
	IN SIP_INDIRECT_DATA *pIndirectData);
```
[SIP_SUBJECTINFO](https://msdn.microsoft.com/en-us/library/windows/desktop/bb736434(v=vs.85).aspx)  [SIP_INDIRECT_DATA][9]
1387/5000
提供给这些函数的参数由调用信任提供者负责填充（有关信任提供者架构的更多细节，请参见以下部分）。当CryptSIPGetSignedDataMsg被调用时，SIP将提取编码的数字签名（最常用的是[CERT_SIGNED_CONTENT_INFO][10]结构体，ASN.1 PKCS_7_ASN_ENCODING和X509_ASN_ENCODING编码），并通过“pbSignedDataMsg”参数返回。CERT_SIGNED_CONTENT_INFO内容由签名证书（包括其发行链）、用于对文件进行哈希和签名的算法以及文件的签名散列组成。调用信任提供者然后对数字签名进行解码，提取散列算法和签名哈希值，然后将它们传递给CryptSIPVerifyIndirectData。在校验认证码哈希计算并与已签名哈希进行比较后，如果匹配，则CryptSIPVerifyIndirectData返回TRUE，否则返回FALSE，然后WinVerifyTrust将返回一个错误，表明哈希不匹配。

CryptSIPVerifyIndirectData是最重要的数字签名验证功能之一，但这将会犯错：因为攻击者可以将现有的合法数字签名应用于其恶意软件——这是一种[在野](https://twitter.com/craiu/status/879690795946827776?lang=en)的攻击技术。
以下是一个适用于合法认证码签名的恶意软件示例的哈希失真的示例：
![在使用微软认证码签名的未签名文件上显示哈希不匹配错误的示例（注意相同的SignerCertificate指纹值）](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-2.png)
*在使用微软认证码签名的未签名文件上显示哈希不匹配错误的示例（注意相同的SignerCertificate指纹值）*

![未签名的文件在应用于签名文件的认证码签名时无法验证。微软就是这么设计的。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-3.png)
*未签名的文件在应用于签名文件的认证码签名时无法验证。微软就是这么设计的。*

## 信任提供者架构
到目前为止，已经讨论了SIP的基本架构。如现在应该理解的，SIP仅负责数字签名应用、检索和散列计算、验证。应用于文件的数字签名的存在是无意义的，除非某些标准被实际验证。这就是信任提供者发挥作用的地方——除了内置到所需的信任提供者中的标准之外，还可以根据调用者指定的参数组合对WinVerifyTrust进行验证。

像SIP一样，信任提供者也由GUID唯一标识。 截至到Windows 10，有以下信任提供者存在：

| GUID                                 | 描述                                     |
| :----------------------------------- | :------------------------------------- |
| A7F4C378-21BE-494e-BA0F-BB12C5D208C5 | UNKNOWN .NET VERIFIER                  |
| 7801EBD0-CF4B-11D0-851F-0060979387EA | CERT_CERTIFICATE_ACTION_VERIFY         |
| 6078065B-8F22-4B13-BD9B-5B762776F386 | CONFIG_CI_ACTION_VERIFY                |
| D41E4F1F-A407-11D1-8BC9-00C04FA30A41 | COR_POLICY_LOCKDOWN_CHECK              |
| D41E4F1D-A407-11D1-8BC9-00C04FA30A41 | COR_POLICY_PROVIDER_DOWNLOAD           |
| 31D1ADC1-D329-11D1-8ED8-0080C76516C6 | COREE_POLICY_PROVIDER                  |
| F750E6C3-38EE-11D1-85E5-00C04FC295EE | DRIVER_ACTION_VERIFY                   |
| 573E31F8-AABA-11D0-8CCB-00C04FC295EE | HTTPSPROV_ACTION                       |
| 5555C2CD-17FB-11d1-85C4-00C04FC295EE | OFFICESIGN_ACTION_VERIFY               |
| 64B9D180-8DA2-11CF-8736-00AA00A485EB | WIN_SPUB_ACTION_PUBLISHED_SOFTWARE     |
| C6B2E8D0-E005-11CF-A134-00C04FD7BF43 | WIN_SPUB_ACTION_PUBLISHED_SOFTWARE_NOB |
| 189A3842-3041-11D1-85E1-00C04FC295EE | WINTRUST_ACTION_GENERIC_CERT_VERIFY    |
| FC451C16-AC75-11D1-B4B8-00C04FB66EA0 | WINTRUST_ACTION_GENERIC_CHAIN_VERIFY   |
| 00AAC56B-CD44-11D0-8CC2-00C04FC295EE | WINTRUST_ACTION_GENERIC_VERIFY_V2      |
| 573E31F8-DDBA-11D0-8CCB-00C04FC295EE | WINTRUST_ACTION_TRUSTPROVIDER_TEST     |

信任提供者的部分组件的声明在MSDN和windowsSDk的SoftPub.h的文档中能找到，但是它们的实现并没有文档化。对开发人员而言，这就需要从信任证书、签名、信任链、吊销和时间戳正确执行验证。开发人员调用WinVerifyTrust使用的更常见的信任提供程序之一是WINTRUST_ACTION_GENERIC_VERIFY_V2以用来确认通用校验码签名。如果需要在用户模式下验证驱动程序的可信性任, 则应使用 DRIVER_ACTION_VERIFY。

与 sip 一样, 信任提供程序也在注册表中注册了以下项:
	- HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\Providers\\Trust

在"信任"键中,是一个子项列表,对应于可能发生的每个信任提供程序验证步骤:初始化(Initialization)、消息(Message)、签名(Signature)、证书(Certificate)、认证检查(CertCheck)、最终策略(FinalPolicy)、诊断策略(DiagnosticPolicy)和清理(Cleanup)。其中的每个密钥都是实现每个步骤的信任提供程序 guid (不是所有的都是必需的. 例如, 证书检查、诊断策略和清理)。在每个各自的 GUID 子项中, 都是由注册表里的 dll 和导出函数来实现信任提供程序步骤的`$DLL `和 `$Function`。
![在注册表中注册的信任提供者的示例](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-4.png)
*在注册表中注册的信任提供者的示例*

每个信任提供程序步骤的用途可以大致细分如下:
1. 初始化：
  a. 初始化 [CRYPT_PROVIDER_DATA][11] 结构体（该结构体基于[WINTRUST_DATA][12] 结构体），然后传递给WinVerifyTrust。CRYPT_PROVIDER_DATA是在所有信任提供程序函数之间传递的结构体,用于在所有调用中维护状态,包括可能在执行过程中的每个步骤的错误代码 (请参见 wintrust 中的 TRUSTERROR_STEP 值)。
  b. 打开要验证的文件的只读句柄。
2. 消息：
  a. 从主题接口包中获取签名者信息。这是验证过程中的唯一步骤,它调用各自的SIP以获取正确的签名。请注意,在尝试从嵌入的验证码签名获取签名之前,某些信任校验实用程序将首先检查签名的目录存储。
  b. "初始化" 和 "消息" 步骤都被称为 "对象提供程序"。
3. 签名：
  a. 在此步骤中, 将生成数字签名, 并验证 counter-signers 和时间戳。
  b. 这一步骤被称为“签名提供者”。
4. 证书：
  a. 这一步中，整个证书链将被生成。
  b. 这一步被称为“证书提供者”。
5. 认证检查：
  a. 如果实现此可选步骤, 则为证书链中的每个索引调用此函数, 并用于向信任提供者指示证书链应继续构建。
6. 最终策略：
  a. 这是大多数信任决策的作用。此时, 签名和证书链已被解码、解析并提供给这个实现函数。
  b. 验证签名、证书链和证书存储的哪些组件因信任提供程序而异。下面是使用 WINTRUST_ACTION_GENERIC_VERIFY_V2 信任提供程序时发生的一些检查的小列表 (实现 WINTRUST!SoftPubAuthenticode)：
  	i. 验证文件是否已使用指定的代码签名证书（由 "1.3. 6.1. 5.5. 7.3. 3" 的增强密钥用法 (EKU) 表示）进行签名。
  	ii. 检查证书是否已过期，是否有时间戳。
  	iii. 检查证书是否被吊销。
  	iv. 验证文件是否使用“弱”哈希算法进行了签名。
  	v. 如果文件是指定为 "Windows 系统证书签名的组件验证 "(EKU-1.3. 6.1. 4.1. 311.10.3. 6), 则验证签名证书链到一组固定的受信任的 Microsoft 根证书。
7. 诊断策略：
  a. 此可选步骤旨在帮助信任提供程序开发人员进行调试。它的目的是让微软的开发者在返回到 WinVerifyTrust 之前可以把结构体内容dump出来。
  b. `WINTRUST_ACTION_TRUSTPROVIDER_TEST`是实现此步骤的唯一信任提供程序。`WINTRUST_ACTION_TRUSTPROVIDER_TEST`和`WINTRUST_ACTION_GENERIC_VERIFY_V2`是相同的，不过它是实现`wintrust!SoftpubDumpStructure`的一个额外步骤。`SoftpubDumpStructure`将填充的 `CRYPT_DATA_PROVIDER` 结构转储到 `C:\TRUSTPOL.txt`。从命令提示符(需要有写入c盘的权限)使用 signtool.exe (在 Windows SDK 中) 可以轻松地测试此步骤。指定WINTRUST_ACTION_TRUSTPROVIDER_TEST (认证码测试) 信任提供程序的GUID:
  i.  signtool verify /pg {573E31F8-DDBA-11D0-8CCB-00C04FC295EE} filename.exe
8. 清理：
  a. 在此可选步骤中, 信任提供程序可以清除所有已填充的 `CRYPT_PROVIDER_PRIVDATA`结构体, 以便跨信任提供程序步骤传递特定策略的数据。

[1]:https://msdn.microsoft.com/en-us/library/dd878324(v=vs.85).aspx	"PowerShell脚本模块"
[2]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388208(v=vs.85).aspx	"WinVerifyTrust"
[3]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542590(v=vs.85).aspx	"CryptSIPRetrieveSubjectGuid"
[4]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa379927(v=vs.85).aspx
[5]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542636(v=vs.85).aspx
[6]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542640(v=vs.85).aspx
[7]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542585(v=vs.85).aspx
[8]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542591(v=vs.85).aspx
[9]:https://msdn.microsoft.com/en-us/library/windows/desktop/bb736433(v=vs.85).aspx
[10]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa377540(v=vs.85).aspx
[11]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa381453(v=vs.85).aspx
[12]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388205(v=vs.85).aspx

