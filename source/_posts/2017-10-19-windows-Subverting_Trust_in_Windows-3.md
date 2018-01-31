---
layout: post
category: "Win"
title:  "[翻译]颠覆windows的信任体系(3)"
date: 2017/10/19 20:19:05
tags: [Win,Trust,certificate]
---
## 信任提供者和SIP注册

了解信任提供者和 sip 在注册表中注册的合法方法, 以便了解攻击者如何利用注册过程 (或完全颠覆它)，这非常重要。

### SIP 注册
SIP通过调用[DllRegisterServer][1]的导出函数“wintrust!
[CryptSIPAddProvider][2]”来完成注册。这使得SIP可以通过调用 “regsvr32.exe SIPfilename.dll” 来完成注册。CryptSIPAddProvider 需要 [SIP_ADD_NEWPROVIDER][3] 结构体, 它由在实现签名功能的SIP DLL中的导出函数组成。需要以下SIP_ADD_NEWPROVIDER字段：

1. pwszDLLFileName:
  SIP DLL 的名称。这可能只是文件名, 但它应该是完整的路径。
2. pwszGetFuncName:
  实现[CryptSIPGetSignedDataMsg][4]的导出函数名
3. pwszPutFuncName:
  实现[CryptSIPPutSignedDataMsg][5]的导出函数名
4. pwszCreateFuncName:
  实现[CryptSIPCreateIndirectData][6]的导出函数名
5. pwszVerifyFuncName:
  实现[CryptSIPVerifyIndirectData][7]的导出函数名
6. pwszRemoveFuncName:
  实现[CryptSIPRemoveSignedDataMsg][8]的导出函数名

下列 SIP_ADD_NEWPROVIDER 字段是可选的：
1. pwszIsFunctionNameFmt2:
  实现[pfnIsFileSupportedName][9]
2. pwszGetCapFuncName:
  实现[pCryptSIPGetCaps][10]
3. pwszIsFunctionName:
  实现[pfnIsFileSupported][11]

在调用 CryptSIPAddProvider 时, wintrust.dll 将各自的导出函数名和实现 dll 添加到
`HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\OID\EncodingType 0`
注册表子键中。
SIP dll 还应实现 [DllUnregisterServer][12] 注销功能, 该函数调用 [CryptSIPRemoveProvider][13]删除所有相关的 SIP 注册表项。

### 信任提供者注册

信任提供者通过调用 DllRegisterServer的导出函数wintrust[WintrustAddActionID][14]实现。这使得信任提供者可以通过调用 "regsvr32.exe TrustProviderfilename.dll" 来正式注册。 WintrustAddActionID 需要一个
 [CRYPT_REGISTER_ACTIONID][15]——由在执行所有信任验证步骤的信任提供程序 DLL 中的导出函数组成的结构体,。信任提供程序注册功能可以与 SIP 注册的函数共享, 也可以在专用 DLL 中独立。

在调用 WintrustAddActionID 时, wintrust.dll 将各自的导出函数名和实现 dll 添加到
`HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\Providers\Trust`
注册表子键中。
信任提供者通过调用DllUnregisterServer的导出函数 wintrust! [WintrustRemoveActionID][16] 来取消注册。

### 信任提供者和 SIP 注册示例
最重要的信任提供者注册位于wintrust！DllRegisterServer中，执行以下注册步骤：
1. 调用 WintrustDllRegisterServer
  a.  调用 wintrust!CryptRegisterOIDFunction函数，使用CryptEncodeObject 和 CryptDecodeObject注册 ASN.1编码/解码例程。这类的许多函数在创建数字签名时被调用。在分析数字签名以进行验证时, 通常会调用它们的解码对应函数。与 SIP 和信任提供程序注册一样, 这些实现函数也存储在注册表中：
  - HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\OID\\EncodingType1\\[CryptDllDecodeObject|CryptDllEncodeObject]

  所有这些编码函数都接受以下函数签名:
  - BOOL WINAPI EncoderDecoderFunction(DWORD
    dwCertEncodingType, LPCSTR lpszStructType,
    PSPC_PE_IMAGE_DATA pInfo, BYTE *pbEncoded, DWORD
    *pcbEncoded);

  WintrustDllRegisterServer 注册以下编码/解码例程:

  i. 1.3.6.1.4.1.311.2.1.15 (SPC_PE_IMAGE_DATA_OBJID)
  函数: wintrust!WVTAsn1SpcPeImageDataEncode
  ii.  1.3.6.1.4.1.311.2.1.25 (SPC_CAB_DATA_OBJID)
  函数: wintrust!WVTAsn1SpcLinkEncode
  iii.  1.3.6.1.4.1.311.2.1.20 (SPC_JAVA_CLASS_DATA_OBJID)
  函数: wintrust!WVTAsn1SpcLinkEncode
  iv.  1.3.6.1.4.1.311.2.1.28 (SPC_LINK_OBJID)
  函数: wintrust!WVTAsn1SpcLinkEncode
  v.  1.3.6.1.4.1.311.2.1.30 (SPC_SIGINFO_OBJID)
  函数: wintrust!WVTAsn1SpcSigInfoEncode
  vi.  1.3.6.1.4.1.311.2.1.4 (SPC_INDIRECT_DATA_OBJID)
  函数: wintrust!WVTAsn1SpcIndirectDataContentEncode
  vii.  1.3.6.1.4.1.311.2.1.10 (SPC_SP_AGENCY_INFO_OBJID)
  函数: wintrust!WVTAsn1SpcSpAgencyInfoEncode
  viii.  1.3.6.1.4.1.311.2.1.26 (SPC_MINIMAL_CRITERIA_OBJID)
  函数: wintrust!WVTAsn1SpcMinimalCriteriaInfoEncode
  ix.  1.3.6.1.4.1.311.2.1.27 (SPC_FINANCIAL_CRITERIA_OBJID)
  函数: wintrust!WVTAsn1SpcFinancialCriteriaInfoEncode
  x.  1.3.6.1.4.1.311.2.1.11 (SPC_STATEMENT_TYPE_OBJID)
  函数: wintrust!WVTAsn1SpcStatementTypeEncode
  xi.  1.3.6.1.4.1.311.12.2.1 (CAT_NAMEVALUE_OBJID)
  函数: wintrust!WVTAsn1CatNameValueEncode
  xii.  1.3.6.1.4.1.311.12.2.2 (CAT_MEMBERINFO_OBJID)
  函数: wintrust!WVTAsn1CatMemberInfoEncode
  xiii.  1.3.6.1.4.1.311.12.2.3 (CAT_MEMBERINFO2_OBJID)
  函数: wintrust!WVTAsn1CatMemberInfo2Encode
  xiv.  1.3.6.1.4.1.311.2.1.12 (SPC_SP_OPUS_INFO_OBJID)
  函数: wintrust!WVTAsn1SpcSpOpusInfoEncode
  xv.  1.3.6.1.4.1.311.2.4.2 (szOID_INTENT_TO_SEAL)
  函数: wintrust!WVTAsn1IntentToSealAttributeEncode
  xvi.  1.3.6.1.4.1.311.2.4.3 (szOID_SEALING_SIGNATURE)
  函数: wintrust!WVTAsn1SealingSignatureAttributeEncode
  xvii.  1.3.6.1.4.1.311.2.4.4 (szOID_SEALING_TIMESTAMP)
  函数: wintrust!WVTAsn1SealingTimestampAttributeEncode

2. 接下来, SoftpubDllRegisterServer 调用 WintrustAddActionID 来注册下列信任提供者:
    a. WINTRUST_ACTION_GENERIC_VERIFY_V2
    b. WIN_SPUB_ACTION_PUBLISHED_SOFTWARE
    c. WIN_SPUB_ACTION_PUBLISHED_SOFTWARE_NOBADUI
    d. WINTRUST_ACTION_GENERIC_CERT_VERIFY
    e. WINTRUST_ACTION_TRUSTPROVIDER_TEST
    f. HTTPSPROV_ACTION. 下面的相关[默认 "用法"][17] 也注册 (全部存储在注册表`HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\Providers\Trust\Usages`中):
    ​	 i. 1.3.6.1.4.1.311.10.3.3 (szOID_SERVER_GATED_CRYPTO)
    ​	    Alloc/dealloc 函数: wintrust!SoftpubLoadDefUsageCallData
    ​	ii. 1.3.6.1.5.5.7.3.1 (szOID_PKIX_KP_SERVER_AUTH)
    ​	    Alloc/dealloc 函数: wintrust!SoftpubLoadDefUsageCallData
    ​	iii. 1.3.6.1.5.5.7.3.2 (szOID_PKIX_KP_CLIENT_AUTH)
    ​	    Alloc/dealloc 函数: wintrust!SoftpubLoadDefUsageCallData
    ​	iv. 2.16.840.1.113730.4.1 (szOID_SGC_NETSCAPE)
    ​	    Alloc/dealloc 函数: wintrust!SoftpubLoadDefUsageCallData
    g. DRIVER_ACTION_VERIFY
    h. WINTRUST_ACTION_GENERIC_CHAIN_VERIFY

3. 最后, mssip32DllRegisterServer 被调用来注册SIP。具体来说, 调用 CryptSIPAddProvider 来注册以下SIP:
  a. DE351A42-8E59-11D0-8C47-00C04FC295EE
  ​    CRYPT_SUBJTYPE_FLAT_IMAGE
  b. C689AABA-8E78-11d0-8C47-00C04FC295EE
  ​    CRYPT_SUBJTYPE_CABINET_IMAGE
  c. C689AAB8-8E78-11D0-8C47-00C04FC295EE
  ​    CRYPT_SUBJTYPE_PE_IMAGE
  d. DE351A43-8E59-11D0-8C47-00C04FC295EE
  ​    CRYPT_SUBJTYPE_CATALOG_IMAGE
  e. 9BA61D3F-E73A-11D0-8CD2-00C04FC295EE
  ​    CRYPT_SUBJTYPE_CTL_IMAGE

4. mssip32DllRegisterServer 还显式注销了以下 sip (实际上, Java SIP 组件保留在windows默认的注册表中):

  a. C689AAB9-8E78-11D0-8C47-00C04FC295EE

  ​    CRYPT_SUBJTYPE_JAVACLASS_IMAGE

  b. 941C2937-1292-11D1-85BE-00C04FC295EE

  ​    [CRYPT_SUBJTYPE_SS_IMAGE][18]

虽然不建议这样做, 但所有 wintrust 的信任提供程序和 SIP 注册都可以使用以下命令 (从提升权限的命令提示符中) 正式注销：
`regsvr32.exe /u C:\Windows\System32\wintrust.dll`
运行上述命令将剥离 Windows 在用户模式下的 执行大多数数字签名检索和信任验证的用户模式的能力。

## 信任提供者和 SIP 交互
虽然在前面的 "消息" 信任提供者步骤中提到了 SIP 和信任提供者之间的交互, 不过按顺序说明所有步骤的图表应该更有用吧。
![WinVerifyTrust、信任提供者和SIP之间的交互说明](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-5.png)
*WinVerifyTrust、信任提供者和SIP之间的交互说明*
希望到目前为止, 对信任提供者和SIP的角色有一个基本的了解, 以及它们的体系架构在很大程度上是通过注册注册表来实现模块化的。在下一节中, 将讨论对 Windows 信任体系结构的模块化的攻击。

[1]:https://msdn.microsoft.com/en-us/library/windows/desktop/ms682162(v=vs.85).aspx
[2]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa380283(v=vs.85).aspx
[3]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa387767(v=vs.85).aspx
[4]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542585(v=vs.85).aspx
[5]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542587(v=vs.85).aspx
[6]:https://msdn.microsoft.com/en-us/library/windows/desktop/bb736358(v=vs.85).aspx
[7]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542591(v=vs.85).aspx
[8]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542589(v=vs.85).aspx
[9]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542640(v=vs.85).aspx
[10]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542640(v=vs.85).aspx
[11]:https://msdn.microsoft.com/en-us/library/windows/desktop/cc542636(v=vs.85).aspx
[12]:https://msdn.microsoft.com/en-us/library/windows/desktop/ms691457(v=vs.85).aspx
[13]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa380284(v=vs.85).aspx
[14]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388196(v=vs.85).aspx
[15]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa381463(v=vs.85).aspx
[16]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388199(v=vs.85).aspx
[17]:https://msdn.microsoft.com/en-us/library/windows/desktop/hh802766(v=vs.85).aspx
[18]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa380369(v=vs.85).aspx

