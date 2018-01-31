---
layout: post
category: "Win"
title:  "[翻译]颠覆windows的信任体系(4)"
date: 2017/10/19 23:33:53
tags: [Win,Trust,certificate]
---
## Windows 信任体系架构攻击
---
通过对 Windows 用户模式信任体系结构的基本了解以及较高的权限级别, 攻击者拥有了他需要破坏信任体系的武器。那么攻击者通过颠覆信任可以来实现什么呢？
1. 让操作系统相信攻击者提供的代码是以 "受信任的" 代码签名证书 (例如, 用于签名 Microsoft 代码的) 签名和验证的。这种攻击背后的动机是:
  a. 使安全产品将攻击者提供的代码分类为良性。
  b. 从执行签名验证的安全/诊断工具中隐藏。
  c. 一般情况下，在实时检测工具之下，安全人员可能更容易忽略 "使用合法证书签名" 的代码。
  d. 在执行用户模式信任验证的任何进程的上下文中加载恶意代码。
2. 颠覆应用程序强制基于可信签名权限策略的白名单发布规则。发布者强校验是最常见的名单规则方案之一,因为它甚至允许受信任发布者签名的代码可以绕过不允许软件更新的哈希规则而更新、执行，这种情况下更难维护和审核。
### SIP 劫持 #1: CryptSIPDllGetSignedDataMsg
如前所述,SIP的CryptSIPDllGetSignedDataMsg组件是允许从已签名的文件中检索编码的数字证书的。再次提醒下,SIP的CryptSIPDllGetSignedDataMsg组件的已实现导出功能存在于以下注册表项中:
- HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllGetSignedDataMsg\\**{SIP Guid}**
  - Dll -实现数字签名检索函数的 DLL 的路径
  - FuncName -实现数字签名检索功能的导出函数的名称

此外, 如前所述, CryptSIPDllGetSignedDataMsg 函数具有以下原型:
```c
BOOL WINAPI CryptSIPGetSignedDataMsg(
	IN SIP_SUBJECTINFO *pSubjectInfo,
	OUT DWORD *pdwEncodingType,
	IN DWORD dwIndex,
	IN OUT DWORD *pcbSignedDataMsg,
	OUT BYTE *pbSignedDataMsg);
```
任何熟悉 c/c++ 的攻击者都能够轻松地实现此类功能, 并将现有的 SIP 条目替换为其恶意功能。首先, 了解每个参数的含义是很重要的：
1. pSubjectInfo:从调用信任提供者传入的结构体指针, 包含有关提取签名的文件的所有相关信息。这里是一个例子：传递给 pwrshsip!PsGetSignature (PowerShell SIP的 CryptSIPDllGetSignedDataMsg组件)结构体的转储(dump):
  ![pSubjectInfo dump](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-6.png)
2. pdwEncodingType:在从pSubjectInfo中指定的文件检索数字签名时,此参数指示调用函数(信任提供者"消息"组件)如何正确解码返回数字签名。最常见是的PKCS_7_ASN_ENCODING 和 X509_ASN_ENCODING 一起进行二进制或运算 。
3. dwIndex: 此参数应为零, 但理论上 SIP 可以包含多个嵌入的签名, dwIndex 表示从指定文件中提取哪一个数字签名。
4. pcbSignedDataMsg: 通过 pbSignedDataMsg 返回的数字签名的长度 (以字节为单位)。
5. pbSignedDataMsg: 返回到调用信任提供程者的已编码的数字签名。

因此,如果攻击者要实现此功能并使用它作为示例,来覆盖可执行文件的SIP(C689AAB8-8E78-11D0-8C47-00C04FC295EE)的CryptSIPDllGetSignedDataMsg组件,则任何 PE 文件都可能返回攻击者选择的任意数字签名。

想象一下下面虚构的攻击场景:
1. 攻击者在注册表中实现了可执行文件SIP的CryptSIPDllGetSignedDataMsg组件。

2. 简单地说, 无论是否有嵌入的验证码签名, 为任何可执行文件返回相同的 Microsoft 证书。

3. 为了确保返回适当格式的数字签名,最好在对其进行劫持之前在调试器中的合法CryptSIPDllGetSignedDataMsg上设置断点。这样做可以确保PKCS#7认证签名数据始终可以正确地返回。

   a. 在 PowerShell 脚本中, 这涉及 base64 解码 "SIG # 开始签名块"（SIG # Begin signature block）。
   b. 在带有嵌入验证码签名的PE文件中, PKCS #7 校验签名的数据存在于[PE校验码规范(PE Authenticode specification)](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)中所记录的嵌入式[WIN_CERTIFICATE][1]结构体的bCertificate 字段中。
   c. 编录文件本身就是 PKCS #7 校验码签名的数据 (实际上可以在嵌入的 PE 校验码签名中使用)。
4. 现在, 攻击者的实现只需要返回正确的编码签名数据长度和签名数据。

在这种攻击场景中,被劫持的CryptSIPDllGetSignedDataMsg可以返回用于签署许多系统组件(如notepad.exe)的目录文件的字节。为了方便地确定与已签名文件关联的编录文件,可以使用 sigcheck.exe:
`sigcheck -i C:\Windows\System32\notepad.exe`
在当前的例子中，返回下面的编录文件路径：
`C:\WINDOWS\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Client-Features-Package-AutoMerged-shell~31bf3856ad364e35~amd64~~10.0.15063.0.cat`
现在,攻击者实现只需要从该编录文件返回字节,使任何PE文件看起来都使用了与notepad.exe相同的证书进行签名。模块化设计方法是将所需的签名内容嵌入到攻击者提供的SIP DLL中的资源中。
下面的示例说明了 PowerShell SIP CryptSIPDllGetSignedDataMsg 组件是如何使用自定义的恶意 SIP来劫持的, 它将始终返回与 PowerShell 文件相同的合法 Microsoft 证书:
![PowerShell CryptSIPDllGetSignedDataMsg 劫持的演示](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-7.png)
*PowerShell CryptSIPDllGetSignedDataMsg 劫持的演示*

可以看出, 在劫持之前, 不出所料，test.ps1 显示为未签名。然而, 在劫持发生后,test.ps1 似乎是用 Microsoft 证书签名的：
![一个未经签名的 PowerShell 脚本, 似乎突然间就被微软给签名了](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-8.png)
*一个未经签名的 PowerShell 脚本, 似乎突然间就被微软给签名了*

![虽然未签名的 PowerShell 脚本看起来由 Microsoft 签名了, 但它的哈希验证并没有通过。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-9.png)
*虽然未签名的 PowerShell 脚本看起来由 Microsoft 签名了, 但它的哈希验证并没有通过。*

虽然看起来劫持是成功的, 但有一个缺陷-签名无法验证, 因为计算的哈希与数字签名中的已签名哈希不匹配。此劫持的另一个不良影响是,任何PowerShell代码都将使用相同的数字签名, 这将在大多数情况下导致哈希不匹配。

为了防止信任验证因哈希不匹配而失败, 还需要劫持CryptSIPDllVerifyIndirectData 。

### SIP 劫持 #2: CryptSIPDllVerifyIndirectData

正如前面的劫持场景中所解释的,劫持已注册SIP的CryptSIPDllGetSignedDataMsg组件允许未经签名的代码看起来像是被签名了。但是,考虑到哈希值不匹配,数字签名将无法在攻击者提供的代码上进行验证。然而, 再劫持 CryptSIPDllVerifyIndirectData 下函数就不存在这个问题了。
再次提醒下， CryptSIPDllVerifyIndirectData 实现存储在以下注册表值中:
 - HKLM\\SOFTWARE\\[WOW6432Node\\]Microsoft\\Cryptography\\OID\\EncodingType 0\\CryptSIPDllVerifyIndirectData\\{SIP Guid}
  - Dll
  - FuncName

函数原型：
```c
BOOL WINAPI CryptSIPVerifyIndirectData(
	IN SIP_SUBJECTINFO *pSubjectInfo,
	IN SIP_INDIRECT_DATA *pIndirectData);
```
调试CryptSIPVerifyIndirectData的合法实现，可以确认当计算出的验证码哈希与签名的哈希值匹配时,CryptSIPVerifyIndirectData返回TRUE。因此,所有恶意SIP需要做的就是为被劫持的相应SIP匹配生成，返回TRUE,从而使之看起来可以通过哈希验证。继续执行PowerShell劫持示例,恶意SIP仅为哈希验证例程返回true,将解决攻击者提供的代码无法正确验证的问题。

```c
BOOL WINAPI AutoApproveHash(SIP_SUBJECTINFO *pSubjectInfo,SIP_INDIRECT_DATA *pIndirectData) {
	UNREFERENCED_PARAMETER(pSubjectInfo);
	UNREFERENCED_PARAMETER(pIndirectData);
	return TRUE;
}
```

接下来, 劫持哈希验证处理程序 (连同以前的劫持签名检索功能) 将通过所有的检查, 将未经签名的 PowerShell 代码伪装为已签署Microsoft的代码:

![劫持 PowerShell SIP 的 CryptSIPVerifyIndirectData 组件](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-10.png)
*劫持 PowerShell SIP 的 CryptSIPVerifyIndirectData 组件*

![现在, 未签名的 PowerShell 文件出现签名并经过正确验证](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-11.png)

*现在, 未签名的 PowerShell 文件出现签名并经过正确验证*

!["数字签名" UI 选项卡显示一个未签名的 PowerShell 文件, 它显示签名并经过正确验证。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-12.png)

*"数字签名" UI 选项卡显示一个未签名的 PowerShell 文件, 它显示签名并经过正确验证。*

![Sysinternals sigcheck 显示一个未签名的 PowerShell 文件, 它显示签名并经过正确验证。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-13.png)

*Sysinternals sigcheck 显示一个未签名的 PowerShell 文件, 它显示签名并经过正确验证。*

一个更理想的劫持场景是甚至懒得劫持 CryptSIPDllGetSignedDataMsg 的目标 SIP。 相反, 只需应用合法的验证码签名 (例如 从 C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ISE\ise.psm1) 到攻击者提供的代码, 并只劫持 CryptSIPVerifyIndirectData。这样做为攻击者提供了以下好处:

1. 有更少的劫持和清理工作；
2. 良性、合法签名的代码将正确应用其各自的签名；
3. 攻击者提供的带有 "合法" 的嵌入式校验码证书的代码很可能会受到安全产品的严格审查。

![test.ps1 具有和ise.psm1相同的嵌入式校验码签名, 并且证书指纹值相匹配](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-14.png)

*test.ps1 具有和ise.psm1相同的嵌入式校验码签名, 并且证书指纹值相匹配*

虽然目前为止示例集中在 PowerShell SIP 上, 但这些劫持原则适用于所有SIP。下面是一个被劫持的可执行文件的SIP (C689AAB8-8E78-11D0-8C47-00C04FC295EE) 的示例, 它将合法的 Microsoft 数字签名应用于攻击者提供的二进制文件上:

![notepad_backdoored.exe拥有应用于本属于notepad.exe (编录签名) 的数字签名](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-15.png)

*notepad_backdoored.exe拥有应用于本属于notepad.exe (目录签名) 的数字签名*



!["数字签名" UI 选项卡还确认攻击者-suppled notepad_backdoored. exe 验证为已签名的 Microsoft 文件。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-16.png)

*"数字签名" UI 选项卡还确认攻击者-suppled notepad_backdoored. exe 验证为已签名的 Microsoft 文件。*

此劫持将骗过任何执行用户模式信任/签名验证的程序, 包括 Sysinternals 的Process Explorer：

![notepad_backdoored.exe 在 Sysinternals 的Process Explorer中显示为“已验证签名"。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-17.png)

*notepad_backdoored.exe 在 Sysinternals 的Process Explorer中显示为“已验证签名"。*

[1]:https://msdn.microsoft.com/en-us/library/windows/desktop/dn582059(v=vs.85).aspx



