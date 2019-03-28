---
layout: post
category: "Win"
title:  "[翻译]颠覆windows的信任体系(5)"
date: 2017/10/20 21:46:25
tags: [Win,Trust,certificate]
---
### 绕过 UMCI 设备保护 执行

在应用程序白名单方案中, 使用未经签名的/未经批准的二进制文件来验证信任的机制，构成了一个 "鸡和蛋" 问题，即需要根据部署的恶意 SIP DLL 的信任来验证白名单政策。结果是, 至少使用设备保护,系统将无法加载恶意的 SIP DLL, 不过这将导致信任验证在许多情况下失败。这可以理解地有可能导致系统稳定性问题。理想情况下 (对于攻击者) 将有一个可以为 CryptSIPVerifyIndirectData 角色提供服务的签名 DLL。幸运的是，回想一下，CryptSIPVerifyIndirectData 函数接受以下函数签名：

```c
BOOL WINAPI CryptSIPVerifyIndirectData(
	IN SIP_SUBJECTINFO *pSubjectInfo,
	IN SIP_INDIRECT_DATA *pIndirectData);
```

此外, 为了通过验证检查, 函数必须返回 TRUE。因此, 我们面临以下要求, 以产生一个签名的CryptSIPVerifyIndirectData 函数：

1. Dll文件必须有签名；
2. 函数必须接受两个参数；
3. 函数必须使用WINAPI/stdcall 调用规范；
4. 函数必须返回TRUE（通常为非零数或者奇数）；
5. 函数不能改变传入的参数, 因为这可能导致内存损坏；
6. 除了返回 "TRUE" 之外, 该函数最好没有其他意料之外的影响；
7. 函数必须导出。

毫无疑问, 这样一个查找候选函数的过程可以通过将函数转换为中间语言来进行自动分析, 而不需要很长时间就能找到候选输出函数-ntdll!DbgUiContinue:

![ntdll!DbgUiContinue的反汇编及注释](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-18.png)

*ntdll!DbgUiContinue的反汇编及注释*

只需将目标 SIP 的 CryptSIPVerifyIndirectData 注册表项设置为 `C:\Windows\System32\ntdll.dll` 和 `DbgUiContinue`，就足以通过对任何应用了合法的嵌入校验码签名的代码进行哈希校验检查。实际上，在对强制启用设备保护的系统上的可执行文件 SIP 进行测试时, 攻击者提供的代码被阻止执行。但是, 劫持 PowerShell SIP 启用了受约束的语言模式绕过, 从而实现了任意的、无签名的代码执行。不过，对于使用可执行文件与 PowerShell 代码进行的其他 (可能是内核支持的) 信任断言, 还不清楚。也有可能存在比DbgUiContinue更好用的劫持函数 , 但这足以证明攻击者提供的无签名的 SIP DLL足够可以用来劫持。

下面的示例演示了PowerShell在启用了设备保护的约束语言模式下，防止在发生劫持事件之前执行添加类型，并防止 CryptSIPVerifyIndirectData 在被劫持之后进行后续旁路操作:

![在劫持之前，由于受限的语言模式，test.psm1中的代码将被阻止执行](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-19.png)

*在劫持之前，由于受限的语言模式，test.psm1中的代码将被阻止执行*

![在 "签名代码重用" 攻击发生之后，将绕过受约束的语言模式。](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-20.png)

*在 "签名代码重用" 攻击发生之后，将绕过受约束的语言模式。*

尽管这种形式的劫持并不代表完全接管强制设备保护用户模式完整性 (UMCI)，但它确实从隐形角度提出了一种良好的劫持方法，因为它不需要攻击者将任何恶意代码丢弃到磁盘-即攻击者提供 SIP。

### 信任提供者“最终策略”（FinalPolicy ）劫持

正如在 "信任提供者体系架构" 部分中所描述的那样, 最终的信任决策由信任提供程序的 `最终策略`组件进行。这是 FinalPolicy 的函数签名:

```c
HRESULT WINAPI FinalPolicyFunction(_Inout_ struct _CRYPT_PROVIDER_DATA *pProvData);
```

FinalPolicy 为各自的信任提供者实现功能，其位于这里：

`HKLM\SOFTWARE\[WOW6432Node\]Microsoft\Cryptography\Providers\Trust\FinalPolicy\{trust provider GUID}`

虽然攻击者可以选择实现自己的信任提供程序 DLL 来颠覆 FinalPolicy，但这需要攻击者将恶意代码在硬盘落地。此外, 与 SIP 相比, 完全实现信任提供者的接口比较复杂。不过，如前所述，可以用已签名代码来劫持 FinalPolicy，以此来模拟传递其所有检查。备选的已签名的劫持函数需要满足以下要求：

1. DLL 必须有签名；
2. 函数必须只接受一个参数；
3. 函数必须使用WINAPI/stdcall 调用规范；
4. 函数的返回结果必须是 0 (S_OK) ，以表示HRESULT成功；
5. 函数不能改变传入的参数, 因为这可能导致内存损坏；
6. 除了返回 0之外, 该函数最好没有别的影响；
7. 函数必须被导出。

未实现的导出函数 wintrust!SoftpubCleanup 满足了执行劫持的所有要求。

![SoftpubCleanup函数的反汇编](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-21.png)

*SoftpubCleanup函数的反汇编*

转化为C语言的话，等效于下面的内容：

```c
HRESULT WINAPI SoftpubCleanup(CRYPT_PROVIDER_DATA *data)
{
	return S_OK;
}
```

例如, 设置 WINTRUST_ACTION_GENERIC_VERIFY_V2 (00AAC56B-CD44-11D0-8CC2-00C04FC295EE)
 的 FinalPolicy 组件将导致许多签名验证工具 (如AuthenticodeSignature、sigcheck、signtool 等)认为未签名的代码或应用合法签名的代码作为受信任的。在实践中, 使用 SoftpubCleanup 执行此劫持会导致进程资源管理器 (procexp)必现崩溃。

### 躲避Autoruns的检测

将合法的 microsoft 校验码数字签名应用于攻击者提供的代码劫持目标 SIP 的 CryptSIPVerifyIndirectData 组件的额外影响是, 默认情况下, 它将从启动中隐藏, 而不显示 "microsoft" 或 "Windows"项。

随着可执行程序 SIP 劫持完成，默认情况下，一个持久的攻击者提供的 EXE 不会出现：

![在Autoruns的默认视图中看不到notepad_backdoored.exe](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-22.png)

*在Autoruns的默认视图中看不到notepad_backdoored.exe*



但是, 当 取消选择"隐藏 Microsoft 条目" 和 "隐藏 Windows 条目" 时, Run 键中的恶意条目将变为可见：

![确认只有在取消选择 "隐藏 Windows 条目" 时才会出现 notepad_backdoored.exe](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-23.png)

*确认只有在取消选择 "隐藏 Windows 条目" 时才会出现 notepad_backdoored.exe*



### 持久化和代码执行

了解了如何劫持 SIP和信任提供者，应该清楚的是，除了颠覆信任之外，这些劫持攻击还允许在执行代码签名或签名验证的任何应用程序的上下文中执行代码。通过实现 SIP 或信任提供程序，代码可能在下列列表的程序中执行：

1.  DllHost.exe——当在文件属性中显示“数字签名”标签时
2.  Process Explorer——当显示“签名校验”标签时
3.  Autoruns
4.  Sigcheck
5.  consent.exe——任何时候显示UAC弹窗时
6.  signtool.exe
7.  smartscreen.exe
8.  Get-AuthenticodeSignature
9.  Set-AuthenticodeSignature
10.  基于对 WinVerifyTrust 的调用执行证书验证的安全供应商软件

可以通过在进程监视器（Process Monitor）中筛选下列注册表项路径来发现其他的代码执行和持久化：

 - HKLM\SOFTWARE\Microsoft\Cryptography\Providers
 - HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Providers
 - HKLM\SOFTWARE\Microsoft\Cryptography\OID
 - HKLM\SOFTWARE\WOW6432Node\Microsoft\Cryptography\OID

在使用攻击者提供的代码劫持信任提供程序时，出于稳定性考虑，一种可能的是将恶意逻辑作为 "诊断策略(DiagnosticPolicy)"  组件的一部分来实现, 以不影响合法的信任功能。

当试图在 SIP 的上下文中获取代码执行时, 一种获取代码执行考虑可能是在 "CryptSIPDllIsMyFileType" 组件中实现恶意逻辑， 并返回 "FALSE"，表示其他 "CryptSIPDllIsMyFileType" 和 "CryptSIPDllIsMyFileType2 "组件应该被调用，以确定哪个 SIP 代表了有问题的文件。然而, 要注意的是, 任何武器化方案都有它自己独特的一套指标或折中方案来确保恶意代码可以被签名。

最后一个考虑是, SIP 和信任提供者 dll 不需要在注册表中指定它们的完整路径。如果只指定了 SIP 或信任提供程序文件名, 则通过标准的 DLL 加载顺序来加载它。这使攻击者能够在不需要修改注册表的情况下劫持现有的 SIP/信任提供程序 dll。例如, 在 Windows 10 中, Microsoft Office SIP VBA 宏 sip (9FA65764-C36F-4319-9737-658A34585BB7) 只使用其文件名注册 (仅限 WoW64): mso.dll。此外, 仅在指定了 "mso.dll" 的文件名的情况下, 在执行用户模式信任验证的任何代码中都有可能出现泛型 dll 加载顺序劫持漏洞。

### 颠覆 CryptoAPI v2 (CAPI) 事件日志

虽然默认情况下未启用，但是启用 Microsoft-Windows-CAPI2/Operational 事件日志可能是获取失败的信任验证相关的上下文信息的宝贵来源。每当调用 WinVerifyTrust 时，都会生成 EID 81，如果签名或信任验证失败, 则事件将被填充为错误。例如, 以下是与 "notepad_backdoored" 的失败的信任验证相关的事件详细信息，它具有合法的 Microsoft 认证数字签名 (相关部分加粗)：

![](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-24.png)

上面的事件是一个 "错误" 事件。在本例中, 如果可执行程序 SIP 的 CryptSIPVerifyIndirectData 组件被劫持, 则 WinVerifyTrust 事件仍将被记录, 但作为 "信息" 事件表示信任验证成功：![](/uploads/img/Subverting_Trust_in_Windows/Subverting_Trust_in_Windows-24.png)

因此, 虽然 Microsoft-Windows-CAPI2/Operational 事件日志可以提供有价值的攻击上下文 (主要是文件路径和验证过程的名称)信息，但它的预期行为可以被信任验证攻击来破坏掉。

### 攻击操作注意事项

以下建议旨在帮助在实现恶意 SIP 时缓解检被检测到的可能性：

- 如果 SIP被用来劫持现有的 SIP功能，请实现与您劫持的函数相同的函数名，这样就没必要再更改 "FuncName" 注册表值了。
- 虽然建议不要将合法的 SIP 二进制文件替换为你自己的 (例如 wintrust.dll)，但最好让你的SIP  dll 与被劫持的dll 同名。除了具有相对路径 (例如 WoW64  mso.dll) 的 SIP 注册之外，还需要更改 "dll" 注册表值。更改 "dll" 值的最不可疑的方法是更改从 "dll" 中剥离文件路径，并把自己的 SIP Dll 放在目标应用程序的当前目录中。 例如, 将 "C:\Windows\System32\WINTRUST.dll" 更改为 "WINTRUST.dll"。请注意， wintrust.dll 不存在于 [KnownDlls](https://blogs.msdn.microsoft.com/larryosterman/2004/07/19/what-are-known-dlls-anyway/) 中。
- 如果实现完整的 SIP (如具有适当的注册/注销功能), 请注意与 SIP 操作相关的函数相对容易生成Yara签名。考虑直接通过注册表执行 SIP 注册/劫持。例如, 以下导入将为一个良好的Yara 规则：
   - CryptSIPAddProvider
   - CryptSIPRemoveProvider
   - CryptSIPLoad
   - CryptSetOIDFunctionValue
   - CryptRegisterOIDFunction
- 如果你的SIP DLL直接操作注册表的`Microsoft\Cryptography\OID`键值，则需要混淆下子键的路径。
- 对于计划使用 SIP dll 劫持的合法 dll，请将其校验码签名应用于二进制文件。尽管存在哈希不匹配，理想情况下，仍可以劫持 CryptSIPVerifyIndirectData SIP 组件来缓解此问题。需要注意的是，许多系统二进制文件都是编录签名的。不过你也可以将编录签名应用于内嵌的校验码签名。 应用同一证书将产生相同的指纹计算，并绕过安全产品可能执行的一些简单检查。
- 如果要注册一个新的 SIP GUID，请使用以前定义过的一个但是当前未注册的文件，并应用与所使用的SIP GUID 相同的文件名和导出函数名称。例如, Silverlight 具有以下 GUID 的 SIP: BA08A66F-113B-4D58-9329-A1B37AF30F0E

   - 文件名：xapauthenticodesip.dll
   - 导出函数：XAP_CryptSIPCreateIndirectData, XAP_CryptSIPGetSignedDataMsg, XAP_CryptSIPPutSign
     edDataMsg,XAP_CryptSIPRemoveSignedDataMsg,XAP_CryptSIPVerifyIndirectData,XAP_IsFileSupportedName