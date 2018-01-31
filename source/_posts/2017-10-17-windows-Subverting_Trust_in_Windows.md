---
layout: post
category: "Win"
title:  "[翻译]颠覆windows的信任体系(1)"
date: 2017/10/17 20:56:24
tags: [Win,Trust,certificate]
---

## 背景
在计算机安全领域，什么是信任呢？现代安全解决方案——遇到恶意代码或者恶意操作弹个窗提示下——提供的隐含的安全感？还是企业里对某个工作必需的软件经过认真评估后的信任？实际上，并没有唯一的正确答案。信任本质上是主观的。重要的是，每个组织都要认真考虑在技术层面信任的意义。即便具有成熟信任定义的组织，也应该质疑下由安全解决方案和操作系统验证过的信任是否可信。

既然你的脑子里有了关于信任对你意味着什么，不包括涉及人工干预的代码审查，什么是信任验证的技术手段？这显然是一个难以回答的问题，当然你也可能没有问过自己。本白皮书的目的是展示微软的Windows是怎样决策信任的。通过展示如何在Windows中颠覆信任，您将有机会有更多的机会多问问自己，信任对您而言到底意味着什么——一些在安全方面非常重要和不清楚的概念。

除了验证签名代码的来源和完整性之外，代码签名和信任验证也是许多安全产品（例如防病毒和EDR解决方案）的重要恶意软件分类组件。适当的信任验证也是大多数应用程序的执行组件白名单解决方案（AppLocker，Device Guard等）。 在许多情况下颠覆Windows的信任架构也有可能颠覆安全产品的功效。
## Windows用户模式信任架构
使用 [Authenticode][1] 数字签名，可以验证来自于特定供应商的可执行代码的合法性。在用户模式下，验证签名代码的信任的 API 是 [WinVerifyTrust][2] 和 [WinVerifyTrustEx][3]（它只是WinVerifyTrust的封装器，具有更明确定义的函数原型）。

随着Windows的更新迭代，同时也有必要扩展签名和信任架构以便支持额外的文件格式和二进制Blob格式，签名可能就需要以不同的格式存储，信任也跟着这种技术以特有的方式进行验证。例如，数字签名以特定的[PE文件格式](http://download.microsoft.com/download/9/c/5/9c5b2167-8017-4bae-9fde-d599bac8184a/Authenticode_PE.docx)存储二进制格式。PowerShell脚本，从另一方面来看的话也是可以签名的文本文件，因此可以理解其签名需要不同的存储格式。另外，当签名代码时，需要计算要签名的代码的哈希（通常称为签名证书哈希），并且根据文件/ blob格式执行此操作的方式是不同的。可以理解，关于数字签名的认证，设备驱动程序的信任的验证方法与HTTPS证书的信任方式是不同的。

考虑到需要支持独特格式的数字签名，并以独特的方式执行信任验证，微软设计了可扩展架构来支持这一点。主题接口包（[subject interface package][4],SIP）架构旨在支持数字签名的创建，检索和哈希计算、验证。使用[信任提供者](https://msdn.microsoft.com/en-us/library/ms721627(v=vs.85).aspx)来执行签名代码的信任验证。通过使用WinVerifyTrust和wintrust.dll、crypt32.dll中的各种导出函数， 信任提供者和SIP架构帮助软件开发人员从执行代码签名和信任验证的具体步骤中完全抽象出来。在撰写本文时，没有证据表明该架构的文档已被扩展到可支持第三方软件开发人员希望支持的其特定文件格式的签名。这可能是因为无论格式如何变化任何文件都可以在技术上通过使用目录签名([catalog signing](https://docs.microsoft.com/en-us/windows-hardware/drivers/install/catalog-files)，一种包含可以被认证码签名的文件哈希列表的文件格式)进行“签名”。需要注意的是编录文件的验证只有在“CryptSvc”服务运行的情况下才能生效。

除了各种[Windows SDK](https://developer.microsoft.com/windows/downloads/windows-10-sdk)头文件以及零星的关于wintrust.dll和crypt32.dll导出函数的[MSDN文档][5]外，信任提供者和SIP并没有文档化。由于第三方实施的复杂性，微软可能故意选择对这些架构不进行文档化。该白皮书用于记录信任提供者和SIP架构，同时还解释攻击者如何将其滥用的方式作为破坏信任的手段，并且在执行信任验证的进程的上下文中获取代码执行的权限。

本白皮书中主要介绍的是[CryptoAPI][6]的可扩展性，主要包括加密编码、解码、证书管理等。微软不可能预见未来的加密要求，所以他们设计了一个完全可扩展的架构（大概可追溯到90年代初），以适应当前和未来的需求。不幸的是，这一非常广泛的可扩展性，有可能允许攻击者（具有提升的权限）来劫持现有的功能。

[1]:https://msdn.microsoft.com/en-us/library/ms537359(v=vs.85).aspx	"Authenticode"
[2]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388208(v=vs.85).aspx	"WinVerifyTrust"
[3]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa388209(v=vs.85).aspx	"WinVerifyTrustEx"
[4]:https://msdn.microsoft.com/en-us/library/ms721625(v=vs.85).aspx	"subject interface package"
[5]:https://msdn.microsoft.com/en-us/library/windows/desktop/aa380252(v=vs.85).aspx	"MSDN文档"
[6]:https://msdn.microsoft.com/en-us/library/windows/desktop/ms721572(v=vs.85).aspx#_security_cryptoapi_gly	"CryptoAPI"

