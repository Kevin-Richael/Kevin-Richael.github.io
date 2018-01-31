---
layout: post
title:  pin to taskbar 添加快捷方式到任务栏
date: 2017/9/22 20:46:25
category:
- Win
tags:
- taskbar
- pin
- Win
---
### 今天写个安装包添加快捷方式到任务栏

```c++
ShellExecute(NULL, "taskbarpin", "C:\Users\用户名\Desktop\应用软件.lnk", NULL, NULL, 0) //定在任务栏，快捷方式必须存在且有效
ShellExecute(NULL, "taskbarunpin", "C:\Users\用户名\Desktop\应用软件.lnk", NULL, NULL, 0)//取消固定，快捷方式必须存在且有效
```

以上代码在win7/8/8.1下执行没问题，但是在win10下会添加失败，并且导致程序执行。

遂Google之，在[stackoverflow](https://stackoverflow.com/questions/31720595/pin-program-to-taskbar-using-ps-in-windows-10)发现同样的问题，然后[在这里](http://alexweinberger.com/main/pinning-network-program-taskbar-programmatically-windows-10/)找到了解决方案。原来win10 下会进行进程名检查，只要是explorer就行，所以呢，要么自己就叫explorer，要么按照文章说的另一种方式修改下peb欺骗下系统。

NSIS安装的话，推荐个 stdutils 插件

```nsis
!include "stdutils.nsh"
Function CreateBarlnk    ;创建快速启动栏
  ReadRegStr $R0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentVersion"
  ${if} $R0 >= 6.0
    ${StdUtils.InvokeShellVerb} $0 "$INSTDIR" "${PRODUCT_EXECUTE_NAME}" ${StdUtils.Const.ShellVerb.PinToTaskbar}
  ${else}
    CreateShortCut "$QUICKLAUNCH\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_EXECUTE_NAME}"
  ${Endif}
FunctionEnd
```






