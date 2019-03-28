---
layout: post
category: "iOS"
title:  "mac包管理器homebrew安装"
date: 2017/10/5 7:26:15
tags: [mac,homebrew,brew-cast]
---

打开bash,复制下：

```shell
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```

敲下回车等待下就OK了。默认也会安装 brew-cast，一个很好用的gui包管理工具。例如安装下MacDown：

```shell
brew cask install macdown
```

