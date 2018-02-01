---
layout: post
category: "tools"
title:  "git子目录下包括另一个git仓库"
tags: [git,tip]
---

## 起因

因为这个博客先托管在github.io上了，然后想换成 hexo 的主题next，于是就在目录下直接clone下来一个next主题。结果目录树就变成了下面这个样子:

blog  （当前目录）

├ .git

├ source

├ themes

┊	      ├ next

┊	      ┊	     ├ .git

┊	      ┊	     ├ test

┊	      ┊	     ├ etc.

因为next下已经有git仓库了，在 blog 目录进行版本管理的时候，导致next目录添加不到git文件版本控制中去。

## 解决

搜了下，在[知乎](https://www.zhihu.com/question/24467417/answer/93008944)上发现了答案，具体做法是:

1. 删除子目录也就是 next 目录下的 .git 目录

2. 因为该目录已经纳入到了 blog 目录下的版本管理中，所以即使删除了也不能重新添加进去。重新运行下删除下本地暂存再添加。

   ``` shell
   git rm -r --cached path # -r 递归删除子目录
   git add path
   ```

然后搜索了下 git rm 命令

```shell
git rm path          # 删除暂存区或分支上的文件, 同时工作区也不需要这个文件了,和 rm 命令类似
git rm --cached path # 只是删除git 暂存区的文件，对本地文件没有影响
```





