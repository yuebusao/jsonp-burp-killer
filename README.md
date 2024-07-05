# jsonp-cors-burp-killer
#### 简介

大四时写的一款被动扫描检测`jsonp`及`cors`漏洞的`burp`插件，魔改自`https://github.com/YoDiDi/cors-jsonp`。优化了`JSONP`及`CORS`的检测逻辑，在原有基础上降低了`jsonp`漏洞检测误报。

#### 功能

* 低误报检测`JSONP`漏洞，检测有无`Referer`头校验。
* 针对`jsonp`漏洞检测内置了一些参数关键字，使用者可自行添加参数。
* 内置文本相似度计算阈值（默认0.9），用于判断该`JSONP`接口是否存在`Referer`头校验
* 零误报检测`CORS`配置漏洞。

#### JSONP检测算法步骤

1. 解析`url`路径，检查`query`中的`key`是否包含预先定义好的关键字。
2. 根据关键字修改`http`包，重新发包1。
3. 检测是否存在`JSONP`，如果满足以下条件则认为存在`JSONP`：
   * `Callee.Name` 与 `callback`函数名相同
   * 返回包满足`JSONP`回显包的特征

3. 修改`Referer`头检测重新发包2，通过计算发包1及发包2内容的相似度来判断该`JSONP`漏洞是否可利用。

#### TODO

1. 自动化提取`JSONP`敏感参数。
2. 优化检测算法。