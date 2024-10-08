# jsonp-cors-burp-killer
#### 简介

一款被动扫描检测`jsonp`及`cors`漏洞的`burpsuite`插件，魔改自`https://github.com/YoDiDi/cors-jsonp`。优化了`JSONP`及`CORS`的检测逻辑，在原有基础上降低了`jsonp`漏洞检测误报。

#### 功能

* 低误报检测`JSONP`漏洞，检测有无`Referer`头校验，可选择是否只检测存在泄漏敏感信息字段的`JSONP`接口。
* 内置了`JSONP`特征检测及敏感信息抽取正则表达式，使用者可灵活修改参数。
* 零误报检测`CORS`配置漏洞。

#### JSONP检测思路

1. 解析`url`路径，检查`query`中的`key`是否包含预先定义好的关键字。
2. 根据关键字修改`http`包，重新发包1。
3. 检测是否存在`JSONP`，如果满足以下条件则认为存在`JSONP`：
   * `Callee.Name` 与 `callback`函数名相同
   * 返回包满足`JSONP`回显包的特征
4. 修改`Referer`头检测重新发包2，通过计算发包1及发包2内容的`LevenshteinDistance`相似度来判断该`JSONP`漏洞是否可利用。

#### 使用说明

编译`jsonp-cors-killer`项目，将`jsonp-cors-killer.jar`导入`burp`，检测到的漏洞会输出到图形界面中。

如果提取到敏感信息字段，则会在`issue`中看到抽取出来的敏感字段（见下图包1、2）；若检测到是`JSONP`接口但未发现敏感信息字段，在打开`onlySensitiveJSONP`检测的情况下也会将`payload`显示在界面中。

![image-20240708154155787](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240708154155787.png)

`jsonp key words`为`jsonp`接口常见的`query key`，可自行添加。

![image-20240708154546780](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240708154546780.png)

`config`为`JSONP`检测算法的参数

![image-20240708154613309](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240708154613309.png)

1. `threshold`：计算两个`response body`的相似度，用于检测是否有`Referer`头防护。经分析发现，`JSONP`可能会带有时间戳等信息，即便没有`Referer`头检测，两个回显包也可能不一致，因此用`equals`来判断两次发包得到的内容会带来误报，这里使用`LevenshteinDistance`算法计算两个文本相似度来降低误报。
2. `jsonpRegex`：`jsonp`模式的正则匹配表达式，一般不用修改。
3. `sensitiveInfoRegex`：抽取敏感信息正则表达式。
4. `onlySensitiveJSONP`：是否显示存在敏感信息泄漏的`JSONP`接口，若不过滤则修改为`false`。
5. `cors`：是否检测`cors`漏洞，若检测修改为`true`。

#### TODO

> 欢迎contribute

1. 优化检测算法
1. 优化`GUI`