# NSA emissary多个漏洞分析复现和CodeQL实践

## 0x00 前言

先是Sonarsource的安全研究员在审计NSA的开源项目emissary的过程中发现了若干漏洞，其中包括：
- Code Injection (CVE-2021-32096)
- Arbitrary File Upload (CVE-2021-32094)
- Arbitrary File Disclosure (CVE-2021-32093)
- Arbitrary File Delete (CVE-2021-32095)
- Reflected cross-site scripting (CVE-2021-32092)

后来在浏览Github安全实验室的博客时，看到@pwntester在Sonarsource安全研究员的基础上，使用CodeQL编写规则，在emissary除了检测出以上漏洞外，还发现了新的漏洞：
- Unsafe deserialization (CVE-2021-32634)
- Server-side request forgery (CVE-2021-32639)

刚好最近除了在做漏洞分析外，也在学习CodeQL的使用，故决定用emissary项目来练手。

## 0x01 漏洞分析和复现


<iframe src="//player.bilibili.com/player.html?aid=292240694&bvid=BV12f4y1V73i&cid=384406848&page=1" scrolling="no" border="0" frameborder="no" framespacing="0" allowfullscreen="true"> </iframe>




## 0x02 编写CodeQL规则来检测漏洞

## Reference

[1] https://blog.sonarsource.com/code-vulnerabilities-in-nsa-application-revealed <br>
[2] https://securitylab.github.com/research/NSA-emissary/