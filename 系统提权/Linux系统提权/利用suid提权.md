## 利用suid提权

可通过以下命令查找系统上拥有suid

```
find / -perm -u=s -type f 2>/dev/null
```

---
- 在以下环境可成功提权：
Ubuntu 14.04.5
Debian 8
Debian 9
>
- 在以下环境不行
Ubuntu 16.04
Debian 10 

>这是因为在一些高版本的linux发行版中，默认情况下`sh`或`bash`在执行时，如果发现`uid`和`euid`不匹配，则会将`euid`(即suid) 强制重置为 uid。如果使用了 `-p`参数，则不会覆盖。
但是在下面这些命令实例中，我只在 `find`命令中，成功通过`-p`参数在一些高版本的linux发行版中进行提权。其他命令在提权过程中无法加上 `-p`参数(语法问题)。

---

### 1、利用具有suid位的vim提权

![](pic/linux-suid-vim-1.png)
![](pic/linux-suid-vim-2.png)
![](pic/linux-suid-vim-3.png)
![](pic/linux-suid-vim-4.png)

### 2、利用具有suid位的find提权

![](pic/linux-suid-find.png)

在`Ubuntu 18.04`中：

![](pic/linux-suid-find-2.png)

