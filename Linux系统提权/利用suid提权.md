## 利用suid提权

可通过以下命令查找系统上拥有suid

```
find / -perm -u=s -type f 2>/dev/null
```