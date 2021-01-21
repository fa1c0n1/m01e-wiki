#### 1.搜索仓库标题、仓库描述、README

##### 查找仓库名称包含关键字的仓库

- in:name 关键词

##### 查找描述内容

- in:description 关键词

##### 查找README文件包含的内容

- in:readme 关键词

#### 2.搜索star、fork数大于多少的

##### 查找star数大于多少
- stars:>数字 关键词 (也可以是大于等于 >= )

##### 查找star数在某个区间
- stars:数字1..数字2 关键词

- fork数同理，把stars换成forks即可。

#### 3.搜索仓库大小

场景：比如你只想看个简单的 Demo，不想找特别复杂的且占用磁盘空间较多的，可以在搜索的时候直接限定仓库的 size 。

- size:>数字 (也可以是大于等于 >=)

注意：这个数字代表K, 5000代表着5M。另外，size的搜索也支持区间。

#### 4.搜索仓库是否还在近期更新维护

- pushed:>yyyy-mm-dd 关键词

如：pushed:>2020-01-03 spring cloud


#### 5.搜索仓库的创建时间

- 把 `pushed` 改为 `created`即可

#### 6.搜索仓库的`LICENSE`

- license:协议 关键词

场景：
咱们经常使用开源软件，一定都知道，开源软件也是分不同的「门派」不同的LICENSE。开源不等于一切免费，不同的许可证要求也大不相同。 2018年就出现了 Facebook 修改 React 的许可协议导致各个公司纷纷修改自己的代码，寻找替换的框架。

例如咱们要找协议是最为宽松的 Apache License 2 的代码，可以这样： license:apache-2.0 spring cloud

#### 7.搜索仓库的语言

- language:语言 关键词
如：
language:java 关键词

#### 8.搜索某个人或组织的仓库

- user:joshlong

搜索语法组合一下，可以这样:
user:joshlong language:java

#### 9.搜索文件中包含指定关键词的仓库

- in:file 关键词

#### 10 github搜索也可以使用逻辑运算符

> github搜索中，逻辑运算符需要大写，即`AND`, `OR`, `NOT`

