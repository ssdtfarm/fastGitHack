fastGitHack是一个.git泄露利用脚本，通过泄露的.git文件夹下的文件，重建还原工程源代码。

渗透测试人员、攻击者，可以进一步审计代码，挖掘：文件上传，SQL注射等安全漏洞。

## 脚本的工作原理 ##

* 解析.git/index文件，找到工程中所有的： ( 文件名，文件sha1 )
* 去.git/objects/ 文件夹下下载对应的文件
* zlib解压文件，按原始的目录结构写入源代码


## 效率 ##
write in c, so it is more fast than other githack tool.
