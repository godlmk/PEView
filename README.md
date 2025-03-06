# PEView

PE相关工具:
1. kml_shell是壳子程序
2. loadPE文件夹是一个windows界面程序，包含PE解析逻辑和加壳程序。

都是用VS开发，为了方便loadPE可以查看64位进程的模块信息，loadPE使用了64位编译，但是只能查看32位程序的节表信息和目录项信息