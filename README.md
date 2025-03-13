# PEView

## 简介

PE相关工具:
1. kml_shell是壳子程序
2. loadPE文件夹是一个windows界面程序，包含PE解析逻辑和加壳程序。

使用VS2022在Unicode环境编译

只能查看32位程序的节表信息和目录项信息

## 主界面功能截图

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/PE%E6%9F%A5%E7%9C%8B%E5%99%A8%E4%B8%BB%E7%95%8C%E9%9D%A2.png)

## PE信息功能截图

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/%E6%9F%A5%E7%9C%8BPE%E7%BB%93%E6%9E%84%E5%9F%BA%E7%A1%80%E4%BF%A1%E6%81%AF.png)

## 节表信息截图

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/%E8%8A%82%E8%A1%A8%E7%95%8C%E9%9D%A2.png)

## 目录项信息截图

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/%E7%9B%AE%E5%BD%95%E9%A1%B9%E9%A2%84%E8%A7%88.png)

## 目录项详细信息

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/%E7%9B%AE%E5%BD%95%E9%A1%B9%E8%AF%A6%E7%BB%86%E4%BF%A1%E6%81%AF%E6%9F%A5%E7%9C%8B.png)

## 注入功能截图

有三种注入方式
1. 在目标进程创建线程使用`LoadLibrary`加载PE
2. 在高地址运行后在低地址加载内存镜像运行目标程序
3. 将自身内存镜像加载到目标进程修复IAT表后运行

![](https://cdn.jsdelivr.net/gh/godlmk/picture@main/mdPicture/%E6%B3%A8%E5%85%A5%E7%95%8C%E9%9D%A2.png)