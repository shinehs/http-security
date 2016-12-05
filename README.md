#JavaScript防http劫持与XSS
1、使用方法：调用 httpSecurity.init()

2、建立自己的黑白名单、上报系统及接收后端

3、防范范围：  
   1）所有内联事件执行的代码    
   2）href 属性 javascript: 内嵌的代码  
   3）静态脚本文件内容   
   4）动态添加的脚本文件内容   
   5）document-write添加的内容   
   6）iframe嵌套  
   未完待续
