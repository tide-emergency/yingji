1、rizhi_find.py  主要是用于检索日志中的关键字；
2、rizhifenxi.py 用于汇总日志的url、ip地址；
3、tiquipdizhi.py用于处理netstat -ant的结果处理，分析连接数量大于80的ip地址，进行归属地查询，保存到excel表格中；
4、tiqurizhi.py 主要对ngix日志进行处理，利用panda函数统计ip地址、useragent、访问url等参数的数量，并将结果保存在excel表格中；
5、为了方便大家修改使用，未设置异常处理，可在根据自己的需求在此基础上在做修改；
