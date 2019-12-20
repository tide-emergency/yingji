#!/usr/bin/env python
# -*- coding:utf-8 -*-
import re
import requests
from retrying import retry
import os
from collections import Counter
# 需要分析的日志名称
# print dir(rizhifenxi_auto)
# 1、打开日志文件,将需要分析的日志保存log目录下
def  open_file():
    fpath = os.getcwd() + "/log/"
    files = os.listdir(fpath)
    for f in files:
        for f in files:  #
            if os.path.isfile(fpath + f):
                fhandle = open(fpath + f, 'r')
                aa = fhandle.readlines()
                return aa,len(aa)
file,count=open_file()
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko','Accept': 'text/html, application/xhtml+xml, image/jxr, */*','Accept-Language': 'zh-CN','Connection': 'close'}
# 输出结果保存在result目录下
def save_path():
    path = os.getcwd() + "/result/"
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        pass
    return path
weicha_ip=list()
guowai_ip=set()
ip_address = list()
path = save_path()
yichang_ip = list()
guowai_ip_lianjie = open(path + "guowai_ip_lianjie.txt", "w")
# 在进行ip地址归属地查询过程中，可能由于查询归属地接口原因，造成ip归属地查询失败，查询未成功的ip地址会保存在shibai_ip.txt中
@retry(stop_max_attempt_number=3)
def check_ip(dizhi):
    URL='http://ip-api.com/json/'+dizhi+'?lang=zh-CN'
    # try:
    r = requests.get(URL, timeout=3,headers=headers)
    json_data = r.json()
    if json_data[u'status'] == 'success':
        country = json_data[u'country'].encode('utf-8')
        provice=json_data[u'regionName'].encode('utf-8')
        city = json_data[u'city'].encode('utf-8')
        if country not  in "中国":
            guowai_ip.add(dizhi)
        aa= country,provice,city
        # print aa
        return aa
    # except :
    #     yichang_ip.append(dizhi)
ip_list=list()
# 1、提取日志中ip地址
def ip_tiqu():
    for i in file:
        ip=re.findall(r'\d+.\d+.\d+.\d+', i.strip())
        ip_list.append(ip[0])
    return ip_list
# 2、对提取到的ip地址进行频率统计，并判断相关地址归属地
def ip_guishudi():
    ip_tiqu()
    result = Counter(ip_list)
    result1 = dict(result)
    res = sorted(result1.items(), key=lambda d: d[1], reverse=True)
    for i in  range(len(res)):
       # print  len (res);
       ip=res[i][0];
       if res[i][1]>20:
        try:
           bb=check_ip(dizhi=ip);
           result= i,ip,bb,res[i][1]
           ip_address.append(result)
        except:
           result = i, ip, '查询失败', res[i][1]
           ip_address.append(result)
    return ip_address
# 4、根据输入的关键字进行搜索,支持最多两个关键字同时查找
def find_str():
    find_result=open(path+"find_result.txt","w")
    canshu1,canshu2,dingzhi=raw_input("please input keywords1:").split(',')
    # print len(canshu2)
    if len(canshu1)>0 and len(canshu2)==0 and len(dingzhi)==0:
        for i in file:
            if canshu1   in i:
                # print i.strip()
                find_result.write(i.strip()+'\n')
    elif len(canshu1)>0 and len(canshu2)>0 and dingzhi is str(1):
        for i in file:
            if canshu1  in i.strip() and canshu2 in i.strip():
                print i.strip()
                find_result.write(i.strip() + '\n')
    elif len(canshu1)>0 and len(canshu2)>0 and dingzhi is str(2):
        for i in file:
           if canshu1 in i or canshu2 in i:
               # print i.strip()
               find_result.write(i.strip() + '\n')
    else:
       print "type error,please check your input"
    find_result.close()
# 5、对查找到的结果进行ip地址提取，将提取结果保存在列表ip1中
    fenxi_result=open(path+"find_result.txt","r").readlines()
    for i1 in fenxi_result:
        ip = re.findall(r'\d+.\d+.\d+.\d+', i1.strip())[0]
        ip1.append(ip)
    return ip1
# 6、查看ip1中的地址列表还访问过哪些url,并将结果保存在log.txt中
def url_tongji():
    log=open(path+"log.txt","w")
    for ip in find_str():
        print ip
        for i in file:
            if ip in i.strip() :
                if str(200) or str(500) in i.strip():
                    # print i.strip()
                    log.write(i.strip()+'\n')

# 7、筛选国外ip访问过的链接
def guowai_lianjie():
    for i in guowai_ip:
        for i in file:
                for i1 in  guowai_ip:
                    if i1 in i and i.split(' ')[8]  in "200":
                        print i1.strip
                        guowai_ip_lianjie.write(i.strip()+'\n')
if __name__=='__main__':
    ip1=list()
    ip_list=list()
#     find_str()
    url_tongji()
    # guowai_lianjie

