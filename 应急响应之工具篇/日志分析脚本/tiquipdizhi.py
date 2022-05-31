# -*- coding: utf-8 -*-
import requests
import pandas as pd
import re
import xlwt
import os
import pandas as pd
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko','Accept': 'text/html, application/xhtml+xml, image/jxr, */*','Accept-Language': 'zh-CN','Connection': 'close'}
# 根据netstat连情况，筛选访问量过大的ip地址，并判断其归属地，导出相关结果
def read_ip():
    ips = []
    file = open("G:\\000.txt")
    for i in file.readlines():
        # print(i.strip())
        ip=re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", i.strip())
        if len(ip)>1:
            ips.append(ip[1])
    num=0
    for ip in set(ips):
        # 统计连接出现超过80的ip地址
        if ips.count(ip) >80:
            # print(ip, ips.count(ip))
            num=num+1
            count=ips.count(ip)
            ip_guishu=ip_address(num,ip,count)

#判断ip地址归属地
def ip_address(num,ip,count):
    URL = 'http://ip-api.com/json/' + ip + '?lang=zh-CN'
    try:
        r = requests.get(URL, timeout=3, headers=headers)
    except requests.RequestException as e:
        print(e)
    else:
        json_data = r.json()
        if json_data[u'status'] == 'success':
            country = json_data[u'country']
            regionName=json_data[u'regionName']
            city=json_data[u'city']
            guishu=country+'_'+regionName+'_'+city
            # print(num,ip,guishu,count)
            save_excel(num, ip, guishu, count)

        else:
            print
            '查询失败,请稍后再试！'
# 保存到excel表格
def save_excel(i,ip,ip_guishu,ip_count):
    head = ['id', 'ip地址', 'ip_归属', 'count']  # 将结果导出到某一个表格，此处是设置新表格的首行内容
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER
    alignment.vert = xlwt.Alignment.VERT_CENTER
    style = xlwt.XFStyle()  # Create Style
    font = xlwt.Font()  # 为样式创建字体
    font.name = 'SimSun'
    font.bold = False  # 黑体
    style.font = font
    style.alignment = alignment  # Add Alignment to Style
    for h in range(len(head)):
        sheet.write(0, h, head[h], style)
    sheet.col(0).width = 256 * 5
    sheet.col(1).width = 256 * 15
    sheet.col(2).width = 256 * 15
    sheet.col(3).width = 256 * 50
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER
    alignment.vert = xlwt.Alignment.VERT_CENTER
    sheet.write(i, 0, i, style)
    sheet.write(i, 1, ip, style)
    sheet.write(i, 2, ip_guishu, style)
    sheet.write(i, 3, ip_count, style)
    # 下面的表格名称可自行修改

if __name__ == '__main__':
    save_path = os.getcwd() + "/result/"  # 此路径可进行修改，默认是保存在result目录中
    if not os.path.exists(save_path):
        os.makedirs(save_path)
    else:
        pass
    workbook = xlwt.Workbook(encoding='utf-8')
    sheet = workbook.add_sheet('all_result', cell_overwrite_ok=True)
    read_ip()
    workbook.save(save_path + 'ip_tongji.xls')
    print("数据提取完毕，结果保存在" + save_path + 'ip_tongji.xls')
    df = pd.read_excel(save_path+"ip_tongji.xls", index_col='id')
    df.sort_values(by='count', inplace=True, ascending=False)
    print(df)
    df.to_excel(save_path + 'ip_result.xlsx')  # 保存文件，如果不想保存在同级目录下面，此处的参数应该为路径+文件名


