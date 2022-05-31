# -*- coding: utf-8 -*-
# 读取ngix日志，筛选出访问量比较大的ip地址、user_agent头信息
import os
import pandas as pd
import xlwt
import re
import requests
import matplotlib.pyplot as plt
# 对日志进行分析
def log_ana(line):
    res_dic = {}
    ip=line.split(' ')[0]
    res_obj = reg_obj.match(line)
    if ip == "-" or ip == "":
        return
    res_dic["ip"] = ip
    url=line.split('"')[1].split(' ')[1]
    res_dic["url"] = url
    status = res_obj.group("status").strip()
    res_dic["status"] = status
    refer = res_obj.group("refer").strip()
    res_dic["refer"] = refer
    ua = res_obj.group("ua").strip()
    res_dic["ua"]=ua
    # print(res_dic)
    return res_dic
#数据处理,将日志中的数据存储到列表中，方便pandas进行数据处理
def analysis(res_list):
    df = pd.DataFrame(res_lst)
    ip_count = pd.value_counts(df["ip"]).reset_index().rename(columns={"index": "ip", "ip": "counts"}).iloc[:10, :]
    url_count = pd.value_counts(df["url"]).reset_index().rename(columns={"index": "url", "url": "counts"}).iloc[:10, :]
    ua_count = pd.value_counts(df["ua"]).reset_index().rename(columns={"index": "ua", "ua": "counts"}).iloc[:10, :]
    ua_count_values = ua_count.values
    ip_count_values = ip_count.values
    url_count_values = url_count.values
    wb = xlwt.Workbook()
    write_excel(wb, ip_count_values, "ip")
    write_excel(wb, url_count_values, "url")
    write_excel(wb, ua_count_values, "useragent")
    wb.save("nginx_log.xls")
    save_path = os.getcwd()+"\\nginx_log.xls"
    print("日志分析完毕，保存路径为"+save_path)
# 保存表格
def write_excel(wb, ip_count_values, style1):
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER
    alignment.vert = xlwt.Alignment.VERT_CENTER
    style = xlwt.XFStyle()  # Create Style
    font = xlwt.Font()  # 为样式创建字体
    font.name = 'SimSun'
    font.bold = False  # 黑体
    style.font = font
    style.alignment = alignment
    sheet = wb.add_sheet(f"{style1}_count")
    sheet.col(0).width = 256 * 40
    sheet.col(1).width = 256 * 15
    row = 0
    sheet.write(row, 0, style1,style)
    sheet.write(row, 1, style1+"counts",style)
    if style1 is "ip":
        sheet.col(2).width = 256 * 30
        sheet.write(row, 2, "ip_guishudi",style)
        for item in ip_count_values:
            row += 1
            sheet.write(row, 0, item[0],style)
            sheet.write(row, 1, item[1],style)
            sheet.write(row, 2, ip_guishu(item[0]),style)
    else:
        for item in ip_count_values:
            row += 1
            sheet.write(row, 0, item[0],style)
            sheet.write(row, 1, item[1],style)

# ip归属地查询
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko','Accept': 'text/html, application/xhtml+xml, image/jxr, */*','Accept-Language': 'zh-CN','Connection': 'close'}
def ip_guishu(ip):
    URL = 'http://ip-api.com/json/' + ip + '?lang=zh-CN'
    try:
        r = requests.get(URL, timeout=3, headers=headers)
    except requests.RequestException as e:
        print(e)
    else:
        json_data = r.json()
        if json_data[u'status'] == 'success':
            country = json_data[u'country']
            regionName = json_data[u'regionName']
            city = json_data[u'city']
            guishu = country + '_' + regionName + '_' + city
            print(ip+'_'+guishu)
            # print(num,ip,guishu,count)
        else:
            print ('查询失败,请稍后再试！')
            guishu=" "
    return guishu

if __name__ == '__main__':
    res_lst=[]
    reg_obj = re.compile(
        r'(?P<ip>.*?) - - \[(?P<time>.*?)\] "(?P<api>.*?)" (?P<status>.*?) (?P<bytes_len>.*?) "(?P<refer>.*?)" "(?P<ua>.*?)"')
    with open("g:\\bb.log", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            res_dic= log_ana(line)
            res_lst.append(res_dic)
    analysis(res_lst)
