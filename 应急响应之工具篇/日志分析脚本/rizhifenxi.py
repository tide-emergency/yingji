#!/usr/bin/env python
# -*- coding:utf-8 -*-
# 对日志中的访问路径进行汇总，根据数量进行排名，并将访问量前20的统计情况输出保存到表格中。
import xlwt
import re
from collections import Counter
import os
import rizhi_find
# _*_coding:utf-8_*_
url_list = list()
bb = list()
# 2、对日志url汇总规则：1、不对以css、txt等下面列表中后缀的url统计；2、通过空格分割，统计日志中的访问路径，存在？的路径只选取？前面的路径；3、由于可能存在不标准的日志格式，此处的切割规则也会不同，可以根据实际情况在做修改；
def  countfiles():
    info,count=rizhi_find.open_file()
    for i in info:
        if len(i.strip().split(' '))>6 and i.strip().split(' ')[6].endswith(('css', 'CSS', 'dae', 'DAE', 'eot', 'EOT', 'gif', 'GIF', 'ico', 'ICO', 'jpeg','JPEG', 'jpg', 'JPG', 'js', 'JS', 'map', 'MAP', 'mp3', 'MP3', 'pdf', 'PDF', 'png','PNG', 'svg', 'SVG', 'swf', 'SWF', 'ttf', 'TTF', 'txt', 'TXT', 'woff','WOFF')) == False:
            path=i.strip().split('"')[1].rstrip(' HTTP/1.1')
            # print path.rstrip(' HTTP/1.1')
            time=i.strip().split(' ')[3]
            # print time
            url=path.split('?')[0]
            url_list.append(url)
    result = Counter(url_list)
    result1 = dict(result)
    # print result1
    res = sorted(result1.items(), key=lambda d: d[1], reverse=True)
# 3、这里是保存了url访问量前20的数据，也可以在做修改。
    for i in  range(0,20):
        fangwen_url= res[i][0]
        bili="%.2f%%" % (round(float(res[i][1])/float(count),2) * 100)
        fangwen_cishu=res[i][1]
        aa= i, fangwen_url,fangwen_cishu,bili
        bb.append(aa)
    return bb
# 4、将输出结果保存到url_tongji.xls的表格中
def baocun_url_biaoge():
    path=os.getcwd() + "/result/"
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        pass
    workbook = xlwt.Workbook(encoding='utf-8')
    sheet = workbook.add_sheet('url_tongji',cell_overwrite_ok=True)
    sheet1 = workbook.add_sheet('ip_tongji',cell_overwrite_ok=True)
    head = ['序号', '访问次数', '访问占比' ,'url']  # sheet表头
    head1 = ['序号', 'ip', '访问次数' ,'ip归属地']  # sheet表头
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
        sheet.write(0, h, head[h],style)
    result=countfiles()
    sheet.col(0).width = 256 * 5
    sheet.col(1).width = 256 * 15
    sheet.col(2).width = 256 * 15
    sheet.col(3).width = 256 * 50
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER
    alignment.vert = xlwt.Alignment.VERT_CENTER
    i=1
    for a in result:
        sheet.write(i,0,a[0],style)
        sheet.write(i,1, a[2],style)
        sheet.write(i, 2, a[3],style)
        sheet.write(i, 3, a[1],style)
        i += 1
# 5、生成ip查询情况统计表,此处只是统计了出现20次以上的ip地址；
    for h1 in range(len(head1)):
        sheet1.write(0, h1, head1[h1],style)
    result1=rizhi_find.ip_guishudi()
    sheet1.col(0).width = 256 * 5
    sheet1.col(1).width = 256 * 20
    sheet1.col(2).width = 256 * 15
    sheet1.col(3).width = 256 * 50
    alignment = xlwt.Alignment()
    alignment.horz = xlwt.Alignment.HORZ_CENTER
    alignment.vert = xlwt.Alignment.VERT_CENTER
    h=1
    for b in range(len(result1)):
        quzhi= result1[b]
        # print quzhi
        sheet1.write(h,0,quzhi[0],style)
        sheet1.write(h,1, quzhi[1],style)
        sheet1.write(h, 2, quzhi[3],style)
        sheet1.write(h, 3, quzhi[2],style)
        h += 1
    workbook.save(path+'tongji.xls')
    print "请在"+path+"文件夹下查看相关结果"

if __name__=="__main__":
    baocun_url_biaoge()
    # countfiles()


