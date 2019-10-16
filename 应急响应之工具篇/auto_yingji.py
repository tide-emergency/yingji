#!/usr/bin/env python
# -*- coding:utf-8 -*-
'''
#作者：tide_应急小组
# 版本：v1.0
应急自动化分析脚本，采用python2.0,主要是通过ssh远程登录实现常见命令查看，所以在使用之前需要输入正确的服务器ip、ssh连接端口、ssh登录用户名、ssh登录密码，
主要实现如下功能:
1、获取系统基本信息，ip地址，主机名称，版本；
2、根据netstat、cpu占用率，获取异常程序pid，并定位异常所在路径；
3、常见系统命令可能会被恶意文件替换修改，识别常见系统命令是否被修改；
4、查看系统启动项目，根据时间排序，列出最近修改的前5个启动项
5、查看历史命令，列出处存在可疑参数的命令；
6、查看非系统用户；
7、查看当前登录用户（tty 本地登陆  pts 远程登录）；
8、通过查看passwd文件，确定系统当前用户
9、查看crontab定时任务
10、查看、保存最近三天系统文件修改情况
11、查看passwd，存在哪些用户id为0的特权用户
12、分析secure日志，判断其中是否存在异常ip地址
上述所有操作均输出保存在log文件中
'''
import requests
import paramiko
import re
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # 跳过了远程连接中选择‘是’的环节,
ssh.connect('x.x.x.x', xxx, 'xx', 'xx')
headers = {'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko','Accept': 'text/html, application/xhtml+xml, image/jxr, */*','Accept-Language': 'zh-CN','Connection': 'close'}
# 通过netstat、top确定异常程序pid，通过pid定位异常程序位置
class netstat_Analysis:
    def __init__(self):
        self.pid=' '
        # 获取网络链接，并查看是否存在异常
    def check_netstat(self):
        try:
            ip=set()
            command="netstat -antp  | grep 'ESTABLISHED \| SYN_SENT \|SYN_RECEIVED' | awk '{print $1,$5,$7}' "
            command1="netstat -antp"
            stdin, stdout, stderr = ssh.exec_command(command)
            info= stdout.read().splitlines()
            stdin, stdout1, stderr = ssh.exec_command(command1)
            info1 = stdout1.read()
            file2.write(info1)
            return info
        except  Exception, e:
            print str(e)
    # 判断ip地址归属地，看是否是异常连接
    def check_yichangip(self):
        yichang=list()
        remot_ip=set()
        result=self.check_netstat()
        try:
            for net in result:
                # print net
                ip = str(net).split(' ')[1].split(':')[0]
                pid = str(net).split(' ')[2].split('/')[0]
                application = str(net).split(' ')[2].split('/')[1]
                remot_ip.add(ip)
            for i in  remot_ip:
                URL = 'http://ip-api.com/json/'+i+'?lang=zh-CN'
                try:
                    r = requests.get(URL, timeout=3,headers=headers)
                except requests.RequestException as e:
                    print (e)
                else:
                    json_data = r.json()
                    if json_data[u'status'] == 'success':
                        country= json_data[u'country'].encode('utf-8')
                        # print country
                        keyword=['中国','局域网','共享地址','本机地址','本地链路','保留地址','XX']
                        if country not  in keyword:
                            wrong_ip=i
                            info= "异常链接ip："+wrong_ip+'，ip归属地：'+country
                            file.write(info)
                            # print info
                            command1="netstat -antp  | grep "+wrong_ip+" | awk '{print $1,$5,$7}' "
                            stdin, stdout1, stderr = ssh.exec_command(command1)
                            info1= stdout1.read().splitlines()
                            # print type(info1)
                            yichang=yichang+info1
                            return yichang
                        else:
                            file.write('\n'+"查看netstat未发现国外ip地址链接"+'\n')

                    else:
                        print '查询失败,请稍后再试！'
        except:
            print "暂时未发现异常链接"
 # 对异常pid进行检测，定位文件位置
    def jiance_pid(self):
        try:
            # pid=1
            command1 = "ls -l /proc/"+self.pid
            stdin, stdout, stderr = ssh.exec_command(command1)
            info = stdout.read().splitlines()
            mulu=str(info[9]).split(' ')[10:]
            kezhixingwenjian=str(info[11]).split(' ')[10:]
            yichangtixing= "pid 为"+self.pid+"的异常程序，存在位置为："+mulu[0]+"，可执行文件为"+kezhixingwenjian[0]+"，请手工进行验证。"
            file.write(yichangtixing+'\n')
            print yichangtixing
        except:
            print "未发现异常行为"
    # 检测cpu高于15%的程序，并获取其pid，查看是否为异常进程
    def check_cpu(self):
        command_cpu = "ps -aux | sort -nr -k 3 | head -5 | awk '{if($3>=15) print $2,$3}'"
        stdin, stdout, stderr = ssh.exec_command(command_cpu)
        yichang_cpu = stdout.read().splitlines()
        try:
            for n in range(len(yichang_cpu)):
                self.pid=yichang_cpu[n].split(' ')[0]
                # print self.pid
                info= "pid 为"+self.pid+"的程序，cpu占用率为"+yichang_cpu[n].split(' ')[1]
                file.write(info+'\n')
                print info
                self.jiance_pid()
        except Exception, e:
            print str(e)
    # 通过netstat查看链接，获取异常pid的程序位置
    def ps_aux(self):
        a = self.check_yichangip()
        if a!=None:
            try:
                for i in a:
                    # print i
                    self.pid = str(i).split(' ')[2].split('/')[0]
                    self.jiance_pid()
            except Exception, e:
                print str(e)
        else:
            print "查看netstat未发现异常ip地址"

# 有些恶意程序会替换ps,netstat命令，此处用来判断系统命令是否被替换（此处判断bin目录下命令）
class check_mingling:
    def __init__(self):
        stdin, stdout, stderr = ssh.exec_command("stat /bin/mkdir")
        info = stdout.read().splitlines()
        if __name__ == '__main__':
            self.time=info[5].split(' ')[1].split('-')[0]
    def mingling(self):
        command=['ps','netstat']
        for i in range(len(command)):
            try:
                command1 = "stat  /bin/"+command[i]
                stdin, stdout, stderr = ssh.exec_command(command1)
                info1 = stdout.read().splitlines()
                time=info1[5].split(' ')[1].split('-')[0]
            except:
                print "所查询命令不在bin目录下"
            # print time,self.time
            # print int(self.time),int(time)
            try:
                if int(self.time)<int(time):
                    info1= command[i]+' 命令存在异常，修改时间为：'+info1[5].split(' ')[1]
                    file.write(info1+'\n')
                    print info1
                else:
                    print '未发现'+command[i]+'命令存在异常'
            except:
                print '暂无异常命令'
# 检查系统启动项目,查看init.d文件
class check_init():
    def get_init(self):
        try:
            command1 = "ls -lth /etc/rc.d/init.d | sed -n '2,6p'"
            stdin, stdout, stderr = ssh.exec_command(command1)
            info1 = stdout.read()
            tishi="根据最近修改时间，系统启动项前5名如下："
            if len(info1) !=0:
                info=(tishi+'\n'+info1)
                file.write(info+'\n')
            else:
                print "查看默认启动项时，查看路径与实际不符合，请根据情况自行修改commad1中路径"
        except Exception, e:
            print str(e)
#历史命令查看
class check_history():
    def get_history(self):
        try:
            command1 = "cat /root/.bash_history | grep -a 'wget\|curl\|rpm\|install\|tar\|zip\|chmod\|rm\|mv'"
            stdin, stdout, stderr = ssh.exec_command(command1)
            info1 = stdout.read()
            print '通过查看历史命令发现以下可疑命令，需要进行手动确认'+'\n'+info1
            file.write('通过查看历史命令发现以下可疑命令，需要进行手动确认'+'\n'+info1)
        except Exception, e:
            print str(e)
# 获取主机信息
class Host_Info:
    def __init__(self):
        self.ip = ""
        # 主机名
        self.hostname = ""
        # 主机ip
        self.ip = ""
        # 主机内核版本
        self.version = ""
        #主机系统版本
        self.version1=""
        # 主机时间
        self.time = ""
    def get_ip(self):
        try:
            command1 = "ifconfig -a | grep -w inet | grep -v 127.0.0.1 | awk 'NR==1{print $2}'&&hostname&&uname -a &&date&&cat " \
                       "/etc/issue| awk 'NR==1' "
            stdin, stdout, stderr = ssh.exec_command(command1)
            info=stdout.read().splitlines()
            # print info
            self.ip=info[0]
            self.hostname=info[1]
            self.version=info[2]
            self.time=info[3]
            self.version1=info[4]
            info_write='当前系统IP地址为：'+self.ip+'\n'+'当前系统主机名称为：'+self.hostname+'\n'+'当前系统内核版本为:'+self.version+'\n'+"当前系统版本："+self.version1+'\n'+'当前系统时间为：'+self.time+'\n'
            file.write(info_write)
            print info_write
        except Exception, e:
            print str(e)
# 获取当前用户情况
class check_user:
    def __init__(self):
        self.user=""
        self.nosystemuser=""
        self.current_yonghu=""
    def get_user(self):
        command1 = ["uid=$(grep UID_MIN /etc/login.defs | awk '{print $2}') &&gawk -F: '{if ($3>='$uid' && $3!=65534) {print            $1}}' /etc/passwd","who","cat /etc/passwd"]
        try:
            stdin, stdout, stderr = ssh.exec_command(command1[0])
            if len(self.nosystemuser) ==0:
                self.nosystemuser='无'
            else:
                self.nosystemuser = stdout.read()
        except:
            print "查看非系统用户时出错"
        try:
            stdin, stdout, stderr = ssh.exec_command(command1[1])
            self.current_yonghu=stdout.read()
        except:
            print "查看当前登录用户出错"
        try:
            stdin, stdout, stderr = ssh.exec_command(command1[2])
            self.user=stdout.read()
        except:
            print "查看用户信息出错"
        # print self.user
        text='\n'+'存在以下非系统用户:'+'\n'+self.nosystemuser+'\n'+"当前登录用户如下："+'\n'+self.current_yonghu+'\n'+'系统当前用户信''息如下：'+'\n'+self.user
        print text
        file.write(text)
class find_filerevise():
    def get_filerevise(self):
        try:
            command2 = "find ./ -mtime 0 -o -mtime 1 -o -mtime 2  -o -mtime 3"
            stdin, stdout, stderr = ssh.exec_command(command2)
            info2 = stdout.read()
            file1.write('近三天修改文件如下：'+'\n'+info2)
        except Exception, e:
            print str(e)
 #查看、保存当前定时任务
class find_crontab():
    def get_crontab(self):
        try:
            command3 = "cat /etc/crontab"
            stdin, stdout, stderr = ssh.exec_command(command3)
            info3 = str(stdout.read()).strip()
            print 'crontab当前定时任务如下：'+'\n'+info3
            file.write('crontab当前定时任务如下：'+'\n'+info3)
        except Exception, e:
            print str(e)
 #排查提权账户
class find_gid():
    def get_gid(self):
        user_list=set()
        try:
            command4 = "cat /etc/passwd"
            stdin, stdout, stderr = ssh.exec_command(command4)
            info3 = stdout.read().splitlines()
            # print(info3)

            for i in info3:
                # print(i)
                gid = str(i).split(':')[3]
                # print(type(gid))
                if gid == str(0):
                    user = str(i).split(':')[0]
                    user_list.add(user)
            if len(user_list) !=0:
                print 'gid为0账户如下：'+str(user_list)
                file.write('\n' + 'gid为0账户如下：')
                for i in user_list:
                    file.write('\n' +i)
            else:
                print "不存在uid为0的特权用户"
        except Exception, e:
            print str(e)
#查看日志文件,判断secure日志是否存在异常，由于日志查看的内容比较多，此处只是对secure日志中ip地址进行分析，判断是否存在国外异常ip归属
class check_log():
    try:
        def cat_log(self):
            command="cat /var/log/secure"
            stdin, stdout, stderr = ssh.exec_command(command)
            info3 = stdout.read()
            if len(info3)!=0:
                file4.write(info3)
                file4.close()
                ip_list=set()
                for i in open("secure.txt",'r').readlines():
                    ip = re.findall(r'(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])', str(i), re.S)
                    if len(ip) !=0:
                        ip_list.add(ip[0])
                    else:
                        pass
                for i in  ip_list:
                    URL = URL='http://ip-api.com/json/'+i+'?lang=zh-CN'
                    try:
                        r = requests.get(URL, timeout=3,headers=headers)
                    except requests.RequestException as e:
                        file.write('在secure日志中未发现异常ip地址' + '\n')
                        print(e)
                    else:
                        json_data = r.json()
                        if json_data[u'code'] == 0:
                            country = json_data[u'data'][u'country'].encode('utf-8')
                            keyword = ['中国', '共享地址','局域网', '本机地址', '本地链路', '保留地址','XX']
                            if country not in keyword:
                                print '在secure日志中发现如下异常ip地址：'+'\n'+i+"  地址归属地"+country+'\n'
                                file.write('在secure日志中发现如下异常ip地址：'+'\n'+i+"  地址归属地"+country+'\n')
                            else:
                                pass
            else:
                print "系统未发现存在secure日志,请根据实际情况修改所需要查看的日志路径"
    except:
        print "系统未发现存在secure日志"
if __name__=='__main__':
    '''
    输出结果默认保存在log.txt中，查看最近3天文件的修改情况默认保存在file_edit.txt中，
    通过netstat查看链接情况默认保存在netstat.txt中，secure日志的查看情况保存在secure.txt中
    '''
    file = open("log.txt", 'a')
    file1=open("file_edit.txt",'w')
    file2=open("netstat.txt",'w')
    file4 = open("secure.txt", 'w')
    e = Host_Info()
    e.get_ip()
    a=netstat_Analysis()
    a.ps_aux()
    a.check_cpu()
    b=check_mingling()
    b.mingling()
    c=check_init()
    c.get_init()
    d=check_history()
    d.get_history()
    f=check_user()
    f.get_user()
    g = find_filerevise()
    g.get_filerevise()
    h = find_crontab()
    h.get_crontab()
    i = find_gid()
    i.get_gid()
    j=check_log()
    j.cat_log()