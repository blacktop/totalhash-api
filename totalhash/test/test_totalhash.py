#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Josh Maine'

from totalhash.totalhash_api import TotalHashApi


t0tal = TotalHashApi()

res = t0tal.get_usage()
print t0tal.json_response(res) # '8 of 300'

sha1_hash = '5f6b0a5d976cd370bdc213eb11c21ef99262e9aa'

res = t0tal.get_analysis(sha1_hash)
print t0tal.json_response(res)

query = "av:*bot*"

res = t0tal.do_search(query)
print t0tal.json_response(res)

###############################################################################################################
#
# xml = """<?xml version="1.0"?>
# <!-- TopCat sandbox copyright (c) 2013 -->
#
# <analysis tcversion="0.3" sha1="5f6b0a5d976cd370bdc213eb11c21ef99262e9aa" md5="c8c3529e4fc8b86d6fca51f68d201e42" time="2013-10-25 00:38:45">
#   <static strings_sha1="6a9e89273748a973a4244b4712de9b22b688ae2b" strings_md5="b4e60fd041c3d4fb10a01730111409e5">
#     <magic value="PE32 executable for MS Windows (GUI) Intel 80386 32-bit"></magic>
#     <section name=".text" md5="7ed43c221264e5f4cfd00bd874766050" sha1="9026a4884db7a7b38dfde11e6fa1ac6eee6bf3d3" size="13312"></section>
#     <section name=".pdata" md5="2a321ab8c14285cb6a445cb3e63a24c2" sha1="4d92a73a9f6a3b9992679563558fe82db99967b7" size="1024"></section>
#     <section name=".rdata" md5="d87943c6f2425691ad5c7a42b50b10c5" sha1="24ba421d66772c146c0711c76f90409276f90377" size="10240"></section>
#     <section name=".adata" md5="b4202f7fe985b9648b4676e6f70832bd" sha1="d37c2b3927946ed617455b3c5913fcab0bc1af52" size="3584"></section>
#     <imports dll="wavemsp.dll"></imports>
#     <imports dll="kernel32.dll"></imports>
#     <pehash value="f084ef01bb5cf8906ee4262079d5c74f48167c33"></pehash>
#     <timestamp value="2007-04-18 11:23:51"></timestamp>
#     <av scanner="avg" timestamp="2013-10-25 00:38:45" signature="Crypt_s.DWM"></av>
#     <av scanner="avira" timestamp="2013-10-25 00:38:45" signature="TR/Urausy.25564851"></av>
#   </static>
#   <calltree>
#     <process_call index="1" filename="C:\malware.exe" pid="1224" startreason="AnalysisTarget"></process_call>
#   </calltree>
#   <processes scr_shot_sha1="b2c6c02bcec05be68cd78009d57fe380421a933b" scr_shot_md5="f10e8a0fd673df042a028bb7ef42b232">
#     <process index="1" pid="1224" filename="C:\malware.exe" executionstatus="OK">
#       <dll_handling_section>
#         <load_dll filename="c:\windows\system32\wshtcpip.dll"></load_dll>
#         <load_dll filename="wsock32.dll"></load_dll>
#         <load_dll filename="dnsapi.dll"></load_dll>
#         <load_dll filename="hnetcfg.dll"></load_dll>
#         <load_dll filename="kernel32.dll"></load_dll>
#         <load_dll filename="ntdll.dll"></load_dll>
#         <load_dll filename="c:\windows\system32\mswsock.dll"></load_dll>
#         <load_dll filename="c:\windows\system32\winrnr.dll"></load_dll>
#         <load_dll filename="rasadhlp.dll"></load_dll>
#       </dll_handling_section>
#       <filesystem_section>
#         <create_file filetype="file" srcfile="\Device\Afd\Endpoint"></create_file>
#         <create_file filetype="file" srcfile="\Device\Afd\AsyncConnectHlp"></create_file>
#       </filesystem_section>
#     </process>
#   </processes>
#   <running_processes>
#     <running_process pid="0" filename="[System Process]" ppid="0"></running_process>
#     <running_process pid="4" filename="System" ppid="0"></running_process>
#     <running_process pid="320" filename="smss.exe" ppid="4"></running_process>
#     <running_process pid="544" filename="csrss.exe" ppid="320"></running_process>
#     <running_process pid="568" filename="winlogon.exe" ppid="320"></running_process>
#     <running_process pid="612" filename="services.exe" ppid="568"></running_process>
#     <running_process pid="624" filename="lsass.exe" ppid="568"></running_process>
#     <running_process pid="784" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="840" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="1004" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="1048" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="1092" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="1348" filename="spoolsv.exe" ppid="612"></running_process>
#     <running_process pid="1872" filename="alg.exe" ppid="612"></running_process>
#     <running_process pid="224" filename="userinit.exe" ppid="568"></running_process>
#     <running_process pid="248" filename="explorer.exe" ppid="224"></running_process>
#     <running_process pid="528" filename="reader_sl.exe" ppid="248"></running_process>
#     <running_process pid="1148" filename="svchost.exe" ppid="612"></running_process>
#     <running_process pid="1180" filename="monitor.exe" ppid="1148"></running_process>
#     <running_process pid="1224" filename="malware.exe" ppid="1180"></running_process>
#   </running_processes>
#   <network_pcap sha1="7f66263624ff1db19f22d35140a1ce73e76f36c8" md5="6cb3826cb7f827b794afc7bb795f6a9a">
#     <flows src_ip="192.168.1.1" src_port="1031" dst_ip="109.110.68.68" dst_port="80" protocol="6" bytes="0"></flows>
#     <flows src_ip="192.168.1.1" src_port="1031" dst_ip="109.110.68.68" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1032" dst_ip="31.192.16.21" dst_port="80" protocol="6" bytes="49"></flows>
#     <flows src_ip="192.168.1.1" src_port="1033" dst_ip="31.170.146.20" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1034" dst_ip="176.8.17.7" dst_port="80" protocol="6" bytes="47"></flows>
#     <flows src_ip="192.168.1.1" src_port="1035" dst_ip="5.58.28.68" dst_port="80" protocol="6" bytes="47"></flows>
#     <flows src_ip="192.168.1.1" src_port="1036" dst_ip="93.77.83.252" dst_port="80" protocol="6" bytes="49"></flows>
#     <flows src_ip="192.168.1.1" src_port="1037" dst_ip="188.143.142.98" dst_port="80" protocol="6" bytes="51"></flows>
#     <flows src_ip="192.168.1.1" src_port="1038" dst_ip="176.112.1.35" dst_port="80" protocol="6" bytes="49"></flows>
#     <flows src_ip="192.168.1.1" src_port="1039" dst_ip="176.8.244.116" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1040" dst_ip="176.111.42.68" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1041" dst_ip="46.172.125.93" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1042" dst_ip="5.248.31.50" dst_port="80" protocol="6" bytes="48"></flows>
#     <flows src_ip="192.168.1.1" src_port="1043" dst_ip="176.99.125.55" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1044" dst_ip="176.101.10.125" dst_port="80" protocol="6" bytes="51"></flows>
#     <flows src_ip="192.168.1.1" src_port="1045" dst_ip="5.248.106.151" dst_port="80" protocol="6" bytes="50"></flows>
#     <flows src_ip="192.168.1.1" src_port="1046" dst_ip="37.229.225.112" dst_port="80" protocol="6" bytes="51"></flows>
#     <http type="GET">http://109.110.68.68/survik1.exe</http>
#     <http type="GET">http://31.192.16.21/survik1.exe</http>
#     <http type="GET">http://31.170.146.20/survik1.exe</http>
#     <http type="GET">http://176.8.17.7/survik1.exe</http>
#     <http type="GET">http://5.58.28.68/survik1.exe</http>
#     <http type="GET">http://93.77.83.252/survik1.exe</http>
#     <http type="GET">http://188.143.142.98/survik1.exe</http>
#     <http type="GET">http://176.112.1.35/survik1.exe</http>
#     <http type="GET">http://176.8.244.116/survik1.exe</http>
#     <http type="GET">http://176.111.42.68/survik1.exe</http>
#     <http type="GET">http://46.172.125.93/survik1.exe</http>
#     <http type="GET">http://5.248.31.50/survik1.exe</http>
#     <http type="GET">http://176.99.125.55/survik1.exe</http>
#     <http type="GET">http://176.101.10.125/survik1.exe</http>
#     <http type="GET">http://5.248.106.151/survik1.exe</http>
#     <http type="GET">http://37.229.225.112/survik1.exe</http>
#   </network_pcap>
# </analysis>"""
#
# xml2dict = "[(u'analysis', OrderedDict([(u'@tcversion', u'0.3'), (u'@sha1', u'5f6b0a5d976cd370bdc213eb11c21ef99262e9aa'), (u'@md5', u'c8c3529e4fc8b86d6fca51f68d201e42'), (u'@time', u'2013-10-25 00:38:45'), (u'static', OrderedDict([(u'@strings_sha1', u'6a9e89273748a973a4244b4712de9b22b688ae2b'), (u'@strings_md5', u'b4e60fd041c3d4fb10a01730111409e5'), (u'magic', OrderedDict([(u'@value', u'PE32 executable for MS Windows (GUI) Intel 80386 32-bit')])), (u'section', [OrderedDict([(u'@name', u'.text'), (u'@md5', u'7ed43c221264e5f4cfd00bd874766050'), (u'@sha1', u'9026a4884db7a7b38dfde11e6fa1ac6eee6bf3d3'), (u'@size', u'13312')]), OrderedDict([(u'@name', u'.pdata'), (u'@md5', u'2a321ab8c14285cb6a445cb3e63a24c2'), (u'@sha1', u'4d92a73a9f6a3b9992679563558fe82db99967b7'), (u'@size', u'1024')]), OrderedDict([(u'@name', u'.rdata'), (u'@md5', u'd87943c6f2425691ad5c7a42b50b10c5'), (u'@sha1', u'24ba421d66772c146c0711c76f90409276f90377'), (u'@size', u'10240')]), OrderedDict([(u'@name', u'.adata'), (u'@md5', u'b4202f7fe985b9648b4676e6f70832bd'), (u'@sha1', u'd37c2b3927946ed617455b3c5913fcab0bc1af52'), (u'@size', u'3584')])]), (u'imports', [OrderedDict([(u'@dll', u'wavemsp.dll')]), OrderedDict([(u'@dll', u'kernel32.dll')])]), (u'pehash', OrderedDict([(u'@value', u'f084ef01bb5cf8906ee4262079d5c74f48167c33')])), (u'timestamp', OrderedDict([(u'@value', u'2007-04-18 11:23:51')])), (u'av', [OrderedDict([(u'@scanner', u'avg'), (u'@timestamp', u'2013-10-25 00:38:45'), (u'@signature', u'Crypt_s.DWM')]), OrderedDict([(u'@scanner', u'avira'), (u'@timestamp', u'2013-10-25 00:38:45'), (u'@signature', u'TR/Urausy.25564851')])])])), (u'calltree', OrderedDict([(u'process_call', OrderedDict([(u'@index', u'1'), (u'@filename', u'C:\\malware.exe'), (u'@pid', u'1224'), (u'@startreason', u'AnalysisTarget')]))])), (u'processes', OrderedDict([(u'@scr_shot_sha1', u'b2c6c02bcec05be68cd78009d57fe380421a933b'), (u'@scr_shot_md5', u'f10e8a0fd673df042a028bb7ef42b232'), (u'process', OrderedDict([(u'@index', u'1'), (u'@pid', u'1224'), (u'@filename', u'C:\\malware.exe'), (u'@executionstatus', u'OK'), (u'dll_handling_section', OrderedDict([(u'load_dll', [OrderedDict([(u'@filename', u'c:\\windows\\system32\\wshtcpip.dll')]), OrderedDict([(u'@filename', u'wsock32.dll')]), OrderedDict([(u'@filename', u'dnsapi.dll')]), OrderedDict([(u'@filename', u'hnetcfg.dll')]), OrderedDict([(u'@filename', u'kernel32.dll')]), OrderedDict([(u'@filename', u'ntdll.dll')]), OrderedDict([(u'@filename', u'c:\\windows\\system32\\mswsock.dll')]), OrderedDict([(u'@filename', u'c:\\windows\\system32\\winrnr.dll')]), OrderedDict([(u'@filename', u'rasadhlp.dll')])])])), (u'filesystem_section', OrderedDict([(u'create_file', [OrderedDict([(u'@filetype', u'file'), (u'@srcfile', u'\\Device\\Afd\\Endpoint')]), OrderedDict([(u'@filetype', u'file'), (u'@srcfile', u'\\Device\\Afd\\AsyncConnectHlp')])])]))]))])), (u'running_processes', OrderedDict([(u'running_process', [OrderedDict([(u'@pid', u'0'), (u'@filename', u'[System Process]'), (u'@ppid', u'0')]), OrderedDict([(u'@pid', u'4'), (u'@filename', u'System'), (u'@ppid', u'0')]), OrderedDict([(u'@pid', u'320'), (u'@filename', u'smss.exe'), (u'@ppid', u'4')]), OrderedDict([(u'@pid', u'544'), (u'@filename', u'csrss.exe'), (u'@ppid', u'320')]), OrderedDict([(u'@pid', u'568'), (u'@filename', u'winlogon.exe'), (u'@ppid', u'320')]), OrderedDict([(u'@pid', u'612'), (u'@filename', u'services.exe'), (u'@ppid', u'568')]), OrderedDict([(u'@pid', u'624'), (u'@filename', u'lsass.exe'), (u'@ppid', u'568')]), OrderedDict([(u'@pid', u'784'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'840'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1004'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1048'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1092'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1348'), (u'@filename', u'spoolsv.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1872'), (u'@filename', u'alg.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'224'), (u'@filename', u'userinit.exe'), (u'@ppid', u'568')]), OrderedDict([(u'@pid', u'248'), (u'@filename', u'explorer.exe'), (u'@ppid', u'224')]), OrderedDict([(u'@pid', u'528'), (u'@filename', u'reader_sl.exe'), (u'@ppid', u'248')]), OrderedDict([(u'@pid', u'1148'), (u'@filename', u'svchost.exe'), (u'@ppid', u'612')]), OrderedDict([(u'@pid', u'1180'), (u'@filename', u'monitor.exe'), (u'@ppid', u'1148')]), OrderedDict([(u'@pid', u'1224'), (u'@filename', u'malware.exe'), (u'@ppid', u'1180')])])])), (u'network_pcap', OrderedDict([(u'@sha1', u'7f66263624ff1db19f22d35140a1ce73e76f36c8'), (u'@md5', u'6cb3826cb7f827b794afc7bb795f6a9a'), (u'flows', [OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1031'), (u'@dst_ip', u'109.110.68.68'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'0')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1031'), (u'@dst_ip', u'109.110.68.68'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1032'), (u'@dst_ip', u'31.192.16.21'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'49')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1033'), (u'@dst_ip', u'31.170.146.20'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1034'), (u'@dst_ip', u'176.8.17.7'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'47')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1035'), (u'@dst_ip', u'5.58.28.68'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'47')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1036'), (u'@dst_ip', u'93.77.83.252'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'49')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1037'), (u'@dst_ip', u'188.143.142.98'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'51')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1038'), (u'@dst_ip', u'176.112.1.35'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'49')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1039'), (u'@dst_ip', u'176.8.244.116'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1040'), (u'@dst_ip', u'176.111.42.68'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1041'), (u'@dst_ip', u'46.172.125.93'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1042'), (u'@dst_ip', u'5.248.31.50'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'48')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1043'), (u'@dst_ip', u'176.99.125.55'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1044'), (u'@dst_ip', u'176.101.10.125'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'51')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1045'), (u'@dst_ip', u'5.248.106.151'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'50')]), OrderedDict([(u'@src_ip', u'192.168.1.1'), (u'@src_port', u'1046'), (u'@dst_ip', u'37.229.225.112'), (u'@dst_port', u'80'), (u'@protocol', u'6'), (u'@bytes', u'51')])]), (u'http', [OrderedDict([(u'@type', u'GET'), ('#text', u'http://109.110.68.68/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://31.192.16.21/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://31.170.146.20/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.8.17.7/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://5.58.28.68/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://93.77.83.252/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://188.143.142.98/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.112.1.35/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.8.244.116/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.111.42.68/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://46.172.125.93/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://5.248.31.50/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.99.125.55/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://176.101.10.125/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://5.248.106.151/survik1.exe')]), OrderedDict([(u'@type', u'GET'), ('#text', u'http://37.229.225.112/survik1.exe')])])]))]))]"