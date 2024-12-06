import requests
import time
import re
from encryption.srun_md5 import *
from encryption.srun_sha1 import *
from encryption.srun_base64 import *
from encryption.srun_xencode import *
import argparse
header={
	'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.26 Safari/537.36'
}
init_url="http://202.201.252.10"
get_challenge_api="http://202.201.252.10/cgi-bin/get_challenge"

srun_portal_api="http://202.201.252.10/cgi-bin/srun_portal"
get_info_api="http://202.201.252.10/cgi-bin/rad_user_info?callback=jQuery112406118340540763985_1556004912581&_=1556004912582"
n = '200'
type = '1'
ac_id='1'
enc = "srun_bx1"

def get_chksum(args):
	chkstr = token+args.username
	chkstr += token+hmd5
	chkstr += token+ac_id
	chkstr += token+args.host_ip
	chkstr += token+n
	chkstr += token+type
	chkstr += token+i
	return chkstr
def get_info(args):
	info_temp={
		"username":args.username,
		"password":args.password,
		"ip":args.host_ip,
		"acid":ac_id,
		"enc_ver":enc
	}
	i=re.sub("'",'"',str(info_temp))
	i=re.sub(" ",'',i)
	return i
# def init_getip():
#     global ip
#     init_res=requests.get(init_url,headers=header)
#     print(init_res.text)
#     print("初始化获取ip")
#     ip=re.search('ip: "(.*?)",',init_res.text)
#     #ip ="172.31.0.12"
#     print("ip:"+ip)
def get_token(args):
	# print("获取token")
	global token
	get_challenge_params={
		"callback": "jQuery112404953340710317169_"+str(int(time.time()*1000)),
		"username":args.username,
		"ip":args.host_ip,
		"_":int(time.time()*1000),
	}
	get_challenge_res=requests.get(get_challenge_api,params=get_challenge_params,headers=header)
	token=re.search('"challenge":"(.*?)"',get_challenge_res.text).group(1)
	print(get_challenge_res.text)
	print("token为:"+token)
def do_complex_work(args):
	global i,hmd5,chksum
	i=get_info(args)
	i="{SRBX1}"+get_base64(get_xencode(i,token))
	hmd5=get_md5(args.password,token)
	chksum=get_sha1(get_chksum(args))
	print("所有加密工作已完成")
def login(args):
	srun_portal_params={
	'callback': 'jQuery11240645308969735664_'+str(int(time.time()*1000)),
	'action':'login',
	'username':args.username,
	'password':'{MD5}'+hmd5,
	'ac_id':ac_id,
	'ip':args.host_ip,
	'chksum':chksum,
	'info':i,
	'n':n,
	'type':type,
	'os':'windows+10',
	'name':'windows',
	'double_stack':'0',
	'_':int(time.time()*1000)
	}
	# print(srun_portal_params)
	srun_portal_res=requests.get(srun_portal_api,params=srun_portal_params,headers=header)
	print(srun_portal_res.text)
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='ubuntu login ')
    parser.add_argument('--host_ip', type=str, help='host IP')
    parser.add_argument('--username', type=str, help='username')
    parser.add_argument('--password', type=str, help='password')
    args = parser.parse_args()
    username="001036"
    password="001036"
    get_token(args)
    do_complex_work(args)
    login(args)
    res=requests.get(get_info_api,headers=header)
    print(res.text)