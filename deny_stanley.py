#!/usr/local/bin/python3
import os,sys,re,json,requests,time
import threading
import paramiko
import socket,select
import logging

app_path = os.path.dirname(os.path.abspath(sys.argv[0]))
self_name=os.path.basename(sys.argv[0])
self_name=os.path.join(app_path,self_name)
logname=os.path.basename(sys.argv[0]).split('.')[0]+'.log'


debug=0
if os.environ.get('debug'):
    debug=1


def now(ts=None):
    if not ts:
        ts=time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))

def mylog(ss, log=os.path.join(app_path, logname)):
    ss = str(ss)
    print(now() + '  ' + ss)
    f = open(log, 'a+', encoding='utf8')
    f.write(now() + '  ' + ss + "\n")
    f.close()

class sshClient(): #封装下ssh的连接类
    def __init__(self, ):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # 此函数实现ssh登录主机
    def login_user_pass(self, host_ip, port,username, password):
        try:
            # self.tn = telnetlib.Telnet(host_ip,port=23)
            self.ssh.connect(host_ip, port, username, password)
            self.shell = self.ssh.invoke_shell()
            login_resp = self.shell.recv(655350).decode('utf8','ignore')
        except Exception as e:
            mylog('%s网络连接失败,Error:%s' % (host_ip, e))
            return False
        time.sleep(2)
        #mylog(login_resp)
        return True


    # 此函数实现执行传过来的命令，并输出其执行结果
    def exec_cmd(self, command,wait_for=2,read_interval=0.001):
        '''
        :param command:  要执行的命令
        :param wait_for:   需要等待的超时时间，以stdout没有输出开始计时，如果再次stdout有输出，重新清零。累加值超过此数值，则超时退出。单位为秒
        :param read_interval: 每次等待阻塞sock时的时间，用于buffer下数据
        :return:  返回相关命令执行后的命令结果
        '''
        # 执行命令
        self.shell.send(command + "\n")
        ss=''
        tmout=0
        while True:
            time.sleep(read_interval)
            # 获取命令结果
            if self.shell.exit_status_ready():
                break
            rl, wl, xl = select.select([self.shell], [], [], 0.0)
            if len(rl) > 0:
                line=self.shell.recv(1024).decode('utf8','ignore')
                tmout=0 #如果收到buf里面的字符，就不计算超时时间
                if debug:
                    mylog('buffer信息：\n%s' % line)
                ss+=line
            else:
                tmout+=read_interval
                if debug:
                    mylog(f"tmout={tmout}")
                if tmout >wait_for:
                    break
        #mylog('命令执行结果：\n%s' % ss)
        return ss

def deny_stanley(action='on'):
    ssh=sshClient()
    ssh.login_user_pass('192.168.31.254',22,'user','password')
    ssh.exec_cmd("edit")
    if action=='off':
        ssh.exec_cmd("deactivate security policies from-zone trust to-zone untrust policy deny_black_list")
    else:
        ssh.exec_cmd("activate security policies from-zone trust to-zone untrust policy deny_black_list")
    ssh.exec_cmd("commit")
    ssh.exec_cmd("quit")
    ssh.exec_cmd("quit")
    
def enable_wifi_black(enable='on'):
    s=requests.session()
    address='192.168.1.1'
    rand_url = f'http://{address}/asp/GetRandCount.asp'  # 获得一个随机数
    r=s.get(rand_url)
    if not r.status_code==200:
        print("get rand num failed")
        sys.exit(1)
    token=r.text.replace("\u00ef\u00bb\u00bf",'') #联通路由器那面返回的文本是Unicode带BOM头的，把这个头丢掉
    #print(json.dumps(token))
    login_url=f'http://{address}/login.cgi'
    login_data={"UserName":"user","PassWord":"password2","Language":"chinese",
                "x.X_HW_Token":token,
                }
    r=s.post(login_url,data=login_data)
    if not r.status_code==200:
        print("login failed")
        sys.exit(1)
    open('login.html','w',encoding='utf8').write(r.text)
    wifi_black_url=f'http://{address}/html/bbsp/wlanmacfilter/wlanmacfilter.asp'
    r=s.get(wifi_black_url)
    if not r.status_code==200:
        print("get wifi black list failed")
        sys.exit(1)
    open('wifi_list.html','w',encoding='utf8').write(r.text)
    isEnable=re.search(r"enableFilter\s*=\s*\'(\d+)\'", r.text)[1]
    new_token=re.search(r'id="hwonttoken" value="(\S+)"', r.text)[1]
    if enable.lower()=='get':
        print(f"wifi black list enable={isEnable}")
        return
    set_url=f'http://{address}/html/bbsp/wlanmacfilter/set.cgi?x=InternetGatewayDevice.X_HW_Security&RequestFile=html/bbsp/wlanmacfilter/wlanmacfilter.asp'
    setEnable=1
    if enable.lower()=='on':
        setEnable=1
        data={'x.WlanMacFilterPolicy':0,'x.WlanMacFilterRight':1,'x.X_HW_Token':new_token}
    elif enable.lower()=='off':
        setEnable = 0
        data = {'x.WlanMacFilterPolicy': 0, 'x.WlanMacFilterRight': 0, 'x.X_HW_Token': new_token}
    else:
        setEnable = 1
        data = {'x.WlanMacFilterPolicy': 0, 'x.WlanMacFilterRight': 1, 'x.X_HW_Token': new_token}
    mylog(f"set wifi black list enable :{setEnable}")
    r=s.post(set_url,data=data)
    if r.status_code==200:
        print("success")
        r = s.get(wifi_black_url)
        isEnable = re.search(r"enableFilter\s*=\s*\'(\d+)\'", r.text)[1]
        print(f"wifi black list enable={isEnable}")
    else:
        print("ERROR:not set")
        sys.exit(1)
        
def enable_rule_OLD(enable='on'):
    s=requests.session()
    login_url='http://192.168.31.254'
    login_data={"method":"do","login":{"username":"user","password":"password"}}
    r=s.post(login_url,json=login_data)
    if not r.status_code==200:
        print("login failed")
        sys.exit(1)
    stok=json.loads(r.text)['stok']
    op_url=login_url+'/stok=%s/ds' % stok
    query_data={"method":"get","app_restrict":{"table":"app_restrict_rule","para":{"start":0,"end":9}}}
    r=s.post(op_url,json=query_data)
    if not r.status_code==200:
        print("can not get policy rule!")
        sys.exit(1)
    rule=json.loads(r.text)['app_restrict']['app_restrict_rule'][0]
    rule_name=list(rule.keys())[0]
    if enable.lower()=='get':
        print("rule_name=%s,current enable=%s" % (rule_name,rule[rule_name]['enable'] ))
        enable_wifi_black('get') #再看下联通光猫上的wifi mac地址过滤规则是否开启
        sys.exit()
    set_data={"method":"set","app_restrict":rule}
    rule[rule_name]['enable']=enable
    mylog(f"deny rule policy:{enable}")
    r=s.post(op_url,json=set_data)
    if r.status_code==200:
        print("success")
        r = s.post(op_url, json=query_data)
        rule = json.loads(r.text)['app_restrict']['app_restrict_rule'][0]
        rule_name = list(rule.keys())[0]
        print("rule_name=%s,current enable=%s" % (rule_name,rule[rule_name]['enable'] ))
    else:
        print("ERROR:not set")
        sys.exit(1)
    enable_wifi_black(enable) #再对联通光猫上的wifi mac地址过滤进行开启或者关闭

def enable_rule(enable='on'):
    s=requests.session()
    ssh=sshClient()
    ssh.login_user_pass('192.168.31.254',22,'user','password')
    if enable.lower()=='get':
        ss=ssh.exec_cmd("show configuration security policies from-zone trust to-zone untrust policy deny_black_list | display set | match deactivate")
        ssh.exec_cmd("quit")
        print("check if there are deactivate key word: %s" % ss)
        enable_wifi_black('get') #再看下联通光猫上的wifi mac地址过滤规则是否开启
        sys.exit()
    elif enable.lower()=='off':
        ssh.exec_cmd("edit")
        ssh.exec_cmd("deactivate security policies from-zone trust to-zone untrust policy deny_black_list")
        ssh.exec_cmd("commit")
        ss=ssh.exec_cmd("show configuration security policies from-zone trust to-zone untrust policy deny_black_list | display set | match deactivate")
        ssh.exec_cmd("quit")
        ssh.exec_cmd("quit")
        print("check if there are deactivate key word: %s" % ss)
    else:
        ssh.exec_cmd("edit")
        ssh.exec_cmd("activate security policies from-zone trust to-zone untrust policy deny_black_list")
        ssh.exec_cmd("commit")
        ss=ssh.exec_cmd("show configuration security policies from-zone trust to-zone untrust policy deny_black_list | display set | match deactivate")
        ssh.exec_cmd("quit")
        ssh.exec_cmd("quit")
        print("check if there are deactivate key word: %s" % ss)
    mylog(f"deny rule policy:{enable}")
    enable_wifi_black(enable) #再对联通光猫上的wifi mac地址过滤进行开启或者关闭


def delay_enable_rule(t='300'): #定义多少时间后，开启禁用策略
    if re.search(r'^\d+$',t) :  #如果是纯数字，就直接转数字时间
        delay=int(t)
    elif re.search(r'^([0-9\.]+)[sS]+$',t): #如果类似300s这样的，就取300转数字
        delay=re.search(r'^([0-9\.]+)[sS]+$',t).group(1)
        delay=int(delay)
    elif re.search(r'^([0-9\.]+)[mM]+$',t): #如果是类似30m这样的，就取30转数字*60
        delay=re.search(r'^([0-9\.]+)[mM]+$',t).group(1)
        delay=int(float(delay)*60)
    elif re.search(r'^([0-9\.]+)[hH]+$',t): #如果是类似1h这样的，就取1转数字*60*60
        delay=re.search(r'^([0-9\.]+)[hH]+$',t).group(1)
        delay=int(float(delay)*60*60)
    else:
        delay=300
    mylog(f"allow {delay/60} minutes to {now(time.time()+delay)}")
    script_file=os.path.join(app_path,'deny_daemon.sh')
    f=open(script_file,'w',encoding='utf8')
    f.write(f"{self_name} off\n")
    f.write(f"sleep {delay}\n")
    f.write(f"{self_name}\n")
    f.close()
    os.system(f"chmod 755 {script_file}")
    os.system(f"nohup {script_file} &")
    
    
if __name__=='__main__':
    '''
    用法：  deny_stanley.py off  #放开禁用策略
            deny_stanley  on    #开启禁用策略
            deny_stanley off 300s #放开禁用策略，再300s后，开启禁用策略
            deny_stanley off 60m #放开禁用策略，再60m后，开启禁用策略
    '''
    if len(sys.argv)==1:
        enable_rule('on')
    elif len(sys.argv)==2:
        enable_rule(sys.argv[1])
    elif len(sys.argv)>=3:
        ct=threading.Thread(target=delay_enable_rule,args=(sys.argv[2],))
        ct.start()
    else:
        enable_rule('on')

