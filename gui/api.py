import requests, json
import sys
import argparse
from getpass import getpass
from requests.sessions import session
import urllib3
import time
from cp_gui.cp_gui import Ui_MainWindow
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import sys
import csv
from threading import Thread


urllib3.disable_warnings()

# parser = argparse.ArgumentParser()
# parser.add_argument('--user', type=str, help="username", required='--file' not in sys.argv)
# parser.add_argument('--grp_name', type=str, help="group name", required=True)
# parser.add_argument('--ip', type=str, help="Management ip address", required=True)
# parser.add_argument('--cmd', type=str, help='add-group or set-group',
#                     required=True)
# parser.add_argument('--file', required=True, type=str, help='read from any file containing ips 1 ip in line')
# parser.add_argument('--policy', type=str, required=False, help='please enter policy name')
# parser.add_argument('--targets', type=str, required=False, help='please enter target to install policy on, seperated by [,]: fw, fw2 ')
# parser.add_argument('--name_prefix', type=str, required=False, help='frefix for object name')
# args = parser.parse_args()

class Application(Ui_MainWindow, QMainWindow):

    def __init__(self, parent=None):
        self.threadpool = QThreadPool()
        self.file = None
        self.sid = None
        self.uid = None
        super(Application, self).__init__(parent)
        self.setupUi(self)
        self.toolButton.clicked.connect(self.getfile)
        self.start.clicked.connect(self.start_import)
        self.logout.clicked.connect(self.logout_session)
        

    def api_call(self, ip_addr, port, command, json_payload, sid=None):
        url = f'https://{ip_addr}:{port}/web_api/{command}'
        print(url)
        if not sid:
            request_headers = {'Content-Type' : 'application/json'}
        else:
            request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
        r = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)
        return r.json()


    def login(self, user,password,enter_last_published_session=False):
        payload = {'user':user, 'password' : password, 'enter-last-published-session': enter_last_published_session}
        response = self.api_call(self.ip.text(), 443, 'login',payload, '')
        return response

    def getfile(self):

        try:
            path, _ = QFileDialog.getOpenFileName(self, 'Open csv', QDir.rootPath(), '*.csv, *.txt')
            self.file = open(path).readlines()
        except Exception as error:
            print(error)

    def show_group(self, name, sid):
        m = []
        group = self.api_call(self.ip.text(), 443,'show-group', {'name': name} , sid)
        if 'code' in group.keys() and group['code'] != 'generic_err_object_not_found':
            lock_status = {
                "locked": group['meta-info']['lock'], 
                "locking-admin": group['meta-info'].get("locking-admin"), 
                "locking-session-id": group['meta-info'].get("locking-session-id")
                }
            print(lock_status)
        
            
            
            for i in group['members']:
                m.append(i['name'])
            return m, lock_status
        return m, {"locked": "unlocked"}


    def parse_object_msg(host):
        if "warnings" in host.keys():
            print(host["warnings"][0]["message"])


    def add_host_from_file(self, file=None, sid=None):
        # with open(file) as file:
        for line in file:
            name = line.strip().rstrip()
            if len(self.name_prefix.text()) >=1:
                name = f"{self.name_prefix.text()}{name}"
            new_host_data = {'name':name, 'ip-address': line.strip().rstrip()}
            host = self.api_call(self.ip.text(), 443,'show-host', {"name": name} , sid)
            if host.get("code") == "generic_err_object_not_found":
            # print(host)
                new_host_result = self.api_call(self.ip.text(), 443,'add-host', new_host_data , sid)
                self.parse_object_msg(new_host_result)
            else:
                print(f'{line.strip().rstrip()} already exists!')


    def add_net_from_file(self, file=None, sid=None):
        
        for line in file:
            line = line.strip().rstrip().split("/")
            
            name = line[0]
            subnet = line[0]
            prefix = line[1]
            if len(self.name_prefix.text()) >=1:
                name = f"{self.name_prefix.text()}{name}"
            new_host_data = {'name':name, 'subnet': subnet, 'mask-length': prefix}
            host = self.api_call(self.ip.text(), 443,'show-network', {"name": name} , sid)
            if host.get("code") == "generic_err_object_not_found":
            # print(host)
                new_host_result = self.api_call(self.ip.text(), 443,'add-network', new_host_data , sid)
                self.parse_object_msg(new_host_result)
                # print(json.dumps(new_host_result))
            else:
                print(f'{line.strip().rstrip()} already exists!')    
            



    def add_net_obj(self, file, sid):
        with open(file) as file:
            for line in file.readlines():
                if "/" in line:
                    self.add_net_from_file([line], sid)
                else:
                    self.add_host_from_file([line], sid)


    def add_group(self, name=None, members=None, sid=None):
        with open(members) as file:
            member_list = []
            for member in file.readlines():
                member = member.strip().rstrip()
                if self.name_prefix.text():
                    member = f"{self.name_prefix.text()}{member}"
                member_list.append(member)
            group = {
                'name': name, 
                'members': member_list 
                }
            self.api_call(self.ip.text(), 443,'add-group', group ,sid)
            
        publish_result = self.api_call(self.ip.text(), 443,"publish", {},sid)
        print("publish result: " + json.dumps(publish_result))
        # api_call(self.ip.text(), 443,"logout", {},sid)

    def set_group(self, name=None, members=None, sid=None):
        m = self.show_group(self.grp_name.text(), sid)
        with open(members) as file:
            for member in file.readlines():
                if "/" in member:
                    member = member.strip().rstrip().split("/")[0]
                member = member.strip().rstrip()
                if self.name_prefix.text():
                    member = f"{self.name_prefix.text()}{member}"
                if member not in m:
                # member_list.append(member.strip().rstrip())
                    group = {
                        'name': name, 
                        'members': 
                        {"add": member.strip().rstrip() }
                    }
                    a = self.api_call(self.ip.text(), 443,'set-group', group ,sid)
        publish_result = self.api_call(self.ip.text(), 443,"publish", {},sid)
        print("publish result: " + json.dumps(publish_result))


    def show_session(self, sid, uid):
        session = self.api_call(self.ip.text(), 443,"show-session", {"uid": uid}, sid)
        
        return {
            'type':session.get("type"),
            "changes": session.get("changes"),
            "mode": session.get("connection-mode"), 
            "locks": session.get("locks"),
            "publish-time": session.get("publish-time"),
            "state": session.get("state"),
            'creator': session.get('creator'),
            'ip-address': session.get('ip-address'),
            'uid': uid
        }


    def show_task(self, sid, task_id, task_name):
        task = self.api_call(self.ip.text(), 443, "show-task", {"task-id" : task_id}, sid)
        status = task["tasks"][0]["status"]
        while status == 'in progress':
            print(f'{task_name} policy in progress')
            time.sleep(5)
            status = self.api_call(self.ip.text(), 443, "show-task", {"task-id" : task_id}, sid)["tasks"][0]["status"]
            
        print(f"{task_name} policy {status}")
        return status


    def show_sessions(self, sid):
        sessions = self.api_call(self.ip.text(), 443,"show-sessions", { "limit" : 50, "offset" : 0, "details-level" : "standard"}, sid)
        for session in sessions["objects"]:
            print(self.show_session(sid, session['uid']))
        return sessions


    def install_policy(self, sid):
        install = self.api_call(self.ip.text(), 443, "install-policy", {"policy-package" : self.policy.text(), "access" : True, "threat-prevention" : True, "targets": self.targets.text().split()}, sid)
        return self.show_task(sid, install["task-id"], "install")
                

    def verify_policy(self, sid):
        verify = self.api_call(self.ip.text(), 443, "verify-policy", {"policy-package" : self.policy.text()}, sid)
        return self.show_task(sid, verify["task-id"], "verify")
        

    def veryfy_and_install(self, sid):
        status = self.verify_policy(sid)
        if status == "succeeded":
            status = self.install_policy(sid)
        return status



    def switch_policy(self, sid):
        try:
            if self.verify.checkState() == 2:
                print("Verify policy")
                return self.verify_policy(sid),
            elif self.install.checkState() == 2:
                print("install policy")
                return self.install_policy(sid),
            elif self.verify_and_install.checkState() == 2:
                print("Verify and install policy")
                return self.veryfy_and_install(sid),
        except:
            return False
        
    def logout_session(self):
        print(f'Logged out {self.api_call(self.ip.text(), 443,"logout", {},self.sid)["message"]}')
    
    
    def start_import(self):
        if self.sid is None:
            login_data = self.login(self.username_2.text(), self.password.text())
            self.sid = login_data["sid"]
            self.uid = login_data["uid"]
        group, locked = self.show_group(self.grp_name.text(), self.sid)
        
        # new_hosts = input("add new network objects?\n: ")
        # if new_hosts.lower() == "yes" or new_hosts.lower() == "y":
        if self.add_new_hosts.checkState() == 2:
            self.add_net_obj(self.file, self.sid)
        if locked.get('locked') == "unlocked":
            if self.cmd.currentText() == 'set-group':
                self.set_group(name=self.grp_name.text(), members=self.file, sid=self.sid)
            elif self.cmd.currentText() == 'add-group':
                self.add_group(name=self.grp_name.text(), members=self.file, sid=self.sid)

            publish_result = self.api_call(self.ip.text(), 443,"publish", {},self.sid)
            print("publish result: " + json.dumps(publish_result))
        else:
            print(locked)
        if len(self.policy.text()) > 3:
            # q = input("choose from options:\n\t1. verify policy\n\t2. install policy\n\t3. verify and install\nanything else will logout from this session:\n: ")
            self.switch_policy(self.sid)
        session = self.show_session(self.sid, self.uid)
        print(
            f'type: {session.get("type")}\n',
            f'changes: {session.get("changes")}\n',
            f'mode: {session.get("connection-mode")}\n', 
            f'locks: {session.get("locks")}\n',
            f'publish-time: {session.get("publish-time")}\n',
            f'state: {session.get("state")}')
        
        
        
        
                

def main():
    try:
       app = QApplication(sys.argv)
       ex = Application()
       ex.show()
       sys.exit(app.exec_())
    except Exception as error:
        print(error)


if __name__ == "__main__":
    main()

