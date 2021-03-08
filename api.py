import requests, json
import sys
import argparse
from getpass import getpass
from requests.sessions import session
import urllib3
import time


urllib3.disable_warnings()

parser = argparse.ArgumentParser()
parser.add_argument('--user', type=str, help="username", required='--file' not in sys.argv)
parser.add_argument('--grp_name', type=str, help="group name", required=True)
parser.add_argument('--ip', type=str, help="Management ip address", required=True)
parser.add_argument('--cmd', type=str, help='add-group or set-group',
                    required=True)
parser.add_argument('--file', required=True, type=str, help='read from any file containing ips 1 ip in line')
parser.add_argument('--policy', type=str, required=False, help='please enter policy name')
parser.add_argument('--targets', type=str, required=False, help='please enter target to install policy on, seperated by [,]: fw, fw2 ')
args = parser.parse_args()

def api_call(ip_addr, port, command, json_payload, sid=None):
    url = f'https://{ip_addr}:{port}/web_api/{command}'
    if not sid:
        request_headers = {'Content-Type' : 'application/json'}
    else:
        request_headers = {'Content-Type' : 'application/json', 'X-chkp-sid' : sid}
    r = requests.post(url,data=json.dumps(json_payload), headers=request_headers, verify=False)
    return r.json()


def login(user,password,enter_last_published_session=False):
    payload = {'user':user, 'password' : password, 'enter-last-published-session': enter_last_published_session}
    response = api_call(args.ip, 443, 'login',payload, '')
    return response


def show_group(name, sid):
    group = api_call(args.ip, 443,'show-group', {'name': name} , sid)
    lock_status = {
        "locked": group['meta-info']['lock'], 
        "locking-admin": group['meta-info'].get("locking-admin"), 
        "locking-session-id": group['meta-info'].get("locking-session-id")
        }
    print(lock_status)
    m = []
    for i in group['members']:
        m.append(i['name'])
    return m, lock_status


def add_host_from_file(file=None, sid=None):
    with open(file) as file:
        for line in file.readlines():
            new_host_data = {'name':line.strip().rstrip(), 'ip-address': line.strip().rstrip()}
            host = api_call(args.ip, 443,'show-host', {"name": line.strip().rstrip()} , sid)
            if host.get("code") == "generic_err_object_not_found":
            # print(host)
                new_host_result = api_call(args.ip, 443,'add-host', new_host_data , sid)
                print(json.dumps(new_host_result))
            else:
                print(f'{line.strip().rstrip()} already exists!')

    

def add_group(name=None, members=None, sid=None):
    with open(members) as file:
        member_list = []
        for member in file.readlines():
            member_list.append(member.strip().rstrip())
        group = {
            'name': name, 
            'members': member_list 
            }
        a = api_call(args.ip, 443,'set-group', group ,sid)
    publish_result = api_call(args.ip, 443,"publish", {},sid)
    print("publish result: " + json.dumps(publish_result))
    # api_call(args.ip, 443,"logout", {},sid)

def set_group(name=None, members=None, sid=None):
    m = show_group(args.grp_name, sid)
    with open(members) as file:
        for member in file.readlines():
            if member.strip().rstrip() not in m:
            # member_list.append(member.strip().rstrip())
                group = {
                    'name': name, 
                    'members': 
                    {"add": member.strip().rstrip() }
                }
                a = api_call(args.ip, 443,'set-group', group ,sid)
    publish_result = api_call(args.ip, 443,"publish", {},sid)
    print("publish result: " + json.dumps(publish_result))


def show_session(sid, uid):
    session = api_call(args.ip, 443,"show-session", {"uid": uid}, sid)
    
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


def show_task(sid, task_id, task_name):
    task = api_call(args.ip, 443, "show-task", {"task-id" : task_id}, sid)
    status = task["tasks"][0]["status"]
    while status == 'in progress':
        print(f'{task_name} policy in progress')
        time.sleep(5)
        status = api_call(args.ip, 443, "show-task", {"task-id" : task_id}, sid)["tasks"][0]["status"]
        
    print(f"{task_name} policy {status}")
    return status


def show_sessions(sid):
    sessions = api_call(args.ip, 443,"show-sessions", { "limit" : 50, "offset" : 0, "details-level" : "standard"}, sid)
    for session in sessions["objects"]:
        print(show_session(sid, session['uid']))
    return sessions


def install_policy(sid):
    install = api_call(args.ip, 443, "install-policy", {"policy-package" : args.policy, "access" : True, "threat-prevention" : True, "targets": args.targets.split()}, sid)
    return show_task(sid, install["task-id"], "install")
            

def verify_policy(sid):
    verify = api_call(args.ip, 443, "verify-policy", {"policy-package" : args.policy}, sid)
    return show_task(sid, verify["task-id"], "verify")
    

def veryfy_and_install(sid):
    status = verify_policy(sid)
    if status == "succeeded":
        status = install_policy(sid)
    return status



def switch_policy(q, sid):
    try:
        a = {
        "1": verify_policy,
        "2": install_policy,
        "3": veryfy_and_install,
        }
        return a[q](sid)
    except:
        return False
    

def start():
    password = getpass()
    login_data = login(args.user, password)
    sid = login_data["sid"]
    uid = login_data["uid"]
    group, locked = show_group(args.grp_name, sid)
    
    new_hosts = input("add new hosts?\n: ")
    if new_hosts.lower() == "yes":
        add_host_from_file(file=args.file, sid=sid)
    if locked.get('locked') == "unlocked":
        if args.cmd == 'set-group':
            set_group(name=args.grp_name, members=args.file, sid=sid)
        elif args.cmd == 'add-group':
            set_group(name=args.grp_name, members=args.file, sid=sid)

        publish_result = api_call(args.ip, 443,"publish", {},sid)
        print("publish result: " + json.dumps(publish_result))
    else:
        print(locked)
    session = show_session(sid, uid)
    print(
        f'type: {session.get("type")}\n',
        f'changes: {session.get("changes")}\n',
        f'mode: {session.get("connection-mode")}\n', 
        f'locks: {session.get("locks")}\n',
        f'publish-time: {session.get("publish-time")}\n',
        f'state: {session.get("state")}')
    q = input("choose from options:\n\t1. verify policy\n\t2. install policy\n\t3. verify and install\nanything else will logout from this session:\n: ")
    switch_policy(q, sid)
    
    print(f'Logged out {api_call(args.ip, 443,"logout", {},sid)["message"]}')
    	    

start()
