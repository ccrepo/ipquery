import sys
import requests
import socket
import subprocess
from itertools import filterfalse
from shutil import which

# configuration
URL = "http://localhost:8080/tomcat/server/ip/query"


def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False


def is_on_path(command):
    return which(command) is not None


def do_reload():
    parameters = "daemon-reload"

    try:
        print(reload_command + " " + parameters)
        subprocess.run([reload_command, parameters])
        return True
    except:
        print(reload_command + "failed")
    return False;


def ip_list_to_prefix_set(ip_list, description):
    results = []
    for ip in ip_list:
        index = ip.rfind(".")
        result = ip[:index]
        results.append(result)

    ip_set = set(results)
    for ip in ip_set:
        print(description + " " + ip)

    return ip_set


def build_command(*arg):
    command = ""
    for i in range(len(arg)):
        if len(arg[i]) == 0:
            continue
        if len(command) > 0:
            command = command + "|"
        command = command + arg[i]
    return command


def get_sub1():
    return ufw_command + " status numbered "


def get_sub2():
    sub2_regexp = "[0-9][0-9]\\{0,2\\}"
    sub2_octal = sub2_regexp + "\\."
    sub2 = "grep '^\\[\\s*[0-9]*] 3389\\s*ALLOW IN\\s*"
    for i in range(3):
        sub2 = sub2 + sub2_octal
    sub2 = sub2 + sub2_regexp + "' "
    return sub2


def get_sub7():
    return "tr '\\n' ' ' "


def get_filtered_deletions(ip_filter_set):
    sub3 = ""
    for ip_filter in ip_filter_set:
        if len(sub3) > 0:
            sub3 = sub3 + " |"
        sub3 = sub3 + "grep -v '" + ip_filter + "'"
    sub4 = "awk '{ print $2 }' "
    sub5 = "cut -d']' -f 1 "
    sub6 = "sort -rn "

    try:
        stdout = subprocess.getoutput(build_command(get_sub1(), get_sub2(), sub3, sub4, sub5, sub6, get_sub7()))
        return stdout.split()
    except:
        print("failed")

    return []


def get_filtered_additions(ip_candidate_set):
    ip_candidate_list = list(ip_candidate_set)
    localhost = "127.0.0"
    if localhost in ip_candidate_list:
        ip_candidate_list.remove(localhost)

    sub3 = "awk '{ print $6 }' "
    sub4 = "cut -d'/' -f 1"
    sub5 = "sort"
    sub6 = "uniq"
    sub8 = "grep -v '127.0.0.1'"

    try:
        command = build_command(get_sub1(), get_sub2(), sub3, sub4, sub5, sub6, sub8, get_sub7())
        #print(command)
        stdout = subprocess.getoutput(command)
        ip_filters = []

        for ip_filter in stdout.split():
            if is_valid_ip(ip_filter):
                ip_filters.append(ip_filter)

        ip_filter_set = ip_list_to_prefix_set(ip_filters, "filter set")

        for ip_filter in ip_filter_set:
            if ip_filter in ip_candidate_list:
                ip_candidate_list.remove(ip_filter)

        results = []
        for candidate in ip_candidate_list:
            results.append(candidate + ".0")

        return results
    except:
        print("failed")

    return []


def do_httpget():
    print("http get '" + URL + "'")

    try:
        r = requests.get(url=URL)
    except:
        print("exception do_httpget '" + URL + "' - ")
        return None

    if r.status_code != 200:
        print("status code " + str(r.status_code) + " do_httpget '" + URL + "' - ")
        return []

    ip_list = r.text.split(",")

    for ip in ip_list[:]:
        if is_valid_ip(ip):
            print("get " + ip)
        else:
            print("ignoring " + ip)
            ip_list.remove(ip)

    return ip_list


def do_delete(delete_list):
    for ip in delete_list:
        parameters = "delete " + ip
        delete_command = "yes | " + ufw_command + " " + parameters
        print(delete_command)
        try:
            stdout = subprocess.getoutput(delete_command)
        except:
            print("failed")


def do_add(add_list):
    for ip in add_list:
        parameters = "allow from " + ip + "/24 to any port 3389"
        insert_command = "yes | " + ufw_command + " " + parameters
        print(insert_command)
        try:
            stdout = subprocess.getoutput(insert_command)
        except:
            print("failed")


# checks
print("start.")

ufw_command = "ufw";
if not is_on_path(ufw_command):
    print("command ufw not in path")
    exit (1)

reload_command = "systemctl";
if not is_on_path(reload_command):
    print("command systemctl not in path")
    exit (1)


ip_get_list = do_httpget()

if ip_get_list is None:
    print("http failed")
    exit(1)

if len(ip_get_list) == 0:
    print("nothing to do")
    exit(0)

ip_prefix_get_set = ip_list_to_prefix_set(ip_get_list, "get set")

ip_deletions = get_filtered_deletions(ip_prefix_get_set)

ip_additions = get_filtered_additions(ip_prefix_get_set)

do_add(ip_additions)

do_delete(ip_deletions)

if not do_reload():
    print("do reload failed")
    exit(1)

print("fini.")
exit(0)
