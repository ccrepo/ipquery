import sys
import requests
import socket
import subprocess
from shutil import which

# configuration
URL = "http://localhost:8080/tomcat/server/ip/query"
BUFFER_LIMIT = 1024

stdout_fileno = sys.stdout
stderr_fileno = sys.stderr


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
        stdout_fileno.write(reload_command + " " + parameters + "\n")
        subprocess.run([reload_command, parameters])
        return True
    except:
        stderr_fileno.write(reload_command + "failed\n")
    return False;


def ip_list_to_prefix_set(ip_list, description):
    results = []
    for ip in ip_list:
        index = ip.rfind(".")
        result = ip[:index]
        results.append(result)

    ip_set = set(results)
    for ip in ip_set:
        stdout_fileno.write(description + " " + ip + "\n")

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


def get_ufw():
    return ufw_command + " status numbered "


def get_grep():
    sub2_regexp = "[0-9][0-9]\\{0,2\\}"
    sub2_octal = sub2_regexp + "\\."
    sub2 = "grep '^\\[\\s*[0-9]*] 3389\\s*ALLOW IN\\s*"
    for i in range(3):
        sub2 = sub2 + sub2_octal
    sub2 = sub2 + sub2_regexp + "' "
    return sub2


def get_tr():
    return "tr '\\n' ' ' "


def build_deletions(ip_filter_set):
    grep_v = ""
    for ip_filter in ip_filter_set:
        if len(grep_v) > 0:
            grep_v = grep_v + " |"
        grep_v = grep_v + "grep -v '" + ip_filter + "'"
    awk = "awk '{ print $2 }' "
    cut = "cut -d']' -f 1 "
    sort = "sort -rn "

    ufw_numbers_command = ""
    try:
        ufw_numbers_command = build_command(get_ufw(), get_grep(), grep_v, awk, cut, sort, get_tr())
        stdout_fileno.write(ufw_numbers_command + "\n")
        buffer = subprocess.getoutput(ufw_numbers_command)
        if len(buffer) > BUFFER_LIMIT:
            stderr_fileno.write("BUFFER_LIMIT breached for " + ufw_numbers_command + "\n")
        return buffer.split()
    except:
        stderr_fileno.write("failed " + ufw_numbers_command + "\n")

    return []


def build_additions(ip_candidate_set):
    ip_candidate_list = list(ip_candidate_set)
    localhost = "127.0.0"
    if localhost in ip_candidate_list:
        ip_candidate_list.remove(localhost)

    awk = "awk '{ print $6 }' "
    cut = "cut -d'/' -f 1"
    sort = "sort"
    uniq = "uniq"
    grep_v = "grep -v '127.0.0.1'"

    ufw_ip_list_command = ""
    try:
        ufw_ip_list_command = build_command(get_ufw(), get_grep(), awk, cut, sort, uniq, grep_v, get_tr())
        stdout_fileno.write(ufw_ip_list_command + "\n")
        buffer = subprocess.getoutput(ufw_ip_list_command)
        if len(buffer) > BUFFER_LIMIT:
            stderr_fileno.write("BUFFER_LIMIT breached for " + ufw_ip_list_command + "\n")
        ip_filters = []

        for ip_filter in buffer.split():
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
        stderr_fileno.write("failed " + ufw_ip_list_command + "\n")

    return []


def do_httpget():
    stdout_fileno.write("http get '" + URL + "'\n")

    try:
        r = requests.get(url=URL)
    except:
        stderr_fileno.write("exception do_httpget '" + URL + "'\n")
        return None

    if r.status_code != 200:
        stderr_fileno.write("status code " + str(r.status_code) + " do_httpget '" + URL + "'\n")
        return None

    ip_list = r.text.split(",")

    for ip in ip_list[:]:
        if is_valid_ip(ip):
            stdout_fileno.write("get " + ip + "\n")
        else:
            stdout_fileno.write("ignoring " + ip + "\n")
            ip_list.remove(ip)

    return ip_list


def do_delete(delete_list):
    result = True
    for ip in delete_list:
        parameters = "delete " + ip
        delete_command = "yes | " + ufw_command + " " + parameters
        stdout_fileno.write(delete_command + "\n")
        try:
            buffer = subprocess.getoutput(delete_command)
            if len(buffer) > BUFFER_LIMIT:
                stderr_fileno.write("BUFFER_LIMIT breached for " + delete_command + "\n")
        except:
            stderr_fileno.write("failed " + delete_command + "\n")
            result = False
    return result


def do_add(add_list):
    result = True
    for ip in add_list:
        parameters = "allow from " + ip + "/24 to any port 3389"
        add_command = "yes | " + ufw_command + " " + parameters
        stdout_fileno.write(add_command + "\n")
        try:
            buffer = subprocess.getoutput(add_command)
            if len(buffer) > BUFFER_LIMIT:
                stderr_fileno.write("BUFFER_LIMIT breached for " + add_command + "\n")
        except:
            stderr_fileno.write("failed " + add_command + "\n")
            result = False
    return result


# checks
stdout_fileno.write("start.\n")

ufw_command = "ufw";
if not is_on_path(ufw_command):
    stderr_fileno.write("command ufw not in path\n")
    exit (1)

reload_command = "systemctl";
if not is_on_path(reload_command):
    stderr_fileno.write("command systemctl not in path\n")
    exit (1)

ip_get_list = do_httpget()

if ip_get_list is None:
    stderr_fileno.write("http failed\n")
    exit(1)

if len(ip_get_list) == 0:
    stdout_fileno.write("nothing to do\n")
    exit(0)

ip_prefix_get_set = ip_list_to_prefix_set(ip_get_list, "get set")

ip_deletions = build_deletions(ip_prefix_get_set)

ip_additions = build_additions(ip_prefix_get_set)

exit_code = 0

if not do_add(ip_additions):
    stderr_fileno.write("do add had errors\n")
    exit_code += 1

if not do_delete(ip_deletions):
    stderr_fileno.write("do delete had errors\n")
    exit_code += 2

if not do_reload():
    stderr_fileno.write("do reload failed\n")
    exit_code += 4

stdout_fileno.write("fini.\n")
exit(exit_code)
