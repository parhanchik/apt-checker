# This is a sample Python script.

# Press ⌃R to execute it or replace it with your code.
# Press Double ⇧ to search everywhere for classes, files, tool windows, actions, and settings.


import psutil
import os
import re
import time


class Process:
    def __init__(self):
        self.warning = []
        self.critical = []

    def get_connection(self, process):
        try:
            output = ""
            res = process.connections()
            if res:
                pcon = res[0]
                if pcon.raddr:
                    output += f"Network connection:\n\t\tip:\t{pcon.raddr.ip}:{pcon.raddr.port}\n"

                    # get domain name
                    domain = os.popen(f"dig -x {pcon.raddr.ip} +short | awk -F '.' '{{print $0}}'").read()[:-1]
                    output += f"\t\tdomain:\t{domain}\n"

                    try:
                        # get provider name
                        whois_output = os.popen(f'whois {pcon.raddr.ip}').read()
                        provider_name = re.search('OrgName:( *)(.*)', whois_output).group(2)
                        output += f"\t\tprovider name:\t{provider_name}\n"
                    except Exception:
                        pass
                    return output
            return "\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "\n"

    def _get_all(self):
        return set([process for process in psutil.process_iter()])

    def get_process_name(process):
        try:
            processName = process.name()
            processID = process.pid
            return f"name: {processName}\npid: {processID}"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def __sort(self):


    def event_loop(self):

if __name__ == '__main__':
    last_set = set()
    while True:
        proc_set = get_all_processes()
        diff = proc_set - last_set
        last_set = proc_set
        print(proc_set)
        # proc_set = set(proc_list)
        for proc in diff:
            res = ""
            res += get_process_name(proc)
            res += get_process_connection(proc)

            print(res)

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
