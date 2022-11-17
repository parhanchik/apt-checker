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

    def _get_connection(self, process):
        try:
            output = ""
            res = process.connections()
            if res:
                pcon = res[0]
                if pcon.raddr:
                    output += f"Network connection:\n\t\tip:\t{pcon.raddr.ip}:{pcon.raddr.port}\n"

                    # get domain name
                    domain = os.popen(f"dig -x {pcon.raddr.ip} +short | awk -F '.' '{{print $0}}'").read()[:-2]
                    if domain and "connection timed out" not in domain:
                        output += f"\t\tdomain:\t{domain}\n"

                    try:
                        # get provider name
                        whois_output = os.popen(f'whois {pcon.raddr.ip}').read()
                        provider_name = re.search('OrgName:( *)(.*)', whois_output).group(2)
                        output += f"\t\tprovider name:\t{provider_name}\n"
                    except:
                        pass
                    return output
            return "\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return "\n"

    @staticmethod
    def _get_all():
        return set([process for process in psutil.process_iter()])

    def _get_name(self, process):
        try:
            proc_name = process.name()
            proc_id = process.pid
            return f"name: {proc_name}\npid: {proc_id}\n"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    def __sort(self):
        #TODO
        """
        if process.weight >= middle and process.weight < high:
            self.warning.append(process.name)
        elif process.weight >= high:
            self.critical.append(process.name)
        """

    def event_loop(self):
        last_set = set()
        while True:
            proc_set = self._get_all()
            diff = proc_set - last_set
            last_set = proc_set
            for proc in diff:
                res = ""

                base_info = self._get_name(proc)
                connection = self._get_connection(proc)

                res += base_info if base_info is not None else ""
                res += connection if connection is not None else ""

                #if "Network connection" in res:
                #    print(res)
                print(res)


if __name__ == '__main__':
    p = Process()
    p.event_loop()

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
