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



    def wx_checker(self, filename):
        import subprocess
        bashCommand = "readelf --segments --wide  %s" % (filename)
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
        dummy = output
        wx_headers = re.findall('(.*)( *)( 0x.*)+ .?wx', dummy.lower())
        headers = re.findall('(.*)( *)( 0x.*)+ [rwxe]', dummy.lower())
        segments = set()
        for header in wx_headers:
            segment = str(headers.index(header)) if headers.index(header) > 9 else f"0{headers.index(header)}"
            try:
                wx_sections = re.search(f'( *){segment}( *)(\..*)', dummy).group(3).split()
                segments.update(wx_sections)
            except AttributeError:
                pass
        return segments
        #return SET with segments

    @staticmethod
    def get_exec_path_by_pid(pid):
        output = os.popen(f'pwdx {pid}').read()
        path_to_file = re.search('([0-9]*): (.*)', output)
        return path_to_file

    def __sort(self):
        # TODO
        """
        if process.weight >= middle and process.weight < high:
            self.warning.append(process.name)
        elif process.weight >= high:
            self.critical.append(process.name)
        """

    def check_packed_file(filename):
        import subprocess
        packers= { "UPX":"UPX0", "upx":"UPX1", "Upx":"UPX2", "Aspack":"aspack", "aspack":"adata",
                   "NSPack":"NSP0", "nspack":"NSP1", "NSpack":"NSP2", "NTKrnl":"NTKrnl Security Suite",
                   "PECompact":"PEC2", "pecompact":"PECompact2", "Themida":"Themida", "hemida":"aPa2Wa"}
        for el in packers:
            bashCommand = "strings %s | grep %s" % (filename, packers[el])
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            if output != "":
                return "File %s can be packed with %s" % (filename, el)
        return ""

    def compare_memore(self, pid):
        ram_memory = os.popen(f'gcore {pid}').read()
        file_memory = None

        with open(self.get_exec_path_by_pid(pid), 'rb') as exec_file:
            file_memory = exec_file.read()
        if file_memory == ram_memory:
            print('TRUUUUUE')
            #return True
        else:
            print('FAAALSEEEE')
            return False

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
                self.get_exec_path_by_pid(proc.pid)

                # if "Network connection" in res:
                #    print(res)
                print(res)


if __name__ == '__main__':
    p = Process()
    p.event_loop()

