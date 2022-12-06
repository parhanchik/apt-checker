import psutil
import os
import re
import time
from math import pi, atan
import logging
import ctypes, sys
import hashlib
import mitre.mitre as mitre


class CustomFormatter(logging.Formatter):
    yellow = "\033[33m"
    bright_yellow = "\033[93m"
    red = "\033[31m"
    bright_red = "\033[91m"

    bold = "\033[1m"
    reset = "\033[0m"

    date = "%(asctime)s.%(msecs)03d"
    level = " | %(levelname)s"
    message = " %(message)s"

    FORMATS = {
        logging.DEBUG: bold + date + bright_yellow + level + 4 * ' ' + '|' + message + reset,
        logging.INFO: bold + date + level + 5 * ' ' + '|' + message + reset,
        logging.WARNING: bold + date + yellow + level + 2 * ' ' + '|' + message + reset,
        logging.ERROR: bold + date + red + level + 4 * ' ' + '|' + message + reset,
        logging.CRITICAL: bold + date + bright_red + level + ' ' + '|' + message + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%H:%M:%S')
        return formatter.format(record)


class Score:
    def __init__(self):
        self.max = pi / 2
        self.warn = self.max * 0.85
        self.critical = self.max * 0.95
        self.total = 0
        self.score = {'sign': 10,
                      'wx_segments': 10,
                      'packed_file': 15,
                      'ip_rating': 20,
                      'mem_diff': 100}

    def get_verdict(self):
        if atan(self.total) >= self.critical:
            return 'critical'
        elif atan(self.total) >= self.warn and atan(self.total) < self.critical:
            return 'warning'
        else:
            return 'harmless'

    def ip_rating(self, reputation):
        if reputation is not None:
            if reputation > 10:
                self.total += self.score['ip_rating']
            elif reputation > 0:
                self.total += self.score['ip_rating'] / 2
            else:
                # good ip
                pass
        else:
            raise Exception('Scoring: IP reputation is None')

    def wx_segments(self, segments):
        self.total += self.score['wx_segments'] * len(segments)

    def sign(self, is_sign):
        if not is_sign:
            self.total += self.score['sign']

    def packed_file(self, is_packed):
        if is_packed:
            self.total += self.score['packed_file']

    def mem_diff(self, is_diff):
        if is_diff:
            self.total += self.score['mem_diff']

class Process:
    def __init__(self):
        self.ip = None
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
                    self.ip = pcon.raddr.ip

                    # get domain name
                    domain = os.popen(f"dig -x {pcon.raddr.ip} +short | awk -F '.' '{{print $0}}'").read()[:-2]
                    if domain and "connection timed out" not in domain:
                        output += f"\t\tdomain:\t{domain}\n"

                    try:
                        # get provider name
                        whois_output = os.popen(f'whois {pcon.raddr.ip}').read()
#                        print("HERE 2")
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
            proc_file = process.exe()
        except Exception as e:
            proc_file = f'/proc/{process.pid}/exe'
#        proc_file = process._exe
#        if proc_file == None: proc_file = f'/proc/{process.pid}/exe'
        return proc_file
    #def _get_name(self):
        #try:
        #    output = os.popen(f'ls -l /proc/{process.pid}/exe').read()
        #    #output = os.popen(f'ls -l /proc/3396/exe').read()
        #    if not re.match('->', output):
        #        return 0
        #    #print(output)
        #    return output.split(' ')[-1][:-1]





            #proc_name = process.name()
            # proc_id = process.pid
            #return proc_name
            # return f"name: {proc_name}\npid: {proc_id}\n"
        #except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        #    pass

    def wx_checker(self, filename):
        import subprocess
        #bashCommand = "readelf --segments --wide  %s" % (filename)
        #process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        #output, error = process.communicate()
        output = os.popen(f'readelf --segments --wide {filename}').read()
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
        # return SET with segments

    def sign_checker(self, filename):
        output = os.popen(f'readelf --sections {filename}').read()
        res = re.search('\[\s*[0-9]*\]\s*.*sig.*', output)
        if res:
            return True
        else:
            return False

    @staticmethod
    def get_exec_path_by_pid(pid):
        output = os.popen(f'pwdx {pid}').read()
        path_to_file = re.search('([0-9]*): (.*)', output)
        return path_to_file

    def __sort(self, pname, verdict, weight, max_weight, report):
        # TODO
        """
        if process.weight >= middle and process.weight < high:
            self.warning.append(process.name)
        elif process.weight >= high:
            self.critical.append(process.name)
        """
        if verdict == 'critical':
            self.critical.append(pname)
            logger.critical(f"Process {pname} mark as CRITICAL (total - {weight}/{max_weight}): {report}")
        elif verdict == 'warning':
            self.warning.append(pname)
            logger.critical(f"Process {pname} mark as WARNING (total - {weight}/{max_weight}): {report}")

    @staticmethod
    def check_packed_file(filename):
        import subprocess
        packers = {"UPX": "UPX0", "upx": "UPX1", "Upx": "UPX2", "Aspack": "aspack", "aspack": "adata",
                   "NSPack": "NSP0", "nspack": "NSP1", "NSpack": "NSP2", "NTKrnl": "NTKrnl Security Suite",
                   "PECompact": "PEC2", "pecompact": "PECompact2", "Themida": "Themida", "hemida": "aPa2Wa"}
        for el in packers:
            #bashCommand = "strings %s | grep %s" % (filename, packers[el])
            #process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            #output, error = process.communicate()
            output = os.popen(f'strings {filename} | grep -e "^{packers[el]}$"').read()
            if output != "":
                # return "File %s can be packed with %s" % (filename, el)
                return True
        return False
        # return ""

    @staticmethod
    def get_ip_info_from_virustotal(ip):
        import requests
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                                headers={
                                    'x-apikey': '87e1316d0cbe224ca6295c8f22451f4ad2ac47919e059979ef5baacb17cba903'})
        if response.ok:
#            print(f"{ip} :: {response.json()}")
#            print(response.json()['data']['attributes']['reputation'])
            return response.json()['data']['attributes']['reputation']
        else:
            logger.critical(
                f'VirusTotal response code == {response.status_code} on get IP info request: {response.json()}')

    def mem_diff_checker(self, pid): #add 'filename'
        c_ptrace = ctypes.CDLL("libc.so.6").ptrace
        c_pid_t = ctypes.c_int32
        c_ptrace.argtypes = [ctypes.c_int, c_pid_t, ctypes.c_void_p, ctypes.c_void_p]

        def ptrace(attach, pid):
            op = ctypes.c_int(16 if attach else 17)  # PTRACE_ATTACH or PTRACE_DETACH
            c_pid = c_pid_t(pid)
            null = ctypes.c_void_p()
            err = c_ptrace(op, c_pid, null, null)
            if err != 0:
                raise Exception(f'ptrace {err}')

        def maps_line_range(line):
            m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
            return [int(m.group(1), 16), int(m.group(2), 16), m.group(3)]

        ptrace(True, int(pid))
        maps_file = open(f"/proc/{pid}/maps", 'r')
        ranges = map(maps_line_range, maps_file.readlines())
        maps_file.close()
        mem_file = open(f"/proc/{pid}/mem", 'rb', 0)
        all_mem = b''
        for r in ranges:
            if r[2] == 'r':
                mem_file.seek(r[0])
                chunk = mem_file.read(r[1] - r[0])
                all_mem += chunk
        mem_file.close()
        ptrace(False, int(pid))

        print(all_mem)
        """
        mem_checksum = hashlib.md5(all_mem.encode('utf-8')).hexdigest()
        with open(filename, 'rb') as file:
            code = file.read()
        file_code_checksum = hashlib.md5(code.encode('utf-8')).hexdigest()
            
        if file_code_checksum is None:
            raise Exception(f'File {filename} can not open')
        
        if mem_checksum == file_code_checksum:
            return False
        else:
            diffs = []
            diff_code_part = ''
            for mem_byte, code_byte in zip([a for a in all_mem], [b for b in code]):
                if mem_byte != code_byte:
                    diff_code_part += mem_byte
                else:
                    if diff_code_part != '':
                        diffs.append(diff_code_part)
                        diff_code_part = ''
            return True
                
        
        """


    def event_loop(self):
        last_set = set()
        while True:
            proc_set = self._get_all()
            diff = proc_set - last_set
            last_set = proc_set
            for proc in diff:
                print(str(proc.pid))
                if len(proc.cmdline()) == 0 or not proc.is_running():
                    continue
                #if self._get_name(proc) in ['blueberry-obex-agent', 0] or proc.pid < 1000:
                #    continue
                scoring = Score()

                proc_file = self._get_name(proc)
                connection = self._get_connection(proc)

                if self.ip is not None:
                    scoring.ip_rating(self.get_ip_info_from_virustotal(self.ip))

                scoring.wx_segments(self.wx_checker(proc_file))
                scoring.sign(self.sign_checker(proc_file))
                scoring.packed_file(self.check_packed_file(proc_file))
                #scoring.mem_diff(self.mem_diff_checker(proc.pid))

                if scoring.get_verdict() != 'harmless':
                    mitre_techniques = mitre.get_mitre_techniques(proc_file)
                    print(f'mitre_techniques - {mitre_techniques}')








                """
                res = ""

                base_info = self._get_name(proc)
                connection = self._get_connection(proc)
                res += base_info if base_info is not None else ""
                res += connection if connection is not None else ""
                self.get_exec_path_by_pid(proc.pid)
                # if "Network connection" in res:
                #    print(res)
                print(res)
                """


if __name__ == '__main__':
    logging.Formatter(datefmt='%H:%M:%S')
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    p = Process()
    p.event_loop()

"""
import re
maps_file = open("/proc/self/maps", 'r')
mem_file = open("/proc/self/mem", 'rb', 0)
output_file = open("self.dump", 'wb')
for line in maps_file.readlines():  # for each mapped region
    m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
    if m.group(3) == 'r':  # if this is a readable region
        start = int(m.group(1), 16)
        end = int(m.group(2), 16)
        mem_file.seek(start)  # seek to region start
        chunk = mem_file.read(end - start)  # read region contents
        output_file.write(chunk)  # dump contents to standard output
maps_file.close()
mem_file.close()
output_file.close()

res = re.search('\[\s*[0-9]*\]\s*.*sig.*', sig)

"""

"""
#!/usr/bin/env python



"""
