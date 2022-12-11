import psutil
import os
import re
import time
from math import pi, atan
import logging
import ctypes, sys
import hashlib
import mitre.mitre as mitre
from operator import itemgetter


class CustomFormatter(logging.Formatter):
    yellow = "\033[33m"
    bright_yellow = "\033[93m"
    red = "\033[31m"
    bright_red = "\033[91m"
    green = '\033[92m'

    bold = "\033[1m"
    reset = "\033[0m"

    date = "%(asctime)s.%(msecs)03d"
    level = " | %(levelname)s"
    message = " %(message)s"

    FORMATS = {
        logging.DEBUG: bold + date + bright_yellow + level + 4 * ' ' + '|' + message + reset,
        logging.INFO: bold + date + green + level + 5 * ' ' + '|' + message + reset,
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
        self.warn = self.max * 0.985
        self.critical = self.max * 0.995
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

    def mem_diff_checker(self, pid, filepath):
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

        def maps_line_range(line, filepath):
            m = re.match(fr'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r]).*{filepath}', line)
            if m:
                return [int(m.group(1), 16), int(m.group(2), 16), m.group(3)]
            else:
                return []

        try:
            ptrace(True, int(pid))
        except Exception as e:
            return False
        maps_file = open(f"/proc/{pid}/maps", 'r')
        ranges = [maps_line_range(line, filepath) for line in maps_file.readlines()]
        ranges = list(filter(None, ranges))
        maps_file.close()
        mem_file = open(f"/proc/{pid}/mem", 'rb', 0)
        all_mem = b''
        for r in ranges:
            if r[2] == 'r':
                mem_file.seek(r[0])
                chunk = mem_file.read(r[1] - r[0])
                all_mem += chunk
        mem_file.close()
        try:
            ptrace(False, int(pid))
        except Exception as e:
            return False
#        f = open(f"{pid}.my_mem", "wb")
#        f.write(all_mem)
#        f.close()
#        print(all_mem)
        
        mem_checksum = hashlib.md5(all_mem[0:100000]).hexdigest()
        with open(filepath, 'rb') as file:
            code = file.read()
        file_code_checksum = hashlib.md5(code[0:100000]).hexdigest()
#        print(mem_checksum, file_code_checksum)         
        if mem_checksum == file_code_checksum:
            return False
        """        
        if file_code_checksum is None:
            raise Exception(f'File {filepath} can not open')
        
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
            top_processes = []
            for proc in diff:
                cur_proc = {}
                #print(str(proc.pid))
                if len(proc.cmdline()) == 0 or not proc.is_running():
                    continue
                #if self._get_name(proc) in ['blueberry-obex-agent', 0] or proc.pid < 1000:
                #    continue
                scoring = Score()

                proc_file = self._get_name(proc)
                connection = self._get_connection(proc)

                output = f'{proc.pid}  -  {proc_file.split("/")[-1]}'
                if self.ip is not None:
                    scoring.ip_rating(self.get_ip_info_from_virustotal(self.ip))

                sign_checker_result = self.sign_checker(proc_file)
                wx_checker_result = self.wx_checker(proc_file)
                check_packed_file_result = self.check_packed_file(proc_file)
                mem_diff_result = self.mem_diff_checker(proc.pid, proc_file)

                scoring.wx_segments(wx_checker_result)
                scoring.sign(sign_checker_result)
                scoring.packed_file(check_packed_file_result)
                scoring.mem_diff(mem_diff_result)

                cur_proc['sign_checker'] = sign_checker_result
                cur_proc['wx_checker'] = wx_checker_result
                cur_proc['check_packed_file'] = check_packed_file_result
                cur_proc['mem_diff'] = mem_diff_result

                output += f'  -  {scoring.get_verdict()}({scoring.total})'

                cur_proc['mitre_techniques'] = {}
                cur_proc['name'] = proc_file.split('/')[-1]
                if scoring.get_verdict() != 'harmless':
                    mitre_techniques = mitre.get_mitre_techniques(proc_file)
                    output += f'  -  mitre_techniques: {mitre_techniques}'
                    cur_proc['mitre_techniques'] = mitre_techniques
                #if scoring.get_verdict() == 'harmless':
                #    logger.info(output)
                #elif scoring.get_verdict() == 'warning':
                #    logger.warning(output)
                #elif scoring.get_verdict() == 'critical':
                #    logger.critical(output)

                cur_proc['verdict'] = scoring.get_verdict()
                cur_proc['total'] = scoring.total
                top_processes.append(cur_proc)
                top_processes = sorted(top_processes, key=itemgetter('total'))#, reverse = True)
                for item in top_processes:
                    print(f"{item['name']} - {item['total']} - {item['sign_checker']} - {item['wx_checker']} - {item['check_packed_file']} - {item['mem_diff']} - {item['mitre_techniques']}")
                #os.system('clear')

if __name__ == '__main__':
    logging.Formatter(datefmt='%H:%M:%S')
    handler = logging.StreamHandler()
    handler.setFormatter(CustomFormatter())

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    p = Process()
    p.event_loop()

