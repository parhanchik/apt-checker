import psutil
import os
import re
import time
from math import pi, atan
import logging


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
                      'ip_rating': 20}

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
                self.total += self.score['ip_rating']/2
            else:
                # good ip
                pass
        else:
            raise Exception('Scoring: IP reputation is None')

    def wx_segments(self, segments):
        self.total += self.score['wx_segments'] * len(segments)

    def sign(self, is_sign):
        if is_sign:
            self.total += self.score['is_sign']

    def packed_file(self, is_packed):
        if is_packed:
            self.total += self.score['packed_file']


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
            #proc_id = process.pid
            return proc_name
            #return f"name: {proc_name}\npid: {proc_id}\n"
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
        # return SET with segments

    def sign_checker(self, filename):
        #output = os.popen(f'pwdx {pid}').read()
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
            bashCommand = "strings %s | grep %s" % (filename, packers[el])
            process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
            output, error = process.communicate()
            if output != "":
                #return "File %s can be packed with %s" % (filename, el)
                return True
        return False
        #return ""

    """
    def compare_memore(self, pid):
        ram_memory = os.popen(f'gcore {pid}').read()
        file_memory = None

        with open(self.get_exec_path_by_pid(pid), 'rb') as exec_file:
            file_memory = exec_file.read()
        if file_memory == ram_memory:
            print('TRUUUUUE')
            # return True
        else:
            print('FAAALSEEEE')
            return False
    """
    @staticmethod
    def get_ip_info_from_virustotal(ip):
        import requests
        response = requests.get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
                                headers={
                                    'x-apikey': '87e1316d0cbe224ca6295c8f22451f4ad2ac47919e059979ef5baacb17cba903'})
        if response.ok:
            print(f"{ip} :: {response.json()}")
            print(response.json()['data']['attributes']['reputation'])
            return response.json()['data']['attributes']['reputation']
        else:
            logger.critical(f'VirusTotal response code == {response.status_code} on get IP info request: {response.json()}')

    def event_loop(self):
        last_set = set()
        while True:
            proc_set = self._get_all()
            diff = proc_set - last_set
            last_set = proc_set
            for proc in diff:
                scoring = Score()

                base_info = self._get_name(proc)
                connection = self._get_connection(proc)

                if self.ip is not None:
                    scoring.ip_rating(self.get_ip_info_from_virustotal(self.ip))
                scoring.wx_segments(self.wx_checker(self._get_name()))
                scoring.sign(self.sign_checker(self._get_name()))
                scoring.packed_file(self.check_packed_file(self._get_name()))
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
    # p.event_loop()


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