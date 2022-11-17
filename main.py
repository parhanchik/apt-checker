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



    def wx_checker(self):
        dummy = """Elf file type is DYN (Shared object file)
Entry point 0x38a0
There are 9 program headers, starting at offset 64

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  PHDR           0x000040 0x0000000000000040 0x0000000000000040 0x0001f8 0x0001f8 RwxE 0x8
  INTERP         0x000238 0x0000000000000238 0x0000000000000238 0x00001c 0x00001c R   0x1
      [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x00a470 0x00a470 R E 0x200000
  LOAD           0x00a930 0x000000000020a930 0x000000000020a930 0x0007d0 0x0015a8 RW  0x200000
  DYNAMIC        0x00a990 0x000000000020a990 0x000000000020a990 0x000210 0x000210 RWX 0x8
  NOTE           0x000254 0x0000000000000254 0x0000000000000254 0x000044 0x000044 R   0x4
  GNU_EH_FRAME   0x009640 0x0000000000009640 0x0000000000009640 0x0001ec 0x0001ec Rwx   0x4
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWx  0x10
  GNU_RELRO      0x00a930 0x000000000020a930 0x000000000020a930 0x0006d0 0x0006d0 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp 
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rela.dyn .rela.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame 
   03     .init_array .fini_array .data.rel.ro .dynamic .got .data .bss 
   04     .dynamic 
   05     .note.ABI-tag .note.gnu.build-id 
   06     .eh_frame_hdr 
   07     
   08     .init_array .fini_array .data.rel.ro .dynamic .got 
"""
        wx_headers = re.findall('(.*)( *)( 0x.*)+ .?wx', dummy.lower())
        headers = re.findall('(.*)( *)( 0x.*)+ [rwxe]', dummy.lower())
        segments = set()
        for header in wx_headers:
            segment = str(headers.index(header)+1) if headers.index(header)+1 > 9 else f"0{headers.index(header)+1}"
            try:
                wx_sections = re.search(f'( *){segment}( *)(\..*)', dummy).group(3).split()
                segments.update(wx_sections)
            except AttributeError:
                pass
        return segments
        #return SET with segments

    def __sort(self):
        # TODO
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

                # if "Network connection" in res:
                #    print(res)
                print(res)


if __name__ == '__main__':
    p = Process()
    print(p.wx_checker())
    #p.event_loop()

