# -*- coding: utf-8 -*-

import volatility.plugins.common as common
from volatility.renderers.basic import Address
import volatility.plugins.taskmods as taskmods
import volatility.plugins.vadinfo as vadinfo
from volatility.renderers import TreeGrid
import re

'''Constante des expressions regulieres'''

INUM="(1?[0-9]{1,2}|2([0-4][0-9]|5[0-5]))"
HEX="[0-9a-f]"
ALNUM="[a-zA-Z0-9]"
PC="[\x20-\x7E]"
TLD="(AC|AD|AE|AERO|AF|AG|AI|AL|AM|AN|AO|AQ|AR|ARPA|AS|ASIA|AT|AU|AW|AX|AZ|BA|BB|BD|BE|BF|BG|BH|BI|BIZ|BJ|BL|BM|BN|BO" \
    +"|BR|BS|BT|BV|BW|BY|BZ|CA|CAT|CC|CD|CF|CG|CH|CI|CK|CL|CM|CN|CO|COM|COOP|CR|CU|CV|CX|CY|CZ|DE|DJ|DK|DM|DO|DZ|EC|EDU" \
    +"|EE|EG|EH|ER|ES|ET|EU|FI|FJ|FK|FM|FO|FR|GA|GB|GD|GE|GF|GG|GH|GI|GL|GM|GN|GOV|GP|GQ|GR|GS|GT|GU|GW|GY|HK|HM|HN|HR" \
    +"|HT|HU|ID|IE|IL|IM|IN|INFO|INT|IO|IQ|IR|IS|IT|JE|JM|JO|JOBS|JP|KE|KG|KH|KI|KM|KN|KP|KR|KW|KY|KZ|LA|LB|LC|LI|LK|LR" \
    +"|LS|LT|LU|LV|LY|MA|MC|MD|ME|MF|MG|MH|MIL|MK|ML|MM|MN|MO|MOBI|MP|MQ|MR|MS|MT|MU|MUSEUM|MV|MW|MX|MY|MZ|NA|NAME|NC|NE" \
    +"|NET|NF|NG|NI|NL|NO|NP|NR|NU|NZ|OM|ORG|PA|PE|PF|PG|PH|PK|PL|PM|PN|PR|PRO|PS|PT|PW|PY|QA|RE|RO|RS|RU|RW|SA|SB|SC|SD" \
    +"|SE|SG|SH|SI|SJ|SK|SL|SM|SN|SO|SR|ST|SU|SV|SY|SZ|TC|TD|TEL|TF|TG|TH|TJ|TK|TL|TM|TN|TO|TP|TR|TRAVEL|TT|TV|TW|TZ|UA" \
    +"|UG|UK|UM|US|UY|UZ|VA|VC|VE|VG|VI|VN|VU|WF|WS|YE|YT|YU|ZA|ZM|ZW|ac|ad|ae|aero|af|ag|ai|al|am|an|ao|aq|ar|arpa|as|asia" \
    +"|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|biz|bj|bl|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cat|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|" \
    +"com|coop|cr|cu|cv|cx|cy|cz|de|dj|dk|dm|do|dz|ec|edu|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|" \
    +"gn|gov|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|info|int|io|iq|ir|is|it|je|jm|jo|jobs|jp|ke|kg|kh|ki|km|kn|" \
    +"kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mf|mg|mh|mil|mk|ml|mm|mn|mo|mobi|mp|mq|mr|ms|mt|mu|museum|mv|" \
    +"mw|mx|my|mz|na|name|nc|ne|net|nf|ng|ni|nl|no|np|nr|nu|nz|om|org|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|pro|ps|pt|pw|py|qa|re|ro|rs|ru|" \
    +"rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tel|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|travel|tt|tv|tw|tz|ua" \
    +"|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)"
YEAR="(19[6-9][0-9]|20[0-1][0-9])"
DAYOFWEEK="(Mon|Tue|Wed|Thu|Fri|Sat|Sun)"
MONTH="(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
ABBREV="(UTC?|GMT|EST|EDT|CST|CDT|MST|MDT|PST|PDT|[ZAMNY])"

class MemScan(common.AbstractWindowsCommand):
    ''' Memory Scanner '''
    
    
    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        self._config.add_option('pid',
                                short_option = 'p',
                                default = None,
                                help = 'Choose a pid to scan',
                                action = 'store',
                                type = "string")
        
        self._config.add_option('after',
                                short_option = 'a',
                                default = None,
                                help = 'Print X bits after each pattern found',
                                action = 'store',
                                type = "int")
        
        self._config.add_option('before',
                                short_option = 'b',
                                default = None,
                                help = 'Print X bits before each pattern found',
                                action = 'store',
                                type = "int")

        self._config.add_option('inputfile',
                                short_option = 'i',
                                default = None,
                                help = 'Regular expressions input filename',
                                action = 'store',
                                type = "string")
    
        self.regex_dict = {"Email": r"" + ALNUM + "(\.?[a-zA-Z0-9_%\-+])+\.?" + ALNUM + "@" + ALNUM + "(\.?[a-zA-Z0-9_%\-])+\." + TLD + "[^\z41-\z5A\z61-\z7A]",
            "URL": r"((https?):((//)|(\\\\))+([\w\d: #@%/;$()~_?\+-=\\\.&](#!)?)*)",
            "IP Address": r"[^\z30-\z39\z2E]" + INUM + "(\." + INUM + "){3}[^\z30-\z39\z2B\z2D\z2E\z41-\z5A\z5F\z61-\z7A]"}

    def calculate(self):
        return self.Get_MemMap()
    
    def Get_MemMap(self):
        return taskmods.MemMap(self._config).calculate()
    
    def search_pattern(self, pattern, data):
        reg = re.finditer(pattern, data)
        return reg
    
    def getRegexdict(self):
        if self._config.inputfile:
            filename=str(self._config.inputfile)
            try:
                fd = open(filename, 'rb')
            except IOError:
                print('IOError')
                return self.regex_dict
            line = fd.readline()
            self.regex_dict={}
            cpt=1
            while line:
                regex=r""+line
                self.regex_dict['Custom Reg'+str(cpt)]=regex
                line = fd.readline()
                cpt+=1
        return self.regex_dict

    def reg_print(self, result, reg_type, proc_name, pid, pa, vad, match_offset, prot):
        print("[{0}]".format(reg_type) + " Pattern found: " + result + "\n" \
              + "Process Name: " + proc_name + "\n" \
              + "Pid :" + str(pid) + "\n" \
              + "Physical Address: " + str(pa) + "\n" \
              + "Virtual Address: " + str(vad.Start) + "\n" \
              + "Length: " + str(vad.Length) + "\n" \
              + "Offset of the pattern: " + str(match_offset) + "\n" \
              + "Virtual Address of the pattern: " + str(vad.Start + match_offset) + "\n" \
              + "Access Right: " + prot + "\n")
    
    def unified_output(self, data):
        return TreeGrid([("Pattern type", str),
                         ("Process", str),
                         ("PID", int),
                         ("Virtual Add.", Address),
                         ("Physical Add.", Address),
                         ("Size", Address),
                         ("Access Right", str),
                         ("Pattern off.", Address),
                         ("Pattern VA", Address),
                         ("Pattern found", str)],
                        self.generator(data))
    
    def generator(self, data):
        arg_pid = self._config.pid
        arg_after = self._config.after or 0
        arg_before = self._config.before or 0

        for pid, task, pagedata in data:
            if not pagedata:
                continue
            
            if arg_pid and int(arg_pid) != pid:
                continue
    
            proc_name = task.ImageFileName
    
            for vad, process_space in task.get_vads():
                prot = vad.u.VadFlags.Protection.v()
                prot = vadinfo.PROTECT_FLAGS.get(prot, "")
    
                pa = process_space.vtop(vad.Start)
                if pa != None:
                    data = process_space.zread(vad.Start, vad.Length)
    
                    for regex in self.getRegexdict():
                        reg = self.search_pattern(self.regex_dict[regex], data)
                        for match in reg:
                            foundStr=match.string[match.start()-arg_before:match.end()+arg_after]
                            yield (0, [regex, str(proc_name), int(pid), Address(vad.Start), Address(pa), Address(vad.Length), prot, Address(match.start()), Address(vad.Start + match.start()), str(foundStr)])
    
    def render_text(self, outfd, data):
        arg_pid = self._config.pid
        arg_after = self._config.after or 0
        arg_before = self._config.before or 0
        
        for pid, task, pagedata in data:
            if not pagedata:
                continue
            
            if arg_pid and int(arg_pid) != pid:
                continue
            
            self.table_header(outfd,
                              [("Pattern type", "10"),
                               ("Process", "20s"),
                               ("PID", ">6"),
                               ("Virtual Add.", "[addrpad]"),
                               ("Physical Add.", "[addrpad]"),
                               ("Size", "[addr]"),
                               ("Access Right", "42s"),
                               ("Pattern off.", "[addrpad]"),
                               ("Pattern VA", "[addrpad]"),
                               ("Pattern found", "100s")])
            
            proc_name = task.ImageFileName
        
            for vad, process_space in task.get_vads():
                prot = vad.u.VadFlags.Protection.v()
                prot = vadinfo.PROTECT_FLAGS.get(prot, "")
            
                pa = process_space.vtop(vad.Start)
                
                if pa != None:
                    data = process_space.zread(vad.Start, vad.Length)
                
                    for regex in self.getRegexdict():
                        reg = self.search_pattern(self.regex_dict[regex], data)
                        for match in reg:
                            foundStr=match.string[match.start()-arg_before:match.end()+arg_after]
                            self.table_row(outfd, regex, str(proc_name), int(pid), Address(vad.Start), Address(pa), Address(vad.Length), prot, Address(match.start()), Address(vad.Start + match.start()), str(foundStr))
