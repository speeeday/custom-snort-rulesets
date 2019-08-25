#!/usr/bin/python2.7
import requests
import shlex
import subprocess
import sys
import sqlite3
import argparse
from insert_db import InsertDB
import progressbar
import pprint
import urllib2
from bs4 import BeautifulSoup
import time

###############################################################################
#                                                                             #
# Written By: sanjayc                                                         #
#                                                                             #
# Purpose: This file is used to maintain the database of snort firewall       #
#          rules that we will be build our snort docker containers with.      #
#          You can use this file to intialize a snort database from a snort   #
#          configuration and rule files. You can also use this file to retag  #
#          a database with more specific info while maintaining all previous  #
#          tags in the DB. You can also use the file to query the database    #
#          and iterate over that set of rules. This is useful for testing     #
#          out possible ways to tag rules or gather statistics.               #
#                                                                             #
# Usage: python initialize_db.py --init <db_name>                             #
#        python initialize_db.py --retag <db_name>                            #
#        python initialize_db.py --query <query_string>                       #
#                                                                             #
###############################################################################


pp = pprint.PrettyPrinter()

def e(cmd):
    subprocess.check_call(shlex.split(cmd))

columns = ['commented',
           'rev',
           'direction',
           'dstip',
           'protocol',
           'reference',
           'flow',
           'sid',
           'srcport',
           'repr',
           'content',
           'srcip',
           'metadata',
           'flowbits',
           'classtype',
           'action',
           'dstport',
           'msg',
           'fast_pattern',
           'http_header',
           'http_uri',
           'http_method',
           'http_client_body',
           'http_cookie',
           'http_raw_header',
           'http_raw_uri',
           'http_raw_cookie',
           'http_stat_msg',
           'http_stat_code',
           'file_data',
           'nocase',
           'distance',
           'pcre',
           'base64_decode',
           'base64_data',
           'pkt_data',
           'rawbytes',
           'dce_stub_data',
           'byte_test',
           'byte_extract',
           'urilen',
           'dsize',
           'detection_filter',
           'byte_jump',
           'stream_size',
           'byte_math',
           'ssl_state',
           'icode',
           'itype',
           'flags',
           'dce_opnum',
           'dce_iface',
           'ssl_version',
           'file',            # rule filename that the rule comes from
           'attr_windows',         # windows, linux, unix, osx, freebsd, solaris, android, ios,
           'attr_linux',
           'attr_unix',
           'attr_osx',
           'attr_freebsd',
           'attr_solaris',
           'attr_android',
           'attr_ios',
           'attr_js',         # True
           'attr_php',         # True
           'attr_sql',        # True,
           'attr_dns',        # True,
           'attr_adobe_flash', # True,
           'attr_office_tools', # True,
           'attr_kubernetes',
           'attr_oracle_weblogic',
           'attr_apache',
           'attr_prestashop',
           'attr_omron_cx_supervisor',
           'attr_web_assembly',
           'attr_ultra_player',
           'attr_ms_edge_pdf_builder',
           'attr_open_type',
           'attr_adobe_acrobat_reader',
           'attr_adobe_reader',
           'attr_cctv_dvr',
           'attr_qnap_qcenter',
           'attr_dlink_dir_816',
           'attr_blueimp_jquery_file_upload',
           'attr_cgit',
           'attr_gpon_router',
           'attr_netiq_access_manager',
           'attr_reprise_license_manager', # $HOME_NET 5054
           'attr_sap_config_servlet', # $HOME_NET 50000
           'attr_jboss',
           'attr_oracle_glassfish_server',
           'attr_sophos_web_protection_appliance',
           'attr_tenda_W302R',
           'attr_red_hat_cloudforms',
           'attr_netgear_DGN1000B',
           'attr_hp_intelligent_management_center_som',
           'attr_seagate_nas',
           'attr_emc_connectrix_manager',
           'attr_cisco_prime_data_center_network_manager',
           'attr_zimbra',
           'attr_hp_loadrunner_virtual_user_generator',
           'attr_hp_intelligent_management_center',
           'attr_hp_system_management',
           'attr_arcserve_unified_data_protection',
           'attr_joomla',           
           'attr_emc_alphastor_device_manager',
           'attr_file_magic_detected',
           'attr_file_download_request',
           'attr_file_attachment_detected',
           'attr_exploit_kit_action',
           'attr_pdfescape',
           'attr_java',
           'attr_perl',
           'attr_outbound_connections',
           'attr_inbound_commands',
           'attr_user_agent_detected',
           'attr_mini_upnpd',
           'attr_sybase_open_server',
           'attr_veritas_netbackup',
           'attr_hp_aio_archive_query_server',
           'attr_openssl',
           'attr_sap_netweaver',
           'attr_cmsimple',
           'attr_auracms',
           'attr_hp_autopass_license_server',
           'attr_hp_network_node_manager',
           'attr_hp_openview_storage_data_protector',
           'attr_hp_procurve_manager',
           'attr_novell_groupwise',
           'attr_ibm_tivoli_storage_manager',
           'attr_nuuo_nvrmini2',
           'attr_mitsubishi_electric_edesigner',
           'attr_advantech_webaccess',
           'attr_cisco_ios',
           'attr_symantec_endpoint_protection_manager',
           'attr_magneto',
           'attr_redis',
           'attr_cisco_asa',
           'attr_sql_ingres_database',
           'attr_sql_ibm_db2',
           'attr_sql_wincc_db',
           'attr_sql_ibm_solid_db',
           'attr_sql_sap_max_db',
           'attr_adobe_primetime_sdk',
           'attr_adobe_shockwave_player',
           'attr_google_chrome',
           'attr_adobe_action_script',
           'attr_alienvault_ossim',
           'attr_supermicro_intelligent_management_controller',
           'attr_fireye_java_decompiler',
           'attr_allen_bradley_compact_logix',
           'attr_oracle_server',
           'attr_drupal',
           'attr_symantec_decomposer_engine',
           'attr_wordpress',
           'attr_sonicwall_secure_remote_access',
           'attr_trend_micro',
           'attr_dlink_DSL_2750B',
           'attr_lib_graphite',
           'attr_oracle_oit',
           'attr_symantec',
           'attr_wireshark',
           'attr_visual_basic',
           'attr_ge_cimplicity',
           'attr_winrar',
           'attr_real_player',
           'attr_ftp_banner_detected',
           'attr_sinkhole_action',
           'attr_iframe_detected',
           'attr_phishing_detected',
           'attr_trackware',
           'attr_keylogger_detected',
           'attr_malvertising_detected',
           'attr_cnc_detected',
           'attr_trojan_detected',
           'attr_image_magick', # vulnerable images to exploit imagemagick
           'attr_malicious_file', #FILE-IDENTIFY recognizes an evil file
           'attr_firefox',
           'attr_silverlight', # IF you have a browser, and have the plugin
           'attr_trimble_sketchup', # sketching 3d software
           'attr_malicious_indicator',
           'attr_netbios', # netbios network protocol
           'attr_joyent_os',
           'attr_x86', #x86 side channel
           'attr_scada',
           'attr_telnet',
           'attr_voip',
           'attr_snmp',
           'attr_cisco_webex',
           'attr_itunes',
           'attr_safari',
           'attr_hp_loadrunner', #in windows and linux
           'attr_adobe_drm_manager',
           'attr_samba',
           'attr_server_misc'


           
           
]
# add this to columns after RETAGGING!!
new_cols = [
    

]

def show_table():
#    print "---------------"
    cur = conn.cursor()
    cur.execute("SELECT * FROM rules WHERE commented = 'False'")
    rows = cur.fetchall()
    for row in rows:
        print row

def show_conf():
#    print "---------------"
    cur = conn.cursor()
    cur.execute("SELECT (repr) FROM rules WHERE commented = 'False'")
    rows = cur.fetchall()
    for row in rows:
        print row[0].replace("''", "'")

def create_table(conn):
    tble = "CREATE TABLE rules("
    for k in (columns+new_cols):
        tble += k + " Varchar,"
    tble = tble[:-1] + ")"
    cur = conn.cursor()
    cur.execute(tble)
    conn.commit()
    #print tble

#        print d



def parse_rule(rule, commented=False):
    if commented:
        # strip off the '# '
        rule = rule[2:]
    rs = rule.split()
    d = {}
    d['commented'] = str(commented)
    d['repr'] = rule.replace("'", "''")
    d['action'] = rs[0]
    d['protocol'] = rs[1]
    d['srcip'] = rs[2]
    d['srcport'] = rs[3]
    d['direction'] = rs[4]
    d['dstip'] = rs[5]
    d['dstport'] = rs[6]
    options = ' '.join(rs[7:])[1:-1]
    opts = options.split('; ')
    for opt in opts:
        if ':' not in opt:
            #print d
            d[opt] = opt.replace("'", "''")
        else:
            ops = opt.split(':')

            if ops[0] == "within" or ops[0] == "depth" or ops[0] == "isdataat" or ops[0] == "offset":
                continue
            
            jj = ':'.join(ops[1:])
            if jj[0] == "'":
                d[ops[0]] = jj[1:-1].replace("'", "''")
            else:
                d[ops[0]] = jj.replace("'", "''")
    return d

def insert_rule(conn, d):
    if d['commented'] == "False":
        #print "[{}-{}] ".format(d['sid'],d['rev']) + d['msg'][1:-1].strip('APP-DETECT').strip(' ')
        qry = "INSERT INTO rules("
        vls = "VALUES("
        for k in d:
            if d[k] == '':
                continue
            if k not in (columns+new_cols):
                print "Need to Add " + str(k) + " to DB columns"
                sys.exit()
            jj = d[k]
            if jj[0] == "'":
                jj = jj[1:-1].replace("'", "''")
            else:
                jj = jj.replace("'", "''")
            qry += k + ","
            vls += "'" + jj + "',"
        qry = qry[:-1] + ")\n"
        vls = vls[:-1] + ") "
        cur = conn.cursor()
        #print qry + vls
        #print "--------------"
        #print d
        #print d['repr']
        cur.execute(qry+vls)
        conn.commit()


# pass in the file as argv[1]
def parse_rule_file(conn, filename, tag_fns):
    r = open(filename).read()
    s = r.strip('\n').split('\n')
    ff = filename.split("/")[-1][:-6]
    print(ff)
    for j in progressbar.progressbar(range(len(s))):
        l = s[j]
        if l == "":
            continue
        elif l[0] == '#':
            # commented line, check if rule or not
            if '# alert' not in l:
                # comment
                continue
            else:
                # commented rule
                rule = parse_rule(l, commented=True)
        else:
            rule = parse_rule(l, commented=False)
        for tag_fn in tag_fns:
            rule = tag_fn(rule)
        rule['file'] = filename.split('/')[-1][:-6]
        insert_rule(conn, rule)

# Main Tagging Function when --init        
def tag_msg(d):
    msg = ""
    if 'msg' in d:
        msg = d['msg'][1:-1]
    # attr_os
    if "Win." in msg or "Windows" in msg or "Win32" in msg or "powershell" in msg.lower() or "portable executable" in msg.lower() or "HTA script" in msg:
        d['attr_windows'] = "True"
    elif "Linux" in msg:
        d['attr_linux'] = "True"
    elif "Unix." in msg:
        d['attr_unix'] = "True"
    elif "Osx" in msg or "OSX" in msg:
        d['attr_osx'] = "True"
    elif "FreeBsd" in msg or "Freebsd" in msg or "FreeBSD" in msg:
        d['attr_freebsd'] = "True"
    elif "Solaris" in msg:
        d['attr_solaris'] = "True"
    elif "Andr." in msg or "Android" in msg or "ANDR." in msg:
        d['attr_android'] = "True"
    elif "iOS" in msg:
        d['attr_ios'] = "True"
    #else:
    #    d = tag_ref(d)

    # attr_js
    if "Js." in msg or "JS." in msg:
        d['attr_js'] = "True"
        
    # attr_php
    if "Php." in msg or "PHP." in msg:
        d['attr_php'] = "True"
        
    # attr_dns
    if "DNS" in msg:
        d['attr_dns'] = "True"

    # attr_adobe_flash
    if "Adobe Flash Player" in msg:
        d['attr_adobe_flash'] = "True" 

    # attr_office_tools
    if "Microsoft Office" in msg or "Open Office" in msg or "Doc." in msg or "Rtf." in msg:
        d['attr_office_tools'] = "True"

        
    return d

def tag_os_linux(d):
    d['attr_linux'] = "True"
    return d

def tag_os_solaris(d):
    d['attr_solaris'] = "True"
    return d
    
def tag_os_windows(d):
    d['attr_windows'] = "True"
    return d
    
def tag_sql(d):
    d['attr_sql'] = "True"
    return d

exts = {}
exif_missing = []
add_info_missing = []

def tag_virustotal_malware_cnc(d):

    ###### STOPPED RIGHT HERE, MAKE SURE TO PRINT URL AND SCRAPE VIRUSTOTAL
    #print d
    if 'reference' in d:
        if 'virustotal' in d['reference']:
            url = 'https://www.virustotal.com/vtapi/v2/file/report'
            hsh = ''
            hhsh = d['reference'].split("url,")[-1]
            hsh = hhsh.split('/')
#                print hhsh
            try:
                ish = hsh.index('analysis')
            except:
                try:
                    ish = hsh.index('detection')
                except:
                    ish = len(hsh)
            #print hsh[ish-1]
            params = { 'apikey':'164ee4c4e6936700f4d4e00391ecce808c395b749284f2a9a275c11a039ad5a6',
                       'resource':hsh[ish-1],
                       'allinfo':'true' }
            #print params

            response = requests.get(url, params=params)

            rsp = response.json()

            if 'additional_info' in rsp:
                add_info = rsp['additional_info']
                if 'exiftool' in add_info:
                    exif = add_info['exiftool']
                    if 'FileType' in exif:
                        ext = exif['FileType']
                        if "Win32" in ext or "Win64" in ext:
                            d['attr_windows'] = "True"
                        elif "ELF" in ext:
                            d['attr_linux'] = "True"
                            d['attr_unix'] = "True"
                        elif "Mach-O" in ext:
                            d['attr_osx'] = "True"
                        elif "PHP" in ext:
                            d['attr_php'] = "True"
                        if ext not in exts:
                            count_b = 0
                            count_nb = 0
                        else:
                            (count_b,count_nb) = exts[ext]
                        # executed in virus total sandbox
                        if 'behaviour-v1' in add_info:
                            count_b += 1
                            exts[ext] = (count_b,count_nb)
                        else:
                            count_nb += 1
                            exts[ext] = (count_b,count_nb)

                else:
                    exif_missing.append(hsh[ish-1])
                    #print "ExifTool Info missing from Sample {}".format(hsh[ish-1])
                    #print rsp
            else:
                add_info_missing.append(hsh[ish-1])
                #print "Additional Info missing from Sample {}".format(hsh[ish-1])
                #print rsp

    else:
        return d
    return d
 
fails = []
bheaders = []
pforms = {}

def tag_helpx_adobe_acrobat(d):
    # skip already tagged rules
    if 'reference' in d:
        if 'helpx.adobe.com/security/products/acrobat' in d['reference']:
            url_page = d['reference'].lower().split("url,")[-1]
            if "http://" not in url_page and "https://" not in url_page:
                url_page = "https://" + url_page
            try:
                page = urllib2.urlopen(url_page)
                time.sleep(0.5)
            except urllib2.HTTPError as e:
                fails.append(url_page)
                return d
            soup = BeautifulSoup(page, 'html.parser')

            table = soup.find('div', attrs={'class':'noHeader'})

            rows = table.find_all('tr')

            headers = [i.text.strip() for i in rows[0].find_all('strong')]

            pl_off = 0
            if headers == []:
                headers = [i.text.strip() for i in rows[0].find_all('span')]
                pl_off = 1
            pl_ind = -1
            for i in range(len(headers)):
                if headers[i] == "Platform":
                    pl_ind = i + pl_off
                    break
            if pl_ind == -1:
                #print "Couldnt find platform column in URL: {}".format(d['reference'])
                #pp.pprint(headers)
                bheaders.append((headers, url_page))
                return d
                
            for i in range(1,len(rows)):
                vs = [i.text.strip() for i in rows[i].find_all('td')]
                pform = vs[pl_ind]
                if "Windows" in pform:
                    d['attr_windows'] = "True"
                if "macOS" in pform or "Macintosh" in pform:
                    d['attr_osx'] = "True"
                if "Linux" in pform:
                    d['attr_linux'] = "True"
                pforms[pform] = ''
                        
    
    return d

# local vars
retag_vars = {
    'win_count': 0,
    'osx_count': 0
}

# only modifies entries when called with '--retag'
# d is a dictionary representation of  the columns:values for each DB entry

# Add New logic to retag rules here:
# any new attributes added to the dictionary that are not in 'columns' should
# be added to 'new_cols' when running with --retag and then should be moved
# to the 'columns' list

def retag_rule(d):
    msg = ""
    if 'msg' in d:
        msg = d['msg'][1:-1]
    else:
        return d

    tagged = False
    
    for k in d:
        if 'attr_' in k:
            tagged = True
            break
    
    
#    if not(tagged) and "INDICATOR-" in msg or "MALWARE-BACKDOOR" in msg or "MALWARE-CNC" in msg or "MALWARE-OTHER" in msg or "MALWARE-TOOLS" in msg:
#        d['attr_malicious_indicator'] = "True"
#
#    if not(tagged) and "SERVER-SAMBA" in msg:
#        d['attr_samba'] = "True"
#
#    if not(tagged) and "SERVER-OTHER" in msg:
#        d['attr_server_misc'] = "True"
#
#    if not(tagged) and "SERVER-ORACLE" in msg:
#        d['attr_oracle_server'] = "True"
#        
        
#    if "Trimble SketchUp" in msg:
#        d['attr_trimble_sketchup'] = "True"
#    elif "Apple iTunes" in msg:
#        d['attr_itunes'] = "True"
#    elif "Cisco WebEx" in msg:
#        d['attr_cisco_webex'] = "True"
#    elif "Apple WebKit" in msg:
#        d['attr_safari'] = "True"
#    elif "HP LoadRunner" in msg:
#        d['attr_hp_loadrunner'] = "True"
#    elif "Adobe PSDK DRM Manager" in msg:
#        d['attr_adobe_drm_manager'] = "True"
#        
#    if "BROWSER-FIREFOX" in msg or "Mozilla Firefox" in msg:
#        d['attr_firefox'] = "True"
#    elif "Microsoft Silverlight" in msg:
#        d['attr_silverlight'] = "True"
#    elif "Adobe flash player" in msg:
#        d['attr_adobe_flash'] = "True"
#    elif "Adobe Acrobat" in msg or "Acrobat Reader" in msg:
#        d['attr_adobe_acrobat_reader'] = "True"
#    elif "FILE-OFFICE" in msg and "RFT" in msg:
#        d['attr_office_tools'] = "True"
#    elif "RTF document" in msg:
#        d['attr_office_tools'] = "True"
#    elif "Microsoft XML" in msg or "MSXML" in msg:
#        d['attr_windows'] = "True"
#    elif "Google Chrome" in msg:
#        d['attr_google_chrome'] = "True"
#    elif "NETBIOS" in msg:
#        d['attr_netbios'] = "True"
#    elif "OS-OTHER" in msg and "Bash" in msg:
#        d['attr_windows'] = "True"
#        d['attr_linux'] = "True"
#        d['attr_unix'] = "True"
#        d['attr_osx'] = "True"
#        d['attr_freebsd'] = "True"
#        d['attr_solaris'] = "True"
#        d['attr_android'] = "True"
#        d['attr_ios'] = "True"
#    elif "Joyent SmartOS" in msg:
#        d['attr_joyent_os'] = "True"
#    elif "Intel x86" in msg:
#        d['attr_x86'] = "True"
#    elif "PROTOCOL-SCADA" in msg:
#        d['attr_scada'] = "True"
#    elif "PROTOCOL_TELNET" in msg:
#        d['attr_telnet'] = "True"
#    elif "PROTOCOL_VOIP" in msg:
#        d['attr_voip'] = "True"
#    elif "PROTOCOL_SNMP" in msg:
#        d['attr_snmp'] = "True"
#
        
#    if "ImageMagick" in msg:
#        d['attr_image_magick'] = "True"

#    if "FILE-IDENTIFY" in msg:
#        d['attr_malicious_file'] = "True"
    
#    if "Microsoft Access" in msg or "Microsoft JET Database" in msg or " ntdll " in msg:
#        d['attr_windows'] = "True"
#    if " Dec2SS " in msg:
#        d['attr_windows'] = "True"
#        d['attr_osx'] = "True"
#    if "Microsoft PowerPoint" in msg or "Microsoft Visio" in msg or "Microsoft Access" in msg:
#        d['attr_office_tools'] = "True"
#    if "Symantec multiple product" in msg:
#        d['attr_symantec'] = "True"
#    if 'reference' in d and (("technet.microsoft.com/en-us/security/bulletin/ms16-015" in d['reference']) or ("technet.microsoft.com/en-us/security/bulletin/ms15-110" in d['reference']) or ("technet.microsoft.#com/en-us/security/bulletin/MS09-017" in d['reference'])):
#        d['attr_windows'] = "True"
#        d['attr_osx'] = "True"
#    if 'reference' in d and (("technet.microsoft.com/en-us/security/bulletin/MS12-027" in d['reference'])):
#        d['attr_windows'] = "True"
#    if "known command and control channel traffic" in msg or "C2 response" in msg or "Potential Gozi Trojan HTTP Header Structure" in msg:
#        d['attr_cnc_detected'] = "True"
#    if "exploit kit post-compromise behavior" in msg:
#        d['attr_exploit_kit_action'] = "True"        
#    if (('outbound connection' in msg) or ('outbound connection' in msg) or ('outbound communication' in msg)):
#        d['attr_outbound_connections'] = "True"
#    if ((d['file'] == 'file-other') or (d['file'] == 'file-other')) and (' php ' in msg or '.php' in msg or ('content' in d and '.php' in d['content'])):
#        d['attr_php'] = "True"
#    if "Acrobat Adobe Pro" in msg or "Adobe Acrobat Pro" in msg or "Adobe AcrobatDC" in msg:
#        d['attr_adobe_acrobat_reader'] = "True"
#    elif "Microsoft .NET" in msg or "Microsoft Internet Explorer" in msg or "Microsoft Edge" in msg or "Microsoft Journal" in msg:
#        d['attr_windows'] = "True"
#    elif "LibGraphite" in msg:
#        d['attr_lib_graphite'] = "True"
#    elif "Oracle OIT" in msg:
#        d['attr_oracle_oit'] = "True"
#    elif "Symantec Antivirus" in msg or "Symantec TNEF" in msg:
#        d['attr_symantec'] = "True"
#    elif "Wireshark" in msg:
#        d['attr_wireshark'] = "True"
#    elif "Microsoft Word WordPerfect" in msg:
#        d['attr_office_tools'] = "True"
#    elif "Visual Basic" in msg:
#        d['attr_visual_basic'] = "True"
#    elif "Java JRE" in msg or "Oracle Java SE" in msg or "malicious jar archive" in msg or "Java FileDialog" in msg:
#        d['attr_java'] = "True"
#    elif "GE Cimplicity" in msg:
#        d['attr_ge_cimplicity'] = "True"
#    elif "WinRAR" in msg:
#        d['attr_winrar'] = "True"
#    elif "RealNetworks RealPlayer" in msg:
#        d['attr_real_player'] = "True"
#    elif "known malicious FTP" in msg and "banner" in msg:
#        d['attr_ftp_banner_detected'] = "True"
#    if "exploit download attempt" in msg or "leads to Exploit Kit" in msg:
#        d['attr_exploit_kit_action'] = "True"
#    if "GPON exploit" in msg:
#        d['attr_gpon_router'] = "True"
#    if "Sinkhole reply" in msg or "connection to malware sinkhole" in msg:
#        d['attr_sinkhole_action'] = "True"
#    if "malicious iframe" in msg or "multi-hop iframe" in msg or "IFRAMEr Tool" in msg or "Malicious IFRAME" in msg:
#        d['attr_iframe_detected'] = "True"
#    if "phishing attack" in msg or "Phishing" in msg:
#        d['attr_phishing_detected'] = "True"
#    if "Trackware" in msg:
#        d['attr_trackware'] = "True"
#    if ("Keylogger" in msg and ("detection" in msg or "detect" in msg)):
#        d['attr_keylogger_detected'] = "True"
#    if 'reference' in d and (("technet.microsoft.com/en-us/security/bulletin/MS04-011" in d['reference']) or ("technet.microsoft.com/en-us/security/bulletin/ms05-039" in d['reference']) or ("technet.microsoft.com/en-us/security/bulletin/MS03-026" in d['reference'])):
#        d['attr_windows'] = "True"
#    if 'win32.' in msg:
#        d['attr_windows'] = "True"
#    if "Malvertising" in msg or "Possible malicious redirect" in msg:
#        d['attr_malvertising_detected'] = "True"
#    if "TDS Sutra" in msg:
#        d['attr_js'] = "True"
#        d['attr_exploit_kit_action'] = "True"













        
#    if d['file'] == 'server-webapp' and (' php ' in msg or '.php' in msg or ('content' in d and '.php' in d['content'])):
#        d['attr_php'] = "True"
#    if "SQL Ingres Database" in msg:
#        d['attr_sql_ingres_database'] = "True"
#    elif "SQL IBM DB2" in msg:
#        d['attr_sql_ibm_db2'] = "True"
#    elif "SQL WinCC" in msg:
#        d['attr_sql_wincc_db'] = "True"
#    elif "SQL IBM SolidDB" in msg:
#        d['attr_sql_ibm_solid_db'] = "True"
#    elif "SQL SAP MaxDB" in msg:
#        d['attr_sql_sap_max_db'] = "True"
#    elif "SQL sa login failed" in msg or "SQL generic sql with comments injection attempt" in msg:
#        d['attr_sql'] = "True"
#    elif d['file'] == 'file-java':
#        d['attr_java'] = "True"
#    elif "Acrobat Flash" in msg or "Adobe Standalone Flash Player" in msg or "Adobe Flash player" in msg or "Adobe Flash" in msg:
#        d['attr_adobe_flash'] = "True"
#    elif "Adobe Primetime SDK" in msg:
#        d['attr_adobe_primetime_sdk'] = "True"
#    elif "Adobe Flash SWF" in msg:
#        d['attr_adobe_shockwave_player'] = "True"
#    elif d['file'] == 'file-flash' and "Google Chrome" in msg:
#        d['attr_google_chrome'] = "True"
#    elif "Adobe AS3" in msg or "Adobe ActionScript" in msg:
#        d['attr_adobe_action_script'] = "True"
#    elif "AlienVault OSSIM" in msg:
#        d['attr_alienvault_ossim'] = "True"
#    elif "Supermicro Intelligent Management Controller" in msg:
#        d['attr_supermicro_intelligent_management_controller'] = "True"
#    elif "Fireeye Java decompiler" in msg:
#        d['attr_fireye_java_decompiler'] = "True"
#    elif "Allen-Bradley Compact Logix" in msg:
#        d['attr_allen_bradley_compact_logix'] = "True"
#    elif d['file'] == 'server-webapp' and "Oracle" in msg:
#        d['attr_oracle_server'] = "True"
#    elif "Drupal" in msg:
#        d['attr_drupal'] = "True"
#    elif "Symantec Decomposer Engine" in msg:
#        d['attr_symantec_decomposer_engine'] = "True"
#    elif d['file'] == 'server-webapp' and "WordPress" in msg:
#        d['attr_wordpress'] = "True"
#    elif "SonicWall Secure Remote Access" in msg:
#        d['attr_sonicwall_secure_remote_access'] = "True"
#    elif "Trend Micro" in msg:
#        d['attr_trend_micro'] = "True"
#    elif "D-Link DSL-2750B" in msg:
#        d['attr_dlink_DSL_2750B'] = "True"
        
        
#    if "MiniUPnPd" in msg:
#        d['attr_mini_upnpd'] = "True"
#    elif "Sybase Open Server" in msg:
#        d['attr_sybase_open_server'] = "True"
#    elif ".exe " in msg or ".dll " in msg:
#        d['attr_windows'] = "True"
#    elif "VERITAS NetBackup" in msg or "Veritas NetBackup" in msg:
#        d['attr_veritas_netbackup'] = "True"
#    elif "HP AIO Archive Query Server" in msg:
#        d['attr_hp_aio_archive_query_server'] = "True"
#    elif d['file'] == 'server-other' and "OpenSSL" in msg:
#        d['attr_openssl'] = "True"
#    elif "SAP NetWeaver" in msg:
#        d['attr_sap_netweaver'] = "True"
#    elif "CMSimple" in msg:
#        d['attr_cmsimple'] = "True"
#    elif "AuraCMS" in msg:
#        d['attr_auracms'] = "True"
#    elif "HP AutoPass License Server" in msg:
#        d['attr_hp_autopass_license_server'] = "True"
#    elif "HP Network Node Manager" in msg:
#        d['attr_hp_network_node_manager'] = "True"
#    elif "HP OpenView Storage Data Protector" in msg:
#        d['attr_hp_openview_storage_data_protector'] = "True"
#    elif "HP ProCurve Manager" in msg:
#        d['attr_hp_procurve_manager'] = "True"
#    elif "Novell Groupwise" in msg:
#        d['attr_novell_groupwise'] = "True"
#    elif "IBM Tivoli Storage Manager" in msg:
#        d['attr_ibm_tivoli_storage_manager'] = "True"
#    elif "node.js" in msg:
#        d['attr_js'] = "True"
#    elif "NUUO NVRMini2" in msg:
#        d['attr_nuuo_nvrmini2'] = "True"
#    elif "Mitsubishi Electric E-Designer" in msg:
#        d['attr_mitsubishi_electric_edesigner'] = "True"
#    elif "Microsoft LDAP" in msg:
#        d['attr_windows'] = "True"
#    elif "Advantech WebAccess" in msg:
#        d['attr_advantech_webaccess'] = "True"
#    elif "Cisco IOS" in msg:
#        d['attr_cisco_ios'] = "True"
#    elif "Symantec Endpoint Protection Manager" in msg:
#        d['attr_symantec_endpoint_protection_manager'] = "True"
#    elif "Magneto" in msg:
#        d['attr_magneto'] = "True"
#    elif "Redis" in msg:
#        d['attr_redis'] = "True"
#    elif "Cisco ASA" in msg:
#        d['attr_cisco_asa'] = "True"
        
        
#    if d['file'] == 'malware-cnc' and 'MacOS' in msg:
#        d['attr_osx'] = "True"    
#    if d['file'] == 'malware-cnc' and (('outbound connection' in msg) or ('outbound connection' in msg) or ('outbound communication' in msg)):
#        d['attr_outbound_connections'] = "True"
#    if d['file'] == 'malware-cnc' and (('Inbound command' in msg) or ('inbound connection' in msg) or ('inbound beacon response' in msg)):
#        d['attr_inbound_commands'] = "True"
#    if d['file'] == 'malware-cnc' and 'User-Agent' in msg:
#        d['attr_user_agent_detected'] = "True"
    

        
#    if d['file'] == 'malware-cnc' and ('.php' in msg or ('content' in d and '.php' in d['content'])):
#        d['attr_php'] = "True"
    

#    if 'PDFEscape' in msg:
#        d['attr_pdfescape'] = "True"
#    elif 'reference' in d and "0a2f74a7787ae904e5a22a3c2b3acf0316c10b95fae08cced7ca5e2fcc7d9bf8" in d['reference']:
#        d['attr_java'] = "True"
#    elif 'reference' in d and "fe9c78249937d57aaed2792238caeea298e715d9cf261add1fbfbaeeab084d40" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "71ce7315d302a7d3ec6fac6534f262de213be59a19f84182c94b182cbe277f14" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "7975cbaa5657d89b45126bf739fd84acd5bbe724f372a20360bd4fc038b67541" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "c20980d3971923a0795662420063528a43dd533d07565eb4639ee8c0ccb77fdf" in d['reference']:
#        d['attr_osx'] = "True"
#    elif 'reference' in d and "15f5aaa71bfa3d62fd558a3e88dd5ba26f7638bf2ac653b8d6b8d54dc7e5926b" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "b04865eedf942078b123b13347930b871a75a02a982c71e68abaac2def7bd1ce" in d['reference']:
#        d['attr_js'] = "True"
#    elif 'reference' in d and "c17f4dc4bd1f81ca7f9729fd2f88f6e3e9738c4cc8ec38426eaed9f919eecf2d" in d['reference']:
#        d['attr_perl'] = "True"
#        d['attr_linux'] = "True"
#        d['attr_unix'] = "True"
#        d['attr_osx'] = "True"
#    elif 'reference' in d and "c0a0c4ca87d1f6b4be7f5f549fce531fbf0df871cc9f1eb38aa12a8273ad7e81" in d['reference']:
#        d['attr_osx'] = "True"
#    elif 'reference' in d and "2271d99e4a0e9d4198c092637d8f3296c1ce781eb2ebf81f2c1a0e2ca62cb6b5" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "0aedfdd0be32eb54ba39716e3bb1be41e662c08a9c0e72d34e6c466309671b31" in d['reference']:
#        d['attr_java'] = "True"
#    elif 'reference' in d and "8061839dfd1167b115865120728c806791f40ee422760866f303607dbd8a9dda" in d['reference']:
#        d['attr_osx'] = "True"
#    elif 'reference' in d and "e23cae7189d6ca9c649afc22c638a45fd94f19ef6b585963164cca52c7b80f9b" in d['reference']:
#        d['attr_windows'] = "True"
#    elif 'reference' in d and "905ba75b5b06cbb2ea75da302c94f6b5605327c59ebdb680c6feabdbc9e242d3" in d['reference']:
#        d['attr_java'] = "True"
#    elif 'reference' in d and "0d68f1d3855543a4732e551e9e4375a2cd85d9ab11a86334f67ad99c5f6990a0" in d['reference']:
#        d['attr_windows'] = "True"
    

        
#    if 'EXPLOIT-KIT' in msg:
#        d['attr_exploit_kit_action'] = "True"
#    if 'file download request' in msg:
#        d['attr_file_download_request'] = "True"
#    if 'file attachment detected' in msg:
#        d['attr_file_attachment_detected'] = "True"
#    if 'file magic detected' in msg:
#        d['attr_file_magic_detected'] = "True"

    
#    if "EMC AlphaStor Device Manager" in msg:
#        d['attr_emc_alphastor_device_manager'] = "True"
#    if "Microsoft LNK" in msg:
#        d['attr_windows'] = "True"
#    if "Microsoft Graphics" in msg:
#        d['attr_windows'] = "True"
#    if "Adobe Acrobat" in msg and 'reference' in d and "/acrobat/APSB" in d['reference']:
#        d = tag_helpx_adobe_acrobat(d)        
#    if "CCTV-DVR" in msg:
#        d['attr_cctv_dvr'] = "True"
#    if "QNAP QCenter" in msg:
#        d['attr_qnap_qcenter'] = "True"
#    if "D-Link DIR-816" in msg:
#        d['attr_dlink_dir_816'] = "True"
#    if "Blueimp jQuery File Upload" in msg:
#        d['attr_blueimp_jquery_file_upload'] = "True"
#    if "CGit" in msg:
#        d['attr_cgit'] = "True"
#    if "GPON Router" in msg:
#        d['attr_gpon_router'] = "True"
#    if "NetIQ Access Manager" in msg:
#        d['attr_netiq_access_manager'] = "True"
#    if "Reprise License Manager" in msg:
#        d['attr_reprise_license_manager'] = "True"
#    if "SAP ConfigServlet" in msg:
#        d['attr_sap_config_servlet'] = "True"
#    if "JBoss" in msg:
#        d['attr_jboss'] = "True"
#    if "Oracle GlassFish Server" in msg:
#        d['attr_oracle_glassfish_server'] = "True"
#    if "Sophos Web Protection Appliance" in msg:
#        d['attr_sophos_web_protection_appliance'] = "True"
#    if "Tenda W302R" in msg:
#        d['attr_tenda_W302R'] = "True"
#    if "Red Hat CloudForms" in msg:
#        d['attr_red_hat_cloudforms'] = "True"
#    if "Netgear DGN1000B" in msg:
#        d['attr_netgear_DGN1000B'] = "True"
#    if "HP Intelligent Management Center SOM" in msg:
#        d['attr_hp_intelligent_management_center_som'] = "True"
#    if "Seagate NAS" in msg:
#        d['attr_seagate_nas'] = "True"
#    if "EMC Connectrix Manager" in msg:
#        d['attr_emc_connectrix_manager'] = "True"
#    if "Cisco Prime Data Center Network Manager" in msg:
#        d['attr_cisco_prime_data_center_network_manager'] = "True"
#    if "Zimbra" in msg:
#        d['attr_zimbra'] = "True"
#    if "HP LoadRunner Virtual User Generator" in msg:
#        d['attr_hp_loadrunner_virtual_user_generator'] = "True"
#    if "HP Intelligent Management Center" in msg:
#        d['attr_hp_intelligent_management_center'] = "True"
#    if "HP System Management" in msg:
#        d['attr_hp_system_management'] = "True"
#    if "Arcserve Unified Data Protection" in msg:
#        d['attr_arcserve_unified_data_protection'] = "True"
#    if "Joomla" in msg:
#        d['attr_joomla'] = "True"
#    if "SQL injection attempt" in msg or "sql injection attempt" in msg:
#        d['attr_sql'] = "True"
#    if "Omron CX-Supervisor" in msg:
#        d['attr_omron_cx_supervisor'] = "True"
#    if "WebAssembly" in msg:
#        d['attr_web_assembly'] = "True"
#    if "UltraPlayer" in msg:
#        d['attr_ultra_player'] = "True"
#    if "Microsoft Edge PDF Builder" in msg:
#        d['attr_ms_edge_pdf_builder'] = "True"
#    if "OpenType" in msg:
#        d['attr_open_type'] = "True"
#    if "Adobe Acrobat Reader" in msg:
#        d['attr_adobe_acrobat_reader'] = "True"
#    if "Adobe Reader" in msg:
#        d['attr_adobe_reader'] = "True"
        
    return d        

def tag_ref(d):
    d = tag_helpx_adobe_acrobat(d)
    d = tag_virustotal_malware_cnc(d)
    return d

rule_base = './snortrules-snapshot-29120/rules/'
rules = [('app-detect.rules',[tag_msg,tag_ref]),
         ('attack-responses.rules',[tag_msg,tag_ref]),
         ('backdoor.rules',[tag_msg,tag_ref]),
         ('bad-traffic.rules',[tag_msg,tag_ref]),
         ('blacklist.rules',[tag_msg,tag_ref]),
         ('botnet-cnc.rules',[tag_msg,tag_ref]),
         ('browser-chrome.rules',[tag_msg,tag_ref]),
         ('browser-firefox.rules',[tag_msg,tag_ref]),
         ('browser-ie.rules',[tag_os_windows]),
         ('browser-other.rules',[tag_msg,tag_ref]),
         ('browser-plugins.rules',[tag_msg,tag_ref]),
         ('browser-webkit.rules',[tag_msg,tag_ref]),
         ('chat.rules',[tag_msg,tag_ref]),
         ('content-replace.rules',[tag_msg,tag_ref]),
         ('ddos.rules',[tag_msg,tag_ref]),
         ('dns.rules',[tag_msg,tag_ref]),
         ('dos.rules',[tag_msg,tag_ref]),
         ('experimental.rules',[tag_msg,tag_ref]),
         ('exploit.rules',[tag_msg,tag_ref]),
         ('exploit-kit.rules',[tag_msg,tag_ref]),
         ('file-executable.rules',[tag_msg,tag_ref]),
         ('file-flash.rules',[tag_msg,tag_ref]),
         ('file-identify.rules',[tag_msg,tag_ref]),
         ('file-image.rules',[tag_msg,tag_ref]),
         ('file-java.rules',[tag_msg,tag_ref]),
         ('file-multimedia.rules',[tag_msg,tag_ref]),
         ('file-office.rules',[tag_msg,tag_ref]),
         ('file-other.rules',[tag_msg,tag_ref]),
         ('file-pdf.rules',[tag_msg,tag_ref]),
         ('finger.rules',[tag_msg,tag_ref]),
         ('ftp.rules',[tag_msg,tag_ref]),
         ('icmp.rules',[tag_msg,tag_ref]),
         ('icmp-info.rules',[tag_msg,tag_ref]),
         ('imap.rules',[tag_msg,tag_ref]),
         ('indicator-compromise.rules',[tag_msg,tag_ref]),
         ('indicator-obfuscation.rules',[tag_msg,tag_ref]),
         ('indicator-scan.rules',[tag_msg,tag_ref]),
         ('indicator-shellcode.rules',[tag_msg,tag_ref]),
         ('info.rules',[tag_msg,tag_ref]),
         ('malware-backdoor.rules',[tag_msg,tag_ref]),
         ('malware-cnc.rules',[tag_msg,tag_ref]),
         ('malware-other.rules',[tag_msg,tag_ref]),
         ('malware-tools.rules',[tag_msg,tag_ref]),
         ('misc.rules',[tag_msg,tag_ref]),
         ('multimedia.rules',[tag_msg,tag_ref]),
         ('mysql.rules',[tag_msg,tag_ref]),
         ('netbios.rules',[tag_msg,tag_ref]),
         ('nntp.rules',[tag_msg,tag_ref]),
         ('oracle.rules',[tag_msg,tag_ref]),
         ('os-linux.rules',[tag_os_linux]),
         ('os-mobile.rules',[tag_msg,tag_ref]),
         ('os-other.rules',[tag_msg,tag_ref]),
         ('os-solaris.rules',[tag_os_solaris]),
         ('os-windows.rules',[tag_os_windows]),
         ('other-ids.rules',[tag_msg,tag_ref]),
         ('p2p.rules',[tag_msg,tag_ref]),
         ('phishing-spam.rules',[tag_msg,tag_ref]),
         ('policy.rules',[tag_msg,tag_ref]),
         ('policy-multimedia.rules',[tag_msg,tag_ref]),
         ('policy-other.rules',[tag_msg,tag_ref]),
         ('policy-social.rules',[tag_msg,tag_ref]),
         ('policy-spam.rules',[tag_msg,tag_ref]),
         ('pop2.rules',[tag_msg,tag_ref]),
         ('pop3.rules',[tag_msg,tag_ref]),
         ('protocol-dns.rules',[tag_msg,tag_ref]),
         ('protocol-finger.rules',[tag_msg,tag_ref]),
         ('protocol-ftp.rules',[tag_msg,tag_ref]),
         ('protocol-icmp.rules',[tag_msg,tag_ref]),
         ('protocol-imap.rules',[tag_msg,tag_ref]),
         ('protocol-nntp.rules',[tag_msg,tag_ref]),
         ('protocol-other.rules',[tag_msg,tag_ref]),
         ('protocol-pop.rules',[tag_msg,tag_ref]),
         ('protocol-rpc.rules',[tag_msg,tag_ref]),
         ('protocol-scada.rules',[tag_msg,tag_ref]),
         ('protocol-services.rules',[tag_msg,tag_ref]),
         ('protocol-snmp.rules',[tag_msg,tag_ref]),
         ('protocol-telnet.rules',[tag_msg,tag_ref]),
         ('protocol-tftp.rules',[tag_msg,tag_ref]),
         ('protocol-voip.rules',[tag_msg,tag_ref]),
         ('pua-adware.rules',[tag_msg,tag_ref]),
         ('pua-other.rules',[tag_msg,tag_ref]),
         ('pua-p2p.rules',[tag_msg,tag_ref]),
         ('pua-toolbars.rules',[tag_msg,tag_ref]),
         ('rpc.rules',[tag_msg,tag_ref]),
         ('rservices.rules',[tag_msg,tag_ref]),
         ('scada.rules',[tag_msg,tag_ref]),
         ('scan.rules',[tag_msg,tag_ref]),
         ('server-apache.rules',[tag_msg,tag_ref]),
         ('server-iis.rules',[tag_msg,tag_ref]),
         ('server-mail.rules',[tag_msg,tag_ref]),
         ('server-mssql.rules',[tag_os_windows, tag_sql]),
         ('server-mysql.rules',[tag_os_linux, tag_sql]),
         ('server-oracle.rules',[tag_msg,tag_ref]),
         ('server-other.rules',[tag_msg,tag_ref]),
         ('server-samba.rules',[tag_msg,tag_ref]),
         ('server-webapp.rules',[tag_msg,tag_ref]),
         ('shellcode.rules',[tag_msg,tag_ref]),
         ('smtp.rules',[tag_msg,tag_ref]),
         ('snmp.rules',[tag_msg,tag_ref]),
         ('specific-threats.rules',[tag_msg,tag_ref]),
         ('spyware-put.rules',[tag_msg,tag_ref]),
         ('sql.rules',[tag_msg,tag_ref]),
         ('telnet.rules',[tag_msg,tag_ref]),
         ('tftp.rules',[tag_msg,tag_ref]),
         ('virus.rules',[tag_msg,tag_ref]),
         ('voip.rules',[tag_msg,tag_ref]),
         ('web-activex.rules',[tag_msg,tag_ref]),
         ('web-attacks.rules',[tag_msg,tag_ref]),
         ('web-cgi.rules',[tag_msg,tag_ref]),
         ('web-client.rules',[tag_msg,tag_ref]),
         ('web-coldfusion.rules',[tag_msg,tag_ref]),
         ('web-frontpage.rules',[tag_msg,tag_ref]),
         ('web-iis.rules',[tag_msg,tag_ref]),
         ('web-misc.rules',[tag_msg,tag_ref]),
         ('web-php.rules',[tag_msg,tag_ref]),
         ('x11.rules',[tag_msg,tag_ref])]


def parse_rule_files(conn):
    for i in range(len(rules)):
        (r,fns) = rules[i]
        parse_rule_file(conn, rule_base + r,fns)

def parse_row(r):
    d = {}
    for i in range(len(columns)):
        v = r[i]
        if v is not None:
            d[columns[i]] = r[i]
    return d
        
def parse_db(gconn, conn, qry=None, insert=True):
    cur = gconn.cursor()
    if qry is None:
        qry = "SELECT {} FROM rules".format(str(tuple(columns)).replace('\'', '').replace(' ','')[1:-1])
    #print qry
    cur.execute(qry)
    rows = cur.fetchall()
    for k in progressbar.progressbar(range(len(rows))):
    #for k in range(len(rows)):
        row = rows[k]
#        print row
        rule = parse_row(row)
        rule = retag_rule(rule)
        if insert:
            insert_rule(conn, rule)
    if fails != []:
        print "fails:"
        pp.pprint(fails)
    if fails != []:
        print "bheaders:"
        pp.pprint(bheaders)
    if fails != []:
        print "pforms:"
        pp.pprint(pforms)
    if fails != []:
        print "exts:"
        pp.pprint(exts)
    if fails != []:
        print "exif_missing:"
        pp.pprint(exif_missing)
    if fails != []:
        print "add_info_missing:"
        pp.pprint(add_info_missing)
if __name__ == '__main__':

    parser=argparse.ArgumentParser(description='Update Snort Rules Database')
    parser.add_argument('--init','-i', help='initialize a new DB to INIT', required=False, type=str)
    parser.add_argument('--copy','-c', help='copy the DB to COPY', required=False, type=str)
    parser.add_argument('--retag','-r', help='retag the DB to RETAG', required=False, type=str)
    parser.add_argument('--query','-q', help='query to iterate over', required=False, type=str)
    args=parser.parse_args()

    database = "databases/test-snort-rules.db"

    if args.copy:
        e('cp {} {}'.format(database, args.copy))
        sys.exit()
    
    #sys.stdout = open('rules/autogen.conf', 'w')
    if args.init:
        database = args.init
        ins_db = InsertDB(database)
        conn = ins_db.create_connection()
        create_table(conn)
        parse_rule_files(conn)     
    elif args.retag:
        database_bak = args.retag
        get_db = InsertDB(database)
        ins_db = InsertDB(database_bak)
        gconn = get_db.create_connection()
        conn = ins_db.create_connection()
        create_table(conn)
        parse_db(gconn, conn)
    else:
        get_db = InsertDB(database)
        gconn = get_db.create_connection()
        if args.query:
            parse_db(gconn, None, insert=False, qry=args.query)
        else:
            parse_db(gconn, None, insert=False)
        pp.pprint(retag_vars)
    #show_table()
    #show_conf()
     
