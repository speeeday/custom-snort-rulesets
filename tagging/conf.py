#import nmap

def is_num(c):
     return '0' <= c and c <= '9'

# sudo apt-get install nmap
# sudo pip install python-nmap

# creates a sql qry to pull rules for a snort config for a single device
# takes in a dictionary from nmap scan of port:service, os (-O flag with nmap), mnf (manufacturer)
# dev (device type (e.g., dvr, nas, etc.))

# We take the logical OR of each separate list, which should match on a subset of the rules
# each separate list first will get logical AND to all the nulls which will be added together
# this will filter out all the attributes we dont want, within all the attributes that we want
def create_query(d):
     # attributes we know are definitely FALSE. (be careful with this, determines false pos. rate)
     nulls = []

     # does this device have an interface
     gui = False
     
     ports = []
     for port in d:
          if not is_num(port[0]):
               continue
          ports.append("dstport = '{}'".format(port))
     ports.append("dstport = 'any'")
     ports.append("dstport LIKE '%$HTTP_PORTS%'")
     ports.append("dstport LIKE '%$HTTPS_PORTS%'")
     ports.append("dstport LIKE '%$FILE_DATA_PORTS%'")
     ports.append("dstport LIKE '%$FTP_PORTS%'")
     
          
     # OR

     # Scan OS
     oss = []
     if "Linux" in d['os']:
          oss.append("(attr_linux = 'True' OR attr_unix = 'True')")
          nulls.append("attr_windows ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "Windows" in d['os']:
          oss.append("attr_windows = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "OSX" in d['os']:
          oss.append("attr_osx = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_windows ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "FreeBSD" in d['os']:
          oss.append("attr_freebsd = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_windows ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "Solaris" in d['os']:
          oss.append("attr_solaris = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_windows ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "Android" in d['os']:
          oss.append("attr_android = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_windows ISNULL");
          nulls.append("attr_ios ISNULL");
     elif "iOS" in d['os']:
          oss.append("attr_ios = 'True'")
          nulls.append("attr_linux ISNULL");
          nulls.append("attr_unix ISNULL");
          nulls.append("attr_osx ISNULL");
          nulls.append("attr_freebsd ISNULL");
          nulls.append("attr_solaris ISNULL");
          nulls.append("attr_android ISNULL");
          nulls.append("attr_windows ISNULL");

          
     # OR

     # Scan JS
     # might always be true

     # Scan PHP
     # if web server probably true

     # scan SQL
     # attr_sql_ingres_database
     # attr_sql_ibm_db2
     # attr_sql_wincc_db
     # attr_sql_ibm_solid_db
     # attr_sql_sap_max_db
     # if not running sql service probably false

     # scan DNS
     # iot devices probably have dns

     # scan adobe flash
     # attr_adobe_primetime_sdk
     # attr_adobe_shockwave_player
     # attr_adobe_action_script
     # most probably won't have flash

     # adobe acrobat reader
     # probably wont make sense unless it has some kind of UI
     # adobe reader
     # same as above, wouldnt make sense unless there was a display

     nulls.append('attr_adobe_flash ISNULL')
     nulls.append('attr_adobe_primetime_sdk ISNULL')
     nulls.append('attr_adobe_shockwave_player ISNULL')
     nulls.append('attr_adobe_action_script ISNULL')

     nulls.append('attr_adobe_reader ISNULL')
     nulls.append('attr_adobe_acrobat_reader ISNULL')

     
     # scan office tools
     # won't have microsoft office tools
     nulls.append('attr_office_tools ISNULL')

     # Servers
     #   kubernetes
     #   oracle weblogic
     #   apache
     #   prestashop
     #   netiq access manager identity server
     #      may only make sense if netiq product
     #   jboss
     #   oracle glassfish server
     #   sophos web protection appliance
     #   red hat cloudforms
     #   attr_hp_intelligent_management_center_som
     #              'attr_emc_connectrix_manager',
     #      'attr_cisco_prime_data_center_network_manager',
    #       'attr_zimbra',
     # 'attr_arcserve_unified_data_protection'
     # attr_joomla
     # sybase open server
     # Veritas NetBackup
     # SAP Netweaver
     # cmsimple
     # auracms
     #          'attr_novell_groupwise',
     #           'attr_ibm_tivoli_storage_manager',
     #           'attr_nuuo_nvrmini2',
     # attr_advantech_webaccess
     # symantec_endpoint_protection_manager
     # redis
     # alienvault
     # attr_supermicro_intelligent_management_controller
     # attr_allen_bradley_compact_logix
     # oracle_server
     # drupal
     # attr_symantec_decomposer_engine
     # wordpress - unlikely
     # attr_sonicwall_secure_remote_access
     # attr_trend_micro
     # 
     

     # Omron CX Supervisor
     # doesnt make sense in iot deployment
     nulls.append('attr_omron_cx_supervisor ISNULL')

     # webassembly
     # should be included

     # UltraPlayer
     # doesnt make sense in iot deployment
     nulls.append('attr_ultra_player ISNULL')

     # ms edge pdf builder
     # unless its windows device, doesnt make sense
     if "Windows" not in d['os']:
          nulls.append('attr_ms_edge_pdf_builder ISNULL')
     else:
          if not gui:
               nulls.append('attr_ms_edge_pdf_builder ISNULL')
          
     # opentype
     # might want to include


     # cctv_dvr
     # only true if this is a CCTV dvr
     if "CCTV" not in d['mnf'] or "DVR" not in d['dev']:
          nulls.append('attr_cctv_dvr ISNULL')
     
     # qnap qcenter
     # seagate NAS
     # only relevant if device is a NAS
     if "NAS" not in d['dev']:
          nulls.append('attr_qnap_qcenter ISNULL')
     else:
          if "Seagate" not in d['mnf']:
               nulls.append('attr_seagate_nas ISNULL')

     # dlink_dir_816
     # only relevant if D-Link
     if "D-Link" not in d['mnf']:
          nulls.append('attr_dlink_dir_816 ISNULL')
     else:
          if "DSL" not in d['dev']:
               nulls.append('attr_dlink_DSL_2750B ISNULL')

     

     # blueimp jquery file upload
     # probably won't need this?

     # cgit
     # wouldn't really make sense in iot delpoyment

     # gpon router
     # only relevant if gpon
     if "GPON" not in d['mnf'] or "router" not in d['dev']:
          nulls.append('attr_gpon_router ISNULL')

     # reprise license manager
     # only relevant if port 5054 was open
     if '5054' not in d:
          nulls.append('attr_reprise_license_manager ISNULL')

     # attr sap config servlet
     if '50000' not in d:
          nulls.append('attr_sap_config_servlet ISNULL')

     # tenda w302r
     if "Tenda" not in d['mnf'] or "w302r" not in d['dev']:
          nulls.append('attr_tenda_W302R ISNULL')
          
     #netgear dgn1000b
     if "Netgear" not in d['mnf'] or "dgn1000b" not in d['dev']:
          nulls.append('attr_netgear_DGN1000B ISNULL')

     #             'attr_hp_loadrunner_virtual_user_generator',
     #        'attr_hp_intelligent_management_center',
     #        'attr_hp_system_management',
     if "HP" not in d['mnf']:
          nulls.append('attr_hp_loadrunner_virtual_user_generator ISNULL')
          nulls.append('attr_hp_intelligent_management_center ISNULL')
          nulls.append('attr_hp_system_management ISNULL')
          nulls.append('attr_hp_aio_archive_query_server ISNULL')
          nulls.append('attr_hp_autopass_license_server ISNULL')
          nulls.append('attr_hp_network_node_manager ISNULL')
          nulls.append('attr_hp_openview_storage_data_protector ISNULL')
          nulls.append('attr_hp_procurve_manager ISNULL')
          
     # attr_emc_alphastor_device_manager
     if '3000' not in d:
          nulls.append('attr_emc_alphastor_device_manager ISNULL')

     # identifying files / file downloads / attachments are unecessary. As long as we have network captures we can determine these later. but we are advocating for security
     # Maybe we only want to do this for a NAS
     if "nas" not in d['dev']:
          nulls.append('attr_file_magic_detected ISNULL')
          nulls.append('attr_file_download_request ISNULL')
          nulls.append('attr_file_attachment_detected ISNULL')

     # attr_exploit_kit_action
     # attr_outbound_connections
     # attr_inbound_commands
     # user agent detected
     # we always want these
     

     # attr_pdfescape
     # probably not on device
     nulls.append('attr_pdfescape ISNULL')
     
     # attr_java
     # attr_perl
     # probably on device
     
     # miniupnpd
     # if pnp protocol
     
     # attr_openssl
     # probably has ssl

     #'attr_mitsubishi_electric_edesigner'
     nulls.append('attr_mitsubishi_electric_edesigner ISNULL')
     
     # cisco ios
     # cisco asa

     # attr google chrome
     # likely wont be running chrome
     nulls.append('attr_google_chrome ISNULL')

     # attr fireye java decompiler --- prolly wont have ..
     nulls.append('attr_fireye_java_decompiler ISNULL')

     # attr_lib_graphite
     # if lib graphite files are even applicable..

     # attr_oracle_oit
     # if libvx_mkwd tfile applicable

     # attr_symantec
     # very unlikely that a device has AV protection from symantec
     nulls.append('attr_symantec ISNULL')

     # attr_wireshark
     # most of these devices probably dont have wireshark on them..
     nulls.append('attr_wireshark ISNULL')

     # visual basic
     if "Windows" not in d['os']:
          nulls.append('attr_visual_basic ISNULL')

     # WINRAR could be any OS, probably not on IoT devices
     nulls.append('attr_winrar ISNULL')

     # real player, probably not
     nulls.append('attr_real_player ISNULL')

     # ftp_banner_detected
     # sinkhole
     # iframe
     # phishing detected
     # trackware detected
     # keylogger detected
     # malvertising detected
     # cnc detected
     # trojan detected
     # keep these


     print "SELECT count(repr) FROM rules WHERE " + "(" + " OR ".join(ports) + ")" + " AND " + "(" + " AND ".join(nulls) + ")" + ";"

device_dict = {
     'os':"Linux",
     'dev':"Camera",
     'mnf':'Vizio',
     '8008':'http',
     '8009':'ajp13',
     '9000':'cslistener'
}
     
create_query(device_dict)
     
'''     
ip = '192.168.1.81'

nmScan = nmap.PortScanner()
scan = nmScan.scan(ip, '22-443')

hosts = nmScan.all_hosts()

for host in nmScan.all_hosts():
     print('Host : %s (%s)' % (host, nmScan[host].hostname()))
     print('State : %s' % nmScan[host].state())
     for proto in nmScan[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
 
         lport = nmScan[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('port : %s\tstate : %s' % (port, nmScan[host][proto][port]['state']))
'''

# scan for all IPs
# for a single IP
# scan all ports
# WHERE dstport = port1 OR dstport = port2 
             
#print hosts
#print scan
