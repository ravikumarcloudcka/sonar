#!/usr/bin/env python
import os, pwd, grp, re
from subprocess import call,check_output,CalledProcessError
import platform
import rpm
from time import sleep,tzname
from sys import exit,argv
from collections import OrderedDict
import json
import argparse

########################################################################################################################################################################################
# Variable Declaration
default_disable_list = ['atd.service', 'firewalld.service', 'mdmonitor.service', 'lvm2-monitor.service', 'microcode.service', 'tuned.service', 'libstoragemgmt.service',
                        'dbus-org.fedoraproject.FirewallD1.service', 'dmraid-activation.service', 'abrt-ccpp.service',
                        'abrt-oops.service',
                        'abrt-vmcore.service', 'abrt-xorg.service', 'abrtd.service',
                        'systemd-readahead-collect.service',
                        'systemd-readahead-drop.service', 'systemd-readahead-replay.service', 'rexec.socket',
                        'sendmail.service', 'ksm.service',
                        'ksmtuned.service', 'cups.service', 'mcelog.service', 'NetworkManager.service', 'rpcbind.socket', 'smartd.service',
                        'rpcbind.service', 'rhel-configure.service']
default_enable_service_list = ['puppet.service', 'xinetd.service', 'rsyslog.service', 'fstrim.timer', 'kdump.service', 'rngd.service', 'wazuh-agent.service']
listallenabledservice = os.listdir("/etc/systemd/system/multi-user.target.wants/")
masked_service="ctrl-alt-del.target"
user_root = {'RunCmd':'/bin/runcmd', 'Nlink' :'/bin/nlink', 'OSQuery':'/etc/osquery/osquery.conf'}
user_sas = {'Fexec':'/usr/bin/fexec', 'HomeDirectorySASUser':'/home/sas', 'Partition':'/disk1', 'Partition':'/disk2', 'Partition':'/disk3', 'Partition':'/disk4', 'Partition':'/disk5', 'Partition':'/disk6'}
user_patcher = {'HomeDirectoryPatcherUser':'/home/patcher'}
user_root_ossec = {'OSSec Internal Config':'/var/ossec/etc/local_internal_options.conf', 'OSSec Config':'/var/ossec/etc/ossec.conf'}
suid_and_guid = {'Nlink':'/bin/nlink', 'Arping':'/sbin/arping', 'InterfaceConfig':'/sbin/ifconfig', 'IngValidPW':'/bin/ingvalidpw', 'SendArp':'/bin/send_arp', 'NetStat':'/bin/netstat'}
puppet_binary={'PuppetBinary':'/usr/bin/puppet'}
zoho_custom_binary_dir={'OptCustomDirectoryForZoho':'/opt/zoho/bin'}
perm_750 = {'RemoveHere':'/bin/rm', 'HomeDirectorySASUser':'/home/sas', 'HomeDirectoryPatcherUser':'/home/patcher'}
perm_4755 = {'SocketStatistics':'/usr/sbin/ss', 'SocketStatistics':'/sbin/ss'}
perm_755 = {'OSQuery':'/etc/osquery/osquery.conf', 'HidsRegister':'/etc/cron.hourly/hids-register.sh'}
perm_640 = {'OSSec Config':'/var/ossec/etc/ossec.conf'}
perm_0640 = {'OSSec Internal Config':'/var/ossec/etc/local_internal_options.conf'}
perm_644 = {'SocCustomLogScript':'/usr/local/zoho/scripts/zoho_soc_custom_log_func.sh'}
logs_config = {'Logrotate':'/var/log/puppet-agent.log', 'Logrotate':'/var/log/systemd-logind.log'}
rc_local_config="/etc/rc.local"
logrotate_syslog_config="/etc/logrotate.d/syslog"

#DEVNULL
DEVNULL = open(os.devnull, 'w')

#Package variables
origlist= ['mcelog', 'xfsprogs', 'setup', 'ntpdate', 'python-chardet', 'bind-license', 'smartmontools', 'langtable-python', 'langtable-data', 'at', 'gdb', 'kbd-misc', 'perf', 'nss', 'tzdata', 'kpatch', 'sound-theme-freedesktop', 'libstdc++', 'man-db', 'bind-export-libs', 'nss-util', 'kernel-tools', 'rpm-libs', 'zlib', 'bind-utils', 'libuser', 'libxml2', 'python-dmidecode', 'GeoIP', 'libuuid', 'e2fsprogs', 'python-urlgrabber', 'elfutils-libelf', 'blktrace', 'gnupg2', 'libgcrypt', 'wget', 'rpm-python', 'libcap', 'libXfont', 'libsss_nss_idmap', 'sqlite', 'compat-libtiff3', 'libdaemon', 'gawk', 'unzip', 'libxkbcommon', 'lua', 'ed', 'libsndfile', 'pixman', 'lsof', 'hardlink', 'p11-kit', 'iptraf-ng', 'ustr', 'freetype', 'rdate', 'sgpio', 'libSM', 'compat-libf2c-34', 'libthai', 'e2fsprogs-libs', 'libexif', 'gdk-pixbuf2', 'hunspell-en-US', 'rootfiles', 'procps-ng', 'libnl3', 'words', 'kmod', 'dmidecode', 'systemd-libs', 'libXext', 'elfutils-default-yama-scope', 'libXi', 'abrt-libs', 'numactl-libs', 'device-mapper-event-libs', 'libXcursor', 'grub2-tools-minimal', 'libnl3-cli', 'iputils', 'libassuan', 'policycoreutils', 'libunistring', 'libreport-plugin-mantisbt', 'hostname', 'grub2-tools-extra', 'libglvnd', 'dhcp-common', 'grub2-pc', 'libestr', 'libreport-centos', 'iproute', 'cyrus-sasl', 'ipset', 'abrt-python', 'xorg-x11-xauth', 'abrt-addon-pstoreoops', 'nettle', 'usb_modeswitch-data', 'perl-HTTP-Tiny', 'libgusb', 'perl-Text-ParseWords', 'mesa-libGL', 'perl-macros', 'mesa-libEGL', 'perl-Exporter', 'rpcbind', 'perl-threads-shared', 'libreport-cli', 'perl-File-Temp', 'dconf', 'perl-Getopt-Long', 'glib-networking', 'perl-Net-Daemon', 'alsa-firmware', 'perl-DBI', 'openscap', 'jasper-libs', 'pulseaudio-libs', 'vim-minimal', 'plymouth', 'bc', 'usermode', 'libselinux-utils', 'adwaita-cursor-theme', 'procmail', 'compat-db-headers', 'libproxy', 'kbd-legacy', 'krb5-libs', 'quota', 'python', 'setuptool', 'cyrus-sasl-lib', 'xorg-x11-server-Xvfb', 'shared-mime-info', 'lvm2', 'libcroco', 'rsyslog-mmnormalize', 'python-augeas', 'kernel', 'binutils', 'mlocate', 'gettext', 'lshw', 'python-gobject-base', 'puppet-agent', 'json-glib', 'libgcc', 'grubby', 'centos-release', 'pyliblzma', 'filesystem', 'newt-python', 'fontpackages-filesystem', 'python-kitchen', 'libreport-filesystem', 'sos', 'dejavu-fonts-common', 'libselinux-python', 'basesystem', 'pyxattr', 'kernel-headers', 'logrotate', 'libX11-common', 'nss-pem', 'ncurses-base', 'nss-sysinit', 'glibc-common', 'nss-tools', 'glibc', 'fipscheck-lib', 'ncurses-libs', 'net-snmp-libs', 'nspr', 'libssh2', 'libsepol', 'curl', 'libselinux', 'rpm', 'info', 'xmlrpc-c-client', 'xz-libs', 'passwd', 'bzip2-libs', 'geoipupdate', 'chkconfig', 'bind-libs-lite', 'readline', 'python-pycurl', 'grep', 'mokutil', 'expat', 'pth', 'libgpg-error', 'gpgme', 'libffi', 'rpm-build-libs', 'libattr', 'yum-plugin-fastestmirror', 'libacl', 'jansson', 'json-c', 'kernel-tools-libs', 'libtar', 'libwayland-egl', 'audit-libs', 'gpm-libs', 'cpio', 'lcms2', 'libogg', 'libsss_idmap', 'xmlrpc-c', 'gsm', 'findutils', 'fribidi', 'gdbm', 'ethtool', 'libvorbis', 'compat-glibc', 'xz', 'libXdmcp', 'libpng', 'libsemanage', 'libjpeg-turbo', 'libutempter', 'libICE', 'qrencode-libs', 'tar', 'sg3_utils-libs', 'groff-base', 'libepoxy', 'file-libs', 'libtiff', 'mesa-libglapi', 'gtk-update-icon-cache', 'hunspell', 'kpartx', 'libxshmfence', 'device-mapper', 'slang', 'dracut', 'libtool-ltdl', 'device-mapper-libs', 'libXau', 'elfutils-libs', 'libX11', 'dbus-libs', 'libXrender', 'dbus', 'libXdamage', 'satyr', 'libfastjson', 'libreport', 'libmnl', 'systemd-sysv', 'libtdb', 'libusbx', 'libXtst', 'libreport-web', 'libXrandr', 'polkit-pkla-compat', 'libXcomposite', 'crontabs', 'nss-softokn', 'cronie-anacron', 'libxslt', 'initscripts', 'bzip2', 'dbus-python', 'libgomp', 'libstoragemgmt-python', 'libfontenc', 'libstoragemgmt-python-clibs', 'libedit', 'device-mapper-event', 'efivar-libs', 'libnfnetlink', 'yajl', 'p11-kit-trust', 'lzo', 'lm_sensors-libs', 'liblognorm', 'iptables', 'libXfont2', 'ipset-libs', 'libXxf86vm', 'libXmu', 'libxkbfile', 'xorg-x11-server-common', 'hunspell-en-GB', 'perl-parent', 'perl-podlators', 'perl-Pod-Escapes', 'perl-Encode', 'perl-libs', 'perl-threads', 'perl-Filter', 'perl-Time-HiRes', 'perl-constant', 'perl-Scalar-List-Utils', 'perl-File-Path', 'perl-PathTools', 'perl-Pod-Simple', 'perl', 'perl-Data-Dumper', 'perl-Compress-Raw-Zlib', 'perl-PlRPC', 'perl-DBD-SQLite', 'device-mapper-persistent-data', 'hesiod', 'tcp_wrappers', 'acl', 'libdb-utils', 'pinentry', 'make', 'mozjs17', 'vim-common', 'linux-firmware', 'libmodman', 'snappy', 'libverto', 'openssl-libs', 'python-libs', 'libblkid', 'gzip', 'cracklib', 'glib2', 'atk', 'libxml2-python', 'cracklib-dicts', 'pam', 'python-decorator', 'openssl', 'alsa-lib', 'gettext-libs', 'gsettings-desktop-schemas', 'gobject-introspection', 'pygobject2', 'harfbuzz', 'microcode_ctl', 'iptables-services', 'chrony', 'rng-tools', 'watchdog', 'aic94xx-firmware', 'net-tools', 'irqbalance', 'ledmon', 'strace', 'parted', 'dracut-config-rescue', 'tcpdump', 'sssd-client', 'vim-enhanced', 'yum-utils', 'shim-x64', 'python-psycopg2', 'xfsdump', 'bash-completion', 'cyrus-sasl-plain', 'btrfs-progs', 'iotop', 'tcsh', 'nmap-ncat', 'hunspell-en', 'nethogs', 'numactl', 'ntsysv', 'iftop', 'nvme-cli', 'zip', 'time', 'libpng12', 'psmisc', 'scl-utils', 'htop', 'libyaml', 'compat-libcap1', 'rfkill', 'bridge-utils', 'compat-libgfortran-41', 'rsh', 'nicstat', 'man-pages-overrides', 'ivtv-firmware', 'centos-indexhtml', 'sudo', 'ca-certificates', 'grub2-tools', 'rsyslog', 'openssh', 'dhclient', 'kexec-tools', 'lvm2-libs', 'dmraid-events', 'selinux-policy', 'python-firewall', 'sendmail', 'libreport-plugin-ureport', 'abrt', 'abrt-addon-kerneloops', 'abrt-addon-vmcore', 'abrt-retrace-client', 'usb_modeswitch', 'fprintd', 'colord-libs', 'libdrm', 'libglvnd-glx', 'libglvnd-egl', 'cairo', 'cairo-gobject', 'OpenIPMI-modalias', 'OpenIPMI', 'abrt-tui', 'at-spi2-atk', 'ebtables', 'gnutls', 'libsoup', 'fxload', 'alsa-tools-firmware', 'abrt-addon-python', 'avahi-libs', 'gtk2', 'libcanberra', 'plymouth-scripts', 'elfutils', 'abrt-cli', 'emacs-filesystem', 'xdg-utils', 'adwaita-icon-theme', 'libcanberra-gtk3', 'compat-db47', 'firewalld-filesystem', 'kbd', 'firewalld', 'lldpd', 'pinfo', 'abrt-console-notification', 'ipmitool', 'fprintd-pam', 'selinux-policy-targeted', 'grub2', 'openssh-clients', 'rsyslog-mmjsonparse', 'authconfig', 'xinetd', 'sysstat', 'usbutils', 'pciutils', 'audit', 'libreport-plugin-mailx', 'rsync', 'libXft', 'grub2-common', 'biosdevname', 'python-iniparse', 'langtable', 'mdadm', 'python2-futures', 'xkeyboard-config', 'rsh-server', 'python-slip', 'grub2-pc-modules', 'teamd', 'centos-logos', 'vim-filesystem', 'cryptsetup', 'mailx', 'nss-softokn-freebl', 'virt-what', 'fipscheck', 'bash', 'iprutils', 'libcurl', 'pcre', 'yum-langpacks', 'openldap', 'libcom_err', 'postgresql-libs', 'popt', 'mtr', 'bind-libs', 'sed', 'dstat', 'libtirpc', 'libdb', 'openssl098e', 'pygpgme', 'augeas-libs', 'efibootmgr', 'yum', 'tcp_wrappers-libs', 'giflib', 'libseccomp', 'libcap-ng', 'compat-exiv2-023', 'lsscsi', 'which', 'nano', 'libsysfs', 'libidn', 'osquery', 'libpipeline', 'libpcap', 'traceroute', 'compat-glibc-headers', 'diffutils', 'hdparm', 'shadow-utils', 'libaio', 'dosfstools', 'libasyncns', 'libwayland-client', 'setserial', 'jbigkit-libs', 'file', 'grub2-efi-x64-modules', 'libsmartcols', 'gmp', 'man-pages', 'util-linux', 'newt', 'openssl11-libs', 'cryptsetup-libs', 'libxcb', 'systemd', 'libXfixes', 'libreport-python', 'pciutils-libs', 'hwdata', 'lz4', 'polkit', 'libXinerama', 'cronie', 'libwayland-server', 'dbus-glib', 'kmod-libs', 'libstoragemgmt', 'ncurses', 'os-prober', 'sysvinit-tools', 'dhcp-libs', 'libtasn1', 'dracut-network', 'keyutils-libs', 'dmraid', 'libnetfilter_conntrack', 'python-slip-dbus', 'libteam', 'libreport-plugin-rhtsupport', 'libXt', 'abrt-dbus', 'xorg-x11-xkb-utils', 'abrt-addon-xorg', 'less', 'libfprint', 'perl-Pod-Perldoc', 'libpciaccess', 'perl-Pod-Usage', 'mesa-libgbm', 'perl-Storable', 'pango', 'perl-Time-Local', 'OpenIPMI-libs', 'perl-Carp', 'at-spi2-core', 'perl-Socket', 'trousers', 'perl-Compress-Raw-Bzip2', 'rest', 'perl-IO-Compress', 'systemd-python', 'libwayland-cursor', 'cups-libs', 'flac-libs', 'plymouth-core-libs', 'attr', 'abrt-addon-ccpp', 'libss', 'desktop-file-utils', 'dejavu-sans-fonts', 'gtk3', 'libconfig', 'quota-nls', 'graphite2', 'pm-utils', 'coreutils', 'libcanberra-gtk2', 'fontconfig', 'openscap-scanner', 'libmount', 'arpwatch', 'pkgconfig', 'openssh-server', 'libpwquality', 'grub2-efi-x64', 'python-six', 'wazuh-agent', 'hicolor-icon-theme', 'rasdaemon', 'gstreamer1', 'psacct', 'yum-metadata-parser']
origlist_kvm_pkg= ['libcgroup', 'libvirt-daemon', 'libvirt-daemon-config-network', 'libvirt-bash-completion', 'libvirt-daemon-driver-secret', 'gnutls-dane', 'libvirt-daemon-driver-storage-core', 'libvirt-daemon-driver-storage-scsi', 'lzop', 'libvirt-daemon-driver-storage-iscsi', 'celt051', 'virt-install', 'netcf-libs', 'glusterfs-libs', 'libevent', 'dialog', 'boost-iostreams', 'librbd1', 'iscsi-initiator-utils', 'python-urllib3', 'cyrus-sasl-gssapi', 'usbredir', 'librdmacm', 'ipxe-roms-qemu', 'seabios-bin', 'keyutils', 'libnfsidmap', 'libini_config', 'genisoimage', 'autogen-libopts', 'boost-system', 'fuse-libs', 'python-ipaddress', 'librados2', 'libref_array', 'libverto-libevent', 'glusterfs-client-xlators', 'python-backports-ssl_match_hostname', 'python-requests', 'python-ipaddr', 'libarchive', 'radvd', 'nfs-utils', 'qemu-kvm-common', 'libvirt-libs', 'libvirt-daemon-driver-network', 'libvirt-daemon-config-nwfilter', 'libvirt-daemon-driver-lxc', 'libvirt-daemon-driver-interface', 'libvirt-python', 'gnutls-utils', 'glusterfs', 'qemu-img', 'libvirt-daemon-driver-storage-disk', 'libvirt-daemon-driver-storage-gluster', 'libvirt-daemon-driver-storage-mpath', 'libvirt-daemon-driver-storage-logical', 'libvirt-daemon-driver-storage', 'qemu-kvm', 'libvirt', 'opus', 'iscsi-initiator-utils-iscsiuio', 'numad', 'libibverbs', 'osinfo-db', 'dnsmasq', 'gssproxy', 'libvirt-daemon-driver-nwfilter', 'libvirt-daemon-driver-nodedev', 'virt-manager-common', 'sgabios-bin', 'libvirt-client', 'glusterfs-api', 'libvirt-daemon-driver-qemu', 'libvirt-daemon-driver-storage-rbd', 'seavgabios-bin', 'virt-top', 'libpath_utils', 'libusal', 'gperftools-libs', 'spice-server', 'boost-thread', 'libiscsi', 'boost-random', 'libbasicobjects', 'unbound-libs', 'libcollection', 'glusterfs-cli', 'python-backports', 'rdma-core', 'libosinfo', 'osinfo-db-tools']
origlist_container_pkg= ['fuse-libs', 'fuse-devel', 'fuse', 'megaraid']
origlist_vm_pkg= ['qemu-guest-agent']

kvm_packages = ['libvirt', 'qemu-kvm', 'libvirt-python', 'dialog', 'virt-top', 'virt-install']
kopts = {'Crashkernel':'crashkernel=auto', 'RedhatGraphicalBoot':'rhgb', 'Quite':'quiet', 'NetworkInterfaceNames':'net.ifnames=0', 'BiosDevName':'biosdevname=0', 'KernelPanic':'panic=30', 'IntelPState':'intel_pstate=disable', 'FileSystemRepair':'fsck.repair=yes'}

installed_rpm_list = []
AddPackages=[]
PackagesNotInstalled=[]

#Hostname
hostname= os.uname()[1]

#PATCHER USER SUDO Permissions
#PATCHER USER SUDO Permissions
PATCHER_SUDO = {'patcher_debugtools' : ['/usr/sbin/iotop','/usr/sbin/nethogs','/usr/sbin/iftop','/usr/sbin/arpwatch'],'ipmiutils' : ['/usr/sbin/isensor', '/usr/sbin/isel', '/usr/sbin/ifru', '/usr/sbin/ilan', '/usr/bin/ipmiutil dcmi power get', '/usr/sbin/iseltime -x'], 'lvmcmds' : ['/sbin/lvdisplay *'], 'megaclicmds' : ['/usr/bin/megacli -LdPdInfo -aALL -NoLog', '/usr/bin/megacli -AdpBbuCmd -GetBbuStatus -aALL -NoLog', '/usr/bin/megacli -LdPdInfo -a* -NoLog', '/usr/bin/megacli -AdpBbuCmd -GetBbuStatus -a* -NoLog', '/usr/bin/megacli -EncInfo -aALL', '/usr/bin/megacli -AdpAllInfo -aALL', '/usr/bin/megacli -adpgetpciinfo -aALL', '/usr/bin/megacli -LDInfo -Lall -aALL', '/usr/bin/megacli -AdpEventLog -GetEventLogInfo -aALL -NoLog', '/usr/bin/MegaCli -LdPdInfo -aALL -NoLog', '/usr/bin/MegaCli -AdpBbuCmd -GetBbuStatus -aALL -NoLog', '/usr/bin/MegaCli -LdPdInfo -a* -NoLog', '/usr/bin/MegaCli -AdpBbuCmd -GetBbuStatus -a* -NoLog', '/usr/bin/MegaCli -EncInfo -aALL', '/usr/bin/MegaCli -AdpAllInfo -aALL', '/usr/bin/megacli -adpgetpciinfo -aALL', '/usr/bin/megacli -LDInfo -Lall -aALL', '/usr/bin/MegaCli -AdpEventLog -GetEventLogInfo -aALL -NoLog'], 'monitorcmds' : ['/sbin/hwclock -r', '/bin/cat /etc/ssh/sshd_config', '/usr/local/zoho/bin/DCI', '/usr/bin/slabtop'], 'mi_root_cmds' : ['/usr/local/zoho/bin/getProcPidDetails', '/usr/local/zoho/bin/getLogData', '/usr/local/zoho/bin/getThreadDump', '/usr/local/zoho/bin/getFSfeatures', '/usr/local/zoho/bin/getL3stats'], 'mi_sas_cmds' : ['/usr/local/zoho/bin/getGtype', '/usr/local/zoho/bin/getAppStatus', '/usr/local/zoho/bin/getKafkaConsumerLagStats', '/usr/local/zoho/bin/getCassandraStats', '/usr/local/zoho/bin/getHbaseReplication'], 'puppet_cmds' : ['/usr/bin/puppet agent *', '/etc/init.d/puppet', '/usr/sbin/rmpupssl', '/bin/systemctl status puppet', '/bin/systemctl stop puppet', '/bin/systemctl start puppet', '/bin/systemctl restart puppet', '/bin/systemctl enable puppet', '/bin/systemctl disable puppet', '/sbin/service puppet stop', '/sbin/service puppet start', '/sbin/service puppet restart', '/opt/puppetlabs/bin/puppet agent *'], 'sed_utils' : ['/usr/bin/sedutil-cli --get-discovery0 *', '/usr/bin/sedutil-opal --query *', '/sbin/hdparm -I *'], 'virtwhat_cmds' : ['/usr/sbin/virt-what'],'get_hw_cmds' : ['/usr/bin/isdct', '/usr/sbin/smartctl -a /dev/sd?', '/usr/sbin/nvme list', '/sbin/blkid -t TYPE\=crypto_LUKS -o device'], 'lldp_cmds' : ['/etc/init.d/lldpd', '/usr/sbin/lldpctl'], 'dmi_decode' : ['/usr/sbin/dmidecode -t system', '/usr/sbin/dmidecode -t chassis', '/usr/sbin/dmidecode -t memory'], 'get_vm_mac' : ['/bin/sh /root/scripts/get-mac-address.sh'], 'iptables_cmds' : ['/sbin/iptables -L*']}

PATCHER_KVM_VIRSHCMD_SUDO = ['/usr/bin/virsh list --all', '/usr/bin/virsh dominfo *', '/usr/bin/virsh domblkerror *', '/usr/bin/virsh domblkinfo *', '/usr/bin/virsh domblklist *', '/usr/bin/virsh domblkstat *', '/usr/bin/virsh domcontrol *', '/usr/bin/virsh domif-getlink *', '/usr/bin/virsh domifaddr *', '/usr/bin/virsh domiflist *', '/usr/bin/virsh domifstat *', '/usr/bin/virsh dommemstat *', '/usr/bin/virsh domstate *', '/usr/bin/virsh domstats *', '/usr/bin/virsh domtime *', '/usr/bin/virsh domblkerror *', '/usr/bin/virsh domblkinfo *', '/usr/bin/virsh domblklist *', '/usr/bin/virsh domblkstat *', '/usr/bin/virsh domcontrol *', '/usr/bin/virsh domif-getlink *', '/usr/bin/virsh domifaddr *' , '/usr/bin/virsh domiflist *', '/usr/bin/virsh domifstat *', '/usr/bin/virsh dommemstat *', '/usr/bin/virsh domstate *', '/usr/bin/virsh domstats *', '/usr/bin/virsh domtime *', '/usr/bin/virt-top', '/usr/bin/virsh vcpupin vm[0-9]', '/usr/bin/virsh vcpupin vm[0-9][0-9]', '/usr/bin/virsh vcpupin vm[0-9][0-9][0-9]']

#VM ARP Update Script
vm_arp_script={'System Startup Script':'/root/scripts/vm_arpupdate'}

#VM Disk
vm_disk="vda"

#REPORT.TXT FILE VARIABLES
partition_type_kvm="kvm"
partition_type_cont="Container_Host"
os_c7_default_version="7.9"
os_version_for_macvtab_config ="7.9"

#NTP VARIABLE
NTP_TIME_LAG_THRESHOLD=5

#Time Zone
time_zone = {'US':'PST','IN':'IST','AU':'AEDT','EU':'CET','CT':'IST'}

#Network Configuration Files
bond_config = "/etc/sysconfig/network-scripts/ifcfg-bond0"
macvtap_config = "/etc/sysconfig/network-scripts/ifcfg-macvtap0"
bridge_config = "/etc/sysconfig/network-scripts/ifcfg-br0"

#OS Distro Check Variable
os_distro = platform.linux_distribution()[1][:3]
kernel_version={'7.9':'3.10.0-1160.36.2.el7.x86_64'}

#JSON FORMAT
json_format=OrderedDict({"Access": [],"Asset Tag": [],"DNS Config": [],"HW Config": [],"Hypervisor Packages": [],"Kernel Config": [],"NetworkConfig": [],"OS Config": [],"OS Properties": [],"OS Packages": [],"SecurityConfig": [],"Services": [],"Sudoers": [],"System Config": []})
json_detailed_failure=OrderedDict({"Access": [],"Asset Tag": [],"DNS Config": [],"HW Config": [],"Hypervisor Packages": [],"Kernel Config": [],"NetworkConfig": [],"OS Config": [],"OS Properties": [],"OS Packages": [],"SecurityConfig": [],"Services": [],"Sudoers": [],"System Config": []})

json_format_ver={"version":"1.0"}
json_format_brief={}
json_format_brief_sw={}
json_format_brief_hw={}
########################################################################################################################################################################################

# pwd - It has access to the linux user account and password database
# grp - It has access to the linux group database

def isdisabled(default_disable_list,listallenabledservice):
    service_disabled = []
    flag = 0
    for service in default_disable_list:
        if service in listallenabledservice:
            service_disabled.append(OrderedDict([('name','{}'.format(service)),('expected','disabled'),('actual','enabled'),('state','False')]))
            flag +=1
        else:
            service_disabled.append(OrderedDict([('name','{}'.format(service)),('expected','disabled'),('actual','disabled'),('state','True')]))

    if flag != 0:
       json_format['Services'].append(OrderedDict([('name','Disabled services'),('desc','Expected service should be disabled'),('type','service'),('expected', service_disabled),('actual', service_disabled),('state','False')]))
    else:
       json_format['Services'].append(OrderedDict([('name','Disabled services'),('desc','Expected service should be disabled'),('type','service'),('expected', service_disabled),('actual', service_disabled),('state','True')]))

def isenabled(default_enable_service_list,listallenabledservice):
    service_enabled = []
    flag = 0
    for service in default_enable_service_list:
        if service not in listallenabledservice:
            service_enabled.append(OrderedDict([('name','{}'.format(service)),('expected','enabled'),('actual','disabled'),('state','False')]))
        else:
            service_enabled.append(OrderedDict([('name','{}'.format(service)),('expected','enabled'),('actual','enabled'),('state','True')]))
    if flag != 0:
       json_format['Services'].append(OrderedDict([('name','Enabled Services'),('desc','Expected service should be enabled'),('type','service'),('expected', service_enabled),('actual', service_enabled),('state','False')]))
    else:
       json_format['Services'].append(OrderedDict([('name','Enabled Services'),('desc','Expected service should be enabled'),('type','service'),('expected', service_enabled),('actual', service_enabled),('state','True')]))

def capture_user_and_group(user_group):
    stat_info = os.stat('{}'.format(user_group))
    uid = stat_info.st_uid
    gid = stat_info.st_gid
    user = pwd.getpwuid(uid)[0]
    group = grp.getgrgid(gid)[0]
    return user, group

def is_suid_guid(suid_and_guid):
    s_flag = {}
    for name,binary_file in suid_and_guid.items():
        try:
            stat = os.stat("{}".format(binary_file))
            suid_guid = oct(stat.st_mode)
            s_flag_value = suid_guid[3]
            s_flag[binary_file] = s_flag_value
        except:
            json_format['System Config'].append(OrderedDict([('name','{}'.format(name)),('desc','{} binary should be exists'.format(binary_file)),('type','binary'),('expected','exists'),('actual','not exists'),('state','False')]))
    return s_flag

def capture_permission(file_or_dir):
    stat = os.stat("{}".format(file_or_dir))
    perm_of_file = oct(stat.st_mode)
    mode = perm_of_file[-4:]
    return mode

def suid_guid_check(s_flag_dict, suid_and_guid_bin, name):
    if s_flag_dict[suid_and_guid_bin] is not '6':
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','setuid and setgid flags to be enabled for {}'.format(suid_and_guid_bin)),('type','flags'),('expected','enabled'),('actual','disabled'),('state','False')]))
    else:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','setuid and setgid flags to be enabled for {}'.format(suid_and_guid_bin)),('type','flags'),('expected','enabled'),('actual','enabled'),('state','True')]))

def ownership_check(user, group, file_dir, checker, name):
    if "{}:{}".format(user, group) != checker:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','ownership should be {} for {}'.format(checker,file_dir)),('type','ownership'),('expected','{}'.format(checker)),('actual','{}:{}'.format(user, group)),('state','False')]))
    else:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','ownership should be {} for {}'.format(checker,file_dir)),('type','ownership'),('expected','{}'.format(checker)),('actual','{}:{}'.format(user, group)),('state','True')]))

def permission_check(mode, perm, file_or_dir, name):
    if mode != perm:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','permission should be {} for {}'.format(perm,file_or_dir)),('type','permission'),('expected','{}'.format(perm)),('actual','{}'.format(mode)),('state','False')]))
    else:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','permission should be {} for {}'.format(perm,file_or_dir)),('type','permission'),('expected','{}'.format(perm)),('actual','{}'.format(mode)),('state','True')]))

def is_service_masked(service_mask):
    if not os.path.islink("/usr/lib/systemd/system/{}".format(service_mask)):
        json_format['Services'].append(OrderedDict([('name','{}'.format(service_mask)),('desc','Service {} should be masked'.format(service_mask)),('type','service'),('expected','masked'),('actual','unmasked'),('state','False')]))
    else:
        json_format['Services'].append(OrderedDict([('name','{}'.format(service_mask)),('desc','Service {} should be masked'.format(service_mask)),('type','service'),('expected','masked'),('actual','masked'),('state','True')]))

def is_file_symlink(symlink_file, name):
    if not os.path.islink(symlink_file):
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','Binary {} should be a symbolic link'.format(symlink_file)),('type','symlink'),('expected','link'),('actual','no link'),('state','False')]))
    else:
        json_format['Access'].append(OrderedDict([('name','{}'.format(name)),('desc','Binary {} should be a symbolic link'.format(symlink_file)),('type','symlink'),('expected','link'),('actual','link'),('state','True')]))

def is_config_exist(config, config_file, name):
    try:
        with open(config_file, 'r') as conf:
            content = conf.read()
            if not re.search(config, content):
                json_format['OS Config'].append(OrderedDict([('name','{}'.format(name)),('desc','Configuration {} should be exists in {} configuration file'.format(config,config_file)),('type','config'),('expected','{}'.format(config)),('actual','None'),('state','False')]))
            else:
                json_format['OS Config'].append(OrderedDict([('name','{}'.format(name)),('desc','Configuration {} should be exists in {} configuration file'.format(config,config_file)),('type','config'),('expected','{}'.format(config)),('actual','{}'.format(config)),('state','True')]))
    except IOError:
        json_format['OS Config'].append(OrderedDict([('name','{}'.format(name)),('desc','configuration file {} should be exists'.format(config_file)),('type','config file'),('expected','exists'),('actual','not exists'),('state','False')]))

def check_perm_opt_zoho(directory,name):
    if os.path.isdir(directory):
        opt_zoho_dir = "/opt/zoho"
        perm = "0755"
        checker = "root:root"
        mode = capture_permission(opt_zoho_dir)
        permission_check(mode, perm, opt_zoho_dir,name)
        user, group = capture_user_and_group(opt_zoho_dir)
        ownership_check(user, group, opt_zoho_dir, checker,name)

    else:
        json_format['Access'].append(OrderedDict([('name','OptCustomDirectoryForZoho'),('desc','/opt/zoho/bin directory should be exists'),('type','path'),('expected','exists'),('actual','not exists'),('state','False')]))

def gather_client_variable():
    try:
        with open("/root/report.txt", "r") as variables:
            content = variables.read()
        rep = content.strip().replace("\n", ', ')
        rep = rep.replace("=", ":")
        res = dict(map(str.strip, sub.split(':', 1)) for sub in rep.split(', ') if ':' in sub)
        return res
    except IOError:
        json_format['OS Properties'].append(OrderedDict([('name','OS Properties File'),('desc','/root/report.txt should be exists'),('type','file'),('expected','exists'),('actual','not exists'),('state','False')]))

def is_asset_tag_set():
    status=call("timeout 10s sudo ifru",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        tag = check_output("sudo ifru | grep 'Asset Tag' | cut -d ':' -f2",shell=True).strip()
        if tag == "":
            json_format['Asset Tag'].append(OrderedDict([('name','Machine Label'),('desc','Asset tag should be set'),('type','label'),('expected','exists'),('actual','not exists'),('state','False')]))
        else:
            json_format['Asset Tag'].append(OrderedDict([('name','Machine Label'),('desc','Asset tag should be set'),('type','label'),('expected','exists'),('actual','exists'),('state','True')]))
    else:
       json_format['Asset Tag'].append(OrderedDict([('name','ifru reading'),('desc','Unable to get ifru readings or Slowness in getting ifru readings'),('type','ifru'),('expected','ifru readings'),('actual','no ifru readings'),('state','False')]))

def is_kvm_package_exits(kvm_packages,installed_rpm_list):
    count = 0
    actual_pkg=[]
    for kvm_pkg in kvm_packages:
        if kvm_pkg in installed_rpm_list:
            actual_pkg.append(kvm_pkg)
        else:
            count=+1    
    if count == 0: 
        json_format['Hypervisor Packages'].append(OrderedDict([('name','kvm'),('desc','Hypervisor packages should be installed'),('type','package'),('expected',kvm_packages),('actual',actual_pkg),('state','True')]))
    else:
        json_format['Hypervisor Packages'].append(OrderedDict([('name','kvm'),('desc','Hypervisor packages should be installed'),('type','package'),('expected',kvm_packages),('actual',actual_pkg),('state','False')]))

def eth_interface_file_count(eth,eth_interface_count):
    if os.path.isfile("/etc/sysconfig/network-scripts/ifcfg-{}".format(eth)):
        eth_interface_count.append(eth)

def is_eth_file_exist(eth):
    if not os.path.isfile("/etc/sysconfig/network-scripts/ifcfg-{}".format(eth)):
        json_format['NetworkConfig'].append(OrderedDict([('name','Ethernet Configuration'),('desc','Ethernet configuration {} file should be exists'.format(eth)),('type','file'),('expected','exists'),('actual','not exists'),('state','False')]))
    else:
        json_format['NetworkConfig'].append(OrderedDict([('name','Ethernet Configuration'),('desc','Ethernet configuration {} file should be exists'.format(eth)),('type','file'),('expected','exists'),('actual','exists'),('state','True')]))

def number_of_slaves(client_vars):
    slave_interfaces=check_output("cat /sys/class/net/bond0/bonding/slaves",shell=True).strip().split()
    if client_vars['dcspecific_DCName'] != "CT1" and client_vars['dcspecific_DCName'] != "CT2":
       if (len(slave_interfaces) != 2):
          json_format['NetworkConfig'].append(OrderedDict([('name','Slave Configuration'),('desc','number of slaves should be two'),('type','slave count'),('expected','2'),('actual','{}'.format(len(slave_interfaces))),('state','False')]))
       else:
          json_format['NetworkConfig'].append(OrderedDict([('name','Slave Configuration'),('desc','number of slaves should be two'),('type','slave count'),('expected','2'),('actual','{}'.format(len(slave_interfaces))),('state','True')]))
    else:    
       if len(slave_interfaces) == 1 or len(slave_interfaces) == 2:
          json_format['NetworkConfig'].append(OrderedDict([('name','Slave Configuration'),('desc','number of slaves atleast one or two for localzoho'),('type','slave count'),('expected','1 or 2'),('actual','{}'.format(len(slave_interfaces))),('state','True')]))
       else:
          json_format['NetworkConfig'].append(OrderedDict([('name','Slave Configuration'),('desc','number of slaves atleast one or two for localzoho'),('type','slave count'),('expected','1 or 2'),('actual','{}'.format(len(slave_interfaces))),('state','False')])) 

def bonding_check(client_vars, bond_config):
    module_interfaceconf= 'NetworkConfig'
    try:
        if client_vars['dcspecific_DCName'] == "EU1" or client_vars['dcspecific_DCName'] == "EU2" or client_vars['dcspecific_DCName'] == "US4pilot1" or client_vars['dcspecific_DCName'] == "US4pilot2" or client_vars['dcspecific_DCName'] == "US4" and client_vars['CAGE'] != "QB" or client_vars['dcspecific_DCName'] == "US3" and client_vars['CAGE'] != "TA" and client_vars['ROW'] != "3" or client_vars['dcspecific_DCName'] == "CT1" or client_vars['dcspecific_DCName'] == "CT2":
            is_config_exist("mode=1", bond_config, "BOND Active Backup")
            openafile("/sys/class/net/bond0/bonding/mode", "(.*)active-backup(.*)","BOND Active Backup", module_interfaceconf)
        else:
            is_config_exist("mode=4", bond_config, "BOND Active Active")
            openafile("/sys/class/net/bond0/bonding/mode", "(.*)802.3ad(.*)","BOND Active Active", module_interfaceconf)
    except KeyError:
        json_format['OS Properties'].append(OrderedDict([('name','Bond config'),('desc','Variables dcspecific_DCName,Cage and ROW should be exists in /root/report.txt'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

def is_bond_file_exist(bond_config, client_vars, bridge_config, macvtap_config):
    if os.path.isfile(bond_config):
        json_format['NetworkConfig'].append(OrderedDict([('name','Bonding Configuration'),('desc','bond config {} file should be exists'.format(bond_config)),('type','file'),('expected','exists'),('actual','exists'),('state','True')]))
        bonding_check(client_vars, bond_config)        
        #Check for number of slave in bonding. Number of slave should be 2 for IDC and For localzoho slave atleast one or two
        number_of_slaves(client_vars)
        # Checks if partition is kvm and centos if true check for macvtap interface
        if client_vars['partition_type'] == partition_type_kvm and os_distro == os_version_for_macvtab_config:
            is_macvtap_file_exist(macvtap_config)
        elif client_vars['partition_type'] == partition_type_kvm:
            is_bridge_file_exist(bridge_config)
    else:
        json_format['NetworkConfig'].append(OrderedDict([('name','Bonding Configuration'),('desc','bond config {} file should be exists'.format(bond_config)),('type','file'),('expected','exists'),('actual','exists'),('state','False')]))

def vm_bond_config_exist(bond_config):
    if os.path.isfile(bond_config):
        json_format['NetworkConfig'].append(OrderedDict([('name','VM Bonding Configuration'),('desc','VM bond config {} file should be exists'.format(bond_config)),('type','file'),('expected','exists'),('actual','exists'),('state','True')]))
    else:
        json_format['NetworkConfig'].append(OrderedDict([('name','VM Bonding Configuration'),('desc','VM bond config {} file should be exists'.format(bond_config)),('type','file'),('expected','exists'),('actual','exists'),('state','False')]))

def is_macvtap_file_exist(macvtap_config):
    if not os.path.isfile(macvtap_config):
        json_format['NetworkConfig'].append(OrderedDict([('name','MacVTap Configuration'),('desc','Macvtab config {} file should be exists'.format(macvtap_config)),('type','file'),('expected','exists'),('actual','not exists'),('state','False')]))
    else:
        json_format['NetworkConfig'].append(OrderedDict([('name','MacVTap Configuration'),('desc','Macvtab config {} file should be exists'.format(macvtap_config)),('type','file'),('expected','exists'),('actual','exists'),('state','True')]))

def is_bridge_file_exist(bridge_config):
    if not os.path.isfile(bridge_config):
        json_format['NetworkConfig'].append(OrderedDict([('name','Bridge Configuration'),('desc','Bridge config {} file should be exists'.format(bridge_config)),('type','file'),('expected','exists'),('actual','not exists'),('state','False')]))
    else:
        json_format['NetworkConfig'].append(OrderedDict([('name','Bridge Configuration'),('desc','Bridge config {} file should be exists'.format(bridge_config)),('type','file'),('expected','exists'),('actual','exists'),('state','True')]))

def lldpd_start(active_interface_count,active_interface):
    #LLDPD SERVICE START
    status=call("sudo /etc/init.d/lldpd start",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status != 0:
        json_format['Services'].append(OrderedDict([('name','lldpd'),('desc','Service lldpd should be started'),('type','service'),('expected','started'),('actual','not started'),('state','False')]))

    #Timeout 65 seconds for lldpctl discovery
    count = 0
    while True:
        lldp_interface=[]
        status=call("sudo lldpctl | grep Interface",shell=True,stdout=DEVNULL,stderr=DEVNULL)
        if status == 0:
            lldp_out=check_output("sudo lldpctl | grep Interface",shell=True,stderr=DEVNULL).strip().split()
            for i in lldp_out:
                if i.startswith('eth'):
                    eth_name=i[:-1]
                    lldp_interface.append(eth_name)
            #WAITING ANOTHER 30 sec FOR LLDPD TO DISCOVER DEVICE INFORMATION
            if len(lldp_interface) == active_interface_count:
                json_format['Services'].append(OrderedDict([('name','Discovery'),('desc','LLDPCTL information should be discovered for interfaces {}'.format(active_interface)),('type','service'),('expected','discovered'),('actual','discovered'),('state','True')]))
                break
        sleep(1)
        count +=1
        if count == 65:
            json_format['Services'].append(OrderedDict([('name','Discovery'),('desc','LLDPCTL information should be discovered for interfaces {}'.format(active_interface)),('type','service'),('expected','discovered'),('actual','not discovered'),('state','False')]))
            lldpd_stop()
            break

def lldpd_stop():
    status=call("sudo /etc/init.d/lldpd stop",shell=True,stdout=DEVNULL)
    if status != 0:
        json_format['Services'].append(OrderedDict([('name','lldpd'),('desc','Service lldpd should be stopped'),('type','service'),('expected','stopped'),('actual','not stopped'),('state','False')]))

def management_interface_check(manage_int):
    if os.path.isfile("/etc/sysconfig/network-scripts/ifcfg-{}".format(manage_int)):
        with open("/etc/sysconfig/network-scripts/ifcfg-{}".format(manage_int),"r") as con:
            content = con.read()
            if re.search(content,"SLAVE=yes"):
                json_format['NetworkConfig'].append(OrderedDict([('name','ManagementInterface'),('desc','management interface should not be configured with SLAVE=yes in ifcfg-{} configuration'.format(manage_int)),('type','config'),('expected','not exists'),('actual','exists'),('state','False')]))
            else:
                json_format['NetworkConfig'].append(OrderedDict([('name','ManagementInterface'),('desc','management interface should not be configured with SLAVE=yes in ifcfg-{} configuration'.format(manage_int)),('type','config'),('expected','not exists'),('actual','not exists'),('state','True')]))

def hdd_error_check():
    status=call("dmesg | egrep -wi 'I/O.*error|EXT2-fs.*error|EXT3-fs.*error|EXT4-fs.*error|UncorrectableError|DriveReady SeekComplete Error|I/O Error Detected|Unrecovered read error|mysqld Tainted|EXT.*fs.*error'",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        json_format['HW Config'].append(OrderedDict([('name','Disk'),('desc','Machine should not have any HDD errors I/O.*error, EXT2-fs.*error, EXT3-fs.*error, EXT4-fs.*error, UncorrectableError, DriveReady SeekComplete Error, I/O Error Detected, Unrecovered read error, mysqld Tainted and EXT.*fs.*error'),('type','disk'),('expected','no error'),('actual','error'),('state','False')]))
    else:
        json_format['HW Config'].append(OrderedDict([('name','Disk'),('desc','Machine should not have any HDD errors I/O.*error, EXT2-fs.*error, EXT3-fs.*error, EXT4-fs.*error, UncorrectableError, DriveReady SeekComplete Error, I/O Error Detected, Unrecovered read error, mysqld Tainted and EXT.*fs.*error'),('type','disk'),('expected','no error'),('actual','no error'),('state','True')]))

def raid_status_check(cmd,com):
    LSI_COUNT=check_output("/usr/sbin/lspci |grep -i LSI |wc -l",shell=True).strip()
    if int(LSI_COUNT) > 0:
        status=call("{}".format(cmd),shell=True,stdout=DEVNULL,stderr=DEVNULL)
        if status == 0:
            RAID_STATUS=check_output("{}".format(cmd),shell=True).strip().split('\n')
            if com == "RAID STATE":
                if "State               : Optimal" not in RAID_STATUS:
                    json_format['HW Config'].append(OrderedDict([('name','Raid'),('desc','Machine should not have any RAID DEGRADE issue'),('type','raid status'),('expected','optimal'),('actual','not optimal'),('state','False')]))
                else:
                    json_format['HW Config'].append(OrderedDict([('name','Raid'),('desc','Machine should not have any RAID DEGRADE issue'),('type','raid status'),('expected','optimal'),('actual','optimal'),('state','True')]))

            if com == "RAID BATTERY STATE":
                if "Battery State: Optimal" not in RAID_STATUS:
                    json_format['HW Config'].append(OrderedDict([('name','Raid Battery'),('desc','Machine should not have any RAID BATTERY issue'),('type','raid battery status'),('expected','optimal'),('actual','not optimal'),('state','False')]))
                else:
                    json_format['HW Config'].append(OrderedDict([('name','Raid Battery'),('desc','Machine should not have any RAID BATTERY issue'),('type','raid battery status'),('expected','optimal'),('actual','optimal'),('state','True')]))

def nic_degrade_check(client_vars):
    slave_interfaces=check_output("cat /proc/net/bonding/bond0 | grep 'Interface' | awk -F ':' '{print $2}' | cut -d ' ' -f 2",shell=True).strip().split('\n')
    slave_interfaces_speed=check_output("cat /proc/net/bonding/bond0 | grep Speed | cut -d ':' -f 2 | awk '{print $1}'",shell=True).strip().split('\n')
    slave=dict(zip(slave_interfaces,slave_interfaces_speed))

    if client_vars['dcspecific_DCName'] == "CT1" or client_vars['dcspecific_DCName'] == "CT2":
        if int(slave_interfaces_speed[0]) >= 1000:
            json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[0])),('type','interface speed'),('expected','1000 or 10000'),('actual','{}'.format(slave[slave_interfaces[0]])),('state','True')]))
        else:
            json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[0])),('type','interface speed'),('expected','1000 or 10000'),('actual','{}'.format(slave[slave_interfaces[0]])),('state','False')])
)
    else:
       if len(slave_interfaces_speed) == 2:
          try:
             if int(slave_interfaces_speed[0]) == int(slave_interfaces_speed[1]):
                json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[0])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[0]])),('state','True')]))
                json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[1])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[1]])),('state','True')]))
             elif int(slave[slave_interfaces[0]]) < int(slave[slave_interfaces[1]]):
               json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[0])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[0]])),('state','False')]))
             else:
               json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[1])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[1]])),('state','False')]))
          except ValueError:
             if slave_interfaces_speed[0] == "Unknown":
                json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[0])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[0]])),('state','False')])
)
       else:
            json_format['HW Config'].append(OrderedDict([('name','NIC Degrade'),('desc','Machine should not have any NIC SPEED DEGRADE issue for {} interface'.format(slave_interfaces[1])),('type','interface speed'),('expected','10000 or more'),('actual','{}'.format(slave[slave_interfaces[1]])),('state','False')]))

def check_nic_flap():
    slave_interfaces=check_output("cat /proc/net/bonding/bond0 | grep 'Interface' | awk -F ':' '{print $2}' | cut -d ' ' -f 2",shell=True).strip().split('\n')
    flap_count=check_output("cat /proc/net/bonding/bond0  | grep 'Link Failure Count' | awk -F ':' '{print $2}'",shell=True).strip().split('\n')
    nic_flap=dict(zip(slave_interfaces,flap_count))
    if len(flap_count) == 2:
        if int(flap_count[0]) > 0:
            json_format['HW Config'].append(OrderedDict([('name','NIC Flap'),('desc','Machine should not have any NIC FLAP for {} interface'.format(slave_interfaces[0])),('type','nic flap count'),('expected','0'),('actual','{}'.format(int(nic_flap[slave_interfaces[0]]))),('state','False')]))
        if int(flap_count[1]) > 0:
            json_format['HW Config'].append(OrderedDict([('name','NIC Flap'),('desc','Machine should not have any NIC FLAP for {} interface'.format(slave_interfaces[1])),('type','nic flap count'),('expected','0'),('actual','{}'.format(int(nic_flap[slave_interfaces[1]]))),('state','False')]))
        if int(flap_count[0]) == 0 and int(flap_count[1]) == 0:
            json_format['HW Config'].append(OrderedDict([('name','NIC Flap'),('desc','Machine should not have any NIC FLAP for {} and {} interfaces'.format(slave_interfaces[0],slave_interfaces[1])),('type','nic flap count'),('expected','0'),('actual','0'),('state','True')]))

def check_diff_vlan(interface):
    VLAN_ID=[]
    for eth in interface:
        try:
            LLDP_VLAN=check_output("sudo lldpctl {} | grep VLAN".format(eth),shell=True,stderr=DEVNULL).strip().split()[1].replace(',','')
            VLAN_ID.append(LLDP_VLAN)
        except CalledProcessError:
            #0 will be appended if interface is down and lldpd info not captured
            VLAN_ID.append('None')

    if 'None' not in VLAN_ID and len(VLAN_ID) == 2:
        if int(VLAN_ID[0]) != int(VLAN_ID[1]):
            json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','Both interfaces {} should be in same vlan {}'.format(interface, VLAN_ID)),('type','vlan diff'),('expected','no diff'),('actual','diff'),('state','False')]))
        else:
            json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','Both interfaces {} should be in same vlan {}'.format(interface, VLAN_ID)),('type','vlan diff'),('expected','no diff'),('actual','no diff'),('state','True')]))
    else:
        json_format['Services'].append(OrderedDict([('name','Discovery'),('desc','LLDPCTL information should be discovered for interfaces {}'.format(interface)),('type','service'),('expected','discovered'),('actual','not discovered'),('state','False')]))

def memory_error_check():
    status=call("timeout 10s sudo /usr/sbin/isel | egrep 'Uncorrectable ECC|CPLD CATERR Asserted|Correctable ECC'",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        json_format['HW Config'].append(OrderedDict([('name','Memory'),('desc','Machine should not have any Memory Errors Uncorrectable ECC, CPLD CATERR Asserted and Correctable ECC'),('type','memory'),('expected','no error'),('actual','error'),('state','False')]))
    elif status == 137:
        json_format['HW Config'].append(OrderedDict([('name','ISEL Reading'),('desc','Unable to get ISEL readings'),('type','isel'),('expected','isel readings'),('actual','no isel readings'),('state','False')]))
    else:
        json_format['HW Config'].append(OrderedDict([('name','Memory'),('desc','Machine should not have any Memory Errors Uncorrectable ECC, CPLD CATERR Asserted and Correctable ECC'),('type','memory'),('expected','no error'),('actual','no error'),('state','True')]))

def check_psu_status():
    PS_STATUS={}
    count=0
    status=call("timeout 10s sudo /usr/sbin/isensor -c",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        line=check_output("sudo /usr/sbin/isensor -c | grep 'Power Supply'| grep -i 'Status' | grep -v 'NotAvailable'",shell=True,stderr=DEVNULL).strip()
        for ps in line.split('\n'):
            PS_STATUS['PSU_{}'.format(count)]=ps.split('|')[5].strip()
            count+=1
        for it in PS_STATUS.keys():
            if len(PS_STATUS[it].split()) == 2:
                PS_STATUS[it]=PS_STATUS[it].split()[1]

        for key,value in PS_STATUS.items():

            if PS_STATUS[key] != "Present":
                json_format['HW Config'].append(OrderedDict([('name','{}'.format(key)),('desc','Machine should not have any psu failure'),('type','psu status'),('expected','Present'),('actual','{}'.format(PS_STATUS[key])),('state','False')]))
            else:
                json_format['HW Config'].append(OrderedDict([('name','{}'.format(key)),('desc','Machine should not have any psu failure'),('type','psu status'),('expected','Present'),('actual','{}'.format(PS_STATUS[key])),('state','True')]))

        if count < 2:
            json_format['HW Config'].append(OrderedDict([('name','PSU Count'),('desc','Machine should have atleast two psu'),('type','psu count'),('expected','2'),('actual','{}'.format(count)),('state','False')]))
        else:
            json_format['HW Config'].append(OrderedDict([('name','PSU Count'),('desc','Machine should have atleast two psu'),('type','psu count'),('expected','2'),('actual','{}'.format(count)),('state','True')]))

    else:
        json_format['HW Config'].append(OrderedDict([('name','isensor reading'),('desc','Unable to get isensor readings or Slowness in getting isensor reading'),('type','isensor'),('expected','isensor readings'),('actual','no isensor readings'),('state','False')]))

def funcforpkg(first,second,third,fourth):
    third=[]
    for i in first:
        if i not in second:
            third.append(i)
    pkgcount=len(third)
    if pkgcount != 0:
        if fourth == "Required PACKAGES INSTALLED":
            json_format['OS Packages'].append(OrderedDict([('name','Required Packages'),('desc','Required packages {} should be installed'.format(third)),('type','packages'),('expected',first),('actual',second),('state','False')]))
        else:
            json_format['OS Packages'].append(OrderedDict([('name','Unwanted Packages'),('desc','Unwanted packages {} should not be installed'.format(third)),('type','packages'),('expected','absent'),('actual','present'),('state','False')]))
    else:
        if fourth == "Required PACKAGES INSTALLED":
            json_format['OS Packages'].append(OrderedDict([('name','Required Packages'),('desc','All packages are installed properly'),('type','packages'),('expected',first),('actual',second),('state','True')]))

def ipvalidation(ip):
    host_bytes = ip.split('.')
    p=len(host_bytes)
    if p != 4:
        json_format['System Config'].append(OrderedDict([('name','HOSTNAME'),('desc','Hostname should be set'),('type','hostname'),('expected','enabled'),('actual','disabled'),('state','False')]))
    else:
        json_format['System Config'].append(OrderedDict([('name','HOSTNAME'),('desc','Hostname should be set'),('type','hostname'),('expected','enabled'),('actual','enabled'),('state','True')]))

def openafile(filename, string, filecomment, config_module):
    if filename != "/etc/ssh/sshd_config":
        if os.path.exists(filename):
            with open(filename, "r") as fi:
                content=fi.read()
            if not re.search(string, content):
                json_format[config_module].append(OrderedDict([('name','{}'.format(filecomment)),('desc','Configuration({}) should be exists in {} configuration file'.format(string,filename)),('type','config'),('expected','{}'.format(string)),('actual','None'),('state','False')]))
            else:
                json_format[config_module].append(OrderedDict([('name','{}'.format(filecomment)),('desc','Configuration({}) should be exists in {} configuration file'.format(string,filename)),('type','config'),('expected','{}'.format(string)),('actual','{}'.format(string)),('state','True')]))

    if filename == "/etc/ssh/sshd_config":
        ssh_conf = check_output("sudo cat /etc/ssh/sshd_config",shell=True).strip().split('\n')
        match_str = re.compile(string)
        match_list = list(filter(match_str.match,ssh_conf))
        if len(match_list) == 0:
            json_format[config_module].append(OrderedDict([('name','{}'.format(filecomment)),('desc','Configuration({}) should be exists in {} configuration file'.format(string,filename)),('type','config'),('expected','{}'.format(string)),('actual','None'),('state','False')]))
        else:
            json_format[config_module].append(OrderedDict([('name','{}'.format(filecomment)),('desc','Configuration({}) should be exists in {} configuration file'.format(string,filename)),('type','config'),('expected','{}'.format(string)),('actual','{}'.format(string)),('state','True')]))

def sudopermissions(user_sudo_perm,sudouser):
    cmd="sudo -l -U " + sudouser + " | grep '(.*)' | awk -F 'NOPASSWD:' '{print $2}'"
    SUDO=check_output(cmd,shell=True).strip().replace('\n',',').split(',')
    SUDOOUTPUT=[]
    orig_sudo_list=[]
    actual_sudo = []
    flag = 0
    #Removing Spaces in SUDO binary list
    for i in SUDO:
        SUDOOUTPUT.append(i.strip())
    for val in user_sudo_perm.keys():
        for bin_key in user_sudo_perm[val]:
            orig_sudo_list.append(bin_key)
            if bin_key not in SUDOOUTPUT:
                actual_sudo.append(OrderedDict([('name','{}'.format(val)),('expected','{}'.format(bin_key)),('actual','None'),('state','False')]))
                flag+=1
            else:
                actual_sudo.append(OrderedDict([('name','{}'.format(val)),('expected','{}'.format(bin_key)),('actual','{}'.format(bin_key)),('state','True')]))

    if flag != 0:
       json_format['Sudoers'].append(OrderedDict([('name','Sudoer access for patcher'),('desc','Machine should have expected sudoer access for patcher user'),('type','sudoer'),('expected', actual_sudo),('actual', actual_sudo),('state','False')]))
    else:
       json_format['Sudoers'].append(OrderedDict([('name','Sudoer access for patcher'),('desc','Machine should have expected sudoer access for patcher user'),('type','sudoer'),('expected', actual_sudo),('actual', actual_sudo),('state','True')]))

    ADDITIONAL_ACCESS=[]
    REQUIRED_ACCESS=[]
    if len(orig_sudo_list) == len(SUDOOUTPUT):
       pass
    if len(orig_sudo_list) > len(SUDOOUTPUT) and flag == 0:
        for i in orig_sudo_list:
            if i not in SUDOOUTPUT:
                REQUIRED_ACCESS.append(i)
        if len(REQUIRED_ACCESS) != 0:
            json_format['Sudoers'].append(OrderedDict([('name','Missing access'),('desc','Machine should have this {} missing sudoer access for patcher user'.format(REQUIRED_ACCESS)),('type','sudoer'),('expected','absent'),('actual','present'),('state','False')]))

    if len(orig_sudo_list) < len(SUDOOUTPUT):
        for i in SUDOOUTPUT:
            if i not in orig_sudo_list:
                ADDITIONAL_ACCESS.append(i)
        if len(ADDITIONAL_ACCESS) != 0:
            json_format['Sudoers'].append(OrderedDict([('name','Unwanted access'),('desc','Machine should not have this {} unwanted sudoer access for patcher user'.format(ADDITIONAL_ACCESS)),('type','sudoer'),('expected','absent'),('actual','present'),('state','False')]))

def os_version_check(client_vars,distro):
    try:
        if distro != os_c7_default_version:
            json_format['OS Config'].append(OrderedDict([('name','{}'.format(client_vars['profileName'])),('desc','Should be installed with proper OS'),('type','os version'),('expected','{}'.format(os_c7_default_version)),('actual','{}'.format(distro)),('state','False')]))
        else:
            json_format['OS Config'].append(OrderedDict([('name','{}'.format(client_vars['profileName'])),('desc','Should be installed with proper OS'),('type','os version'),('expected','{}'.format(os_c7_default_version)),('actual','{}'.format(distro)),('state','True')]))
    except (TypeError,KeyError):
        json_format['OS Properties'].append(OrderedDict([('name','OS Version'),('desc','Variable profileName should be exists in /root/report.txt'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))


def kernel_version_check(os_distro,kernel_version,default_os_ver):
    os_kernel=platform.uname()[2]
    try:
        if os_kernel != kernel_version[os_distro]:
            json_format['Kernel Config'].append(OrderedDict([('name','Kernel Version'),('desc','Machine should be installed with proper kernel for {} OS'.format(os_distro)),('type','kernel version'),('expected','{}'.format(kernel_version[os_distro])),('actual','{}'.format(os_kernel)),('state','False')]))
        else:
            json_format['Kernel Config'].append(OrderedDict([('name','Kernel Version'.format(os_distro)),('desc','Machine should be installed with proper kernel for {} OS'.format(os_distro)),('type','kernel version'),('expected','{}'.format(kernel_version[os_distro])),('actual','{}'.format(os_kernel)),('state','True')])
)
    except:
        json_format['Kernel Config'].append(OrderedDict([('name','Kernel Version'),('desc','Machine should be installed with {} OS and {} kernel'.format(os_distro, kernel_version[default_os_ver])),('type','kernel version'),('expected','{}'.format(kernel_version[default_os_ver])),('actual','{}'.format(os_kernel)),('state','False')]))

def check_time_zone(time_zone,client_vars):
    TM_ZONE=tzname[0]
    try:
        DC=client_vars['dcspecific_DCName'][0:2]
        if time_zone[DC] != TM_ZONE:
            json_format['System Config'].append(OrderedDict([('name','Timezone'),('desc','Timezone should be set properly for {} DC'.format(DC)),('type','timezone'),('expected','{}'.format(time_zone[DC])),('actual','{}'.format(TM_ZONE)),('state','False')]))
        else:
            json_format['System Config'].append(OrderedDict([('name','Timezone'.format(DC)),('desc','Timezone should be set properly for {} DC'.format(DC)),('type','timezone'),('expected','{}'.format(time_zone[DC])),('actual','{}'.format(TM_ZONE)),('state','True')]))
    except (TypeError,KeyError):
        json_format['OS Properties'].append(OrderedDict([('name','Time Zone'),('desc','Variable dcspecific_DCName should be exists in /root/report.txt'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

def check_ntp_time_lag(NTP_TIME_LAG_THRESHOLD):
    status=call('which chronyc',shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        st=call('systemctl status chronyd.service',shell=True,stdout=DEVNULL,stderr=DEVNULL)
        if st == 0:
            system_time=check_output('/usr/bin/chronyc -n -p 323 tracking |grep -i "System time"',shell=True)
            diff=system_time.split(' ')[7].split('.')[0]
            if int(diff) > NTP_TIME_LAG_THRESHOLD:
                json_format['Services'].append(OrderedDict([('name','Network Time Lag'),('desc','Machine should not have any NTP lag'),('type','ntp'),('expected','{} or less'.format(NTP_TIME_LAG_THRESHOLD)),('actual','{}'.format(diff)),('state','False')]))
            else:
                json_format['Services'].append(OrderedDict([('name','Network Time Lag'),('desc','Machine should not have any NTP lag'),('type','ntp'),('expected','{} or less'.format(NTP_TIME_LAG_THRESHOLD)),('actual','{}'.format(diff)),('state','True')]))
        else:
            json_format['Services'].append(OrderedDict([('name','Chronyd'),('desc','Chronyd service should be started'),('type','service'),('expected','started'),('actual','not started'),('state','False')]))
    else:
       json_format['Services'].append(OrderedDict([('name','Chronyd'),('desc','Machine should have chronyd installed'),('type','package'),('expected','installed'),('actual','not installed'),('state','False')]))


def check_ntp_source_sync():
    chrony_format = []
    flag = 0
    status=call("which chronyc",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        st=call('systemctl status chronyd.service',shell=True,stdout=DEVNULL,stderr=DEVNULL)
        if st == 0:
            output=check_output("/usr/bin/chronyc -n -p 323 sources | sed 1,3d | awk '{print $5}'",shell=True)
            sources=check_output("/usr/bin/chronyc -n -p 323 sources | sed 1,3d | awk '{print $2}'",shell=True)
            source_list=sources.strip().split('\n')
            reach_value=output.strip().split('\n')
            chrony_source=dict(zip(source_list,reach_value))
            for src in source_list:
                if chrony_source[src] == '0':
                    chrony_format.append(OrderedDict([('name','Chrony Source {}'.format(src)),('expected','non zero'),('actual','{}'.format(chrony_source[src])),('state','False')]))
                    flag += 1
                else:
                    chrony_format.append(OrderedDict([('name','Chrony Source {}'.format(src)),('expected','non zero'),('actual','{}'.format(chrony_source[src])),('state','True')]))
        else:
            json_format['Services'].append(OrderedDict([('name','Chronyd'),('desc','Chronyd service should be started'),('type','service'),('expected','started'),('actual','not started'),('state','False')]))
    else:
        json_format['Services'].append(OrderedDict([('name','Chronyd'),('desc','Machine should have chronyd installed'),('type','package'),('expected','installed'),('actual','not installed'),('state','False')]))

    if flag != 0:
       json_format['Services'].append(OrderedDict([('name','Chrony sources'),('desc','NTP servers should be in sync'),('type','reach value'),('expected', chrony_format),('actual', chrony_format),('state','False')]))
    else:
       json_format['Services'].append(OrderedDict([('name','Chrony sources'),('desc','NTP servers should be in sync'),('type','reach value'),('expected', chrony_format),('actual', chrony_format),('state','True')]))

def check_sestatus():
    SELINUX_STATUS=check_output("/usr/sbin/getenforce",shell=True).strip()
    if SELINUX_STATUS != 'Disabled':
        json_format['SecurityConfig'].append(OrderedDict([('name','SELinux'),('desc','SELINUX should be DISABLED'),('type','sestatus'),('expected','Disabled'),('actual','{}'.format(SELINUX_STATUS)),('state','False')]))
    else:
        json_format['SecurityConfig'].append(OrderedDict([('name','SELinux'),('desc','SELINUX should be DISABLED'),('type','sestatus'),('expected','Disabled'),('actual','{}'.format(SELINUX_STATUS)),('state','True')]))

def check_resolver():
    ret=call('nslookup -timeout=2 z-image',shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if ret != 0:
        json_format['DNS Config'].append(OrderedDict([('name','z-image'),('desc','z-image should have domain resolution'),('type','return status'),('expected','0'),('actual','{}'.format(ret)),('state','False')]))
    else:
        json_format['DNS Config'].append(OrderedDict([('name','z-image'),('desc','z-image should have domain resolution'),('type','return status'),('expected','0'),('actual','{}'.format(ret)),('state','True')]))
        
def check_port_listening():
    ret=call("/usr/bin/ps -u sas | sed 1d | egrep -v 'sshd|bash'",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if ret == 0:
        json_format['System Config'].append(OrderedDict([('name','Listening Ports'),('desc','sas accounts should not have running processes'),('type','running process'),('expected','absent'),('actual','present'),('state','False')]))
    else:
        json_format['System Config'].append(OrderedDict([('name','Listening Ports'),('desc','sas accounts should not have running processes'),('type','running process'),('expected','absent'),('actual','absent'),('state','True')]))
        
def check_iptables():
    iptable_entry_count = check_output("/sbin/iptables-save | grep '^\-' | wc -l",shell=True,stderr=DEVNULL).strip()
    if int(iptable_entry_count) != 0:
       json_format['System Config'].append(OrderedDict([('name','iptable rule'),('desc','machine should not have any iptable rules'),('type','iptable'),('expected','absent'),('actual','present'),('state','False')]))
    else:
       json_format['System Config'].append(OrderedDict([('name','iptable rule'),('desc','machine should not have any iptable rules'),('type','iptable'),('expected','absent'),('actual','absent'),('state','True')]))

def check_hugepage():
    hugepage_value = check_output("cat /proc/sys/vm/nr_hugepages",shell=True,stderr=DEVNULL).strip()
    if int(hugepage_value) == 0:
       json_format['OS Config'].append(OrderedDict([('name','Hugepage'),('desc','hugepage should be enabled for KVM/Container host'),('type','hugepage'),('expected','non zero'),('actual','{}'.format(hugepage_value)),('state','False')]))
    else:
       json_format['OS Config'].append(OrderedDict([('name','Hugepage'),('desc','hugepage should be enabled for KVM/Container host'),('type','hugepage'),('expected','non zero'),('actual','{}'.format(hugepage_value)),('state','True')]))

def numa_memory_distribution():

    status=call("numactl --hardware",shell=True,stdout=DEVNULL,stderr=DEVNULL)
    if status == 0:
        numa_out=check_output("numactl --hardware",shell=True).strip()
        numa_list=[]
        for i in numa_out.split('\n'):
            if 'available' in i:
                numa_list.append(i)
            if 'size' in i:
                numa_list.append(i)

        numa_dict={}
        for i in numa_list:
            ls=i.split(':')
            numa_dict[ls[0]]=ls[1].strip().split()[0]

        total_memory_in_mb=check_output("cat /proc/meminfo | grep 'MemTotal' | awk -F ':' '{print $2/1024}'",shell=True).strip()

        each_numa_mem=int(float(total_memory_in_mb))/int(float(numa_dict['available']))

        for key,_ in numa_dict.items():
            if 'node' in key:
                if (int(numa_dict[key]) + 1024) >= each_numa_mem:
                    json_format['System Config'].append(OrderedDict([('name','NumaMemoryDistribution'),('desc','Memory should be distributed equally across numa nodes {}'.format(key)),('type','numa'),('expected','{} or more'.format(each_numa_mem)),('actual','{}'.format(numa_dict[key])),('state','True')]))
                else:
                    json_format['System Config'].append(OrderedDict([('name','NumaMemoryDistribution'),('desc','Memory should be distributed equally across numa nodes {}'.format(key)),('type','numa'),('expected','{} or more'.format(each_numa_mem)),('actual','{}'.format(numa_dict[key])),('state','False')]))

def sw_validation(client_vars):
                #############################
        #####SW Validation Part######
        #############################

        #Creating RPM packages in LIST
        ts = rpm.TransactionSet()
        rpm_match = ts.dbMatch()
        for pkg in rpm_match:
            rpm_pkg = pkg['name']
            installed_rpm_list.append(rpm_pkg)

        # Check services in default_disable_list are disabled
        isdisabled(default_disable_list,listallenabledservice)

        # Check Services in default_enable_service_list are enabled
        isenabled(default_enable_service_list,listallenabledservice)

        # Check ctrl-alt-del.target is masked
        is_service_masked(masked_service)
        
        #Listening port
        check_port_listening()
        
        #iptable rule check
        check_iptables()
        
        #hugepage check
        try: 
           if client_vars['partition_type'] == partition_type_kvm or client_vars['partition_type'] == partition_type_cont:
              check_hugepage()
        except (TypeError,KeyError):
            json_format['OS Properties'].append(OrderedDict([('name','Hugepage Configuration'),('desc','Variables PARTITION_TYPE should be exists in /root/report.txt file'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

        # Check suid and guid
        s_flag_dict = is_suid_guid(suid_and_guid)
        suid_guid_values = suid_and_guid.values()
        for name,suid_guid_bin in suid_and_guid.items():
            suid_guid_check(s_flag_dict, suid_guid_bin, name)

        # root:root sas:sas patcher:patcher
        check_user = [user_root, user_sas, user_patcher, user_root_ossec]
        count = 0
        for user_group_check in ['root:root', 'sas:sas', 'patcher:patcher', 'root:ossec']:
            if count < len(check_user):
                for name,file_dir in check_user[count].items():
                    if os.path.isfile(file_dir) or os.path.isdir(file_dir):
                        user, group = capture_user_and_group(file_dir)
                        ownership_check(user, group, file_dir, user_group_check, name)
                count += 1

        # Permission check 750, 4755,755, 640,0640,644
        count = 0
        perm_check_file = [perm_750, perm_4755, perm_755, perm_640, perm_0640, perm_644]
        for perm in ['0750', '4755', '0755', '0640', '0640', '0644']:
            if count < len(perm_check_file):
                for name,check_file in perm_check_file[count].items():
                    if os.path.isfile(check_file) or os.path.isdir(check_file):
                        mode = capture_permission(check_file)
                        permission_check(mode, perm, check_file, name)
                    else:
                        json_format['System Config'].append(OrderedDict([('name','{}'.format(name)),('desc','file {} should be exists'.format(check_file)),('type','file'),('expected','exists'),('actual','not exists'),('state','False')]))
                count += 1

        try:
           #Package Validation
            if client_vars['partition_type'] == partition_type_kvm:
              origlist.extend(origlist_kvm_pkg)
            elif client_vars['partition_type'] == partition_type_cont:
                      origlist.extend(origlist_container_pkg)
            elif client_vars['bootdrive'] == vm_disk:
                      origlist.extend(origlist_vm_pkg)
            funcforpkg(installed_rpm_list,origlist,AddPackages,"Additional PACKAGES INSTALLED")
            funcforpkg(origlist,installed_rpm_list,PackagesNotInstalled,"Required PACKAGES INSTALLED")
        except (TypeError,KeyError):
            json_format['OS Properties'].append(OrderedDict([('name','Package Validation'),('desc','Variables PARTITION_TYPE and BOOTDRIVE should be exists in /root/report.txt file'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

        #OS Version Check
        os_version_check(client_vars,os_distro)
        #Kernel Version Check
        kernel_version_check(os_distro,kernel_version,os_c7_default_version)
        #Hostname Validation
        ipvalidation(hostname)
        #NTP TIME ZONE CHECK
        check_time_zone(time_zone,client_vars)
        #NTP TIME LAG
        check_ntp_time_lag(NTP_TIME_LAG_THRESHOLD)
        #NTP Source synchronization
        check_ntp_source_sync()
        #SESTATUS
        check_sestatus()
        #Resolver Configuration
        check_resolver()
        
        #Config check
        module_kopts = "Kernel Config"
        module_osconf = "OS Config"

        for name, options in kopts.items():
            openafile("/proc/cmdline", options, name, module_kopts)
        openafile("/usr/lib/systemd/system/getty@.service","ExecStart=-/sbin/agetty --long-hostname(.*)","Long Hostname", module_osconf)
        openafile("/sys/kernel/mm/transparent_hugepage/enabled","(.*)[never]","Transparent Hugepage", module_osconf)
        openafile("/sys/kernel/mm/transparent_hugepage/defrag","(.*)[never]","Transparent Hugepage Defrag", module_osconf)
        openafile("/sys/kernel/mm/transparent_hugepage/khugepaged/defrag","0","Transparent KHugepage Defrag", module_osconf)
        #SSH Config check
        openafile("/etc/ssh/sshd_config","UseDNS no","Reverse DNS Lookup", module_osconf)
        openafile("/etc/ssh/sshd_config","(.*)REMOTE_USER(.*)","Remote User Environment", module_osconf)

        try:
            #KVMHOST and CONTAINERHOST have SSH_PERMIT_ROOT_LOGIN_YES
            if client_vars['partition_type'] != partition_type_kvm and client_vars['partition_type'] != partition_type_cont:
                openafile("/etc/ssh/sshd_config","PermitRootLogin no","Permit root login", module_osconf)
            else:
                openafile("/etc/ssh/sshd_config","PermitRootLogin yes","Permit root login", module_osconf)
        except (TypeError,KeyError):
            json_format['OS Properties'].append(OrderedDict([('name','SSH Configuration'),('desc','Variables PARTITION_TYPE should be exists in /root/report.txt file'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

        #Patcher USER
        try:
	   if client_vars['partition_type'] == partition_type_kvm:
	      PATCHER_SUDO['virsh_cmds']= PATCHER_KVM_VIRSHCMD_SUDO
           sudopermissions(PATCHER_SUDO,"patcher")
	except (TypeError,KeyError):
	        json_format['os_install_variables'].append({'name': 'KVM Partition Check','type':'variables','expected':'exists','actual':'not exists','description': 'Variables PARTITION_TYPE should be exists in /root/report.txt file','state': 'False'})

        # Check /usr/bin/puppet is symlink
        for name, puppet_bin in puppet_binary.items():
            is_file_symlink(puppet_bin, name)

        # Check /var/log/puppet-agent.log and /var/log/systemd-logind.log exists in /etc/logrotate.d/syslog
        for name,log in logs_config.items():
            is_config_exist(log, logrotate_syslog_config, name)

        # Check permission and ownership for /opt/zoho/bin and /opt/zoho
        for value,directory in zoho_custom_binary_dir.items():
            check_perm_opt_zoho(directory,name)

        try:
            # If true for phsical machine
            if client_vars['bootdrive'] != vm_disk:
                # check if machine have asset tag
                is_asset_tag_set()

                # check if rc.local has vm_arpupdate
                if client_vars['partition_type'] == partition_type_kvm:
                    for name,script in vm_arp_script.items():
                        is_config_exist(script, rc_local_config, name)

                # Check if proper packages are installed for kvmhost
                if client_vars['partition_type'] == partition_type_kvm:
                    is_kvm_package_exits(kvm_packages,installed_rpm_list)

                # Check number of interfaces connected
                count = 0
                interface = []
                while os.path.isdir("/sys/class/net/eth{}".format(count)):
                    interface.append("eth{}".format(count))
                    count += 1

                # Check network configuration exist for the interfaces
                eth_interface_count=[]
                if len(interface) >= 2:
                    json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of ethernet configuration {} file count should be at least two'.format(interface)),('type','ethernet configuration count'),('expected','2 or more'),('actual','{}'.format(len(interface))),('state','True')]))
                    #Gather Primary and Secondary Interfaces
                    for eth in interface:
                        eth_interface_file_count(eth,eth_interface_count)

                    #Active Interface Check
                    active_interface = []
                    for i in eth_interface_count:
                        status=call("/usr/sbin/ethtool {} | grep 'Link detected' | grep -i yes".format(i),shell=True,stdout=DEVNULL,stderr=DEVNULL)
                        if status == 0:
                           active_interface.append(i)
                    active_interface_count=int(len(active_interface))

                    #For Localzoho Active Interface is 1
                    if (client_vars['dcspecific_DCName'] == "CT1" and len(active_interface) == 1) or (client_vars['dcspecific_DCName'] == "CT2" and len(active_interface) == 1):
                        json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of active interface {} count should be atleast one for localzoho'.format(active_interface)),('type','active interface count'),('expected','1 or more'),('actual','{}'.format(len(active_interface))),('state','True')]))
                        for ether in active_interface:
                           is_eth_file_exist(ether)
                        is_bond_file_exist(bond_config, client_vars, bridge_config, macvtap_config)

                    #Active Interface
                    elif active_interface_count >= 2:
                        json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of active interface {} count should be more than or equal to two'.format(active_interface)),('type','active interface count'),('expected','2 or more'),('actual','{}'.format(len(active_interface))),('state','True')]))
                        production_interface=[]
                        management_interface=[]
                        lldpd_start(active_interface_count,active_interface)
                        for prod in active_interface:
                            status=call("sudo lldpctl {} | grep VLAN".format(prod),shell=True,stdout=DEVNULL,stderr=DEVNULL)
                            if status == 0:
                                VLAN=check_output("sudo lldpctl {} | grep VLAN".format(prod),shell=True).strip().split()[1].replace(',','')
                                if int(VLAN) > 1:
                                  production_interface.append(prod)
                                else:
                                  management_interface.append(prod)
                            else:
                                status=call("sudo lldpctl {} | grep Interface".format(prod),shell=True,stdout=DEVNULL,stderr=DEVNULL)
                                if status == 0:
                                    management_interface.append(prod)
                                else:
                                    json_format['Services'].append(OrderedDict([('name','Discovery'),('desc','LLDPCTL information should be discovered for interfaces {}'.format(prod)),('type','service'),('expected','discovered'),('actual','not discovered'),('state','False')]))                                    

                        #Management Interface
                        if len(management_interface) > 0:
                            for manage_int in management_interface:
                                management_interface_check(manage_int)

                        #Production Interface
                        if len(production_interface) == 2:
                            json_format['NetworkConfig'].append(OrderedDict([('name','{}'.format(production_interface)),('desc','number of production interface count should be two'),('type','production interface count'),('expected','2'),('actual','{}'.format(len(production_interface))),('state','True')]))
                            for ether in production_interface:
                                is_eth_file_exist(ether)
                            #VLAN Diff Check
                            check_diff_vlan(production_interface)
                            #lldpd service stop
                            lldpd_stop()
                            # Checks if bond configuration exists if true checks for bonding mode
                            is_bond_file_exist(bond_config, client_vars, bridge_config, macvtap_config)

                        elif len(production_interface) > 2:
                            json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of production interface {} count should be two'.format(production_interface)),('type','production interface count'),('expected','2'),('actual','{}'.format(len(production_interface))),('state','False')]))
                            lldpd_stop()
                        else:
                            json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of production interface {} count should be two'.format(production_interface)),('type','production interface count'),('expected','2'),('actual','{}'.format(len(production_interface))),('state','False')]))
                            lldpd_stop()

                    else:
                        json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of active interface {} count should be more than or equal to two'.format(active_interface)),('type','active interface count'),('expected','2 or more'),('actual','{}'.format(len(active_interface))),('state','False')]))

                else:
                    json_format['NetworkConfig'].append(OrderedDict([('name','Interface Configuration'),('desc','number of ethernet configuration {} file count'.format(interface)),('type','ethernet config count'),('expected','2 or more'),('actual','{}'.format(len(interface))),('state','False')]))

            # It runs if Virtual Machine
            else:
                # VM Network Config Check
                vm_bond_config_exist(bond_config)

        except (TypeError,KeyError):
            json_format['OS Properties'].append(OrderedDict([('name','Physical Machine'),('desc','Variables BOOTDRIVE, dcspecific_DCName, PARTITION_TYPE and ASSET_TAG should be exists in /root/report.txt file'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

def hw_validation(client_vars):
    #############################
    #####HW Validation Part######
    #############################
    try:
        #If true for phsical machine
        if client_vars['bootdrive'] != vm_disk:
            #Check if any HDD ERROR
            hdd_error_check()
            #RAID STATUS CHECK
            raid_status_check("sudo /usr/bin/megacli -LdPdInfo -aALL -NoLog | egrep '^State|Slot Number:|Firmware state:'","RAID STATE")
            #RAID BATTERY STATUS
            raid_status_check("sudo /usr/bin/megacli -AdpBbuCmd -GetBbuStatus -aALL -NoLog | grep 'Battery State'","RAID BATTERY STATE")
            #Check if any NIC Speed Degrade
            nic_degrade_check(client_vars)
            #check if any NIC Flap
            check_nic_flap()
            #MEMORY ERROR CHECK
            memory_error_check()
            #PSU STATUS
            check_psu_status()
            #Numa Node Memory Distribution
            numa_memory_distribution()

    except (TypeError,KeyError):
         json_format['OS Properties'].append(OrderedDict([('name','HW'),('desc','Variables BOOTDRIVE should be exists in /root/report.txt file'),('type','variables'),('expected','exists'),('actual','not exists'),('state','False')]))

def removing_empty_key(remove_emp_dic):
    for keys,values in remove_emp_dic.items():
        if len(values) == 0:
            remove_emp_dic.pop(keys)

def json_brief_format(json_format_in,json_result):
    flag=[]
    for keys,values in json_format_in.items():
        if len(json_format_in[keys]) > 0:
           for i in range(len(json_format_in[keys])):
               if json_format_in[keys][i]['state'] == 'False':
                  json_result[keys]="False"
                  flag.append(1)
           if len(flag) == 0:
               json_result[keys]="True"
           #To clear flag
           flag=[]

def json_exact_failure(json_format_in,json_result):
    for keys,values in json_format_in.items():
        if len(json_format_in[keys]) > 0:
            for i in range(len(json_format_in[keys])):
                if json_format_in[keys][i]['state'] == 'False':
                    json_result[keys].append(json_format_in[keys][i])

def main():

    # Gathering report.txt client variable
    client_vars = gather_client_variable()

    parser = argparse.ArgumentParser(description="os_validation script is a library to validate the server configurations and list the result in JSON format.")

    parser.add_argument("-v","--version", help="Version of osvalidation library",action="store_true")
    parser.add_argument("-a", "--all", help="Print server validation report in boolean result",action="store_true")
    parser.add_argument("-b", "--brief", help="Print server validation report in brief format",action="store_true")
    parser.add_argument("-d", "--detail", help="Print server validation report in detailed format",action="store_true")
    parser.add_argument("-hw", "--hardware", help="Print server validation report related to hardware",action="store_true")
    parser.add_argument("-sw", "--software", help="Print server validation report related to software",action="store_true")
    parser.add_argument("-e", "--exact_failure", help="Print server validation report related to detailed failure",action="store_true")

    args = parser.parse_args()
    if len(argv) == 1:
        parser.print_help()
        exit(102)

    if args.detail:
        sw_validation(client_vars)
        hw_validation(client_vars)
        removing_empty_key(json_format)
        print(json.dumps(json_format, indent = 4))

    if args.brief:
        sw_validation(client_vars)
        hw_validation(client_vars)
        removing_empty_key(json_format)
        json_brief_format(json_format,json_format_brief)
        print(json.dumps(json_format_brief, indent = 4))

    if args.exact_failure:
        sw_validation(client_vars)
        hw_validation(client_vars)
        removing_empty_key(json_format)
        json_exact_failure(json_format,json_detailed_failure)
        removing_empty_key(json_detailed_failure)
        print(json.dumps(json_detailed_failure, indent = 4))

    if args.hardware:
        hw_validation(client_vars)
        removing_empty_key(json_format)
        json_brief_format(json_format,json_format_brief_hw)
        print(json.dumps(json_format_brief_hw, indent = 4))

    if args.software:
        sw_validation(client_vars)
        removing_empty_key(json_format)
        json_brief_format(json_format,json_format_brief_sw)
        print(json.dumps(json_format_brief_sw, indent = 4))

    if args.all:
        json_format_bool={"state":""}
        flag=[]
        sw_validation(client_vars)
        hw_validation(client_vars)
        json_brief_format(json_format,json_format_brief)
        for _,values in json_format_brief.items():
            if values != "True":
                flag.append(1)

        if len(flag) == 0:
            json_format_bool['state'] = "True"
        else:
            json_format_bool['state'] = "False"
        #To clear flag
        flag=[]
        print(json.dumps(json_format_bool, indent = 4, sort_keys=True))

    if args.version:
        print(json.dumps(json_format_ver, indent = 4, sort_keys=True))

if __name__ == '__main__':
    main()
