DEV=/dev/tcpproxy

if [ -n "`lsmod | grep tcpproxy`" ]
then
	echo "stop" > $DEV
	rmmod tcpproxy
	echo "unlaoded kernel module" 
fi
modprobe tcpproxy
chmod a+rw /dev/tcpproxy
echo 8 > /proc/sys/kernel/printk
echo "loaded kernel module"
echo "start" > $DEV
echo tcpproxy started
echo "add echo 0.0.0.0 7 0.0.0.0 0" > $DEV
echo "add iscsi 0.0.0.0 3260 192.168.56.103 3260" > $DEV
echo "flt iscsi add tgt 0.0.0.0 3260 iqn.2005.com.smapper:storage.disk1" > $DEV
echo "flt iscsi add lun 0.0.0.0 3260 iqn.2005.com.smapper:storage.disk1 0" > $DEV
echo "flt iscsi add lun 0.0.0.0 3260 iqn.2005.com.smapper:storage.disk1 1" > $DEV
echo "flt iscsi add lun 0.0.0.0 3260 iqn.2005.com.smapper:storage.disk1 2" > $DEV
