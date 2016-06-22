rmmod tcpproxy
modprobe tcpproxy
printf "start" > /sys/kernel/tcpproxy/ctl
printf "create 0.0.0.0 12865 192.168.60.10 12865" > /sys/kernel/tcpproxy/ctl
printf "create 0.0.0.0 7 192.168.60.10 7" > /sys/kernel/tcpproxy/ctl
printf "create 0.0.0.0 2049 192.168.60.10 2049" > /sys/kernel/tcpproxy/ctl
printf "create 0.0.0.0 1023 192.168.60.10 1023" > /sys/kernel/tcpproxy/ctl
