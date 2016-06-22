DEV=/dev/tcpproxy

echo "sched tb on" > $DEV
#                  rule_name    clnt_iqn                         tgt_iqn                      lun cap rate tao  on
echo "sched tb add Exchange iqn.2005-05.com.smapper:1012484  iqn.2005.com.smapper:storage.disk1 2 2282 2270 6000 1" > $DEV
echo "sched tb add Oracle iqn.2005-05.com.smapper:1716955679 iqn.2005.com.smapper:storage.disk1 2 2282 500 6000 1" > $DEV
echo "sched tb add Apache iqn.2005-05.com.smapper:1792309082 iqn.2005.com.smapper:storage.disk1 2 2282 200 6000 1" > $DEV


#echo "sched tb edit Apache 1000 6000 2 1" > $DEV

#echo "sched tb del Apache" > $DEV

#echo "sched tb off" > $DEV
