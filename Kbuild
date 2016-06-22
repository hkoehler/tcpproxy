ccflags-y 	:= -g -Wall -Werror #-DISCSI_FAULT_INJECT
obj-m		:= tcpproxy.o
tcpproxy-y 	:= tcpproxy_main.o tcpproxy_filter.o tcpproxy_ctl.o \
		tcpproxy_default.o tcpproxy_rpc.o tcpproxy_nfs.o \
		udpproxy_main.o tcpproxy_echo.o tcpproxy_iscsi.o \
		iscsi_target.o iscsi_logger.o io_sched_ctl.o
#tcpproxy-y	+= io_dflt_sched.o
tcpproxy-y	+= io_tb_sched.o
