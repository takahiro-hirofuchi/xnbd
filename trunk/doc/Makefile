default: xnbd-client.1.sgml xnbd-server.8.sgml xnbd-bgctl.1.sgml xnbd-watchdog.1.sgml xnbd-wrapper-ctl.8.sgml xnbd-wrapper.8.sgml
	docbook-to-man xnbd-client.1.sgml > xnbd-client.1
	docbook-to-man xnbd-server.8.sgml > xnbd-server.8
	docbook-to-man xnbd-bgctl.1.sgml > xnbd-bgctl.1
	docbook-to-man xnbd-watchdog.1.sgml > xnbd-watchdog.1
	docbook-to-man xnbd-wrapper.8.sgml > xnbd-wrapper.8
	docbook-to-man xnbd-wrapper-ctl.8.sgml > xnbd-wrapper-ctl.8

clean:
	$(RM) -rf xnbd-client.1 xnbd-server.8 xnbd-bgctl.1 xnbd-watchdog.1 xnbd-wrapper-ctl.8 xnbd-wrapper.8
