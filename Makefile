DEVICE=eth0

help:
	@echo "A ICMP ping-pong response handled by eBPF"
	@echo
	@echo "Usage: make DEVICE=eth0 [command]"
	@echo
	@echo "Remember to set the correct network device to use: DEVICE=<your device>"
	@echo
	@echo "Commands:"
	@echo
	@echo "  qdisc          Create a queueing discipline."
	@echo "                 This is necessary to attach a classifier and action to"
	@echo "  run            Attach the classifier and action"
	@echo "  show           Show the installed qdisc and classifier/action"
	@echo "  exec           Output debug logging"
	@echo "  delete         Delete the attached classifier/action"
	@echo "  qdisc-delete   Delete the qdisc"

bpf.o: bpf.c
	clang -g -O2 -target bpf -I/usr/include/x86_64-linux-gnu -c $< -o $@

qdisc:
	sudo tc qdisc add dev $(DEVICE) ingress handle ffff:
qdisc-delete:
	sudo tc qdisc delete dev $(DEVICE) ingress
run: bpf.o
	sudo tc filter add dev $(DEVICE) parent ffff: bpf obj bpf.o sec classifier flowid ffff:1 \
		action bpf obj bpf.o sec action ok
delete:
	sudo tc filter delete dev $(DEVICE) parent ffff:
show:
	sudo tc filter show dev $(DEVICE) ingress

exec:
	sudo tc exec bpf dbg
