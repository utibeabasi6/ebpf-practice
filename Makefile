hello:
	@python3 hello-world/hello.py

bpf_counter:
	@python3 counter/counter.py

install:
	@sudo apt-get install python3-bpfcc