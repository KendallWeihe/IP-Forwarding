all: ip_forward

ip_forward:
	gcc -g ip_forward.c -o ip_forward

clean:
	rm ip_forward
