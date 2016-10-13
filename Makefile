CC = gcc
CFLAGS = -g -wall
LIBS = -lpcap

mypcap: mypcap.o tcp_packet.o udp_packet.o icmp_packet.o 
	$(CC) mypcap.o tcp_packet.o udp_packet.o icmp_packet.o -o mypcap $(LIBS) 

mypcap.o: mypcap.c
	gcc -c mypcap.c

tcp_packet.o: tcp_packet.c
	gcc -c tcp_packet.c

udp_packet.o: udp_packet.c
	gcc -c udp_packet.c

icmp_packet.o: icmp_packet.c
	gcc -c icmp_packet.c

all: mypcap

clean:
	rm -rf *.o mypcap
