ccarm=mips-openwrt-linux-g++
all:
	g++ main.cpp -o dup -static
	${ccarm} main.cpp -o duparm   -static -lgcc_eh
#g++ forward.cpp aes.c -o forward -static
#	${ccarm} forward.cpp aes.c  -o forwardarm   -static -lgcc_eh
