ccarm=mips-openwrt-linux-g++
all:
	g++ main.cpp -o dupd -static -lrt
	${ccarm} main.cpp -o dupdarm   -static -lgcc_eh -lrt
#g++ forward.cpp aes.c -o forward -static
#	${ccarm} forward.cpp aes.c  -o forwardarm   -static -lgcc_eh
