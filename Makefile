HEADERS = ./BearSSL/inc/

default: SimpleFileCrypter

SimpleFileCrypter.o: SimpleFileCrypter.c 
	gcc -c SimpleFileCrypter.c -o SimpleFileCrypter.o -I$(HEADERS)

SimpleFileCrypter: SimpleFileCrypter.o
	gcc SimpleFileCrypter.o ./BearSSL/build/libbearssl.a -o SimpleFileCrypter

clean:
	-rm -f SimpleFileCrypter.o
	-rm -f SimpleFileCrypter