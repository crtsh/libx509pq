ifndef OPENSSL_HOME
OPENSSL_HOME=/usr
endif
ifndef OPENSSL_INCLUDE
OPENSSL_INCLUDE=${OPENSSL_HOME}/include
endif
ifndef OPENSSL_LIB
OPENSSL_LIB=${OPENSSL_HOME}/lib
endif

libx509pq.so:
	gcc -O3 -fpic -c x509pq.c -I${OPENSSL_INCLUDE} -I`pg_config --includedir-server` -std=gnu99
	gcc -shared -O3 -fpic -o $@ -Wl,-Bsymbolic -Wl,-Bsymbolic-functions -Wl,-rpath=${OPENSSL_LIB} x509pq.o ${OPENSSL_LIB}/libcrypto.a

install:
	su -c "cp libx509pq.so `pg_config --pkglibdir`"

clean:
	rm -f *.o *.so *~
