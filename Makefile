libx509pq.so:
	gcc -O3 -fpic -c x509pq.c -I`pg_config --includedir-server` -I${OPENSSL_HOME}/include -std=gnu99
	gcc -shared -O3 -fpic -o libx509pq.so -Wl,-Bsymbolic -Wl,-Bsymbolic-functions x509pq.o ${OPENSSL_HOME}/lib/libcrypto.a

install:
	su -c "cp libx509pq.so `pg_config --pkglibdir`"

clean:
	rm -f *.o *.so *~
