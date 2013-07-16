#!/bin/sh
mkdir tmp

# Compile libgpg-error
cd dep/libgpg-error-1.10
./configure --enable-static=yes --enable-shared=no
make
cd src
cp libgpg_error*.o ../../../tmp/
cd ..
ln -s src bin

# Compile libgcrypt
cd ..
cd libgcrypt-1.5.0
./configure --with-gpg-error-prefix=../libgpg-error-1.10/ --enable-
static=yes --enable-shared=no
make
cd src/.libs
ar x libgcrypt.a
cp *.o ../../../../tmp/

# Compile libtasn1
cd ../../../libtasn1-2.11
./configure --enable-static=yes --enable-shared=no
make
cd lib/gllib
cp *.o ../../../../tmp/
cd ..
cp *.o ../../../tmp/

# Compile GLS
mkdir lib
gcc -c GLSServer.c -o ./tmp/GLSServer.o
gcc -c GLSSocket.c -o ./tmp/GLSSocket.o
gcc -c Crypto.c -o ./tmp/Crypto.o
gcc -c Certificate.c -o ./tmp/Certificate.o
ar rcs ./lib/libgls.a ./tmp/*.o
cp libgls.h ./lib/

# Clean
rm -r tmp
cd dep/libgpg-error-1.10
rm bin
make clean
cd ../libgcrypt-1.5.0
make clean
cd ../libtasn1-2.11
make clean