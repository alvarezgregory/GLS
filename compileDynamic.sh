#!/bin/sh -e

# local variable
CURRENT=$(pwd)
LIBGPG=$CURRENT"/dep/libgpg-error-1.12"
LIBGCRYPT=$CURRENT"/dep/libgcrypt-1.5.2"
LIBTASN=$CURRENT"/dep/libtasn1-3.3"

# check
rm -r tmp || true
rm -r lib || true
rm gcrypt.h || true
rm gcrypt-module.h || true
rm gpg-error.h || true
rm libtasn1.h || true
cd $LIBGPG 
rm bin || true
cd $LIBGCRYPT
rm ./src/gpg-error.h || true
cd $CURRENT

mkdir tmp

# Compile libgpg-error
echo " "
echo "**************************************"
echo "* GLS Dynamic library compilation... *"
echo "**************************************"
echo " "
echo " "
echo "#################################"
echo "# Compilation Libgpg-error 1.12 #"
echo "#################################"
cd $LIBGPG
./configure 
make
ln -s src bin

# Compile libgcrypt
echo " "
echo "###############################"
echo "# Compilation Libgcrypt 1.5.2 #"
echo "###############################"
cd $LIBGCRYPT
ln -s $LIBGPG/src/gpg-error.h ./src/gpg-error.h
export LDFLAGS="$LDFLAGS -L$LIBGPG/src/.libs"
./configure --with-gpg-error-prefix=$LIBGPG/
make

# Compile libtasn1
echo " "
echo "############################"
echo "# Compilation Libtasn1 3.3 #"
echo "############################"
cd $LIBTASN
./configure
make

# Compile GLS
echo " "
echo "##########################"
echo "# Compilation GLS Alpha  #"
echo "##########################"
cd $CURRENT
ln -s $LIBGCRYPT/src/gcrypt.h gcrypt.h
ln -s $LIBGCRYPT/src/gcrypt-module.h gcrypt-module.h
ln -s $LIBGPG/src/gpg-error.h gpg-error.h
ln -s $LIBTASN/lib/libtasn1.h libtasn1.h
mkdir lib
gcc -fPIC -DEAI_ADDRFAMILY=5001 -DEAI_NODATA=5002 -c GLSServer.c -o ./tmp/GLSServer.o
gcc -fPIC -DEAI_ADDRFAMILY=5001 -DEAI_NODATA=5002 -c GLSSocket.c -o ./tmp/GLSSocket.o
gcc -fPIC -c Crypto.c -o ./tmp/Crypto.o
gcc -fPIC -c Certificate.c -o ./tmp/Certificate.o
gcc -shared -Wl,-soname,libgls.so.1 -o ./lib/libgls.so ./tmp/*.o $LIBGPG/src/.libs/libgpg-error.so $LIBGCRYPT/src/.libs/libgcrypt.so $LIBTASN/lib/.libs/libtasn1.so
cp libgls.h ./lib/
cp $LIBGPG/src/gpg-error.h ./lib/
cp $LIBGCRYPT/src/gcrypt.h ./lib/
cp $LIBGCRYPT/src/gcrypt-module.h ./lib/
cp $LIBGPG/src/.libs/libgpg-error.so ./lib/
cp $LIBGCRYPT/src/.libs/libgcrypt.so ./lib/
cp $LIBTASN/lib/.libs/libtasn1.so ./lib/

# Clean
echo " "
echo "#############"
echo "# Cleaning  #"
echo "#############"
rm -r tmp
rm gcrypt.h
rm gcrypt-module.h
rm gpg-error.h
rm libtasn1.h
cd $LIBGPG
rm bin
make clean
cd $LIBGCRYPT
rm ./src/gpg-error.h
make clean
cd $LIBTASN
make clean

# end
echo " "
echo "***********************************"
echo "* Done ! Your library is in ./lib *"
echo "***********************************"
