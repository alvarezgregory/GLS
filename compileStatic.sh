#!/bin/sh -e

# local variable
CURRENT=$(pwd)
LIBGPG=$CURRENT"/dep/libgpg-error-1.10"
LIBGCRYPT=$CURRENT"/dep/libgcrypt-1.5.0"
LIBTASN=$CURRENT"/dep/libtasn1-2.11"

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
echo "*************************************"
echo "* GLS Static library compilation... *"
echo "*************************************"
echo " "
echo " "
echo "#################################"
echo "# Compilation Libgpg-error 1.10 #"
echo "#################################"
cd $LIBGPG
./configure --enable-static=yes --enable-shared=no
make
cd src
cp libgpg_error*.o $CURRENT/tmp/
cd ..
ln -s src bin

# Compile libgcrypt
echo " "
echo "###############################"
echo "# Compilation Libgcrypt 1.5.0 #"
echo "###############################"
cd $LIBGCRYPT
ln -s $LIBGPG/src/gpg-error.h ./src/gpg-error.h
export LDFLAGS="$LDFLAGS -L$LIBGPG/src/.libs"
./configure --with-gpg-error-prefix=$LIBGPG/ --enable-static=yes --enable-shared=no
make
cd src/.libs
ar x libgcrypt.a
cp *.o $CURRENT/tmp/

# Compile libtasn1
echo " "
echo "#############################"
echo "# Compilation Libtasn1 2.11 #"
echo "#############################"
cd $LIBTASN
./configure --enable-static=yes --enable-shared=no
make
cd lib/gllib
cp *.o $CURRENT/tmp/
cd ..
cp *.o $CURRENT/tmp/

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
gcc -DEAI_ADDRFAMILY=5001 -DEAI_NODATA=5002 -c GLSServer.c -o ./tmp/GLSServer.o
gcc -DEAI_ADDRFAMILY=5001 -DEAI_NODATA=5002 -c GLSSocket.c -o ./tmp/GLSSocket.o
gcc -c Crypto.c -o ./tmp/Crypto.o
gcc -c Certificate.c -o ./tmp/Certificate.o
ar rcs ./lib/libgls.a ./tmp/*.o
cp libgls.h ./lib/
cp $LIBGPG/src/gpg-error.h ./lib/
cp $LIBGCRYPT/src/gcrypt.h ./lib/
cp $LIBGCRYPT/src/gcrypt-module.h ./lib/

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
