#! /bin/sh
set -ex

test -d m4 || mkdir m4
autoreconf -i -f
automake --force
./configure
rm -rf autom4te.cache
