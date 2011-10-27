#! /bin/sh

autoheader
aclocal
autoconf
mkdir config
automake --add-missing
