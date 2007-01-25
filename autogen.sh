#!/bin/sh
echo
echo Warning:
echo
echo Development takes place on the \'gtk2\' cvs branch.
echo You problably don\'t want to compile the old gtk1 branch.
echo Use the \'-r gtk2\' parameter in the \'cvs checkout\' command.
echo
autopoint \
  && aclocal -I m4 \
  && libtoolize --force --copy \
  && autoheader \
  && automake --add-missing --foreign --copy \
  && autoconf \
  && ./configure --enable-maintainer-mode $@
