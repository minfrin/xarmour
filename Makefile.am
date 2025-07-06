
ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = xarmour
xarmour_SOURCES = xarmour.c

EXTRA_DIST = xarmour.spec
dist_man_MANS = xarmour.1

xarmour.1: xarmour
	which txt2man && ./xarmour --help | txt2man -s 1 -t "${PACKAGE_NAME}" -r "${PACKAGE_NAME}-${PACKAGE_VERSION}" > xarmour.1 || true

