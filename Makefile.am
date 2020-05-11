AM_CFLAGS = -std=c99 -Wall -Wextra -Werror -lcurl -lconfig -lcjson -lcrypto -lm -O0

sbin_PROGRAMS=meshvisor
meshvisor_SOURCES = \
 	src/logger.c src/logger.h \
 	src/conf.c src/conf.h \
 	src/aes/crypt.c src/aes/crypt.h \
 	src/aes/aes.c src/aes/aes.h \
 	src/base64/base64.c src/base64/base64.h \
 	src/request/request.c src/request/request.h \
 	src/keygen/keygen.c src/keygen/keygen.h \
 	src/tincStarter/tincStarter.c src/tincStarter/tincStarter.h \
 	src/pidfile/pidfile.c src/pidfile/pidfile.h \
	src/main.c

etcdir = ${prefix}/etc
sbindir = ${prefix}/sbin
localstatedir = ${prefix}/var
libdir = ${localstatedir}/lib/meshvisor
logdir = ${localstatedir}/log
rundir = ${localstatedir}/run/meshvisor


dirs = ${etcdir} ${sbindir} ${localstatedir} ${libdir} ${logdir} $(rundir)

$(shell mkdir -p $(dirs))
$(shell cp ./doc/meshvisor.conf $(etcdir)/)

AM_CPPFLAGS = -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L -DSBINDIR=\"$(sbindir)\" -DETCDIR=\"$(etcdir)\" -DLOCALSTATEDIR=\"$(localstatedir)\" -DLIBDIR=\"$(libdir)\" -DRUNDIR=\"$(rundir)\"