all: hftpd client hmds

hftpd: hftpd.c
	gcc -Wall -Werror -g -O0 -std=gnu11 -o hftpd hftpd.c -lz -lhdb -lhfs -lhmdp -lhiredis

client: client.c
	gcc -Wall -Werror -g -O0 -std=gnu11 -o client client.c -lz -lhdb -lhfs -lhmdp -lm

hmds: hmds.c
	gcc -Wall -Werror -g -O0 -std=gnu11 -o hmds hmds.c -lhdb -lhiredis