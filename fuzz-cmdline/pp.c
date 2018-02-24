#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>

int main(void)
{
	uid_t ruid, euid, suid;
	gid_t rgid, egid, sgid;

	getresuid(&ruid, &euid, &suid);
	getresgid(&rgid, &egid, &sgid);

	printf(" uid: %i,  gid: %i\neuid: %i, egid: %i\nsuid: %i, sgid: %i\n",
		ruid, rgid,
		euid, egid,
		suid, sgid
	);
	exit(0);
}

