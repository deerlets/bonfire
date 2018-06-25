#include "utils.h"
#include <stddef.h>
#include <string.h>
#ifdef unix
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#if 0
bool check_wireless(const char *ifname, char *protocol)
{
	int fd;
	struct iwreq req;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, ifname, IFNAMSIZ);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		return false;

	if (ioctl(fd, SIOCGIWNAME, &req) != -1) {
		if (protocol) strncpy(protocol, req.u.name, IFNAMSIZ);
		close(fd);
		return true;
	}

	close(fd);
	return false;
}
#endif

const char *get_ifaddr()
{
	char *retval = NULL;

#ifdef unix
	struct ifaddrs *ifaddrs = NULL;
	if (getifaddrs(&ifaddrs) == -1)
		return NULL;

	for (struct ifaddrs *pos = ifaddrs; pos != NULL; pos = pos->ifa_next) {
		// only support ipv4
		if (pos->ifa_addr && pos->ifa_addr->sa_family == AF_INET &&
		    pos->ifa_flags & IFF_UP &&
		    pos->ifa_flags & IFF_MULTICAST &&
		    !(pos->ifa_flags & IFF_LOOPBACK)) {
			retval = inet_ntoa(((struct sockaddr_in *)
			                    (pos->ifa_addr))->sin_addr);
			break;
		}
	}

	freeifaddrs(ifaddrs);
#else
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	struct hostent *info = gethostbyname("");
	retval = inet_ntoa(*(struct in_addr *)(*info->h_addr_list));
	WSACleanup();
#endif

	return retval;
}
