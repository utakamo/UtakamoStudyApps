
#include "netlink_tool.h"

void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len) {
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len)) {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}

int netlink_list_if(netlink_if_list *list, int max_if_num) {

    int sock_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock_fd < 0) {
        return ERR_SOCKET;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(sock_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock_fd);
        return ERR_BIND;
    }

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    request.nlh.nlmsg_type = RTM_GETLINK;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.ifm.ifi_family = AF_UNSPEC;

    if (send(sock_fd, &request, request.nlh.nlmsg_len, 0) < 0) {
        close(sock_fd);
        return ERR_SEND;
    }

    char buffer[BUFFER_SIZE];
    ssize_t len = recv(sock_fd, buffer, sizeof(buffer), 0);
    if (len < 0) {
        close(sock_fd);
        return ERR_RECV;
    }

    int item = 0;
    struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
    for (; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {

        if (item >= max_if_num) {
            break;
        }

        if (nlh->nlmsg_type == NLMSG_DONE) break;
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return ERR_RESPONSE;
            break;
        }

        struct ifinfomsg *ifi = NLMSG_DATA(nlh);
        struct rtattr *tb[IFLA_MAX + 1];
        int attr_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));

        parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), attr_len);

        if (tb[IFLA_IFNAME]) {
            list[item].index = ifi->ifi_index;
            snprintf(list[item].ifname, IFNAMSIZ, "%s", (char *)RTA_DATA(tb[IFLA_IFNAME]));
            item++;
        }
    }

    close(sock_fd);
    return 0;
}