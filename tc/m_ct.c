/*
 * m_ct.c		Connection tracking action
 *
 * Copyright (c) 2018 Yossi Kuperman <yossiku@mellanox.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "utils.h"
#include "tc_util.h"
#include <linux/tc_act/tc_ct.h>

static void
explain(void)
{
	fprintf(stderr, "Usage: ... ct [zone ZONE] [CONTROL] [index <INDEX>]\n");
	fprintf(stderr, "where :\n"
		"\tZONE is the ct zone\n"
		"\tCONTROL := reclassify | pipe | drop | continue | ok |\n"
		"\t           goto chain <CHAIN_INDEX>\n");
}

static void
usage(void)
{
	explain();
	exit(-1);
}

static int
parse_conntrack(struct action_util *a, int *argc_p, char ***argv_p, int tca_id,
		struct nlmsghdr *n)
{
	struct tc_conntrack sel = { 0 };
	char **argv = *argv_p;
	int argc = *argc_p;
	int ok = 0;
	struct rtattr *tail;

	while (argc > 0) {
		if (matches(*argv, "ct") == 0) {
			ok = 1;
			argc--;
			argv++;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else {
			break;
		}

	}

	if (!ok) {
		explain();
		return -1;
	}

	if (argc) {
		if (matches(*argv, "zone") == 0) {
			NEXT_ARG();
			if (get_u16(&sel.zone, *argv, 10)) {
				fprintf(stderr, "simple: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	if (argc) {
		if (matches(*argv, "commit") == 0) {
			sel.commit = true;
			argc--;
			argv++;
		}
	}

	parse_action_control_dflt(&argc, &argv, &sel.action, false, TC_ACT_PIPE);
	NEXT_ARG_FWD();

	if (argc) {
		if (matches(*argv, "index") == 0) {
			NEXT_ARG();
			if (get_u32(&sel.index, *argv, 10)) {
				fprintf(stderr, "simple: Illegal \"index\"\n");
				return -1;
			}
			argc--;
			argv++;
		}
	}

	tail = NLMSG_TAIL(n);
	addattr_l(n, MAX_MSG, tca_id, NULL, 0);
	addattr_l(n, MAX_MSG, TCA_CONNTRACK_PARMS, &sel, sizeof(sel));
	tail->rta_len = (char *)NLMSG_TAIL(n) - (char *)tail;

	*argc_p = argc;
	*argv_p = argv;
	return 0;
}

static int print_conntrack(struct action_util *au, FILE *f, struct rtattr *arg)
{
	struct rtattr *tb[TCA_CONNTRACK_MAX + 1];
	struct tc_conntrack *ci;

	if (arg == NULL)
		return -1;

	parse_rtattr_nested(tb, TCA_CONNTRACK_MAX, arg);
	if (tb[TCA_CONNTRACK_PARMS] == NULL) {
		fprintf(stderr, "[NULL conntrack parameters]");
		return -1;
	}

	ci = RTA_DATA(tb[TCA_CONNTRACK_PARMS]);

	print_string(PRINT_ANY, "kind", "%s ", "conntrack");
	print_int(PRINT_ANY, "zone", "zone %d", ci->zone);

	if (ci->commit)
		print_bool(PRINT_ANY, "commit", " commit", true);

	print_uint(PRINT_ANY, "index", "\n \tindex %u", ci->index);
	print_int(PRINT_ANY, "ref", " ref %d", ci->refcnt);
	print_int(PRINT_ANY, "bind", " bind %d", ci->bindcnt);

	if (show_stats) {
		if (tb[TCA_CONNTRACK_TM]) {
			struct tcf_t *tm = RTA_DATA(tb[TCA_CONNTRACK_TM]);

			print_tm(f, tm);
		}
	}

	print_string(PRINT_FP, NULL, "%s", "\n ");

	return 0;
}

struct action_util ct_action_util = {
	.id = "ct",
	.parse_aopt = parse_conntrack,
	.print_aopt = print_conntrack,
};
