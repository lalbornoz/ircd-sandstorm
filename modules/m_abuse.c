/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_abuse.c: Pynchon abuse policy.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *  USA
 *
 *  $Id: m_abuse.c$
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "match.h"

static int m_abuse(struct Client *, struct Client *, int, const char **);

struct Message abuse_msgtab = {
	"ABUSE", 0, 0, 0, MFLG_SLOW | MFLG_UNREG,
	{mg_unreg, {m_abuse, 2}, mg_ignore, mg_ignore, mg_ignore, mg_ignore}
};

mapi_clist_av1 abuse_clist[] = {
	&abuse_msgtab, NULL
};

DECLARE_MODULE_AV1(abuse, NULL, NULL, abuse_clist, NULL, NULL, "$Revision: 1488 $");

/*
 * m_abuse - ABUSE command handler
 *      parv[0] = sender prefix
 *      parv[1] = servername
 */
static int
m_abuse(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
const char *cmd = NULL;

	if (1 > parc)
		return 0;
	else 	cmd = parv[0];

	if (0 == strcasecmp (cmd, "PING"))
		return 1;
	else if (0 == strcasecmp (cmd, "NICK"))
		return 0;
	else if (0 == strcasecmp (cmd, "JOIN"))
		return 1;
	else if (0 == strcasecmp (cmd, "PART"))
		return 1;
	else if (0 == strcasecmp (cmd, "QUIT")) {
		if ((parc > 2) && (parv[2]))
			parv[2] = "";

		return 1;
	} else
	if ((0 == strcasecmp (cmd, "PRIVMSG"))
	||  (0 == strcasecmp (cmd, "NOTICE"))) {
		if ((parc < 3 || EmptyString(parv[2]))
		||  (parc < 4 || EmptyString(parv[3])))
			return 1;
		else 	return parv[3] = "ATTENTION: This message has been censored for the good of mankind.", 1;
	} else 	return 0;
}
