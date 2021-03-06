/*
 *  ircd-sandstorm: The SandNET ircd.
 *  s_serv.h: A header for the server functions.
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
 *  $Id: s_serv.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef INCLUDED_serv_h
#define INCLUDED_serv_h

/*
 * The number of seconds between calls to try_connections(). Fiddle with
 * this ONLY if you KNOW what you're doing!
 */
#define TRY_CONNECTIONS_TIME	60

/*
 * number of seconds to wait after server starts up, before
 * starting try_connections()
 * TOO SOON and you can nick collide like crazy. 
 */
#define STARTUP_CONNECTIONS_TIME 60

struct Client;
struct server_conf;
struct Channel;

/* Capabilities */
struct Capability
{
	const char *name;	/* name of capability */
	unsigned int cap;	/* mask value */
};

#define CAP_CAP         0x000001/* received a CAP to begin with */
#define CAP_QS          0x000002/* Can handle quit storm removal */
#define CAP_ZIP         0x000004/* Can do ZIPlinks */
#define CAP_TB		0x000008/* supports TBURST */
#define CAP_ENCAP	0x000010/* supports ENCAP */
#define CAP_TS6		0x000020/* supports TS6 or above */
#define CAP_SAVE	0x000040/* supports SAVE (nick collision FNC) */
#define CAP_SAVETS_100	0x000080/* supports SAVE at TS 100 */
#define CAP_WIDE_MOTD	0x000100/* increased MOTD line length */
#define CAP_GCLICONN	0x000200/* global CLICONN/EXIT SNOTICEs */
#define CAP_EXT_CHARS	0x000400/* extended nick/user/spoof name charset */
#define CAP_NOCMODES	0x000800/* no (meaningful) CMODEs */
#define CAP_OPERCMODES  0x001000/* oper-only CMODEs +[PS] */
#define CAP_FORCE       0x002000/* force* commands */
#define CAP_FUN_CMODES  0x004000/* nonsensical cmodes */
#define CAP_REGEX       0x008000/* regex channel message filter */

#define CAP_MASK        (CAP_QS | CAP_ZIP | CAP_TB | CAP_ENCAP | \
			 CAP_SAVE | CAP_SAVETS_100 | \
			 CAP_WIDE_MOTD | CAP_GCLICONN | CAP_EXT_CHARS | \
			 CAP_NOCMODES | CAP_OPERCMODES | CAP_FORCE | \
			 CAP_FUN_CMODES | CAP_REGEX)
/*
 * Capability macros.
 */
#define IsCapable(x, cap)       (((x)->localClient->caps & (cap)) == cap)
#define NotCapable(x, cap)	(((x)->localClient->caps & (cap)) == 0)
#define ClearCap(x, cap)        ((x)->localClient->caps &= ~(cap))

/*
 * Globals
 *
 *
 * list of recognized server capabilities.  "TS" is not on the list
 * because all servers that we talk to already do TS, and the kludged
 * extra argument to "PASS" takes care of checking that.  -orabidoo
 */
extern struct Capability captab[];

extern int MaxClientCount;	/* GLOBAL - highest number of clients */
extern int MaxConnectionCount;	/* GLOBAL - highest number of connections */

extern int refresh_user_links;

/*
 * return values for hunt_server() 
 */
#define HUNTED_NOSUCH   (-1)	/* if the hunted server is not found */
#define HUNTED_ISME     0	/* if this server should execute the command */
#define HUNTED_PASS     1	/* if message passed onwards successfully */


int hunt_server(struct Client *client_pt,
		struct Client *source_pt,
		const char *command, int server, int parc, const char **parv);
void send_capabilities(struct Client *, int);
const char *show_capabilities(struct Client *client);
const char *show_capabilities2(struct Client *client, int caps);
void try_connections(void *unused);

int serv_connect(struct server_conf *, struct Client *);

#endif /* INCLUDED_s_serv_h */
