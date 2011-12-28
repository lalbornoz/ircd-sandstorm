/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_forcenames.c: Forcibly change another client's {nick, user, host, real} name.
 *
 *  Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center
 *  Copyright (C) 1996-2002 Hybrid Development Team
 *  Copyright (C) 2002-2005 ircd-ratbox development team
 *  Copyright (C) 2009 Lucio Albornoz
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
 *  $Id$
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "send.h"
#include "hash.h"
#include "s_serv.h"
#include "parse.h"
#include "modules.h"
#include "monitor.h"
#include "whowas.h"

static int mo_forcenick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_forceuser(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_forcehost(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static int mo_forcegecos(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message forcenick_msgtab = {
	"FORCENICK", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forcenick, 3}, {mo_forcenick, 3}, mg_ignore, mg_ignore, {mo_forcenick, 3}}
};

struct Message forceuser_msgtab = {
	"FORCEUSER", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forceuser, 3}, {mo_forceuser, 3}, mg_ignore, mg_ignore, {mo_forceuser, 3}}
};

struct Message forcehost_msgtab = {
	"FORCEHOST", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forcehost, 3}, {mo_forcehost, 3}, mg_ignore, mg_ignore, {mo_forcehost, 3}}
};

struct Message forcegecos_msgtab = {
	"FORCEGECOS", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forcegecos, 3}, {mo_forcegecos, 3}, mg_ignore, mg_ignore, {mo_forcegecos, 3}}
};

mapi_clist_av1 force_clist[] = { &forcenick_msgtab, &forceuser_msgtab,
				 &forcehost_msgtab, &forcegecos_msgtab, NULL };

DECLARE_MODULE_AV1(force, NULL, NULL, force_clist, NULL, NULL, "$Revision$");

/*
 * m_forcenick
 *      parv[0] = sender prefix
 *      parv[1] = user to force
 *      parv[2] = nick name to change to
 */
static int
mo_forcenick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	rb_dlink_node *ptr, *next_ptr;
	char newnick[NICKLEN], note[NICKLEN + 10];
	const char *our_parv[3] = {
		(parv[0] ? parv[0] : NULL),
		(parv[1] ? parv[1] : NULL),
		(parv[2] ? parv[2] : NULL), };

	if(!(((target_p = find_client(parv[1])) != NULL) &&
	     IsClient(target_p)))               /* Target Client not located */
	{
		if((target_p = get_history(parv[1], (long)KILLCHASETIMELIMIT)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), parv[1]);
			return 0;
		}
		else
			sendto_one_notice(source_p, ":FORCENICK changed from %s to %s", parv[1], target_p->name);

		our_parv[1] = target_p->name;
	}

        if((hunt_server(client_p, source_p, ":%s FORCENICK %s %s", 1, parc, our_parv)) != HUNTED_ISME)
                return 0;

	/* Duplicate and NUL terminate the supplied target nick name to enforce change to. */
	rb_strlcpy(newnick, parv[2], sizeof(newnick));
	if(newnick == NULL || EmptyString(newnick))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN),
			   me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return 0;
	}
	
	if(!valid_nick(newnick, 1))
	{
		sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME),
				     me.name, EmptyString(parv[0]) ? "*" : parv[0], parv[1]);
		return 0;
	}

	if(find_client(newnick) != NULL)	/* Duplicate nick name */
		sendto_one(source_p, form_str(ERR_NICKNAMEINUSE), me.name, "*", parv[2]);
	else if(hash_find_nd(newnick))		/* Nick delay */
		sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
				     me.name, EmptyString(source_p->name) ? "*" : source_p->name, newnick);
	else
		goto valid;

	return 0;

valid:
	target_p->localClient->last_nick_change = rb_current_time();
	target_p->localClient->number_of_nick_changes++;

	if(target_p->tsinfo >= rb_current_time())
		target_p->tsinfo++;
	else
		target_p->tsinfo = rb_current_time();
	monitor_signoff(target_p);

	sendto_allops_flags(UMODE_FULL, L_ALL,
		"%s (%s@%s) issued FORCENICK for %s (%s@%s) to %s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host,
		newnick);

	sendto_realops_flags(UMODE_NCHANGE, L_ALL,
			     "Nick change: From %s to %s [%s@%s]",
			     target_p->name, newnick, target_p->username, target_p->host);

	sendto_common_channels_local(target_p, ":%s!%s@%s NICK :%s",
				     target_p->name, target_p->username, target_p->host, newnick);

	if(target_p->user) {
		add_history(target_p, 1);

		sendto_server(NULL, NULL, ":%s NICK %s :%ld",
				target_p->id, newnick, (long)target_p->tsinfo);
	};

	del_from_hash(HASH_CLIENT, target_p->name, target_p);
	strcpy(target_p->user->name, newnick);
	add_to_hash(HASH_CLIENT, newnick, target_p);

	monitor_signon(target_p);

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, target_p->on_allow_list.head)
	{
		target_p = ptr->data;

		rb_dlinkFindDestroy(target_p, &target_p->localClient->allow_list);
		rb_dlinkDestroy(ptr, &target_p->on_allow_list);
	}

	rb_snprintf(note, sizeof(note), "Nick: %s", newnick);
	rb_note(client_p->localClient->F, note);

	return 0;
}


/*
 * m_forceuser
 *      parv[0] = sender prefix
 *      parv[1] = user to force
 *      parv[2] = user name to change to
 */
static int
mo_forceuser(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	char newusername[USERLEN];


	if(!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "forceuser");
		return 0;
	}

	if(!(((target_p = find_client(parv[1])) != NULL) &&
	     IsClient(target_p)))
	{
		if((target_p = get_history(parv[1], (long)KILLCHASETIMELIMIT)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), parv[1]);
			return 0;
		}
		else
			sendto_one_notice(source_p, ":FORCEUSER changed from %s to %s", parv[1], target_p->name);
	}


	rb_strlcpy(newusername, parv[2], sizeof(newusername));

	if(newusername != NULL && !EmptyString(newusername) &&
	   valid_username(newusername))
		rb_strlcpy(target_p->username, newusername, sizeof(target_p->username));

	sendto_allops_flags(UMODE_FULL, L_ALL,
		"%s (%s@%s) issued FORCEUSER for %s (%s@%s) to %s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host,
		newusername);

	sendto_server(client_p, NULL, ":%s FORCEUSER %s %s",
			source_p->name, target_p->name, newusername);

	return 0;
}


/*
 * m_forcehost
 *      parv[0] = sender prefix
 *      parv[1] = user to force
 *      parv[2] = host name to change to
 */
static int
mo_forcehost(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	char newhostname[HOSTLEN];


	if(!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "forcehost");
		return 0;
	}

	if(!(((target_p = find_client(parv[1])) != NULL) &&
	     IsClient(target_p)))
	{
		if((target_p = get_history(parv[1], (long)KILLCHASETIMELIMIT)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), parv[1]);
			return 0;
		}
		else
			sendto_one_notice(source_p, ":FORCEHOST changed from %s to %s", parv[1], target_p->name);
	}


	rb_strlcpy(newhostname, parv[2], sizeof(newhostname));

	if(newhostname != NULL && !EmptyString(newhostname) &&
	   valid_hostname(newhostname))
		rb_strlcpy(target_p->host, newhostname, sizeof(target_p->host));

	sendto_allops_flags(UMODE_FULL, L_ALL,
		"%s (%s@%s) issued FORCEHOST for %s (%s@%s) to %s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host,
		newhostname);

	sendto_server(client_p, NULL, ":%s FORCEHOST %s %s",
			source_p->name, target_p->name, newhostname);

	return 0;
}


/*
 * m_forcegecos
 *      parv[0] = sender prefix
 *      parv[1] = user to force
 *      parv[2] = gecos to change to
 */
static int
mo_forcegecos(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	char newgecos[REALLEN];


	if(!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "forcegecos");
		return 0;
	}

	if(!(((target_p = find_client(parv[1])) != NULL) &&
	     IsClient(target_p)))
	{
		if((target_p = get_history(parv[1], (long)KILLCHASETIMELIMIT)) == NULL)
		{
			sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), parv[1]);
			return 0;
		}
		else
			sendto_one_notice(source_p, ":FORCEGECOS changed from %s to %s", parv[1], target_p->name);
	}


	rb_strlcpy(newgecos, parv[2], sizeof(newgecos));

	if(newgecos != NULL && !EmptyString(newgecos))
		rb_strlcpy(target_p->info, newgecos, sizeof(target_p->info));

	sendto_allops_flags(UMODE_FULL, L_ALL,
		"%s (%s@%s) issued FORCEGECOS for %s (%s@%s) to %s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host,
		newgecos);

	sendto_server(client_p, NULL, ":%s FORCEGECOS %s %s",
			source_p->name, target_p->name, newgecos);

	return 0;
}
