/* contrib/m_force.c
 * Copyright (C) 1996-2002 Hybrid Development Team
 * Copyright (C) 2004 ircd-ratbox Development Team
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *  1.Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  2.Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  3.The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 *  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 *  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id$
 */

#include "stdinc.h"
#include "ratbox_lib.h"
#include "struct.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "common.h"
#include "match.h"
#include "ircd.h"
#include "hostmask.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_log.h"
#include "send.h"
#include "hash.h"
#include "s_serv.h"
#include "parse.h"
#include "modules.h"


static int mo_forcejoin(struct Client *client_p, struct Client *source_p,
			int parc, const char *parv[]);
static int mo_forcepart(struct Client *client_p, struct Client *source_p,
			int parc, const char *parv[]);

struct Message forcejoin_msgtab = {
	"FORCEJOIN", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forcejoin, 3}, {mo_forcejoin, 3}, mg_ignore, mg_ignore, {mo_forcejoin, 3}}
};

struct Message forcepart_msgtab = {
	"FORCEPART", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {mo_forcepart, 3}, {mo_forcepart, 3}, mg_ignore, mg_ignore, {mo_forcepart, 3}}
};

mapi_clist_av1 force_clist[] = { &forcejoin_msgtab, &forcepart_msgtab, NULL };

DECLARE_MODULE_AV1(force, NULL, NULL, force_clist, NULL, NULL, "$Revision$");

static void do_join_0(struct Client *client_p, struct Client *source_p);

/*
 * m_forcejoin
 *      parv[0] = sender prefix
 *      parv[1] = user to force
 *      parv[2] = channel to force them into
 */
static int
mo_forcejoin(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct Channel *chptr;
	char *newch;

	if(!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "forcejoin");
		return 0;
	}

	if((hunt_server(client_p, source_p, ":%s FORCEJOIN %s %s", 1, parc, parv)) != HUNTED_ISME)
		return 0;

	/* if target_p is not existant, print message
	 * to source_p and bail - scuzzy
	 */
	if((target_p = find_client(parv[1])) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, parv[1]);
		return 0;
	}

	if(!IsClient(target_p))
		return 0;

	sendto_allops_flags(UMODE_FULL, L_ALL,
		"%s (%s@%s) issued FORCEJOIN for %s (%s@%s) to %s",
		source_p->name, source_p->username, source_p->host,
		target_p->name, target_p->username, target_p->host,
		parv[2]);

	/* join 0 parts all channels */
	if(parv[2][0] == '0' && parv[2][1] == '\0')
	{
		if(target_p->user->channel.head != NULL)
			do_join_0(&me, target_p);
	}
	else if((chptr = find_channel(parv[2])) != NULL)
	{
		if(IsMember(target_p, chptr))
		{
			/* debugging is fun... */
			sendto_one(source_p, ":%s NOTICE %s :*** Notice -- %s is already in %s",
				   me.name, source_p->name, target_p->name, chptr->chname);
			return 0;
		}

		add_user_to_channel(chptr, target_p, 0);

		sendto_channel_local(chptr, ":%s!%s@%s JOIN :%s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname);

		sendto_server(target_p, chptr,
			":%s JOIN %ld %s +",
			target_p->id, (long)chptr->channelts, chptr->chname);

		if(chptr->topic != NULL)
		{
			sendto_one(target_p, form_str(RPL_TOPIC), me.name,
				   target_p->name, chptr->chname, chptr->topic->topic);
			sendto_one(target_p, form_str(RPL_TOPICWHOTIME),
				   me.name, source_p->name, chptr->chname,
				   chptr->topic->topic_info, chptr->topic->topic_time);
		}

		channel_member_names(chptr, target_p, 1);
	}
	else
	{
		newch = LOCAL_COPY(parv[2]);
		if(!check_channel_name(newch))
		{
			sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
				   source_p->name, (unsigned char *)newch);
			return 0;
		}

		/* channel name must begin with & or # */
		if(!IsChannelName(newch))
		{
			sendto_one(source_p, form_str(ERR_BADCHANNAME), me.name,
				   source_p->name, (unsigned char *)newch);
			return 0;
		}

		/* newch can't be longer than CHANNELLEN */
		if(strlen(newch) > CHANNELLEN)
		{
			sendto_one(source_p, ":%s NOTICE %s :Channel name is too long", me.name,
				   source_p->name);
			return 0;
		}

		chptr = get_or_create_channel(target_p, newch, NULL);
		add_user_to_channel(chptr, target_p, CHFL_CHANOP);

		/* send out a join, make target_p join chptr */
		sendto_server(target_p, chptr,
			      ":%s SJOIN %ld %s +l 1488 :@%s", me.name,
			      (long)chptr->channelts, chptr->chname, target_p->name);

		sendto_channel_local(chptr, ":%s!%s@%s JOIN :%s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname);

		chptr->mode.limit = 1488;

		sendto_channel_local(chptr, ":%s MODE %s +l 1488", me.name, chptr->chname);

		channel_member_names(chptr, target_p, 1);

		/* we do this to let the oper know that a channel was created, this will be
		 * seen from the server handling the command instead of the server that
		 * the oper is on.
		 */
		sendto_one(source_p, ":%s NOTICE %s :*** Notice -- Creating channel %s", me.name,
			   source_p->name, chptr->chname);
	}
	return 0;
}


static int
mo_forcepart(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	struct Channel *chptr;
	struct membership *msptr;

	char *reason = NULL;

	if(!IsOper(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "forcepart");
		return 0;
	}

	if((parc > 3)
	&& (hunt_server(client_p, source_p, ":%s FORCEPART %s %s :%s", 1, parc, parv) != HUNTED_ISME))
		return 0;

	if((parc <= 3)
	&& (hunt_server(client_p, source_p, ":%s FORCEPART %s %s", 1, parc, parv) != HUNTED_ISME))
		return 0;

	/* if target_p == NULL then let the oper know */
	if((target_p = find_client(parv[1])) == NULL)
	{
		sendto_one(source_p, form_str(ERR_NOSUCHNICK), me.name, source_p->name, parv[1]);
		return 0;
	}

	if(!IsClient(target_p))
		return 0;

	if(parc > 3)
		reason = LOCAL_COPY_N(parv[3], REASONLEN);

	if((chptr = find_channel(parv[2])) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}

	if((msptr = find_channel_membership(chptr, target_p)) == NULL)
	{
		sendto_one(source_p, form_str(ERR_USERNOTINCHANNEL),
			   me.name, parv[0], parv[1], parv[2]);
		return 0;
	}

	if(!EmptyString(reason))
	{
		sendto_allops_flags(UMODE_FULL, L_ALL,
			"%s (%s@%s) issued FORCEPART for %s (%s@%s) from %s (reason: %s)",
			source_p->name, source_p->username, source_p->host,
			target_p->name, target_p->username, target_p->host,
			parv[2], reason);

		sendto_server(target_p, chptr,
			      ":%s PART %s :%s", target_p->id, chptr->chname, reason);
		sendto_channel_local(chptr, ":%s!%s@%s PART %s :%s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname, reason);
	}
	else
	{
		sendto_allops_flags(UMODE_FULL, L_ALL,
			"%s (%s@%s) issued FORCEPART for %s (%s@%s) from %s",
			source_p->name, source_p->username, source_p->host,
			target_p->name, target_p->username, target_p->host,
			parv[2]);

		sendto_server(target_p, chptr,
			      ":%s PART %s", target_p->id, chptr->chname);
		sendto_channel_local(chptr, ":%s!%s@%s PART %s",
				     target_p->name, target_p->username,
				     target_p->host, chptr->chname);
	}


	remove_user_from_channel(msptr);

	return 0;
}

/*
 * do_join_0
 *
 * inputs	- pointer to client doing join 0
 * output	- NONE
 * side effects	- Use has decided to join 0. This is legacy
 *		  from the days when channels were numbers not names. *sigh*
 *		  There is a bunch of evilness necessary here due to
 * 		  anti spambot code.
 */
static void
do_join_0(struct Client *client_p, struct Client *source_p)
{
	struct membership *msptr;
	struct Channel *chptr = NULL;
	rb_dlink_node *ptr;

	/* Finish the flood grace period... */
	if(MyClient(source_p) && !IsFloodDone(source_p))
		flood_endgrace(source_p);


	sendto_server(client_p, NULL, ":%s JOIN 0", source_p->id);

	while((ptr = source_p->user->channel.head))
	{
		msptr = ptr->data;
		chptr = msptr->chptr;
		sendto_channel_local(chptr, ":%s!%s@%s PART %s",
				     source_p->name,
				     source_p->username, source_p->host, chptr->chname);
		remove_user_from_channel(msptr);
	}
}


