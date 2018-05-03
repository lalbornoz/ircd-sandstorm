/*
 *  ircd-ratbox: A slightly useful ircd.
 *  m_nick.c: Sets a users nick.
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
 *  $Id: m_nick.c 26094 2008-09-19 15:33:46Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_stats.h"
#include "s_user.h"
#include "hash.h"
#include "whowas.h"
#include "s_serv.h"
#include "s_log.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "scache.h"
#include "s_newconf.h"
#include "monitor.h"
#include "reject.h"

/* Give all UID nicks the same TS. This ensures nick TS is always the same on
 * all servers for each nick-user pair, also if a user with a UID nick changes
 * their nick but is collided again (the server detecting the collision will
 * not propagate the nick change further). -- jilles
 */
#define SAVE_NICKTS 100

static int mr_nick(struct Client *, struct Client *, int, const char **);
static int m_nick(struct Client *, struct Client *, int, const char **);
static int mc_nick(struct Client *, struct Client *, int, const char **);
static int ms_nick(struct Client *, struct Client *, int, const char **);
static int ms_uid(struct Client *, struct Client *, int, const char **);
static int ms_save(struct Client *, struct Client *, int, const char **);
static void save_user(struct Client *, struct Client *, struct Client *);

struct Message nick_msgtab = {
	"NICK", 0, 0, 0, MFLG_SLOW,
	{{mr_nick, 0}, {m_nick, 0}, {mc_nick, 3}, {ms_nick, 8}, mg_ignore, {m_nick, 0}}
};

struct Message uid_msgtab = {
	"UID", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, {ms_uid, 9}, mg_ignore, mg_ignore}
};

struct Message save_msgtab = {
	"SAVE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, {ms_save, 3}, mg_ignore, mg_ignore}
};

mapi_clist_av1 nick_clist[] = { &nick_msgtab, &uid_msgtab, &save_msgtab, NULL };

DECLARE_MODULE_AV1(nick, NULL, NULL, nick_clist, NULL, NULL, "$Revision: 26094 $");

static int change_remote_nick(struct Client *, struct Client *, time_t, char *, int, int, int);

static void set_initial_nick(struct Client *client_p, struct Client *source_p, char *nick);
static void change_local_nick(struct Client *client_p, struct Client *source_p, char *nick, int, int);
static int register_client(struct Client *client_p, struct Client *server,
			   const char *nick, time_t newts, int parc, const char *parv[]);

static int perform_nick_collides(struct Client *, struct Client *,
				 struct Client *, int, const char **,
				 time_t, const char *, const char *);
static int perform_nickchange_collides(struct Client *, struct Client *,
				       struct Client *, time_t, const char *);

/* mr_nick()
 *       parv[0] = sender prefix
 *       parv[1] = nickname
 */
static int
mr_nick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	char nick[NICKLEN];

	if(parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN),
			   me.name, EmptyString(source_p->name) ? "*" : source_p->name);
		return 0;
	}

	/* copy the nick and terminate it */
	rb_strlcpy(nick, parv[1], sizeof(nick));

	nick_sp_fixup (&nick[0], sizeof (nick));

	/* check the nickname is ok */
	if(!valid_nick(nick, 1, 0))
	{
		sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME),
			   me.name, EmptyString(parv[0]) ? "*" : parv[0], parv[1]);
		return 0;
	}
 
	/* check if the nick is resv'd */
	if(!IsExemptResv(source_p) && find_nick_resv(nick))
	{
		sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME),
			   me.name, EmptyString(source_p->name) ? "*" : source_p->name, nick);
		return 0;
	}

	if(hash_find_nd(nick))
	{
		sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
			   me.name, EmptyString(source_p->name) ? "*" : source_p->name, nick);
		return 0;
	}

	if((target_p = find_client(nick)) == NULL)
		set_initial_nick(client_p, source_p, nick);
	else if(source_p == target_p)
		strcpy(source_p->user->name, nick);
	else
		sendto_one(source_p, form_str(ERR_NICKNAMEINUSE), me.name, "*", nick);

	return 0;
}

/* m_nick()
 *     parv[0] = sender prefix
 *     parv[1] = nickname
 */
static int
m_nick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	static char nick[((NICKLEN + 2) * __arraycount(source_p->name_per)) + 1];
	int has_propagated = 0;

	if(parc < 2 || EmptyString(parv[1]))
	{
		sendto_one(source_p, form_str(ERR_NONICKNAMEGIVEN), me.name, source_p->name);
		return 0;
	}

	/* mark end of grace period, to prevent nickflooding */
	if(!IsFloodDone(source_p))
		flood_endgrace(source_p);

	/* terminate nick to NICKLEN, we dont want valid_nick() to error! */
	rb_strlcpy(nick, parv[1], sizeof(nick));

	nick_sp_fixup (&nick[0], sizeof (nick));

	/* check the nickname is ok */
	if(!valid_nick(nick, 1, (strstr(nick, "\\n") ? 1 : 0)))
	{
		sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME), me.name, parv[0], nick);
		return 0;
	}

	if(find_nick_resv(nick))
	{
		sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME), me.name, source_p->name, nick);
		return 0;
	}

	if(hash_find_nd(nick))
	{
		sendto_one(source_p, form_str(ERR_UNAVAILRESOURCE),
			   me.name, EmptyString(source_p->name) ? "*" : source_p->name, nick);
		return 0;
	}

	if((source_p->name_per_len)
	&& (strstr(nick, "\\n") == NULL)) {
	struct membership *msptr;
	struct Channel *chptr;
	rb_dlink_node *ptr;
		source_p->name_per_len = 0, source_p->name_per_cur = 0;
		RB_DLINK_FOREACH(ptr, source_p->user->channel.head) {
			msptr = ptr->data;
			chptr = msptr->chptr;
			sendto_channel_local(chptr,
				":%s NOTICE %s :%s!%s@%s removes multi-line nick",
				me.name, chptr->chname,
				source_p->name, source_p->username, source_p->host);
		}
		/* send the nick change to servers.. */
		if(source_p->user)
		{
			add_history(source_p, 1);

			sendto_server(client_p, NULL, ":%s NICK %s :%ld",
				      source_p->id, nick, (long)source_p->tsinfo);
			has_propagated = 1;
		}
	}

	if((target_p = find_client(nick)))
	{
		/* If(target_p == source_p) the client is changing nicks between
		 * equivalent nicknames ie: [nick] -> {nick}
		 */
		if(target_p == source_p)
		{
			/* check the nick isnt exactly the same */
			if(strcmp(target_p->name, nick))
				change_local_nick(client_p, source_p, nick, 1, has_propagated);

		}

		/* drop unregged client */
		else if(IsUnknown(target_p))
		{
			exit_client(NULL, target_p, &me, "Overridden");
			change_local_nick(client_p, source_p, nick, 1, has_propagated);
		}
		else
			sendto_one(source_p, form_str(ERR_NICKNAMEINUSE), me.name, parv[0], nick);

		return 0;
	}
	else
		change_local_nick(client_p, source_p, nick, 1, has_propagated);

	return 0;
}

/* ms_nick()
 *      
 * server -> server nick change
 *    parv[0] = sender prefix
 *    parv[1] = nickname
 *    parv[2] = TS when nick change
 *
 * server introducing new nick
 *    parv[0] = sender prefix
 *    parv[1] = nickname
 *    parv[2] = hop count
 *    parv[3] = TS
 *    parv[4] = umode
 *    parv[5] = username
 *    parv[6] = hostname
 *    parv[7] = server
 *    parv[8] = ircname
 */
static int
mc_nick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	time_t newts = 0;
	static char nick[((NICKLEN + 2) * __arraycount(source_p->name_per)) + 1];
	rb_dlink_node *ptr;
	int has_propagated = 0, has_removed = 0;

	rb_strlcpy(nick, parv[1], sizeof(nick));

	/* if nicks erroneous, or too long, kill */
	if(!valid_nick(nick, 1, (strstr(nick, "\\n") ? 1 : 0)))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad Nick: %s From: %s(via %s)",
				     nick, source_p->servptr->name, client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad Nickname)", me.name, nick, me.name);

		/* bad nick change, issue kill for the old nick to the rest
		 * of the network.
		 */
		kill_client_serv_butone(client_p, source_p, "%s (Bad Nickname)", me.name);
		source_p->flags |= FLAGS_KILLED;
		exit_client(client_p, source_p, &me, "Bad Nickname");
		return 0;
	}

	newts = atol(parv[2]);
	target_p = find_client(nick);

	if((source_p->name_per_len)
	&& (strstr(nick, "\\n") == NULL)) {
	struct membership *msptr;
	struct Channel *chptr;
		source_p->name_per_len = 0, source_p->name_per_cur = 0;
		RB_DLINK_FOREACH(ptr, source_p->user->channel.head) {
			msptr = ptr->data;
			chptr = msptr->chptr;
			sendto_channel_local(chptr,
				":%s NOTICE %s :%s!%s@%s removes multi-line nick",
				me.name, chptr->chname,
				source_p->name, source_p->username, source_p->host);
		}
		/* send the nick change to servers.. */
		if(source_p->user)
		{
			add_history(source_p, 1);

			sendto_server(client_p, NULL, ":%s NICK %s :%ld",
				      source_p->id, nick, (long)source_p->tsinfo);
			has_propagated = 1; has_removed = 1;
		}
	}

	if(strstr(nick, "\\n") != NULL) {
	int nper = 0, nper_max = __arraycount(source_p->name_per);
		source_p->name_per_len = 0, source_p->name_per_cur = 0;
		for(char *p = nick, *q = strstr(p, "\\n"); p && (nper < nper_max);) {
		size_t name_per_len;
			if(q == NULL) {
				if(source_p->name_per_len == 0)
					break;
				else
					name_per_len = strlen(p);
			} else
				name_per_len = q - p;
			if(name_per_len > (__arraycount(source_p->name_per[nper]) - 1)) {
				source_p->name_per_len = 0;
				sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME), me.name, source_p->name, nick);
				break;
			} else
			if(name_per_len > 0) {
				strncpy(source_p->name_per[nper], p, name_per_len);
				source_p->name_per[nper][name_per_len] = '\0';
				if(find_client(source_p->name_per[nper]) != NULL) {
					source_p->name_per_len = 0;
					sendto_one(source_p, form_str(ERR_NICKNAMEINUSE), me.name, source_p->name, source_p->name_per[nper]);
					break;
				}
				source_p->name_per_len++, nper++;
			}
			if((p = q) != NULL)
				p = &q[strlen("\\n")], q = strstr(p, "\\n");
		}
		if(source_p->name_per_len) {
		struct membership *msptr;
		struct Channel *chptr;
			if(source_p->name_per_len < nper_max)
				source_p->name_per[source_p->name_per_len][0] = '\0';
			for(nper = 0; nper < source_p->name_per_len; nper++) {
				sendto_realops_flags(UMODE_NCHANGE, L_ALL,
						     "Nick change: From %s to %s [%s@%s]",
						     source_p->name, source_p->name_per[nper], source_p->username, source_p->host);
				RB_DLINK_FOREACH(ptr, source_p->user->channel.head) {
					msptr = ptr->data;
					chptr = msptr->chptr;
					sendto_channel_local(chptr,
						":%s NOTICE %s :%s!%s@%s adds multi-line nick line %s",
						me.name, chptr->chname,
						source_p->name, source_p->username, source_p->host,
						source_p->name_per[nper]);
				}
			}
			return 0;
		} else {
			source_p->name_per[0][0] = '\0';
			return 0;
		}
	}

	/* if the nick doesnt exist, allow it and process like normal */
	if(target_p == NULL)
	{
		change_remote_nick(client_p, source_p, newts, nick, 1, has_propagated, has_removed);
	}
	else if(IsUnknown(target_p))
	{
		exit_client(NULL, target_p, &me, "Overridden");
		change_remote_nick(client_p, source_p, newts, nick, 1, has_propagated, has_removed);
	}
	else if(target_p == source_p)
	{
		/* client changing case of nick */
		if(strcmp(target_p->name, nick))
			change_remote_nick(client_p, source_p, newts, nick, 1, has_propagated, has_removed);
	}
	/* we've got a collision! */
	else
		perform_nickchange_collides(source_p, client_p, target_p, newts, nick);

	return 0;
}

static int
ms_nick(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	time_t newts = 0;
	static char nick[((NICKLEN + 2) * __arraycount(source_p->name_per)) + 1];
	char *nl;

	if(parc != 9)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Dropping server %s due to (invalid) command 'NICK' "
				     "with %d arguments (expecting 9)", client_p->name, parc);
		ilog(L_SERVER, "Excess parameters (%d) for command 'NICK' from %s.",
		     parc, client_p->name);
		exit_client(client_p, client_p, client_p, "Excess parameters to NICK command");
		return 0;
	}

	rb_strlcpy(nick, parv[1], sizeof(nick));
	if((nl = strstr(nick, "\\n")) != NULL) {
		*nl = '\0';
	}

	/* if nicks empty, erroneous, or too long, kill */
	if(!valid_nick(nick, 0, 0))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad Nick: %s From: %s(via %s)",
				     nick, parv[7], client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad Nickname)", me.name, nick, me.name);
		return 0;
	}

	/* invalid username or host? */
	if(!valid_username(parv[5]) || !valid_hostname(parv[6]))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad user@host: %s@%s From: %s(via %s)",
				     parv[5], parv[6], parv[7], client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad user@host)", me.name, nick, me.name);
		return 0;
	}

	/* check the length of the clients gecos */
	if(strlen(parv[8]) > REALLEN)
	{
		parv[8] = LOCAL_COPY_N(parv[8], REALLEN);
		/* why exactly do we care? --fl */
		/* sendto_realops_flags(UMODE_ALL, L_ALL,
		 *              "Long realname from server %s for %s", parv[7],
		 *              nick);
		 * i don't care, nobody else does. --androsyn 
		 */
	}

	newts = atol(parv[3]);

	target_p = find_client(nick);

	/* if the nick doesnt exist, allow it and process like normal */
	if(target_p == NULL)
	{
		register_client(client_p, NULL, nick, newts, parc, parv);
	}
	else if(IsUnknown(target_p))
	{
		exit_client(NULL, target_p, &me, "Overridden");
		register_client(client_p, NULL, nick, newts, parc, parv);
	}
	else if(target_p == source_p)
	{
		/* client changing case of nick */
		if(strcmp(target_p->name, nick))
			register_client(client_p, NULL, nick, newts, parc, parv);
	}
	/* we've got a collision! */
	else
		perform_nick_collides(source_p, client_p, target_p, parc, parv,
				      newts, nick, NULL);

	return 0;
}

/* ms_uid()
 *     parv[1] - nickname
 *     parv[2] - hops
 *     parv[3] - TS
 *     parv[4] - umodes
 *     parv[5] - username
 *     parv[6] - hostname
 *     parv[7] - IP
 *     parv[8] - UID
 *     parv[9] - gecos
 */
static int
ms_uid(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;
	time_t newts = 0;

	newts = atol(parv[3]);

	if(parc != 10)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Dropping server %s due to (invalid) command 'UID' "
				     "with %d arguments (expecting 10)", client_p->name, parc);
		ilog(L_SERVER, "Excess parameters (%d) for command 'UID' from %s.",
		     parc, client_p->name);
		exit_client(client_p, client_p, client_p, "Excess parameters to UID command");
		return 0;
	}

	/* if nicks erroneous, or too long, kill */
	if(!valid_nick(parv[1], 0, 0))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad Nick: %s From: %s(via %s)",
				     parv[1], source_p->name, client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad Nickname)", me.id, parv[8], me.name);
		return 0;
	}

	if(!valid_username(parv[5]) || !valid_hostname(parv[6]))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad user@host: %s@%s From: %s(via %s)",
				     parv[5], parv[6], source_p->name, client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad user@host)", me.id, parv[8], me.name);
		return 0;
	}

	if(!valid_uid(parv[8]))
	{
		ServerStats.is_kill++;
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad UID: %s From: %s(via %s)",
				     parv[8], source_p->name, client_p->name);
		sendto_one(client_p, ":%s KILL %s :%s (Bad UID)", me.id, parv[8], me.name);
		return 0;
	}

	/* check length of clients gecos */
	if(strlen(parv[9]) > REALLEN)
	{
		parv[9] = LOCAL_COPY_N(parv[9], REALLEN);
	}

	target_p = find_client(parv[1]);

	if(target_p == NULL)
	{
		register_client(client_p, source_p, parv[1], newts, parc, parv);
	}
	else if(IsUnknown(target_p))
	{
		exit_client(NULL, target_p, &me, "Overridden");
		register_client(client_p, source_p, parv[1], newts, parc, parv);
	}
	/* we've got a collision! */
	else
		perform_nick_collides(source_p, client_p, target_p, parc, parv,
				      newts, parv[1], parv[8]);

	return 0;
}

/* ms_save()
 *   parv[1] - UID
 *   parv[2] - TS
 */
static int
ms_save(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Client *target_p;

	target_p = find_id(parv[1]);
	if(target_p == NULL)
		return 0;
	if(!IsClient(target_p))
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Ignored SAVE message for non-person %s from %s",
				     target_p->name, source_p->name);
	else if(IsDigit(target_p->name[0]))
		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Ignored noop SAVE message for %s from %s",
				     target_p->name, source_p->name);
	else if(target_p->tsinfo == atol(parv[2]))
		save_user(client_p, source_p, target_p);
	else
		sendto_realops_flags(UMODE_SKILL, L_ALL,
				     "Ignored SAVE message for %s from %s",
				     target_p->name, source_p->name);
	return 0;
}

static void
set_initial_nick(struct Client *client_p, struct Client *source_p, char *nick)
{
	char buf[USERLEN + 1];
	char note[NICKLEN + 10];
	/* This had to be copied here to avoid problems.. */
	source_p->tsinfo = rb_current_time();
	if(!EmptyString(source_p->name))
		del_from_hash(HASH_CLIENT, source_p->name, source_p);

	make_user(source_p);
	strcpy(source_p->user->name, nick);
	source_p->name = source_p->user->name;
	add_to_hash(HASH_CLIENT, nick, source_p);

	rb_snprintf(note, sizeof(note), "Nick: %s", nick);
	rb_note(client_p->localClient->F, note);

	if(HasSentUser(source_p))
	{
		rb_strlcpy(buf, source_p->username, sizeof(buf));

		/* got user, heres nick. */
		register_local_user(client_p, source_p, buf);

	}
}

static void
change_local_nick(struct Client *client_p, struct Client *source_p, char *nick, int dosend, int has_propagated)
{
	struct Client *target_p;
	rb_dlink_node *ptr, *next_ptr;
	char note[NICKLEN + 10];
	int samenick;

	if(dosend)
	{
		if((source_p->localClient->last_nick_change + ConfigFileEntry.max_nick_time) <
		   rb_current_time())
			source_p->localClient->number_of_nick_changes = 0;

		if(ConfigFileEntry.anti_nick_flood && !IsOper(source_p) &&
		   source_p->localClient->number_of_nick_changes > ConfigFileEntry.max_nick_changes)
		{
			sendto_one(source_p, form_str(ERR_NICKTOOFAST),
				   me.name, source_p->name, source_p->name,
				   nick, ConfigFileEntry.max_nick_time);
			return;
		}

		source_p->localClient->last_nick_change = rb_current_time();
		source_p->localClient->number_of_nick_changes++;
	}

	/* send the nick change to servers.. */
	if(!has_propagated) {
		if(source_p->user)
		{
			add_history(source_p, 1);

			if(dosend)
				sendto_server(client_p, NULL, ":%s NICK %s :%ld",
					      source_p->id, nick, (long)source_p->tsinfo);
		}
	}

	if(strstr(nick, "\\n") != NULL) {
	int nper = 0, nper_max = __arraycount(source_p->name_per);
		source_p->name_per_len = 0, source_p->name_per_cur = 0;
		for(char *p = nick, *q = strstr(p, "\\n"); p && (nper < nper_max);) {
		size_t name_per_len;
			if(q == NULL) {
				if(source_p->name_per_len == 0)
					break;
				else
					name_per_len = strlen(p);
			} else
				name_per_len = q - p;
			if(name_per_len > (__arraycount(source_p->name_per[nper]) - 1)) {
				source_p->name_per_len = 0;
				sendto_one(source_p, form_str(ERR_ERRONEUSNICKNAME), me.name, source_p->name, nick);
				break;
			} else
			if(name_per_len > 0) {
				strncpy(source_p->name_per[nper], p, name_per_len);
				source_p->name_per[nper][name_per_len] = '\0';
				if(find_client(source_p->name_per[nper]) != NULL) {
					source_p->name_per_len = 0;
					sendto_one(source_p, form_str(ERR_NICKNAMEINUSE), me.name, source_p->name, source_p->name_per[nper]);
					break;
				}
				source_p->name_per_len++, nper++;
			}
			if((p = q) != NULL)
				p = &q[strlen("\\n")], q = strstr(p, "\\n");
		}
		if(source_p->name_per_len) {
		struct membership *msptr;
		struct Channel *chptr;
			if(source_p->name_per_len < nper_max)
				source_p->name_per[source_p->name_per_len][0] = '\0';
			for(nper = 0; nper < source_p->name_per_len; nper++) {
				sendto_realops_flags(UMODE_NCHANGE, L_ALL,
						     "Nick change: From %s to %s [%s@%s]",
						     source_p->name, source_p->name_per[nper], source_p->username, source_p->host);
				RB_DLINK_FOREACH(ptr, source_p->user->channel.head) {
					msptr = ptr->data;
					chptr = msptr->chptr;
					sendto_channel_local(chptr,
						":%s NOTICE %s :%s!%s@%s adds multi-line nick line %s",
						me.name, chptr->chname,
						source_p->name, source_p->username, source_p->host,
						source_p->name_per[nper]);
				}
			}
			return;
		} else {
			source_p->name_per[0][0] = '\0';
			return;
		}
	}

	samenick = irccmp(source_p->name, nick) ? 0 : 1;

	/* dont reset TS if theyre just changing case of nick */
	if(!samenick)
	{
		/* force the TS to increase -- jilles */
		if(source_p->tsinfo >= rb_current_time())
			source_p->tsinfo++;
		else
			source_p->tsinfo = rb_current_time();
		monitor_signoff(source_p);
	}

	sendto_realops_flags(UMODE_NCHANGE, L_ALL,
			     "Nick change: From %s to %s [%s@%s]",
			     source_p->name, nick, source_p->username, source_p->host);

	/* send the nick change to the users channels */
	sendto_common_channels_local(source_p, ":%s!%s@%s NICK :%s",
				     source_p->name, source_p->username, source_p->host, nick);

	/* Finally, add to hash */
	del_from_hash(HASH_CLIENT, source_p->name, source_p);
	strcpy(source_p->user->name, nick);
	add_to_hash(HASH_CLIENT, nick, source_p);

	if(!samenick)
		monitor_signon(source_p);

	/* we used to call del_all_accepts() here, but theres no real reason
	 * to clear a clients own list of accepted clients.  So just remove
	 * them from everyone elses list --anfl
	 */
	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, source_p->on_allow_list.head)
	{
		target_p = ptr->data;

		rb_dlinkFindDestroy(source_p, &target_p->localClient->allow_list);
		rb_dlinkDestroy(ptr, &source_p->on_allow_list);
	}

	rb_snprintf(note, sizeof(note), "Nick: %s", nick);
	rb_note(client_p->localClient->F, note);

	return;
}

/*
 * change_remote_nick()
 */
static int
change_remote_nick(struct Client *client_p, struct Client *source_p,
		   time_t newts, char *nick, int dosend, int has_propagated, int has_removed)
{
	struct nd_entry *nd;
	int samenick;

	samenick = irccmp(source_p->name, nick) ? 0 : 1;

	/* client changing their nick - dont reset ts if its same */
	if(!samenick)
	{
		source_p->tsinfo = newts ? newts : rb_current_time();
		monitor_signoff(source_p);
	}

	if((source_p->name_per_len == 0) && !has_removed) {
		sendto_common_channels_local(source_p, ":%s!%s@%s NICK :%s",
					     source_p->name, source_p->username, source_p->host, nick);
	}

	if(!has_propagated) {
		if(source_p->user)
		{
			add_history(source_p, 1);
			if(dosend)
				sendto_server(client_p, NULL, ":%s NICK %s :%ld",
					      source_p->id, nick, (long)source_p->tsinfo);
		}
	}

	del_from_hash(HASH_CLIENT, source_p->name, source_p);

	/* invalidate nick delay when a remote client uses the nick.. */
	if((nd = hash_find_nd(nick)))
		free_nd_entry(nd);

	strcpy(source_p->user->name, nick);
	add_to_hash(HASH_CLIENT, nick, source_p);

	if(!samenick)
		monitor_signon(source_p);

	/* remove all accepts pointing to the client */
	del_all_accepts(source_p);

	return 0;
}

static int
perform_nick_collides(struct Client *source_p, struct Client *client_p,
		      struct Client *target_p, int parc, const char *parv[],
		      time_t newts, const char *nick, const char *uid)
{
	int sameuser;
	int use_save;
	const char *action;

	use_save = ConfigFileEntry.collision_fnc && uid != NULL;
	action = use_save ? "saved" : "killed";

	/* if we dont have a ts, or their TS's are the same, kill both */
	if(!newts || !target_p->tsinfo || (newts == target_p->tsinfo))
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Nick collision on %s(%s <- %s)(both %s)",
				     target_p->name, target_p->from->name, client_p->name, action);

		if(use_save)
		{
			save_user(&me, &me, target_p);
			ServerStats.is_save++;
			sendto_one(client_p, ":%s SAVE %s %ld", me.id, uid, (long)newts);
			register_client(client_p, source_p, uid, SAVE_NICKTS, parc, parv);
		}
		else
		{
			sendto_one_numeric(target_p, ERR_NICKCOLLISION,
					   form_str(ERR_NICKCOLLISION), target_p->name);

			/* if the new client being introduced has a UID, we need to
			 * issue a KILL for it..
			 */
			if(uid)
				sendto_one(client_p, ":%s KILL %s :%s (Nick collision (new))",
					   me.id, uid, me.name);

			/* we then need to KILL the old client everywhere */
			kill_client_serv_butone(NULL, target_p,
						"%s (Nick collision (new))", me.name);
			ServerStats.is_kill++;

			target_p->flags |= FLAGS_KILLED;
			exit_client(client_p, target_p, &me, "Nick collision (new)");
		}
		return 0;
	}
	/* the timestamps are different */
	else
	{
		sameuser = (target_p->user) && !irccmp(target_p->username, parv[5])
			&& !irccmp(target_p->host, parv[6]);

		if((sameuser && newts < target_p->tsinfo) ||
		   (!sameuser && newts > target_p->tsinfo))
		{
			/* if we have a UID, then we need to issue a KILL,
			 * otherwise we do nothing and hope that the other
			 * client will collide it..
			 */
			if(use_save)
			{
				sendto_one(client_p, ":%s SAVE %s %ld", me.id, uid, (long)newts);
				register_client(client_p, source_p, uid, SAVE_NICKTS, parc, parv);
			}
			else if(uid)
				sendto_one(client_p,
					   ":%s KILL %s :%s (Nick collision (new))",
					   me.id, uid, me.name);
			return 0;
		}
		else
		{
			if(sameuser)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick collision on %s(%s <- %s)(older %s)",
						     target_p->name, target_p->from->name,
						     client_p->name, action);
			else
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick collision on %s(%s <- %s)(newer %s)",
						     target_p->name, target_p->from->name,
						     client_p->name, action);

			if(use_save)
			{
				ServerStats.is_save++;
				save_user(&me, &me, target_p);
			}
			else
			{
				ServerStats.is_kill++;
				sendto_one_numeric(target_p, ERR_NICKCOLLISION,
						   form_str(ERR_NICKCOLLISION), target_p->name);

				/* now we just need to kill the existing client */
				kill_client_serv_butone(client_p, target_p,
							"%s (Nick collision (new))", me.name);

				target_p->flags |= FLAGS_KILLED;
				(void)exit_client(client_p, target_p, &me, "Nick collision");
			}

			register_client(client_p, parc == 10 ? source_p : NULL,
					nick, newts, parc, parv);

			return 0;
		}
	}
}


static int
perform_nickchange_collides(struct Client *source_p, struct Client *client_p,
			    struct Client *target_p, time_t newts, const char *nick)
{
	int sameuser;
	int use_save;
	const char *action;
	static char nick_[((NICKLEN + 2) * __arraycount(source_p->name_per)) + 1];

	use_save = ConfigFileEntry.collision_fnc;
	action = use_save ? "saved" : "killed";

	/* its a client changing nick and causing a collide */
	if(!newts || !target_p->tsinfo || (newts == target_p->tsinfo) || !source_p->user)
	{
		sendto_realops_flags(UMODE_ALL, L_ALL,
				     "Nick change collision from %s to %s(%s <- %s)(both %s)",
				     source_p->name, target_p->name, target_p->from->name,
				     client_p->name, action);

		if(use_save)
		{
			ServerStats.is_save += 2;
			save_user(&me, &me, target_p);
			sendto_one(client_p, ":%s SAVE %s %ld", me.id, source_p->id, (long)newts);
			/* don't send a redundant nick change */
			if(!IsDigit(source_p->name[0]))
				change_remote_nick(client_p, source_p, SAVE_NICKTS, source_p->id,
						   1, 0, 0);
		}
		else
		{
			ServerStats.is_kill++;
			sendto_one_numeric(target_p, ERR_NICKCOLLISION,
					   form_str(ERR_NICKCOLLISION), target_p->name);

			kill_client_serv_butone(NULL, source_p, "%s (Nick change collision)",
						me.name);

			ServerStats.is_kill++;

			kill_client_serv_butone(NULL, target_p, "%s (Nick change collision)",
						me.name);

			target_p->flags |= FLAGS_KILLED;
			exit_client(NULL, target_p, &me, "Nick collision(new)");
			source_p->flags |= FLAGS_KILLED;
			exit_client(client_p, source_p, &me, "Nick collision(old)");
		}
		return 0;
	}
	else
	{
		sameuser = !irccmp(target_p->username, source_p->username) &&
			!irccmp(target_p->host, source_p->host);

		if((sameuser && newts < target_p->tsinfo) ||
		   (!sameuser && newts > target_p->tsinfo))
		{
			if(sameuser)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick change collision from %s to %s(%s <- %s)(older %s)",
						     source_p->name, target_p->name,
						     target_p->from->name, client_p->name, action);
			else
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick change collision from %s to %s(%s <- %s)(newer %s)",
						     source_p->name, target_p->name,
						     target_p->from->name, client_p->name, action);

			if(use_save)
			{
				ServerStats.is_save++;
				/* can't broadcast a SAVE because the
				 * nickchange has happened at client_p
				 * but not in other directions -- jilles */
				sendto_one(client_p, ":%s SAVE %s %ld", me.id,
					   source_p->id, (long)newts);
				/* send a :<id> NICK <id> <ts> (!) */
				if(!IsDigit(source_p->name[0]))
					change_remote_nick(client_p, source_p, SAVE_NICKTS,
							   source_p->id, 1, 0, 0);
			}
			else
			{
				ServerStats.is_kill++;

				sendto_one_numeric(target_p, ERR_NICKCOLLISION,
						   form_str(ERR_NICKCOLLISION), target_p->name);

				/* kill the client issuing the nickchange */
				kill_client_serv_butone(client_p, source_p,
							"%s (Nick change collision)", me.name);

				source_p->flags |= FLAGS_KILLED;

				if(sameuser)
					exit_client(client_p, source_p, &me, "Nick collision(old)");
				else
					exit_client(client_p, source_p, &me, "Nick collision(new)");
			}
			return 0;
		}
		else
		{
			if(sameuser)
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick collision on %s(%s <- %s)(older %s)",
						     target_p->name, target_p->from->name,
						     client_p->name, action);
			else
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Nick collision on %s(%s <- %s)(newer %s)",
						     target_p->name, target_p->from->name,
						     client_p->name, action);

			if(use_save)
			{
				ServerStats.is_save++;
				save_user(&me, &me, target_p);
			}
			else
			{
				sendto_one_numeric(target_p, ERR_NICKCOLLISION,
						   form_str(ERR_NICKCOLLISION), target_p->name);

				/* kill the client who existed before hand */
				kill_client_serv_butone(client_p, target_p,
							"%s (Nick collision)", me.name);

				ServerStats.is_kill++;

				target_p->flags |= FLAGS_KILLED;
				(void)exit_client(client_p, target_p, &me, "Nick collision");
			}
		}
	}

	rb_strlcpy(nick_, nick, sizeof(nick_));
	change_remote_nick(client_p, source_p, newts, nick_, 1, 0, 0);

	return 0;
}

static int
register_client(struct Client *client_p, struct Client *server,
		const char *nick, time_t newts, int parc, const char *parv[])
{
	struct Client *source_p;
	struct User *user;
	struct nd_entry *nd;
	const char *m;
	int flag;

	source_p = make_client(client_p);
	user = make_user(source_p);

	source_p->hopcount = atoi(parv[2]);
	source_p->tsinfo = newts;

	strcpy(source_p->user->name, nick);
	source_p->name = source_p->user->name;
	rb_strlcpy(source_p->username, parv[5], sizeof(source_p->username));
	rb_strlcpy(source_p->host, parv[6], sizeof(source_p->host));

	if(parc == 10)
	{
		rb_strlcpy(source_p->info, parv[9], sizeof(source_p->info));
		rb_strlcpy(source_p->sockhost, parv[7], sizeof(source_p->sockhost));
		rb_strlcpy(source_p->id, parv[8], sizeof(source_p->id));
		add_to_hash(HASH_ID, source_p->id, source_p);
	}
	else
	{
		rb_strlcpy(source_p->info, parv[8], sizeof(source_p->info));

		if((server = find_server(NULL, parv[7])) == NULL)
		{
			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Ghost killed: %s on invalid server %s",
					     source_p->name, parv[7]);
			kill_client(client_p, source_p, "%s (Server doesn't exist)", me.name);
			free_user(source_p->user, source_p);
			free_client(source_p);
			return 0;
		}

	}

	rb_dlinkAddTail(source_p, &source_p->node, &global_client_list);

	/* server is guaranteed to exist at this point */
	source_p->servptr = server;
	rb_dlinkAdd(source_p, &source_p->lnode, &source_p->servptr->serv->users);


	/* remove any nd entries for this nick */
	if((nd = hash_find_nd(nick)))
		free_nd_entry(nd);

	add_to_hash(HASH_CLIENT, nick, source_p);
	add_to_hash(HASH_HOSTNAME, source_p->host, source_p);
	inc_global_cidr_count(source_p);
	monitor_signon(source_p);

	m = &parv[4][1];
	while(*m)
	{
		flag = UserModeBitmask(*m);

		/* increment opered count if theyre opered */
		if(!(source_p->umodes & UMODE_OPER) && (flag & UMODE_OPER))
			Count.oper++;

		source_p->umodes |= (flag & SEND_UMODES);
		m++;
	}

	SetRemoteClient(source_p);

	if(++Count.total > Count.max_tot)
		Count.max_tot = Count.total;

	/* fake direction */
	if(source_p->servptr->from != source_p->from)
	{
		struct Client *target_p = source_p->servptr->from;

		sendto_realops_flags(UMODE_DEBUG, L_ALL,
				     "Bad User [%s] :%s USER %s@%s %s, != %s[%s]",
				     client_p->name, source_p->name,
				     source_p->username, source_p->host,
				     source_p->servptr->name, target_p->name, target_p->from->name);
		kill_client(client_p, source_p,
			    "%s (NICK from wrong direction (%s != %s))",
			    me.name, source_p->servptr->name, target_p->from->name);
		source_p->flags |= FLAGS_KILLED;
		return exit_client(source_p, source_p, &me, "USER server wrong direction");
	}

	introduce_client(client_p, source_p);
	return 0;
}

static void
save_user(struct Client *client_p, struct Client *source_p, struct Client *target_p)
{
	sendto_server(client_p, NULL, ":%s SAVE %s %ld",
		      source_p->id, target_p->id, (long)target_p->tsinfo);
	if(!IsMe(client_p))
		sendto_realops_flags(UMODE_SKILL, L_ALL,
				     "Received SAVE message for %s from %s",
				     target_p->name, source_p->name);
	if(MyClient(target_p))
	{
		sendto_one_numeric(target_p, RPL_SAVENICK, form_str(RPL_SAVENICK), target_p->id);
		change_local_nick(target_p, target_p, target_p->id, 0, 0);
		target_p->tsinfo = SAVE_NICKTS;
	}
	else
		change_remote_nick(target_p, target_p, SAVE_NICKTS, target_p->id, 0, 0, 0);
}
