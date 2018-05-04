/*
 *  ircd-sandstorm: The SandNET ircd.
 *  m_mode.c: Sets a user or channel mode.
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
 *  $Id: m_mode.c 26094 2008-09-19 15:33:46Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_user.h"
#include "s_conf.h"
#include "s_serv.h"
#include "s_log.h"
#include "send.h"
#include "parse.h"
#include "modules.h"
#include "s_newconf.h"

static int m_mode(struct Client *, struct Client *, int, const char **);
static int ms_mode(struct Client *, struct Client *, int, const char **);
static int ms_tmode(struct Client *, struct Client *, int, const char **);
static int ms_rmask(struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);

struct Message mode_msgtab = {
	"MODE", 0, 0, 0, MFLG_SLOW,
	{mg_unreg, {m_mode, 2}, {m_mode, 3}, {ms_mode, 3}, mg_ignore, {m_mode, 2}}
};

struct Message tmode_msgtab = {
	"TMODE", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, {ms_tmode, 4}, {ms_tmode, 4}, mg_ignore, mg_ignore}
};

struct Message rmask_msgtab = {
	"RMASK", 0, 0, 0, MFLG_SLOW,
	{mg_ignore, mg_ignore, mg_ignore, {ms_rmask, 5}, mg_ignore, mg_ignore}
};

mapi_clist_av1 mode_clist[] = { &mode_msgtab, &tmode_msgtab, &rmask_msgtab, NULL };

DECLARE_MODULE_AV1(mode, NULL, NULL, mode_clist, NULL, NULL, "$Revision: 26094 $");

/* bitmasks for error returns, so we send once per call */
#define SM_ERR_NOTS             0x00000001	/* No TS on channel */
#define SM_ERR_NOOPS            0x00000002	/* No chan ops */
#define SM_ERR_UNKNOWN          0x00000004
#define SM_ERR_NOTONCHANNEL     0x00000040	/* Not on channel */

static void set_channel_mode(struct Client *, struct Client *,
			     struct Channel *, struct membership *, int, const char **);

static int add_id(struct Client *source_p, struct Channel *chptr,
		  char *regexid, rb_dlink_list *list, long mode_type);

static int del_id(struct Channel *chptr, const char *regexid,
		  rb_dlink_list *list, long mode_type);

static struct ChModeChange mode_changes[BUFSIZE];
static int mode_count;
static int mode_limit;
static int mask_pos;

/*
 * m_mode - MODE command handler
 * parv[0] - sender
 * parv[1] - channel
 */
static int
m_mode(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr = NULL;
	struct membership *msptr;
	int n = 2;
	const char *dest;
	int operspy = 0;

	dest = parv[1];

	if(IsOperSpy(source_p) && *dest == '!')
	{
		dest++;
		operspy = 1;

		if(EmptyString(dest))
		{
			sendto_one(source_p, form_str(ERR_NEEDMOREPARAMS),
				   me.name, source_p->name, "MODE");
			return 0;
		}
	}

	/* Now, try to find the channel in question */
	if(!IsChanPrefix(*dest))
	{
		/* if here, it has to be a non-channel name */
		user_mode(client_p, source_p, parc, parv);
		return 0;
	}

	if(!check_channel_name(dest))
	{
		sendto_one_numeric(source_p, ERR_BADCHANNAME, form_str(ERR_BADCHANNAME), parv[1]);
		return 0;
	}

	chptr = find_channel(dest);

	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}

	/* Now know the channel exists */
	if(parc < n + 1)
	{
		if(operspy)
			report_operspy(source_p, "MODE", chptr->chname);

		sendto_one(source_p, form_str(RPL_CHANNELMODEIS),
			   me.name, source_p->name, parv[1],
			   operspy ? channel_modes(chptr, &me) : channel_modes(chptr, source_p));

		sendto_one(source_p, form_str(RPL_CREATIONTIME),
			   me.name, source_p->name, parv[1], chptr->channelts);
	}
	else
	{
		msptr = find_channel_membership(chptr, source_p);

		if(is_deop(msptr))
			return 0;

		/* Finish the flood grace period... */
		if(MyClient(source_p) && !IsFloodDone(source_p))
		{
			if(!((parc == 3) && (parv[2][0] == 'b') && (parv[2][1] == '\0')))
				flood_endgrace(source_p);
		}

		set_channel_mode(client_p, source_p, chptr, msptr, parc - n, parv + n);
	}

	return 0;
}

static int
ms_mode(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr;

	chptr = find_channel(parv[1]);

	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return 0;
	}

	set_channel_mode(client_p, source_p, chptr, NULL, parc - 2, parv + 2);

	return 0;
}

static int
ms_tmode(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct Channel *chptr = NULL;
	struct membership *msptr;

	/* Now, try to find the channel in question */
	if(!IsChanPrefix(parv[2][0]) || !check_channel_name(parv[2]))
	{
		sendto_one_numeric(source_p, ERR_BADCHANNAME, form_str(ERR_BADCHANNAME), parv[2]);
		return 0;
	}

	chptr = find_channel(parv[2]);

	if(chptr == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL,
				   form_str(ERR_NOSUCHCHANNEL), parv[2]);
		return 0;
	}

	/* TS is higher, drop it. */
	if(atol(parv[1]) > chptr->channelts)
		return 0;

	if(IsServer(source_p))
	{
		set_channel_mode(client_p, source_p, chptr, NULL, parc - 3, parv + 3);
	}
	else
	{
		msptr = find_channel_membership(chptr, source_p);

		/* this can still happen on a mixed ts network. */
		if(is_deop(msptr))
			return 0;

		set_channel_mode(client_p, source_p, chptr, msptr, parc - 3, parv + 3);
	}

	return 0;
}

static int
ms_rmask(struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	static char modebuf[BUFSIZE];
	static char parabuf[BUFSIZE];
	struct Channel *chptr;
	rb_dlink_list *regexlist;
	char *s;
	char *t;
	char *mbuf;
	char *pbuf;
	long mode_type;
	int mlen;
	int plen = 0;
	int tlen;
	int arglen;
	int modecount = 0;

	if(!IsChanPrefix(parv[2][0]) || !check_channel_name(parv[2]))
		return 0;

	if((chptr = find_channel(parv[2])) == NULL)
		return 0;

	/* TS is higher, drop it. */
	if(atol(parv[1]) > chptr->channelts)
		return 0;

	switch (parv[3][0])
	{
	case 'b':
		regexlist = &chptr->regexlist;
		mode_type = CHFL_REGEX;
		break;

	case 'e':
		regexlist = &chptr->regex_exlist;
		mode_type = CHFL_REGEX_EX;
		break;

		/* maybe we should just blindly propagate this? */
	default:
		return 0;
	}

	parabuf[0] = '\0';
	s = LOCAL_COPY(parv[4]);

	mlen = rb_sprintf(modebuf, ":%s MODE %s +", source_p->name, chptr->chname);
	mbuf = modebuf + mlen;
	pbuf = parabuf;

	while(*s == ' ')
		s++;

	/* next char isnt a space, point t to next one */
	if((t = strchr(s, ' ')) != NULL)
	{
		*t++ = '\0';

		/* double spaces break parser */
		while(*t == ' ')
			t++;
	}

	/* couldve skipped spaces and got nothing.. */
	while(!EmptyString(s))
	{
		/* ban with a leading ':' -- this will break the protocol */
		if(*s == ':')
			goto nextregex;

		tlen = strlen(s);

		/* I dont even want to begin parsing this.. */
		if(tlen > MODEBUFLEN)
			break;

		if(add_id(source_p, chptr, s, regexlist, mode_type))
		{
			/* this new one wont fit.. */
			if(mlen + MAXMODEPARAMS + plen + tlen > BUFSIZE - 5 ||
			   modecount >= MAXMODEPARAMS)
			{
				*mbuf = '\0';
				*(pbuf - 1) = '\0';
				sendto_channel_local(chptr, "%s %s", modebuf, parabuf);

				mbuf = modebuf + mlen;
				pbuf = parabuf;
				plen = modecount = 0;
			}

			*mbuf++ = parv[3][0];
			arglen = rb_sprintf(pbuf, "%s ", s);
			pbuf += arglen;
			plen += arglen;
			modecount++;
		}

	      nextregex:
		s = t;

		if(s != NULL)
		{
			if((t = strchr(s, ' ')) != NULL)
			{
				*t++ = '\0';

				while(*t == ' ')
					t++;
			}
		}
	}

	if(modecount)
	{
		*mbuf = '\0';
		*(pbuf - 1) = '\0';
		sendto_channel_local(chptr, "%s %s", modebuf, parabuf);
	}

	sendto_server(client_p, chptr, ":%s RMASK %ld %s %s :%s",
		      source_p->id, (long)chptr->channelts, chptr->chname, parv[3], parv[4]);
	return 0;
}

/* add_id()
 *
 * inputs	- client, channel, id to add, type
 * outputs	- 0 on failure, 1 on success
 * side effects - given id is added to the appropriate list
 */
static int
add_id(struct Client *source_p, struct Channel *chptr, char *regexid,
       rb_dlink_list *list, long mode_type)
{
	char *p, *posstr;
	struct Regex *actualRegex;
	static char who[REGEXLEN];
	rb_dlink_node *ptr, *ptr_before = NULL;
	int pos = 0, n = 0;

	for(p = regexid; *p && IsDigit(*p); p++);
	if(regexid < p)
	{
		if(':' != *p)
			return 0;

		if(0 == (pos = atoi(posstr = LOCAL_COPY_N(regexid, p - regexid))))
			 pos++;

		++p, memmove(regexid, p, 1 + strlen(p));
	}

	/* dont let local clients overflow the regexlist
	 */
	if(MyClient(source_p))
	{
		if(rb_dlink_list_length(&chptr->regexlist) >=
		   (unsigned long)ConfigChannel.max_regex)
		{
			sendto_one(source_p, form_str(ERR_REGEXLISTFULL),
				   me.name, source_p->name, chptr->chname, regexid);
			return 0;
		}

		RB_DLINK_FOREACH(ptr, list->head)
		{
			actualRegex = ptr->data;
			if(!strcmp(actualRegex->regexstr, regexid))
				return 0;
		}

	}
	/* dont let remotes set duplicates */
	else
	{
		RB_DLINK_FOREACH(ptr, list->head)
		{
			actualRegex = ptr->data;
			if(!strcmp(actualRegex->regexstr, regexid))
				return 0;
		}
	}

	if(IsClient(source_p))
		rb_sprintf(who, "%s!%s@%s", source_p->name, source_p->username, source_p->host);
	else
		rb_strlcpy(who, source_p->name, sizeof(who));

	if(NULL == (actualRegex = allocate_regex(regexid, who, mode_type)))
		return 0;

	actualRegex->when = rb_current_time();

	if(pos)
	{
		RB_DLINK_FOREACH(ptr, list->head)
		{
			if ((++n) == pos)
			{
				ptr_before = ptr;
				break;
			}
		}

		if(NULL != ptr_before)
		{
			rb_dlinkAddBefore(ptr_before, actualRegex, &actualRegex->node, list);
			goto out;
		}
	}

	rb_dlinkAddTail(actualRegex, &actualRegex->node, list);

out:	return 1;
}

/* del_id()
 *
 * inputs	- channel, id to remove, type
 * outputs	- 0 on failure, 1 on success
 * side effects - given id is removed from the appropriate list
 */
static int
del_id(struct Channel *chptr, const char *regexid, rb_dlink_list *list, long mode_type)
{
	rb_dlink_node *ptr;
	struct Regex *regexptr;

	if(EmptyString(regexid))
		return 0;

	RB_DLINK_FOREACH(ptr, list->head)
	{
		regexptr = ptr->data;

		if(strcmp(regexid, regexptr->regexstr) == 0)
		{
			rb_dlinkDelete(&regexptr->node, list);
			free_regex(regexptr);

			return 1;
		}
	}

	return 0;
}

/* chm_*()
 *
 * The handlers for each specific mode.
 */
static void
chm_nosuch(struct Client *source_p, struct Channel *chptr,
	   int alevel, int parc, int *parn,
	   const char **parv, int *errors, int dir, char c, long mode_type)
{
	if(*errors & SM_ERR_UNKNOWN)
		return;
	*errors |= SM_ERR_UNKNOWN;
	sendto_one(source_p, form_str(ERR_UNKNOWNMODE), me.name, source_p->name, c);
}

static void
chm_op(struct Client *source_p, struct Channel *chptr,
       int alevel, int parc, int *parn,
       const char **parv, int *errors, int dir, char c, long mode_type)
{
	struct membership *mstptr;
	const char *opnick;
	struct Client *targ_p;

	if((dir == MODE_QUERY) || (parc <= *parn))
		return;

	opnick = parv[(*parn)];
	(*parn)++;

	/* empty nick */
	if(EmptyString(opnick))
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), "*");
		return;
	}

	if((targ_p = find_chasing(source_p, opnick, NULL)) == NULL)
	{
		return;
	}

	mstptr = find_channel_membership(chptr, targ_p);

	if(mstptr == NULL)
	{
		if(!(*errors & SM_ERR_NOTONCHANNEL) && MyClient(source_p))
			sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
					   form_str(ERR_USERNOTINCHANNEL), opnick, chptr->chname);
		*errors |= SM_ERR_NOTONCHANNEL;
		return;
	}

	if(MyClient(source_p) && (++mode_limit > MAXMODEPARAMS))
		return;

	if(dir == MODE_ADD)
	{
		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_ADD;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = targ_p->id;
		mode_changes[mode_count].arg = targ_p->name;
		mode_changes[mode_count++].client = targ_p;

		mstptr->flags |= CHFL_CHANOP;
		mstptr->flags &= ~CHFL_DEOPPED;
	}
	else
	{
		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_DEL;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = targ_p->id;
		mode_changes[mode_count].arg = targ_p->name;
		mode_changes[mode_count++].client = targ_p;

		mstptr->flags &= ~CHFL_CHANOP;
	}
}

static void
chm_voice(struct Client *source_p, struct Channel *chptr,
	  int alevel, int parc, int *parn,
	  const char **parv, int *errors, int dir, char c, long mode_type)
{
	struct membership *mstptr;
	const char *opnick;
	struct Client *targ_p;

	if((dir == MODE_QUERY) || parc <= *parn)
		return;

	opnick = parv[(*parn)];
	(*parn)++;

	/* empty nick */
	if(EmptyString(opnick))
	{
		sendto_one_numeric(source_p, ERR_NOSUCHNICK, form_str(ERR_NOSUCHNICK), "*");
		return;
	}

	if((targ_p = find_chasing(source_p, opnick, NULL)) == NULL)
	{
		return;
	}

	mstptr = find_channel_membership(chptr, targ_p);

	if(mstptr == NULL)
	{
		if(!(*errors & SM_ERR_NOTONCHANNEL) && MyClient(source_p))
			sendto_one_numeric(source_p, ERR_USERNOTINCHANNEL,
					   form_str(ERR_USERNOTINCHANNEL), opnick, chptr->chname);
		*errors |= SM_ERR_NOTONCHANNEL;
		return;
	}

	if(MyClient(source_p) && (++mode_limit > MAXMODEPARAMS))
		return;

	if(dir == MODE_ADD)
	{
		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_ADD;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = targ_p->id;
		mode_changes[mode_count].arg = targ_p->name;
		mode_changes[mode_count++].client = targ_p;

		if('v' == c)
			mstptr->flags |= CHFL_VOICE;
		else	mstptr->flags_crazy[(int) c] = 1;
	}
	else
	{
		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_DEL;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = targ_p->id;
		mode_changes[mode_count].arg = targ_p->name;
		mode_changes[mode_count++].client = targ_p;

		if('v' == c)
			mstptr->flags &= ~CHFL_VOICE;
		else	mstptr->flags_crazy[(int) c] = 0;
	}
}

static void
chm_limit(struct Client *source_p, struct Channel *chptr,
	  int alevel, int parc, int *parn,
	  const char **parv, int *errors, int dir, char c, long mode_type)
{
	if(dir == MODE_QUERY)
		return;
}

static void
chm_operonly(struct Client *source_p, struct Channel *chptr,
	    int alevel, int parc, int *parn,
	    const char **parv, int *errors, int dir, char c, long mode_type)
{
	char modec;

	switch(mode_type) {
	case MODE_OPERONLY: modec = 'P'; break;
	case MODE_REGEX: modec = 'R'; break;
	case MODE_SSLONLY: modec = 'S'; break;
	case MODE_XCHGSENDER: modec = 'X'; break;
	default:
		sendto_realops_flags(UMODE_ALL, L_ALL,
			"chm_operonly() called with unknown mode %lu", mode_type);
		return;
	}

	if(!IsOper(source_p))
	{
		if(!(*errors & SM_ERR_NOOPS))
			sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		*errors |= SM_ERR_NOOPS;
		return;
	}

	if(dir == MODE_QUERY)
		return;

	if(((dir == MODE_ADD) && (chptr->mode.mode & mode_type)) ||
	   ((dir == MODE_DEL) && !(chptr->mode.mode & mode_type)))
		return;

	/* do not allow our clients to set use_sslonly if it is disabled
	 * we do however allow them to remove it if it gets set 
	 */
	if((mode_type == MODE_SSLONLY) &&
	dir == MODE_ADD && MyClient(source_p) && ConfigChannel.use_sslonly == FALSE)
		return;

	if(dir == MODE_ADD)
		chptr->mode.mode |= mode_type;
	else
		chptr->mode.mode &= ~mode_type;

	if(dir == MODE_ADD || dir == MODE_DEL)
		sendto_realops_flags(UMODE_FULL, L_ALL,
			"%s (%s@%s) set CMODE %c%c on channel %s",
			source_p->name, source_p->username, source_p->host,
			(dir == MODE_ADD ? '+' : '-'), modec, chptr->chname);

	mode_changes[mode_count].letter = c;
	mode_changes[mode_count].dir = dir;
	mode_changes[mode_count].caps = 0;
	mode_changes[mode_count].nocaps = 0;
	mode_changes[mode_count].id = NULL;
	mode_changes[mode_count++].arg = NULL;
}

static void
chm_regex(struct Client *source_p, struct Channel *chptr,
	int alevel, int parc, int *parn,
	const char **parv, int *errors, int dir, char c, long mode_type)
{
	char *mask;
	rb_dlink_list *list;
	rb_dlink_node *ptr;
	struct Regex *regexptr;
	int rpl_list;
	int rpl_endlist;

	switch (mode_type)
	{
	case CHFL_REGEX:
		list = &chptr->regexlist;
		rpl_list = RPL_BANLIST;
		rpl_endlist = RPL_ENDOFBANLIST;
		break;

	case CHFL_REGEX_EX:
		list = &chptr->regex_exlist;
		rpl_list = RPL_EXCEPTLIST;
		rpl_endlist = RPL_ENDOFEXCEPTLIST;
		break;

	default:
		sendto_realops_flags(UMODE_ALL, L_ALL, "chm_regex() called with unknown type!");
		return;
		break;
	}

	if(dir == 0 || parc <= *parn)
	{
		RB_DLINK_FOREACH(ptr, list->head)
		{
			regexptr = ptr->data;
			sendto_one(source_p, form_str(rpl_list),
				me.name, source_p->name, chptr->chname,
				regexptr->regexstr, regexptr->who,
				regexptr->when);
		}
		sendto_one(source_p, form_str(rpl_endlist),
				me.name, source_p->name, chptr->chname);
		return;
	}

	if(!IsOper(source_p))
	{
		if(!(*errors & SM_ERR_NOOPS))
			sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
		*errors |= SM_ERR_NOOPS;
		return;
	}

	if(MyClient(source_p) && (++mode_limit > MAXMODEPARAMS))
		return;

	mask = parv[(*parn)];
	(*parn)++;

	/* empty ban, or starts with ':' which messes up s2s, ignore it */
	if(EmptyString(mask) || *mask == ':')
		return;

	if(!MyClient(source_p))
	{
		if(strchr(mask, ' '))
			return;
	}
	else
	for(const char *q = mask; *q; ++q)
	{
		if(IsSpace(*q))
		{
			return;
		}
	}

	/* we'd have problems parsing this, hyb6 does it too */
	if(strlen(mask) > (MODEBUFLEN - 2))
		return;

	/* if we're adding a NEW id */
	if(dir == MODE_ADD)
	{
		/* dont allow local clients to overflow the regexlist, dont
		 * let remote servers set duplicate regexs
		 */
		if(!add_id(source_p, chptr, mask, list, mode_type))
			return;

		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_ADD;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = NULL;
		mode_changes[mode_count++].arg = mask;
	}
	else if(dir == MODE_DEL)
	{
		del_id(chptr, mask, list, mode_type);

		mode_changes[mode_count].letter = c;
		mode_changes[mode_count].dir = MODE_DEL;
		mode_changes[mode_count].caps = 0;
		mode_changes[mode_count].nocaps = 0;
		mode_changes[mode_count].id = NULL;
		mode_changes[mode_count++].arg = mask;
	}
}


struct ChannelMode
{
	void (*func) (struct Client * source_p, struct Channel * chptr,
		      int alevel, int parc, int *parn,
		      const char **parv, int *errors, int dir, char c, long mode_type);
	long mode_type;
};

/* *INDENT-OFF* */
static struct ChannelMode ModeTable[255] =
{
  {chm_nosuch,	0 },
  {chm_nosuch,  0 },			/* A */
  {chm_voice,	0 },			/* B */
  {chm_voice,	0 },			/* C */
  {chm_voice,	0 },			/* D */
  {chm_voice,	0 },			/* E */
  {chm_voice,	0 },			/* F */
  {chm_voice,	0 },			/* G */
  {chm_nosuch,	0 },			/* H */
  {chm_nosuch,	0 },                    /* I */
  {chm_nosuch,	0 },			/* J */
  {chm_nosuch,	0 },			/* K */
  {chm_nosuch,	0 },			/* L */
  {chm_nosuch,	0 },			/* M */
  {chm_nosuch,	0 },			/* N */
  {chm_nosuch,	0 },			/* O */
  {chm_operonly,  MODE_OPERONLY },	/* P */
  {chm_nosuch,	0 },			/* Q */
  {chm_operonly,  MODE_REGEX },		/* R */
  {chm_operonly,  MODE_SSLONLY },       /* S */
  {chm_nosuch,	0 },			/* T */
  {chm_nosuch,	0 },			/* U */
  {chm_nosuch,  0 },			/* V */
  {chm_nosuch,	0 },			/* W */
  {chm_operonly,  MODE_XCHGSENDER },	/* X */
  {chm_nosuch,	0 },			/* Y */
  {chm_nosuch,	0 },			/* Z */
  {chm_nosuch,	0 },
  {chm_nosuch,	0 },
  {chm_nosuch,	0 },
  {chm_nosuch,	0 },
  {chm_nosuch,	0 },
  {chm_nosuch,	0 },
  {chm_voice,	0 },			/* a */
  {chm_regex,	CHFL_REGEX },		/* b */
  {chm_voice,	0 },			/* c */
  {chm_voice,	0 },			/* d */
  {chm_regex,	CHFL_REGEX_EX },	/* e */
  {chm_voice,	0 },			/* f */
  {chm_voice,	0 },			/* g */
  {chm_voice,	0 },			/* h */
  {chm_voice,	0 },			/* i */
  {chm_voice,	0 },			/* j */
  {chm_voice,	0 },			/* k */
  {chm_limit,	0 },			/* l */
  {chm_voice,	0 },			/* m */
  {chm_voice,	0 },			/* n */
  {chm_op,	0 },			/* o */
  {chm_voice,	0 },			/* p */
  {chm_voice,	0 },			/* q */
  {chm_voice,   0 },			/* r */
  {chm_voice,	0 },			/* s */
  {chm_voice,	0 },			/* t */
  {chm_voice,	0 },			/* u */
  {chm_voice,	0 },			/* v */
  {chm_voice,	0 },			/* w */
  {chm_voice,	0 },			/* x */
  {chm_voice,	0 },			/* y */
  {chm_voice,	0 },			/* z */
};
/* *INDENT-ON* */

/* set_channel_mode()
 *
 * inputs	- client, source, channel, membership pointer, params
 * output	- 
 * side effects - channel modes/memberships are changed, MODE is issued
 */
void
set_channel_mode(struct Client *client_p, struct Client *source_p,
		 struct Channel *chptr, struct membership *msptr, int parc, const char *parv[])
{
	static char modebuf[BUFSIZE];
	static char parabuf[BUFSIZE];
	char *mbuf;
	char *pbuf;
	int cur_len, mlen, paralen, paracount, arglen, len;
	int dir = MODE_ADD;
	int parn = 1;
	int errors = 0;
	int alevel;
	const char *ml = parv[0];
	char c;
	int table_position;

	mask_pos = 0;
	mode_count = 0;
	mode_limit = 0;

	alevel = CHFL_CHANOP;

	for(; (c = *ml) != 0; ml++)
	{
		switch (c)
		{
		case '+':
			dir = MODE_ADD;
			break;
		case '-':
			dir = MODE_DEL;
			break;
		case '=':
			dir = MODE_QUERY;
			break;
		default:
			if(c < 'A' || c > 'z')
				table_position = 0;
			else
				table_position = c - 'A' + 1;
			ModeTable[table_position].func(source_p, chptr, alevel,
						       parc, &parn, parv,
						       &errors, dir, c,
						       ModeTable[table_position].mode_type);
			break;
		}
	}

	/* bail out if we have nothing to do... */
	if(!mode_count)
		return;

	if(IsServer(source_p))
		mlen = rb_sprintf(modebuf, ":%s MODE %s ", source_p->name, chptr->chname);
	else
		mlen = rb_sprintf(modebuf, ":%s!%s@%s MODE %s ",
				  source_p->name, source_p->username,
				  source_p->host, chptr->chname);

	{
		cur_len = mlen;
		mbuf = modebuf + mlen;
		pbuf = parabuf;
		parabuf[0] = '\0';
		paracount = paralen = 0;
		dir = MODE_QUERY;

		for(int i = 0; i < mode_count; i++)
		{
			if(mode_changes[i].letter == 0)
				continue;

			if(mode_changes[i].arg != NULL)
			{
				arglen = strlen(mode_changes[i].arg);

				if(arglen > MODEBUFLEN - 5)
					continue;
			}
			else
				arglen = 0;

			/* if we're creeping over MAXMODEPARAMSSERV, or over
			 * bufsize (4 == +/-,modechar,two spaces) send now.
			 */
			if(mode_changes[i].arg != NULL &&
			   ((paracount == MAXMODEPARAMSSERV) ||
			    ((cur_len + paralen + arglen + 4) > (BUFSIZE - 3))))
			{
				*mbuf = '\0';

				if(cur_len > mlen)
					sendto_channel_local(chptr, "%s %s", modebuf,
							     parabuf);
				else
					continue;

				paracount = paralen = 0;
				cur_len = mlen;
				mbuf = modebuf + mlen;
				pbuf = parabuf;
				parabuf[0] = '\0';
				dir = MODE_QUERY;
			}

			if(dir != mode_changes[i].dir)
			{
				*mbuf++ = (mode_changes[i].dir == MODE_ADD) ? '+' : '-';
				cur_len++;
				dir = mode_changes[i].dir;
			}

			*mbuf++ = mode_changes[i].letter;
			cur_len++;

			if(mode_changes[i].arg != NULL)
			{
				paracount++;
				len = rb_sprintf(pbuf, "%s ", mode_changes[i].arg);
				pbuf += len;
				paralen += len;
			}
		}

		if(paralen && parabuf[paralen - 1] == ' ')
			parabuf[paralen - 1] = '\0';

		*mbuf = '\0';
		if(cur_len > mlen)
			sendto_channel_local(chptr, "%s %s", modebuf, parabuf);
	}

	/* only propagate modes originating locally, or if we're hubbing */
	if(MyClient(source_p) || rb_dlink_list_length(&serv_list) > 1)
		send_cap_mode_changes(client_p, source_p, chptr, mode_changes, mode_count);
}
