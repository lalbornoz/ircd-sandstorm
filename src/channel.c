/*
 *  ircd-ratbox: A slightly useful ircd.
 *  channel.c: Controls channels.
 *
 * Copyright (C) 1990 Jarkko Oikarinen and University of Oulu, Co Center 
 * Copyright (C) 1996-2002 Hybrid Development Team 
 * Copyright (C) 2002-2005 ircd-ratbox development team 
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
 *  $Id: channel.c 26094 2008-09-19 15:33:46Z androsyn $
 */

#include "stdinc.h"
#include "struct.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "hook.h"
#include "match.h"
#include "ircd.h"
#include "numeric.h"
#include "s_serv.h"		/* captab */
#include "s_user.h"
#include "send.h"
#include "whowas.h"
#include "s_conf.h"		/* ConfigFileEntry, ConfigChannel */
#include "s_newconf.h"
#include "s_log.h"

#include <regex.h>

struct config_channel_entry ConfigChannel;
rb_dlink_list global_channel_list;
static rb_bh *channel_heap;
static rb_bh *topic_heap;
static rb_bh *member_heap;
static rb_bh *regex_heap;
struct ev_entry *checksplit_ev;

static int channel_capabs[] = {
	CAP_TS6
};

#define NCHCAPS         (sizeof(channel_capabs)/sizeof(int))
#define NCHCAP_COMBOS   (1 << NCHCAPS)

static struct ChCapCombo chcap_combos[NCHCAP_COMBOS];

char crazy_cmode_tbl[CRAZY_CMODES] =
{
/*  0*/'\0', '\0', '\0', '\0',    '\0', '\0', '\0', '\0',
/*  8*/'\0', '\0', '\0', '\0',    '\0', '\0', '\0', '\0',
/* 16*/'\0', '\0', '\0', '\0',    '\0', '\0', '\0', '\0',
/* 24*/'\0', '\0', '\0', '\0',    '\0', '\0', '\0', '\0',
/* 32*/'\0',
       '\0',				/* ! */
       '\0',				/* " */
       '\0',				/* # */
       '\0',				/* $ */
       '\0',				/* % */
       '\0',				/* & */
       '\0',				/* ' */
       '\0',				/* ( */
       '\0',				/* ) */
       '\0',				/* * */
       '\0',				/* + */
       '\0',				/* , */
       '\0',				/* - */
       '\0',				/* . */
       '\0',				/* / */
       '\0',				/* 0 */
       '\0',				/* 1 */
       '\0',				/* 2 */
       '\0',				/* 3 */
       '\0',				/* 4 */
       '\0',				/* 5 */
       '\0',				/* 6 */
       '\0',				/* 7 */
       '\0',				/* 8 */
       '\0',				/* 9 */
       '\0',				/* : */
       '\0',				/* ; */
       '\0',				/* < */
       '\0',				/* = */
       '\0',				/* > */
       '\0',				/* ? */
       '\0',				/* @ */
       '.',				/* A */
       '<',				/* B */
       '>',				/* C */
       ';',				/* D */
       ':',				/* E */
       '|',				/* F */
       '\0',				/* G */
       '\0',				/* H */
       '\0',				/* I */
       '\0',				/* J */
       '\0',				/* K */
       '\0',				/* L */
       '\0',				/* M */
       '\0',				/* N */
       '\0',				/* O */
       '\0',				/* P */
       '\0',				/* Q */
       '\0',				/* R */
       '\0',				/* S */
       '\0',				/* T */
       '\0',				/* U */
       '\0',				/* V */
       '\0',				/* W */
       '\0',				/* X */
       '\0',				/* Y */
       '\0',				/* Z */
       '\0',				/* [ */
       '\0',				/* \ */
       '\0',				/* ] */
       '\0',				/* ^ */
       '\0',				/* _ */
       '\0',				/* ` */
       '!',				/* a */
       '\0',				/* b */
       '#',				/* c */
       '$',				/* d */
       '%',				/* e */
       '^',				/* f */
       '&',				/* g */
       '*',				/* h */
       '(',				/* i */
       ')',				/* j */
       '~',				/* k */
       '\0',				/* l */
       '+',				/* m */
       '_',				/* n */
       '\0',				/* o */
       '`',				/* p */
       '=',				/* q */
       '\'',				/* r */
       '\\',				/* s */
       ']',				/* t */
       '[',				/* u */
       '\0',				/* v */
       '{',				/* w */
       '}',				/* x */
       '/',				/* y */
       '?',				/* z */
       '\0',				/* { */
       '\0',				/* | */
       '\0',				/* } */
       '\0',				/* ~ */
/*127*/0,
};

static void free_topic(struct Channel *chptr);

/* init_channels()
 *
 * input	-
 * output	-
 * side effects - initialises the various blockheaps
 */
void
init_channels(void)
{
	channel_heap = rb_bh_create(sizeof(struct Channel), CHANNEL_HEAP_SIZE, "channel_heap");
	topic_heap = rb_bh_create(sizeof(struct topic_info), TOPIC_HEAP_SIZE, "topic_heap");
	member_heap = rb_bh_create(sizeof(struct membership), MEMBER_HEAP_SIZE, "member_heap");
	regex_heap = rb_bh_create(sizeof(struct Regex), REGEX_HEAP_SIZE, "regex_heap");
}

/*
 * allocate_channel - Allocates a channel
 */
struct Channel *
allocate_channel(const char *chname)
{
	struct Channel *chptr;
	chptr = rb_bh_alloc(channel_heap);
	chptr->chname = rb_strndup(chname, CHANNELLEN);
	return (chptr);
}

void
free_channel(struct Channel *chptr)
{
	rb_free(chptr->chname);
	rb_bh_free(channel_heap, chptr);
}

struct Regex *
allocate_regex(const char *regexstr, const char *who)
{
	struct Regex *rptr;
	char *pat = rb_strndup(regexstr, REGEXLEN), *subst = NULL, *p;

	regex_t reg;

	if('/' != *pat)
		goto inval;

	for(p = subst = pat + 1; '\0' != *p; p++)
	{
		int slash = 0;

		if('/' == *p)
		{
			for(char *q = p - 1; q >= pat; q--)
				if('\\' == *q)
					slash++;
				else	break;

			if(0 == (slash % 2))
			{
				*p++ = '\0', subst = p;
				break;
			}
		}
	}

	if(0 != regcomp(&reg, pat, REG_EXTENDED))
		goto inval;

	rptr = rb_bh_alloc(regex_heap);
	rptr->regexstr = rb_strndup(regexstr, REGEXLEN);
	rptr->pat = pat;
	rptr->subst = rb_strndup(subst, REGEXLEN);
	rptr->reg = reg;
	rptr->who = rb_strndup(who, REGEXLEN);

	return (rptr);

inval:	rb_free(pat); return NULL;
}

void
free_regex(struct Regex *rptr)
{
	rb_free(rptr->regexstr);
	rb_free(rptr->pat);
	rb_free(rptr->subst);
	rb_free(rptr->who);
	rb_bh_free(regex_heap, rptr);
}


/* find_channel_membership()
 *
 * input	- channel to find them in, client to find
 * output	- membership of client in channel, else NULL
 * side effects	-
 */
struct membership *
find_channel_membership(struct Channel *chptr, struct Client *client_p)
{
	struct membership *msptr;
	rb_dlink_node *ptr;

	if(!IsClient(client_p))
		return NULL;

	/* Pick the most efficient list to use to be nice to things like
	 * CHANSERV which could be in a large number of channels
	 */
	if(rb_dlink_list_length(&chptr->members) < rb_dlink_list_length(&client_p->user->channel))
	{
		RB_DLINK_FOREACH(ptr, chptr->members.head)
		{
			msptr = ptr->data;

			if(msptr->client_p == client_p)
				return msptr;
		}
	}
	else
	{
		RB_DLINK_FOREACH(ptr, client_p->user->channel.head)
		{
			msptr = ptr->data;

			if(msptr->chptr == chptr)
				return msptr;
		}
	}

	return NULL;
}

/* find_channel_status()
 *
 * input	- membership to get status for, whether we can combine flags
 * output	- flags of user on channel
 * side effects -
 */
const char *
find_channel_status(struct membership *msptr, int combine)
{
	static char buffer[3 + CRAZY_CMODES];
	char *p;

	p = buffer;

	if(is_chanop(msptr))
	{
		if(!combine)
			return "@";
		*p++ = '@';
	}

	if(is_voiced(msptr))
		*p++ = '+';

	for(uint8_t c = 0; c < CRAZY_CMODES; c++)
		if (0 != msptr->flags_crazy[c])
			*p++ = crazy_cmode_tbl[c];

	*p = '\0';
	return buffer;
}

/* add_user_to_channel()
 *
 * input	- channel to add client to, client to add, channel flags
 * output	- 
 * side effects - user is added to channel
 */
void
add_user_to_channel(struct Channel *chptr, struct Client *client_p, int flags)
{
	struct membership *msptr;

	s_assert(client_p->user != NULL);
	if(client_p->user == NULL)
		return;

	msptr = rb_bh_alloc(member_heap);

	msptr->chptr = chptr;
	msptr->client_p = client_p;
	msptr->flags = flags;

	rb_dlinkAdd(msptr, &msptr->usernode, &client_p->user->channel);
	rb_dlinkAdd(msptr, &msptr->channode, &chptr->members);

	if(MyClient(client_p))
		rb_dlinkAdd(msptr, &msptr->locchannode, &chptr->locmembers);
}

/* remove_user_from_channel()
 *
 * input	- membership pointer to remove from channel
 * output	-
 * side effects - membership (thus user) is removed from channel
 */
void
remove_user_from_channel(struct membership *msptr)
{
	struct Client *client_p;
	struct Channel *chptr;
	s_assert(msptr != NULL);
	if(msptr == NULL)
		return;

	client_p = msptr->client_p;
	chptr = msptr->chptr;

	rb_dlinkDelete(&msptr->usernode, &client_p->user->channel);
	rb_dlinkDelete(&msptr->channode, &chptr->members);

	if(client_p->servptr == &me)
		rb_dlinkDelete(&msptr->locchannode, &chptr->locmembers);

	if(rb_dlink_list_length(&chptr->members) <= 0)
		destroy_channel(chptr);

	rb_bh_free(member_heap, msptr);

	return;
}

/* remove_user_from_channels()
 *
 * input        - user to remove from all channels
 * output       -
 * side effects - user is removed from all channels
 */
void
remove_user_from_channels(struct Client *client_p)
{
	struct Channel *chptr;
	struct membership *msptr;
	rb_dlink_node *ptr;
	rb_dlink_node *next_ptr;

	if(client_p == NULL)
		return;

	RB_DLINK_FOREACH_SAFE(ptr, next_ptr, client_p->user->channel.head)
	{
		msptr = ptr->data;
		chptr = msptr->chptr;

		rb_dlinkDelete(&msptr->channode, &chptr->members);

		if(client_p->servptr == &me)
			rb_dlinkDelete(&msptr->locchannode, &chptr->locmembers);

		if(rb_dlink_list_length(&chptr->members) <= 0)
			destroy_channel(chptr);

		rb_bh_free(member_heap, msptr);
	}

	client_p->user->channel.head = client_p->user->channel.tail = NULL;
	client_p->user->channel.length = 0;
}

/* check_channel_name()
 *
 * input	- channel name
 * output	- 1 if valid channel name, else 0
 * side effects -
 */
int
check_channel_name(const char *name)
{
	s_assert(name != NULL);
	if(name == NULL)
		return 0;

	for(; *name; ++name)
	{
		if(!IsChanChar(*name))
			return 0;
	}

	return 1;
}

/* destroy_channel()
 *
 * input	- channel to destroy
 * output	-
 * side effects - channel is obliterated
 */
void
destroy_channel(struct Channel *chptr)
{
	rb_dlink_node *ptr, *next_ptr;

	/* Free the topic */
	free_topic(chptr);

	rb_dlinkDelete(&chptr->node, &global_channel_list);
	del_from_hash(HASH_CHANNEL, chptr->chname, chptr);
	free_channel(chptr);
}

/* channel_pub_or_secret()
 *
 * input	- channel
 * output	- "=" (public)
 * side effects	-
 */
static const char *
channel_pub_or_secret(struct Channel *chptr)
{
	return ("=");
}

/* channel_member_names()
 *
 * input	- channel to list, client to list to, show endofnames
 * output	-
 * side effects - client is given list of users on channel
 */
void
channel_member_names(struct Channel *chptr, struct Client *client_p, int show_eon)
{
	struct membership *msptr;
	struct Client *target_p;
	rb_dlink_node *ptr;
	char lbuf[BUFSIZE];
	char *t;
	int mlen;
	int tlen;
	int cur_len;
	int is_member;
	int stack = IsCapable(client_p, CLICAP_MULTI_PREFIX);
	SetCork(client_p);
	{
		is_member = IsMember(client_p, chptr);

		cur_len = mlen = rb_sprintf(lbuf, form_str(RPL_NAMREPLY),
					    me.name, client_p->name,
					    channel_pub_or_secret(chptr), chptr->chname);

		t = lbuf + cur_len;

		RB_DLINK_FOREACH(ptr, chptr->members.head)
		{
			msptr = ptr->data;
			target_p = msptr->client_p;

			/* space, possible "@+" prefix */
			if(cur_len + strlen(target_p->name) + 3 >= BUFSIZE - 3)
			{
				*(t - 1) = '\0';
				sendto_one_buffer(client_p, lbuf);
				cur_len = mlen;
				t = lbuf + mlen;
			}

			tlen = rb_sprintf(t, "%s%s ", find_channel_status(msptr, stack),
					  target_p->name);

			cur_len += tlen;
			t += tlen;
		}

		/* The old behaviour here was to always output our buffer,
		 * even if there are no clients we can show.  This happens
		 * when a client does "NAMES" with no parameters, and all
		 * the clients on a -sp channel are +i.  I dont see a good
		 * reason for keeping that behaviour, as it just wastes
		 * bandwidth.  --anfl
		 */
		if(cur_len != mlen)
		{
			*(t - 1) = '\0';
			sendto_one_buffer(client_p, lbuf);
		}
	}

	if(show_eon)
		sendto_one(client_p, form_str(RPL_ENDOFNAMES),
			   me.name, client_p->name, chptr->chname);
	ClearCork(client_p);
	send_pop_queue(client_p);
}

/* can_send()
 *
 * input	- user to check in channel, membership pointer
 * output	- whether can explicitly send or not, else CAN_SEND_NONOP
 * side effects -
 */
int
can_send(struct Channel *chptr, struct Client *source_p, struct membership *msptr)
{
	if(IsServer(source_p))
		return CAN_SEND_OPV;

	if(chptr->mode.mode & MODE_OPERONLY && !IsOper(source_p))
		return CAN_SEND_NO;

	if(ConfigChannel.use_sslonly && chptr->mode.mode & MODE_SSLONLY && !IsSSL(source_p))
		return CAN_SEND_NO;

	if(msptr == NULL)
	{
		msptr = find_channel_membership(chptr, source_p);

		if(msptr == NULL)
			return CAN_SEND_NONOP;
	}

	if(is_chanop_voiced(msptr))
		return CAN_SEND_OPV;

	return CAN_SEND_NONOP;
}

void
filter_regex(struct Channel *chptr, struct Client *source_p, char **ptext)
{
	static char tmp[BUFSIZE], text[BUFSIZE] = { '\0', };
	regmatch_t rmatch;
	rb_dlink_node *ptr;

	rb_strlcpy(&text[0], *ptext, sizeof(text));
	RB_DLINK_FOREACH(ptr, chptr->regexlist.head)
	{
		char *p, *nul; struct Regex *actualRegex = ptr->data;

		memset(&tmp[0], '\0', sizeof(tmp));
		p = &text[0], nul = strchr(p, '\0');

		while(0 == regexec(&actualRegex->reg, p, 1, &rmatch, 0))
			if(nul < (p + rmatch.rm_eo))
				break;
			else
			{
				rb_snprintf_append(&tmp[0], sizeof(tmp),
					 "%.*s%s", (int) rmatch.rm_so, p,
					actualRegex->subst);
				p += rmatch.rm_eo;
			}

		rb_snprintf_append(&tmp[0], sizeof(tmp), "%s", p);
		rb_strlcpy(&text[0], &tmp[0], sizeof(text));
	}

	(*ptext) = &text[0];
}

/* check_splitmode()
 *
 * input	-
 * output	-
 * side effects - compares usercount and servercount against their split
 *                values and adjusts splitmode accordingly
 */
void
check_splitmode(void *unused)
{
	if(splitchecking && (ConfigChannel.no_join_on_split || ConfigChannel.no_create_on_split))
	{
		/* not split, we're being asked to check now because someone
		 * has left
		 */
		if(!splitmode)
		{
			if(eob_count < split_servers || Count.total < split_users)
			{
				splitmode = 1;
				sendto_realops_flags(UMODE_ALL, L_ALL,
						     "Network split, activating splitmode");
				checksplit_ev =
					rb_event_addish("check_splitmode", check_splitmode, NULL,
							5);
			}
		}
		/* in splitmode, check whether its finished */
		else if(eob_count >= split_servers && Count.total >= split_users)
		{
			splitmode = 0;

			sendto_realops_flags(UMODE_ALL, L_ALL,
					     "Network rejoined, deactivating splitmode");

			rb_event_delete(checksplit_ev);
			checksplit_ev = NULL;
		}
	}
}


/* allocate_topic()
 *
 * input	- channel to allocate topic for
 * output	- 1 on success, else 0
 * side effects - channel gets a topic allocated
 */
static void
allocate_topic(struct Channel *chptr)
{
	if(chptr == NULL)
		return;

	chptr->topic = rb_bh_alloc(topic_heap);
}

/* free_topic()
 *
 * input	- channel which has topic to free
 * output	-
 * side effects - channels topic is free'd
 */
static void
free_topic(struct Channel *chptr)
{
	if(chptr == NULL || chptr->topic == NULL)
		return;

	/* This is safe for now - If you change allocate_topic you
	 * MUST change this as well
	 */
	rb_free(chptr->topic->topic);
	rb_bh_free(topic_heap, chptr->topic);
	chptr->topic = NULL;
}

/* set_channel_topic()
 *
 * input	- channel, topic to set, topic info and topic ts
 * output	-
 * side effects - channels topic, topic info and TS are set.
 */
void
set_channel_topic(struct Channel *chptr, const char *topic, const char *topic_info, time_t topicts)
{
	if(strlen(topic) > 0)
	{
		if(chptr->topic == NULL)
			allocate_topic(chptr);
		else
			rb_free(chptr->topic->topic);

		chptr->topic->topic = rb_strndup(topic, ConfigChannel.topiclen + 1);	/* the + 1 for the \0 */
		rb_strlcpy(chptr->topic->topic_info, topic_info, sizeof(chptr->topic->topic_info));
		chptr->topic->topic_time = topicts;
	}
	else
	{
		if(chptr->topic != NULL)
			free_topic(chptr);
	}
}

/* channel_modes()
 *
 * input	- channel, client to build for, modebufs to build to
 * output	-
 * side effects - user gets list of "simple" modes based on channel access.
 *                NOTE: m_join.c depends on trailing spaces in pbuf
 */
const char *
channel_modes(struct Channel *chptr, struct Client *client_p)
{
	static char buf[BUFSIZE];
	char *mbuf = buf;

	*mbuf++ = '+';

	if(chptr->mode.mode & MODE_OPERONLY)
		*mbuf++ = 'P';

	if(chptr->mode.mode & MODE_REGEX)
		*mbuf++ = 'R';

	if(chptr->mode.mode & MODE_SSLONLY)
		*mbuf++ = 'S';

	if(chptr->mode.mode & MODE_XCHGSENDER)
		*mbuf++ = 'X';

	if(chptr->mode.limit)
	{
		if(IsMe(client_p) || !MyClient(client_p) || IsMember(client_p, chptr))
			rb_sprintf(mbuf, "l %d", chptr->mode.limit);
		else
			strcpy(mbuf, "l");
	}
	else
		*mbuf = '\0';

	return buf;
}

/* Now lets do some stuff to keep track of what combinations of
 * servers exist...
 * Note that the number of combinations doubles each time you add
 * something to this list. Each one is only quick if no servers use that
 * combination, but if the numbers get too high here MODE will get too
 * slow. I suggest if you get more than 7 here, you consider getting rid
 * of some and merging or something. If it wasn't for irc+cs we would
 * probably not even need to bother about most of these, but unfortunately
 * we do. -A1kmm
 */

/* void init_chcap_usage_counts(void)
 *
 * Inputs	- none
 * Output	- none
 * Side-effects	- Initialises the usage counts to zero. Fills in the
 *                chcap_yes and chcap_no combination tables.
 */
void
init_chcap_usage_counts(void)
{
	unsigned long m, c, y, n;

	memset(chcap_combos, 0, sizeof(chcap_combos));

	/* For every possible combination */
	for(m = 0; m < NCHCAP_COMBOS; m++)
	{
		/* Check each capab */
		for(c = y = n = 0; c < NCHCAPS; c++)
		{
			if((m & (1 << c)) == 0)
				n |= channel_capabs[c];
			else
				y |= channel_capabs[c];
		}
		chcap_combos[m].cap_yes = y;
		chcap_combos[m].cap_no = n;
	}
}

/* void set_chcap_usage_counts(struct Client *serv_p)
 * Input: serv_p; The client whose capabs to register.
 * Output: none
 * Side-effects: Increments the usage counts for the correct capab
 *               combination.
 */
void
set_chcap_usage_counts(struct Client *serv_p)
{
	int n;

	for(n = 0; n < NCHCAP_COMBOS; n++)
	{
		if(IsCapable(serv_p, chcap_combos[n].cap_yes) &&
		   NotCapable(serv_p, chcap_combos[n].cap_no))
		{
			chcap_combos[n].count++;
			return;
		}
	}

	/* This should be impossible -A1kmm. */
	s_assert(0);
}

/* void set_chcap_usage_counts(struct Client *serv_p)
 *
 * Inputs	- serv_p; The client whose capabs to register.
 * Output	- none
 * Side-effects	- Decrements the usage counts for the correct capab
 *                combination.
 */
void
unset_chcap_usage_counts(struct Client *serv_p)
{
	int n;

	for(n = 0; n < NCHCAP_COMBOS; n++)
	{
		if(IsCapable(serv_p, chcap_combos[n].cap_yes) &&
		   NotCapable(serv_p, chcap_combos[n].cap_no))
		{
			/* Hopefully capabs can't change dynamically or anything... */
			s_assert(chcap_combos[n].count > 0);

			if(chcap_combos[n].count > 0)
				chcap_combos[n].count--;
			return;
		}
	}

	/* This should be impossible -A1kmm. */
	s_assert(0);
}

/* void send_cap_mode_changes(struct Client *client_p,
 *                        struct Client *source_p,
 *                        struct Channel *chptr, int cap, int nocap)
 * Input: The client sending(client_p), the source client(source_p),
 *        the channel to send mode changes for(chptr)
 * Output: None.
 * Side-effects: Sends the appropriate mode changes to capable servers.
 *
 * Reverted back to my original design, except that we now keep a count
 * of the number of servers which each combination as an optimisation, so
 * the capabs combinations which are not needed are not worked out. -A1kmm
 */
void
send_cap_mode_changes(struct Client *client_p, struct Client *source_p,
		      struct Channel *chptr, struct ChModeChange mode_changes[], int mode_count)
{
	static char modebuf[BUFSIZE];
	static char parabuf[BUFSIZE];
	int i, mbl, pbl, nc, mc, preflen, len;
	char *pbuf;
	const char *arg;
	int dir;
	int j;
	int cap;
	int nocap;
	int arglen;

	/* Now send to servers... */
	for(j = 0; j < NCHCAP_COMBOS; j++)
	{
		if(chcap_combos[j].count == 0)
			continue;

		mc = 0;
		nc = 0;
		pbl = 0;
		parabuf[0] = 0;
		pbuf = parabuf;
		dir = MODE_QUERY;

		cap = chcap_combos[j].cap_yes;
		nocap = chcap_combos[j].cap_no;

		if(cap & CAP_TS6)
			mbl = preflen = rb_sprintf(modebuf, ":%s TMODE %ld %s ",
						   use_id(source_p), (long)chptr->channelts,
						   chptr->chname);
		else
			mbl = preflen = rb_sprintf(modebuf, ":%s MODE %s ",
						   source_p->name, chptr->chname);

		/* loop the list of - modes we have */
		for(i = 0; i < mode_count; i++)
		{
			/* if they dont support the cap we need, or they do support a cap they
			 * cant have, then dont add it to the modebuf.. that way they wont see
			 * the mode
			 */
			if((mode_changes[i].letter == 0) ||
			   ((cap & mode_changes[i].caps) != mode_changes[i].caps)
			   || ((nocap & mode_changes[i].nocaps) != mode_changes[i].nocaps))
				continue;

			if((cap & CAP_TS6) && !EmptyString(mode_changes[i].id))
				arg = mode_changes[i].id;
			else
				arg = mode_changes[i].arg;

			if(arg)
			{
				arglen = strlen(arg);

				/* dont even think about it! --fl */
				if(arglen > MODEBUFLEN - 5)
					continue;
			}

			/* if we're creeping past the buf size, we need to send it and make
			 * another line for the other modes
			 * XXX - this could give away server topology with uids being
			 * different lengths, but not much we can do, except possibly break
			 * them as if they were the longest of the nick or uid at all times,
			 * which even then won't work as we don't always know the uid -A1kmm.
			 */
			if(arg && ((mc == MAXMODEPARAMSSERV) ||
				   ((mbl + pbl + arglen + 4) > (BUFSIZE - 3))))
			{
				if(nc != 0)
					sendto_server(client_p, chptr, cap, nocap,
						      "%s %s", modebuf, parabuf);
				nc = 0;
				mc = 0;

				mbl = preflen;
				pbl = 0;
				pbuf = parabuf;
				parabuf[0] = 0;
				dir = MODE_QUERY;
			}

			if(dir != mode_changes[i].dir)
			{
				modebuf[mbl++] = (mode_changes[i].dir == MODE_ADD) ? '+' : '-';
				dir = mode_changes[i].dir;
			}

			modebuf[mbl++] = mode_changes[i].letter;
			modebuf[mbl] = 0;
			nc++;

			if(arg != NULL)
			{
				len = rb_sprintf(pbuf, "%s ", arg);
				pbuf += len;
				pbl += len;
				mc++;
			}
		}

		if(pbl && parabuf[pbl - 1] == ' ')
			parabuf[pbl - 1] = 0;

		if(nc != 0)
			sendto_server(client_p, chptr, cap, nocap, "%s %s", modebuf, parabuf);
	}
}
