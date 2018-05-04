/*
 *  ircd-sandstorm: The SandNET ircd.
 *  channel.h: The ircd channel header.
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
 *  $Id: channel.h 26094 2008-09-19 15:33:46Z androsyn $
 */

#ifndef INCLUDED_channel_h
#define INCLUDED_channel_h

#include <regex.h>

#define MODEBUFLEN      200

/* Maximum mode changes allowed per client, per server is different */
#define MAXMODEPARAMS   4
#define MAXMODEPARAMSSERV 10

extern struct ev_entry *checksplit_ev;
struct Client;

/* mode structure for channels */
struct Mode
{
	unsigned int mode;
	int limit;
};

struct topic_info
{
	char *topic;
	char topic_info[USERHOST_REPLYLEN];
	time_t topic_time;
};

/* channel structure */
struct Channel
{
	rb_dlink_node node;
	struct Mode mode;
	struct topic_info *topic;

	rb_dlink_list members;	/* channel members */
	rb_dlink_list locmembers;	/* local channel members */

	rb_dlink_list regexlist;
	rb_dlink_list regex_exlist;

	time_t channelts;
	char *chname;
};

#define CRAZY_CMODES		128
char crazy_cmode_tbl[CRAZY_CMODES];

struct membership
{
	rb_dlink_node channode;
	rb_dlink_node locchannode;
	rb_dlink_node usernode;

	struct Channel *chptr;
	struct Client *client_p;
	uint8_t flags;
	uint8_t flags_crazy[CRAZY_CMODES];
};

#define REGEXLEN NICKLEN+USERLEN+HOSTLEN+6
struct Regex
{
	char *regexstr;
	char *pat, *subst;
	regex_t reg;
	char *who;
	time_t when;
	rb_dlink_node node;
};

struct ChModeChange
{
	char letter;
	const char *arg;
	const char *id;
	int dir;
	int caps;
	int nocaps;
	struct Client *client;
};

/* can_send results */
#define CAN_SEND_NO	0
#define CAN_SEND_NONOP  1
#define CAN_SEND_OPV	2

/* channel status flags */
#define CHFL_PEON		0x0000	/* normal member of channel */
#define CHFL_CHANOP     	0x0001	/* Channel operator */
#define CHFL_VOICE      	0x0002	/* the power to speak */
#define CHFL_DEOPPED    	0x0004	/* deopped on sjoin, bounce modes */

#define is_chanop(x)	((x) && (x)->flags & CHFL_CHANOP)
#define is_voiced(x)	((x) && (x)->flags & CHFL_VOICE)
#define is_chanop_voiced(x) ((x) && (x)->flags & (CHFL_CHANOP|CHFL_VOICE))
#define is_deop(x)	((x) && (x)->flags & CHFL_DEOPPED)

/* channel modes ONLY */
#define MODE_SSLONLY	0x0001
#define MODE_OPERONLY	0x0002
#define MODE_XCHGSENDER	0x0004
#define MODE_REGEX	0x0008
#define CHFL_REGEX	0x0010
#define CHFL_REGEX_EX	0x0020

/* mode flags for direction indication */
#define MODE_QUERY     0
#define MODE_ADD       1
#define MODE_DEL       -1

#define IsMember(who, chan) ((who && who->user && \
		find_channel_membership(chan, who)) ? 1 : 0)

#define IsChannelName(name) ((name) && (*(name) == '#' || *(name) == '&'))

extern rb_dlink_list global_channel_list;
void init_channels(void);

struct Channel *allocate_channel(const char *chname);
void free_channel(struct Channel *chptr);
struct Regex *allocate_regex(const char *, const char *, long);
void free_regex(struct Regex *rptr);


void destroy_channel(struct Channel *);

int can_send(struct Channel *chptr, struct Client *who, struct membership *);
void filter_regex(struct Channel *, struct Client *, const char *, char *);

struct membership *find_channel_membership(struct Channel *, struct Client *);
const char *find_channel_status(struct membership *msptr);
void add_user_to_channel(struct Channel *, struct Client *, int);
void remove_user_from_channel(struct membership *);
void remove_user_from_channels(struct Client *);

void free_channel_list(rb_dlink_list *);

int check_channel_name(const char *name);

void channel_member_names(struct Channel *chptr, struct Client *, int show_eon);

const char *channel_modes(struct Channel *chptr, struct Client *who);

void check_splitmode(void *);

void set_channel_topic(struct Channel *chptr, const char *topic,
		       const char *topic_info, time_t topicts);

void send_cap_mode_changes(struct Client *client_p, struct Client *source_p,
			   struct Channel *chptr, struct ChModeChange foo[], int);

void xchg_sender(struct Channel *chptr, struct Client *source_p,
			     const char *text, struct Client **psource_p,
			     struct Client **pclient_p);

#endif /* INCLUDED_channel_h */
