#define _GNU_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include "FilterList.h"
#include "Rules.h"
#include "nfq_proxy_private.h"


const char *ActionTypeStr[] = {
	"nomatch",
	"accept",
	"reject",
	"virus",
	"malware",
	"phishing",
	"trust",
	"continue",
	"last",
	NULL
};

enum Action Action_fromAscii(const char *str)
{
	enum Action action = Action_nomatch;
	int i;

	for (i = 0; ActionTypeStr[i] ; i++) {
		if (strcasestr(str, ActionTypeStr[i])) {
			action |= 1 << i;
		}
	}
	// one extra bit to shift off.
	return action >> 1;
}

char *Action_toAscii(enum Action action, char *buffer, int buf_size)
{
	if (!buffer || buf_size < 4)
		return NULL;

	if (action == Action_nomatch) {
		strncpy(buffer, "nomatch", buf_size);
		return buffer;
	}
	buffer[0] = 0;

	if (action & Action_accept) {
		action &= ~Action_accept;
		strncat(buffer, "accept", buf_size);
		buf_size -= strlen("accept");
	}

	if ((action & Action_reject) && (buf_size > 0)) {
		action &= ~Action_reject;
		strncat(buffer, "reject", buf_size);
		buf_size -= strlen("reject");
	}

	if ((action & Action_virus) && (buf_size > 0)) {
		action &= ~Action_virus;
		strncat(buffer, "virus", buf_size);
		buf_size -= strlen("virus");
	}

	if ((action & Action_malware) && (buf_size > 0)) {
		action &= ~Action_malware;
		strncat(buffer, "malware", buf_size);
		buf_size -= strlen("malware");
	}

	if ((action & Action_phishing) && (buf_size > 0)) {
		action &= ~Action_phishing;
		strncat(buffer, "phishing", buf_size);
		buf_size -= strlen("phishing");
	}

	if ((action & Action_trust) && (buf_size > 0)) {
		action &= ~Action_trust;
		strncat(buffer, "trust", buf_size);
		buf_size -= strlen("trust");
	}

	if ((action & Action_continue) && (buf_size > 0)) {
		action &= ~Action_continue;
		strncat(buffer, "continue", buf_size);
		buf_size -= strlen("continue");
	}

	return buffer;
}


struct Rule* Rule_new(void)
{
	struct Rule* r;
	int i;
	r = calloc(1, sizeof(struct Rule));
	if (!r)
		ERROR_FATAL("calloc of rule failed");

	for (i = 0; i < MAX_FITER_GROUPS; i++) {
		r->filter_groups[i] = FilterList_new();
	}

	return r;
}

void Rule_del(struct Rule **r)
{
	struct Rule *rule = *r;
	int i;

	for (i = 0; i < MAX_FITER_GROUPS; i++) {
		FilterList_del(&(rule->filter_groups[i]));
	}

	free(rule);
	*r = NULL;
}

void Rule_setId(struct Rule *r, int id)
{
	r->rule_id = id;
}

int Rule_getId(struct Rule *r)
{
	return r->rule_id;
}

void Rule_setDiabled(struct Rule *r, bool disabled)
{
	r->disabled = disabled;
}

bool Rule_isDiabled(struct Rule *r)
{
	return r->disabled;
}

void Rule_setAction(struct Rule *r, enum Action a)
{
	r->action = a;
}

void Rule_addFilter(struct Rule *r, unsigned int group, struct Filter *fo)
{
	if (group > MAX_FITER_GROUPS-1) {
		// invalid
		ERROR_FATAL("Invalid filter group %d\n", group);
	}

	FilterList_addTail(r->filter_groups[group], fo);
}

void Rule_setComment(struct Rule *r, const char *comment)
{
	strncpy(r->comment, comment, RULE_COMMENT_LEN -1);
	r->comment[RULE_COMMENT_LEN-1] = 0;
}

static int rule_filter_match_cb(struct Filter *fo, void *data)
{
	struct HttpReq *req = (struct HttpReq *) data;

	if (!fo || !fo->fo_ops) {
		ERROR_FATAL("No filter or no ops\n")
	}
	
	if (!fo->fo_ops->foo_matches_req) {
		return Action_nomatch;
// 		ERROR_FATAL("missing filters match check callback Filter Name= '%s'\n", fo->fo_ops->ops->obj_type)
	}
	return fo->fo_ops->foo_matches_req(fo, req);
}

enum Action Rule_getVerdict(struct Rule *r,  struct HttpReq *req)
{
	int i;
	bool matches;

	for (i = 0 ; i < MAX_FITER_GROUPS; i++) {
		
		/*if group is empty it matches the ANY '*' case */
		if (FilterList_count(r->filter_groups[i])) {
			matches = FilterList_foreach(r->filter_groups[i],
					req, rule_filter_match_cb);

			if (!matches)
				return Action_nomatch;
		}
	}
	/* if we are here either, it matched each group, or the group was empty */
	return r->action;
}

