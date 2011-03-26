#define _GNU_SOURCE

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include "FilterList.h"
#include "Rules.h"
#include "nfq_wf_private.h"


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


void Rule_get(struct Rule *r) {
	r->refcount++;
	DBG(5, "New reference to Rule %p refcount = %d\n",
		r, r->refcount);
}

void Rule_put(struct Rule **r) {

	DBG(5, "removing Rule reference to %p refcount = %d id=%d\n",
		*r, (*r)->refcount, (*r)->rule_id);

	Object_put((struct Object**)r);
}

int Rule_constructor(struct Object *obj)
{
	int i;
	struct Rule* r = (struct Rule*) obj;

	DBG(5, "constructor rule size=%d rule=%p\n", (int) sizeof(struct Rule), r);

	for (i = 0; i < MAX_FITER_GROUPS; i++) {
		r->filter_groups[i] = FilterList_new();
		DBG(5, "new filter list %p for group %d rule = %p \n",
			r->filter_groups[i], i, r);
	}

	return 0;
}

int Rule_destructor(struct Object *obj)
{
	struct Rule *rule = (struct Rule*) obj;
	int i;

	for (i = 0; i < MAX_FITER_GROUPS; i++) {
		FilterList_del(&(rule->filter_groups[i]));
	}

	return 0;
}

static struct Object_ops obj_ops = {
	.obj_type           = "Rule",
	.obj_size           = sizeof(struct Rule),
	.obj_constructor    = Rule_constructor,
	.obj_destructor     = Rule_destructor,

};

static struct Rule* Rule_alloc(struct Object_ops *ops)
{
	return (struct Rule*) Object_alloc(ops);
}


struct Rule* Rule_new(void)
{
	return Rule_alloc(&obj_ops);
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
	DBG(2, "rule id=%d add to group %d list %p rule %p\n", r->rule_id, group,
		r->filter_groups[group], r);

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
	int group_count;

	for (i = 0 ; i < MAX_FITER_GROUPS; i++) {

		group_count = FilterList_count(r->filter_groups[i]);
		DBG(7, "Rule %d Filter group %d has %d filters\n",
			r->rule_id, i, group_count);
		/*if group is empty it matches the ANY '*' case */
		if (group_count) {
			matches = FilterList_foreach(r->filter_groups[i],
					req, rule_filter_match_cb);

			// if matched nothing in this group, does not match
			if (!matches)
				return Action_nomatch;
		}
	}
	/* if we are here either, it matched each group, or the group was empty */
	return r->action;
}

bool Rule_containsFilter(struct Rule *r, struct Filter *fo, unsigned int *group)
{
	int i;

	for (i = 0 ; i < MAX_FITER_GROUPS; i++) {

		/*if group is empty it matches the ANY '*' case */
		if (FilterList_contains(r->filter_groups[i], fo)) {
			if (group) {
				*group = i;
			}
			return true;
		}
	}
	return false;
}
