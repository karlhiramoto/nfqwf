/*
Copyright (C) <2010-2011> Karl Hiramoto <karl@hiramoto.org>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef RULES_H
#define RULES_H 1

#ifdef HAVE_CONFIG_H
#include "nfq-web-filter-config.h"
#endif

#include <stdint.h>

#include <stdbool.h>
#include "Filter.h"


/**
* @ingroup Object
* @defgroup Rules Rule definitions
* @{
*/


/**
*  Different actions/verdicts a rule can take
*/
enum Action {
	Action_nomatch = 0,  /**< not checked, or not matched,  0 so calloc() or memset(0) will init */
	Action_accept = 1 << 0,
	Action_reject = 1 << 1,
	Action_virus = 1 << 2,
	Action_malware = 1 << 3,
	Action_phishing = 1 << 4,
	/** Trust:  will trust the connection, so subsequent requests and packets will not be checked */
	Action_trust = 1 << 5,
	Action_continue = 1 << 6,  /** Rule matches but continue rule list */
};


enum Action Action_fromAscii(const char *str);
char *Action_toAscii(enum Action action, char *buffer, int buf_size);

#define MAX_FITERS_PER_RULE 16
#define MAX_FITER_GROUPS 4
#define SRC_FITER_GROUP 0
#define DST_FITER_GROUP 1
#define WHEN_FITER_GROUP 2
#define CATEGORY_FITER_GROUP 3

#define RULE_COMMENT_LEN 32

/** Rule definition. */
struct Rule {
	OBJECT_COMMON
	int rule_id;   /**< Rule ID */
	bool disabled; /**< Is rule disabled */
	bool log;      /**< Log this rule if it matches */
	bool notify;   /**< Email Notify */
	enum Action action;  /**< Action this rule should take */

	/** if rule matches mark the packet with this mark*/
	uint32_t mark;
	/** mark mask */
	uint32_t mask;

	/// Note possible new way to do filters.
	/** Filter object may be of any objects
	like IP, Network, host, domain, category, etc
	A logical AND is operated on each filter type */

	/** 2D array.  within each group logical OR. Between groups logical AND.
	  See  @link FilterList */
	struct FilterList *filter_groups[MAX_FITER_GROUPS];

	char comment[RULE_COMMENT_LEN];
};


struct Rule* Rule_new(void);
void Rule_get(struct Rule *r);
void Rule_put(struct Rule **r);

void Rule_setId(struct Rule *r, int id);

int Rule_getId(struct Rule *r);

void Rule_setDiabled(struct Rule *r, bool disabled);

bool Rule_isDiabled(struct Rule *r);
void Rule_setAction(struct Rule *r, enum Action a);
void Rule_addFilter(struct Rule *r, unsigned int group, struct Filter *fo);
bool Rule_containsFilter(struct Rule *r, struct Filter *fo, unsigned int *group);
void Rule_setComment(struct Rule *r, const char *comment);

static inline const char *Rule_getComment(struct Rule *r) {
	return r->comment;
}

enum Action Rule_getVerdict(struct Rule *r,  struct HttpReq *req);

static inline void Rule_setMark(struct Rule *r, uint32_t mark) {
	r->mark = mark;
}

static inline uint32_t Rule_getMark(struct Rule *r) {
	return r->mark;
}

static inline void Rule_setMask(struct Rule *r, uint32_t mask) {
	r->mask = mask;
}
static inline uint32_t Rule_getMask(struct Rule *r) {
	return r->mask;
}

/** @}
end of file
*/

#endif

