#include "jsonrpc.h"
#include "lightningd.h"
#include "log.h"
#include "overflows.h"
#include "peer.h"
#include "pseudorand.h"
#include "routing.h"
#include <ccan/array_size/array_size.h>
#include <ccan/crypto/siphash24/siphash24.h>
#include <ccan/htable/htable_type.h>
#include <ccan/structeq/structeq.h>
#include <inttypes.h>

/* 365.25 * 24 * 60 / 10 */
#define BLOCKS_PER_YEAR 52596

static const secp256k1_pubkey *keyof_node(const struct node *n)
{
	return &n->id.pubkey;
}

static size_t hash_key(const secp256k1_pubkey *key)
{
	return siphash24(siphash_seed(), key, sizeof(key));
}

static bool node_eq(const struct node *n, const secp256k1_pubkey *key)
{
	return structeq(&n->id.pubkey, key);
}

HTABLE_DEFINE_TYPE(struct node, keyof_node, hash_key, node_eq, node_map);

struct node_map *empty_node_map(struct lightningd_state *dstate)
{
	struct node_map *map = tal(dstate, struct node_map);
	node_map_init(map);
	return map;
}

struct node *get_node(struct lightningd_state *dstate,
		      const struct pubkey *id)
{
	return node_map_get(dstate->nodes, &id->pubkey);
}

static void destroy_node(struct node *node)
{
	/* These remove themselves from the array. */
	while (tal_count(node->in))
		tal_free(node->in[0]);
	while (tal_count(node->out))
		tal_free(node->out[0]);
}

struct node *new_node(struct lightningd_state *dstate,
		      const struct pubkey *id)
{
	struct node *n;

	assert(!get_node(dstate, id));

	n = tal(dstate, struct node);
	n->id = *id;
	n->in = tal_arr(n, struct node_connection *, 0);
	n->out = tal_arr(n, struct node_connection *, 0);
	n->port = 0;
	node_map_add(dstate->nodes, n);
	tal_add_destructor(n, destroy_node);

	return n;
}

struct node *add_node(
	struct lightningd_state *dstate,
	const struct pubkey *pk,
	char *hostname,
	int port)
{
	struct node *n = get_node(dstate, pk);
	if (!n) {
		n = new_node(dstate, pk);
		log_debug_struct(dstate->base_log, "Creating new node %s",
				 struct pubkey, pk);
	} else {
		log_debug_struct(dstate->base_log, "Update existing node %s",
				 struct pubkey, pk);
	}
	n->hostname = tal_steal(n, hostname);
	n->port = port;
	return n;
}

static bool remove_conn_from_array(struct node_connection ***conns,
				   struct node_connection *nc)
{
	size_t i, n;

	n = tal_count(*conns);
	for (i = 0; i < n; i++) {
		if ((*conns)[i] != nc)
			continue;
		n--;
		memmove(*conns + i, *conns + i + 1, sizeof(**conns) * (n - i));
		tal_resize(conns, n);
		return true;
	}
	return false;
}

static void destroy_connection(struct node_connection *nc)
{
	if (!remove_conn_from_array(&nc->dst->in, nc)
	    || !remove_conn_from_array(&nc->src->out, nc))
		fatal("Connection not found in array?!");
}

static struct node_connection *
get_or_make_connection(struct lightningd_state *dstate,
		       const struct pubkey *from_id,
		       const struct pubkey *to_id)
{
	size_t i, n;
	struct node *from, *to;
	struct node_connection *nc;

	from = get_node(dstate, from_id);
	if (!from)
		from = new_node(dstate, from_id);
	to = get_node(dstate, to_id);
	if (!to)
		to = new_node(dstate, to_id);

	n = tal_count(to->in);
	for (i = 0; i < n; i++) {
		if (to->in[i]->src == from) {
			log_debug_struct(dstate->base_log,
					 "Updating existing route from %s",
					 struct pubkey, &from->id);
			log_add_struct(dstate->base_log, " to %s",
				       struct pubkey, &to->id);
			return to->in[i];
		}
	}

	log_debug_struct(dstate->base_log, "Creating new route from %s",
			 struct pubkey, &from->id);
	log_add_struct(dstate->base_log, " to %s", struct pubkey, &to->id);

	nc = tal(dstate, struct node_connection);
	nc->src = from;
	nc->dst = to;
	log_add(dstate->base_log, " = %p (%p->%p)", nc, from, to);

	/* Hook it into in/out arrays. */
	i = tal_count(to->in);
	tal_resize(&to->in, i+1);
	to->in[i] = nc;
	i = tal_count(from->out);
	tal_resize(&from->out, i+1);
	from->out[i] = nc;

	tal_add_destructor(nc, destroy_connection);
	return nc;
}

/* Updates existing route if required. */
struct node_connection *add_connection(struct lightningd_state *dstate,
				       const struct pubkey *from,
				       const struct pubkey *to,
				       u32 base_fee, s32 proportional_fee,
				       u32 delay, u32 min_blocks)
{
	struct node_connection *c = get_or_make_connection(dstate, from, to);
	c->base_fee = base_fee;
	c->proportional_fee = proportional_fee;
	c->delay = delay;
	c->min_blocks = min_blocks;
	return c;
}

void remove_connection(struct lightningd_state *dstate,
		       const struct pubkey *src, const struct pubkey *dst)
{
	struct node *from, *to;
	size_t i, num_edges;

	log_debug_struct(dstate->base_log, "Removing route from %s",
			 struct pubkey, src);
	log_add_struct(dstate->base_log, " to %s", struct pubkey, dst);

	from = get_node(dstate, src);
	to = get_node(dstate, dst);
	if (!from || !to) {
		log_debug(dstate->base_log, "Not found: src=%p dst=%p",
			  from, to);
		return;
	}

	num_edges = tal_count(from->out);

	for (i = 0; i < num_edges; i++) {
		if (from->out[i]->dst != to)
			continue;

		log_add(dstate->base_log, " Matched route %zu of %zu",
			i, num_edges);
		/* Destructor makes it delete itself */
		tal_free(from->out[i]);
		return;
	}
	log_add(dstate->base_log, " None of %zu routes matched", num_edges);
}

/* Too big to reach, but don't overflow if added. */
#define INFINITE 0x3FFFFFFFFFFFFFFFULL

static void clear_bfg(struct node_map *nodes)
{
	struct node *n;
	struct node_map_iter it;

	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
		size_t i;
		for (i = 0; i < ARRAY_SIZE(n->bfg); i++) {
			n->bfg[i].total = INFINITE;
			n->bfg[i].risk = 0;
		}
	}
}

s64 connection_fee(const struct node_connection *c, u64 msatoshi)
{
	s64 fee;

	if (mul_overflows_s64(c->proportional_fee, msatoshi))
		return INFINITE;
	fee = (c->proportional_fee * msatoshi) / 1000000;
	/* This can't overflow: c->base_fee is a u32 */
	return c->base_fee + fee;
}

/* Risk of passing through this channel.  We insert a tiny constant here
 * in order to prefer shorter routes, all things equal. */
static u64 risk_fee(s64 amount, u32 delay, double riskfactor)
{
	/* If fees are so negative we're making money, ignore risk. */
	if (amount < 0)
		return 1;

	return 1 + amount * delay * riskfactor / BLOCKS_PER_YEAR / 10000;
}

/* We track totals, rather than costs.  That's because the fee depends
 * on the current amount passing through. */
static void bfg_one_edge(struct node *node, size_t edgenum, double riskfactor)
{
	struct node_connection *c = node->in[edgenum];
	size_t h;

	assert(c->dst == node);
	for (h = 0; h < ROUTING_MAX_HOPS; h++) {
		/* FIXME: Bias against smaller channels. */
		s64 fee = connection_fee(c, node->bfg[h].total);
		u64 risk = node->bfg[h].risk + risk_fee(node->bfg[h].total + fee,
							c->delay, riskfactor);
		if (node->bfg[h].total + (s64)fee + (s64)risk
		    < c->src->bfg[h+1].total + (s64)c->src->bfg[h+1].risk) {
			c->src->bfg[h+1].total = node->bfg[h].total + fee;
			c->src->bfg[h+1].risk = risk;
			c->src->bfg[h+1].prev = c;
		}
	}
}

struct peer *find_route(struct lightningd_state *dstate,
			const struct pubkey *to,
			u64 msatoshi,
			double riskfactor,
			s64 *fee,
			struct node_connection ***route)
{
	struct node *n, *src, *dst;
	struct node_map_iter it;
	struct peer *first;
	int runs, i, best;

	/* Note: we map backwards, since we know the amount of satoshi we want
	 * at the end, and need to derive how much we need to send. */
	dst = get_node(dstate, &dstate->id);
	src = get_node(dstate, to);
	if (!src) {
		log_info_struct(dstate->base_log, "find_route: cannot find %s",
				struct pubkey, to);
		return NULL;
	}

	/* Reset all the information. */
	clear_bfg(dstate->nodes);

	/* Bellman-Ford-Gibson: like Bellman-Ford, but keep values for
	 * every path length. */
	src->bfg[0].total = msatoshi;
	src->bfg[0].risk = 0;

	for (runs = 0; runs < ROUTING_MAX_HOPS; runs++) {
		log_debug(dstate->base_log, "Run %i", runs);
		/* Run through every edge. */
		for (n = node_map_first(dstate->nodes, &it);
		     n;
		     n = node_map_next(dstate->nodes, &it)) {
			size_t num_edges = tal_count(n->in);
			for (i = 0; i < num_edges; i++) {
				bfg_one_edge(n, i, riskfactor);
				log_debug(dstate->base_log, "We seek %p->%p, this is %p -> %p",
					  dst, src, n->in[i]->src, n->in[i]->dst);
				log_debug_struct(dstate->base_log,
						 "Checking from %s",
						 struct pubkey,
						 &n->in[i]->src->id);
				log_add_struct(dstate->base_log,
					       " to %s",
					       struct pubkey,
					       &n->in[i]->dst->id);
			}
		}
	}

	best = 0;
	for (i = 1; i <= ROUTING_MAX_HOPS; i++) {
		if (dst->bfg[i].total < dst->bfg[best].total)
			best = i;
	}

	/* No route? */
	if (dst->bfg[best].total >= INFINITE) {
		log_info_struct(dstate->base_log, "find_route: No route to %s",
				struct pubkey, to);
		return NULL;
	}

	/* Save route from *next* hop (we return first hop as peer).
	 * Note that we take our own fees into account for routing, even
	 * though we don't pay them: it presumably effects preference. */
	dst = dst->bfg[best].prev->dst;
	best--;

	*fee = dst->bfg[best].total - msatoshi;
	*route = tal_arr(dstate, struct node_connection *, best);
	for (i = 0, n = dst;
	     i < best;
	     n = n->bfg[best-i].prev->dst, i++) {
		(*route)[i] = n->bfg[best-i].prev;
	}
	assert(n == src);

	/* We should only add routes if we have a peer. */
	first = find_peer(dstate, &dst->id);
	if (!first) {
		log_broken_struct(dstate->base_log, "No peer %s?",
				  struct pubkey, &(*route)[0]->src->id);
		return NULL;
	}

	msatoshi += *fee;
	log_info(dstate->base_log, "find_route:");
	log_add_struct(dstate->base_log, "via %s", struct pubkey, first->id);
	/* If there are intermidiaries, dump them, and total fees. */
	if (best != 0) {
		for (i = 0; i < best; i++) {
			log_add_struct(dstate->base_log, " %s",
				       struct pubkey, &(*route)[i]->dst->id);
			log_add(dstate->base_log, "(%i+%i=%"PRIu64")",
				(*route)[i]->base_fee,
				(*route)[i]->proportional_fee,
				connection_fee((*route)[i], msatoshi));
			msatoshi -= connection_fee((*route)[i], msatoshi);
		}
		log_add(dstate->base_log, "=%"PRIi64"(%+"PRIi64")",
			(*route)[best-1]->dst->bfg[best-1].total, *fee);
	}
	return first;
}

static bool get_slash_u32(const char **arg, u32 *v)
{
	size_t len;
	char *endp;

	if (**arg != '/')
		return false;
	(*arg)++;
	len = strcspn(*arg, "/");
	*v = strtoul(*arg, &endp, 10);
	(*arg) += len;
	return (endp == *arg);
}

/* srcid/dstid/base/var/delay/minblocks */
char *opt_add_route(const char *arg, struct lightningd_state *dstate)
{
	size_t len;
	struct pubkey src, dst;
	u32 base, var, delay, minblocks;

	len = strcspn(arg, "/");
	if (!pubkey_from_hexstr(dstate->secpctx, arg, len, &src))
		return "Bad src pubkey";
	arg += len + 1;
	len = strcspn(arg, "/");
	if (!pubkey_from_hexstr(dstate->secpctx, arg, len, &dst))
		return "Bad dst pubkey";
	arg += len;

	if (!get_slash_u32(&arg, &base)
	    || !get_slash_u32(&arg, &var)
	    || !get_slash_u32(&arg, &delay)
	    || !get_slash_u32(&arg, &minblocks))
		return "Bad base/var/delay/minblocks";
	if (*arg)
		return "Data after minblocks";

	add_connection(dstate, &src, &dst, base, var, delay, minblocks);
	return NULL;
}

static void json_add_route(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *srctok, *dsttok, *basetok, *vartok, *delaytok, *minblockstok;
	struct pubkey src, dst;
	u32 base, var, delay, minblocks;

	if (!json_get_params(buffer, params,
			    "src", &srctok,
			    "dst", &dsttok,
			    "base", &basetok,
			    "var", &vartok,
			    "delay", &delaytok,
			    "minblocks", &minblockstok,
			    NULL)) {
		command_fail(cmd, "Need src, dst, base, var, delay & minblocks");
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + srctok->start,
				srctok->end - srctok->start, &src)) {
		command_fail(cmd, "src %.*s not valid",
			     srctok->end - srctok->start,
			     buffer + srctok->start);
		return;
	}

	if (!pubkey_from_hexstr(cmd->dstate->secpctx,
				buffer + dsttok->start,
				dsttok->end - dsttok->start, &dst)) {
		command_fail(cmd, "dst %.*s not valid",
			     dsttok->end - dsttok->start,
			     buffer + dsttok->start);
		return;
	}

	if (!json_tok_number(buffer, basetok, &base)
	    || !json_tok_number(buffer, vartok, &var)
	    || !json_tok_number(buffer, delaytok, &delay)
	    || !json_tok_number(buffer, minblockstok, &minblocks)) {
		command_fail(cmd,
			     "base, var, delay and minblocks must be numbers");
		return;
	}

	add_connection(cmd->dstate, &src, &dst, base, var, delay, minblocks);
	command_success(cmd, null_response(cmd));
}

const struct json_command dev_add_route_command = {
	"dev-add-route",
	json_add_route,
	"Add route from {src} to {dst}, {base} rate in msatoshi, {var} rate in msatoshi, {delay} blocks delay and {minblocks} minimum timeout",
	"Returns an empty result on success"
};

static void json_getchannels(struct command *cmd,
			     const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct node_map_iter it;
	struct node *n;
	struct node_map *nodes = cmd->dstate->nodes;
	struct node_connection *c;
	int num_conn, i;

	json_object_start(response, NULL);
	json_array_start(response, "channels");
	for (n = node_map_first(nodes, &it); n; n = node_map_next(nodes, &it)) {
	        num_conn = tal_count(n->out);
		for (i = 0; i < num_conn; i++){
			c = n->out[i];
			json_object_start(response, NULL);
			json_add_pubkey(response, cmd->dstate->secpctx, "from", &n->id);
			json_add_pubkey(response, cmd->dstate->secpctx, "to", &c->dst->id);
			json_add_num(response, "base_fee", c->base_fee);
			json_add_num(response, "proportional_fee", c->proportional_fee);
			json_object_end(response);
		}
	}
		json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

const struct json_command getchannels_command = {
	"getchannels",
	json_getchannels,
	"List all known channels.",
	"Returns a 'channels' array with all known channels including their fees."
};

static void json_routefail(struct command *cmd,
			   const char *buffer, const jsmntok_t *params)
{
	jsmntok_t *enabletok;
	bool enable;

	if (!json_get_params(buffer, params,
			     "enable", &enabletok,
			     NULL)) {
		command_fail(cmd, "Need enable");
		return;
	}

	if (!json_tok_bool(buffer, enabletok, &enable)) {
		command_fail(cmd, "enable must be true or false");
		return;
	}

	log_debug(cmd->dstate->base_log, "dev-routefail: routefail %s",
		  enable ? "enabled" : "disabled");
	cmd->dstate->dev_never_routefail = !enable;

	command_success(cmd, null_response(cmd));
}
const struct json_command dev_routefail_command = {
	"dev-routefail",
	json_routefail,
	"FAIL htlcs that we can't route if {enable}",
	"Returns an empty result on success"
};

static void json_getnodes(struct command *cmd,
			  const char *buffer, const jsmntok_t *params)
{
	struct json_result *response = new_json_result(cmd);
	struct node *n;
	struct node_map_iter i;

	n = node_map_first(cmd->dstate->nodes, &i);

	json_object_start(response, NULL);
	json_array_start(response, "nodes");

	while (n != NULL) {
		json_object_start(response, NULL);
		json_add_pubkey(response, cmd->dstate->secpctx,
				"nodeid", &n->id);
		json_add_num(response, "port", n->port);
		if (!n->port)
			json_add_null(response, "hostname");
		else
			json_add_string(response, "hostname", n->hostname);

		json_object_end(response);
		n = node_map_next(cmd->dstate->nodes, &i);
	}

	json_array_end(response);
	json_object_end(response);
	command_success(cmd, response);
}

const struct json_command getnodes_command = {
	"getnodes",
	json_getnodes,
	"List all known nodes in the network.",
	"Returns a 'nodes' array"
};
