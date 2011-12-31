/*
 * this is an implementation of btree in btrfs
 *
 *	Seth Huang<seth.hg AT gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define NODE_SIZE	128
#define MAX_LEVEL	5
#define ORDER   	5
#define MIN_KEYS_PER_NODE	(ORDER/2-1)
#define MAX_KEYS_PER_NODE	(ORDER-1)

typedef int btree_key_t;
typedef void* btree_ptr_t;

/*
 *	helper functions
 */
int comp_key(btree_key_t *k1, btree_key_t *k2)
{
	return (*k2 - *k1);
}

#define min(a, b)	((a) < (b) ? (a) : (b))
#define max(a, b)	((a) > (b) ? (a) : (b))

/*
 *  data structures for btree
 *
 * */

/* tree root */
struct btree_root {
	/* something to add
	 * ...
	 * */
	void *node;
	int node_size;
};

/* pointers for index node */
struct btree_key_ptr {
	btree_key_t key;
	btree_ptr_t ptr;
};

struct btree_item {
	btree_key_t key;
	int data;
};

struct btree_header {
	int nritems;
	int level;
};

/* index nodes contains only pointers */
struct btree_node {
	struct btree_header header;
	struct btree_key_ptr ptrs[MAX_KEYS_PER_NODE];
};

/* leaf nodes contains data items */
struct btree_leaf {
	struct btree_header header;
	struct btree_item items[MAX_KEYS_PER_NODE];
};

/* path to a leaf node */
struct btree_path {
	int lowest_level;
	int slots[MAX_LEVEL];
	void *nodes[MAX_LEVEL];
};

void print_tree(struct btree_root *root);

/*
 * macros and helper functions for btree nodes
 *
 * */

#define btree_header_nritems(buffer) \
	(((struct btree_header *)buffer)->nritems)
#define btree_header_level(buffer) \
	(((struct btree_header *)buffer)->level)

void btree_set_header_nritems(void *node, int nritems)
{
	((struct btree_header *)node)->nritems = nritems;
}

void btree_set_header_level(void *node, int level)
{
	((struct btree_header *)node)->level = level;
}

void btree_node_key(void *node, btree_key_t *key, int nr)
{
	*key = ((struct btree_node *)node)->ptrs[nr].key;
}

void *btree_node_ptr(void *node, int nr)
{
	int nritems = btree_header_nritems(node);
	if (nr < 0 || nr >= nritems)
		return NULL;
	return ((struct btree_node *)node)->ptrs[nr].ptr;
}

unsigned long btree_node_key_ptr_offset(int nr)
{
	return sizeof(struct btree_header) + nr * sizeof(struct btree_key_ptr);
}

void btree_set_node_key(void *node, int nr, btree_key_t *key)
{
	((struct btree_node *)node)->ptrs[nr].key = *key;
}

void btree_set_node_ptr(void *node, int nr, btree_ptr_t ptr)
{
	((struct btree_node *)node)->ptrs[nr].ptr = ptr;
}

unsigned long btree_item_nr_offset(int nr)
{
	return sizeof(struct btree_header) + nr * sizeof(struct btree_item);
}

void btree_item_key(void *node, btree_key_t *key, int nr)
{
	*key = ((struct btree_leaf *)node)->items[nr].key;
}

void btree_set_item_key(struct btree_leaf *leaf, btree_key_t *key, int nr)
{
	leaf->items[nr].key = *key;
}

/* return number of free slots in leaf node */
int btree_leaf_free_space(struct btree_leaf *node)
{
	return MAX_KEYS_PER_NODE - node->header.nritems;
}

struct btree_path* btree_alloc_path(void)
{
	struct btree_path *p;
	int i;

	p = (struct btree_path *) malloc(sizeof(struct btree_path));
	for (i = 0; i < MAX_LEVEL; i++) {
		p->nodes[i] = NULL;
		p->slots[i] = 0;
	}

	return p;
}

void btree_free_path(struct btree_path *p)
{
	free(p);
}

void btree_release_path(struct btree_path *path)
{
	/* nothing here */
}

/*
 * allocate a new btree node
 * @param level: level of this node
 * */
void* btree_new_node(int level)
{
#if 0
	unsigned int size = level ? sizeof(struct btree_key_ptr) 
				: sizeof(struct btree_item);
#endif
	unsigned int size = NODE_SIZE;

	return malloc(sizeof(struct btree_header) + MAX_KEYS_PER_NODE * size);
}

void btree_free_node(void *node)
{
	free(node);
}

/* copy #n pointers from #src to #dst
 * */
void copy_node(void *dst, void *src, int d_nr, int s_nr, int n)
{
	void *d = dst + btree_node_key_ptr_offset(d_nr);
	void *s = src + btree_node_key_ptr_offset(s_nr);
	size_t size = n * sizeof(struct btree_key_ptr);

	bcopy(s, d, size);
}

/* copy #n items from #src to #dst
 * */
void copy_leaf(void *dst, void *src, int d_nr, int s_nr, int n)
{
	void *d = dst + btree_item_nr_offset(d_nr);
	void *s = src + btree_item_nr_offset(s_nr);
	size_t size = n * sizeof(struct btree_item);

	/**/
	bcopy(s, d, size);
}

/* binary search procedure
 *
 * @param buffer: buffer for the node to search
 * @param key:    key to search
 * @param level:  level of the node
 * @param slot:   the resulting slot
 *
 * return 0 if key exisits
 * */
int bin_search(void *buffer, btree_key_t *key, int level, int *slot)
{
	int size;
	btree_key_t *k;
	int low, high, mid;
	int ret;

	if (level != 0)
		size = sizeof(struct btree_key_ptr);
	else
		size = sizeof(struct btree_item);

	low = 0;
	high = btree_header_nritems(buffer);

	while (low < high) {
		mid = ( low + high ) / 2;
		k = buffer + sizeof(struct btree_header) + mid * size;

		ret = comp_key(k, key);
		//printf(" low = %d, high = %d, mid = %d, key = %d, ret = %d\n", low, high, mid, (int)(*k), ret);

		if (ret > 0)
			low = mid + 1;
		else if (ret < 0)
			high = mid;
		else {
			*slot = mid;
			return 0;
		}

	}

	*slot = low;
	return 1;
}

/*
 * split leaf #l into two from #mid.
 * */
int copy_for_split(struct btree_root *root, struct btree_path *path,
		void *l, void* right, int slot, int mid, int nritems)
{
	int data_copy_size;
	int rt_data_off;
	int i;
	int ret = 0;
	int wret;
	btree_key_t key;

	nritems = nritems - mid;
	btree_set_header_nritems(right, nritems);
	copy_leaf(right, l, 0, mid, nritems);
	btree_set_header_nritems(l, mid);

	ret = 0;
	btree_item_key(right, &key, 0);
	wret = insert_ptr(root, path, &key, right, path->slots[1] + 1, 1);
	if (wret)
		ret = wret;

	if (mid <= slot) {
		path->nodes[0] = right;
		path->slots[0] -= mid;
		path->slots[1] += 1;
	} else {
	}

	return ret;
}

/* this will never happen */
int push_for_double_split(struct btree_root *root, struct btree_path *path,
		int data_size)
{
	return 1;
}

/*
 * TODO: 
 *
 * split leaf for insertion
 *
 * @param root  :
 * @param key   :
 * @param path  :
 * @param data_size : = number of items to insert
 * @param extend: ?
 * */
int split_leaf(struct btree_root *root, btree_key_t *ins_key,
		struct btree_path *path, int data_size, int extend)
{
	struct btree_leaf *l;
	struct btree_leaf *right;
	int slot;
	int wret, ret = 0;
	int split;
	int nritems;
	int mid;
	int num_doubles = 0;
	int tried_avoid_double = 0;
	btree_key_t key;

	/*
	printf("spliting leaf: ");
	print_leaf(path->nodes[0]);
	printf("\n");
	*/
	l = path->nodes[0];
	slot = path->slots[0];

	/* try make room by pushing left and right */
	if (data_size) {
		wret = push_leaf_right(root, path, data_size, data_size, 0, 0);
	/*
	printf(" @split_leaf() after push_leaf_right(): wret = %d, l = %p, ", wret, path->nodes[0]);
	print_leaf(path->nodes[0]);
	printf("\n");
	*/
		if (wret < 0)	/* if error happens */
			return wret;
		if (wret) {	/* if no enough space */
			wret = push_leaf_left(root, path, data_size, 
					data_size, 0, (unsigned int)-1);
			if (wret < 0)
				return wret;
		}
	/*
	printf(" @split_leaf() after push_leaf_left(): wret = %d, l = %p, ", wret, path->nodes[0]);
	print_leaf(path->nodes[0]);
	printf("\n");
	*/
		l = path->nodes[0];
		/* got enough space for data */
		if (btree_leaf_free_space(l) >= data_size)
			return 0;
	}

	/* if inserting into root */
	if (!path->nodes[1]) {
		ret = insert_new_root(root, path, 1);
		if (ret)	/* if error */
			return ret;
	}

again:
	split = 1;
	l = path->nodes[0];
	slot = path->slots[0];
	nritems = btree_header_nritems(l);
	mid = (nritems + 1) / 2;

	if (mid <= slot) {
		if (nritems == 1 ||
			nritems - mid + data_size > MAX_KEYS_PER_NODE) {
			if (slot >= nritems)
				split = 0;
			else {
				mid = slot;
				if (mid != nritems && nritems - mid + data_size > MAX_KEYS_PER_NODE) {
					if (data_size && !tried_avoid_double)
						goto push_for_double;
					split = 2;
				}
			}
		}
	} else {
		if (mid + data_size > MAX_KEYS_PER_NODE) {
			if (!extend && data_size && slot == 0) {
				split = 0;
			} else if ((extend || !data_size) && slot == 0) {
				mid = 1;
			} else {
				mid = slot;
				if (mid != nritems && nritems - mid + data_size > MAX_KEYS_PER_NODE) {
					if (data_size && !tried_avoid_double)
						goto push_for_double;
					split = 2;
				}
			}
		}
	}

	if (split != 0)
		btree_item_key(l, &key, mid);

	right = btree_new_node(0);
	btree_set_header_level(right, 0);

	if (split == 0) {
		if (mid <= slot) {
			btree_set_header_nritems(right, 0);
			wret = insert_ptr(root, path, &key, right, 
					path->slots[1] + 1, 1);
			if (wret)
				ret = wret;

			path->nodes[0] = right;
			path->slots[0] = 0;
			path->slots[1] += 1;
		} else {
			btree_set_header_nritems(right, 0);
			wret = insert_ptr(root, path, &key, right,
					path->slots[1], 1);
			if (wret)
				ret = wret;
			path->nodes[0] = right;
			path->slots[0] = 0;
			if (path->slots[1] == 0) {
				wret = fixup_low_keys(root, path, &key, 1);
				if (wret)
					ret = wret;
			}
		}

		return ret;
	} /* end if split == 0 */

	/**/
	//printf(" @split_leaf() mid = %d, nritems = %d\n", mid, nritems);
	copy_for_split(root, path, l, right, slot, mid, nritems);

	if (split == 2) {
		num_doubles++;
		goto again;
	}

	return ret;

push_for_double:
	push_for_double_split(root, path, data_size);
	tried_avoid_double = 1;
	if (btree_leaf_free_space(path->nodes[0]) >= data_size)
		return 0;
	goto again;
}

/*
 * allocate a new root with a single pointer to the current root.
 *
 * return 0 on sucess or < 0 on error.
 *
 * @param level: level of the new root, must be >= 1
 *
 * */
int insert_new_root(struct btree_root *root, struct btree_path *path, int level)
{
	void *lower, *c, *old;
	btree_key_t lower_key;

	printf(" @insert_new_root() \n");
	/* lower points to the current root */
	lower = path->nodes[level-1];
	if (level == 1)
		btree_item_key(lower, &lower_key, 0);
	else
		btree_node_key(lower, &lower_key, 0);

	/* create new root */
	c = btree_new_node(level);

	btree_set_header_nritems(c, 1);
	btree_set_header_level(c, level);

	/* add a pointer to current root */
	btree_set_node_key(c, 0, &lower_key);
	btree_set_node_ptr(c, 0, lower);

	/* switch root */
	old = root->node;
	root->node = c;

	/* FIXME: free old root? */
	//free(old);

	/* adjust the path */
	path->nodes[level] = c;
	path->slots[level] = 0;

	return 0;
}

/*
 * insert a pointer into btree which points to node 
 *
 * @param root  : tree root
 * @param path  : 
 * @param key   : key of the pointer
 * @param node  : target node of the pointer
 * @param slot  :
 * @param level : 
 *
 * */
int insert_ptr(struct btree_root *root, struct btree_path *path,
		btree_key_t *key, btree_ptr_t ptr, int slot, int level)
{
	void *lower;
	int nritems;

	lower = path->nodes[level];
	nritems = btree_header_nritems(lower);

	if (slot != nritems) {
		/* move existing pointers first.
		 * */
		copy_node(lower, lower, slot+1, slot, nritems - slot);
		/*
		memcpy(lower+btree_node_key_ptr_offset(slot+1), 
			lower+btree_node_key_ptr_offset(slot),
			(nritems -slot) * sizeof(struct btree_key_ptr));
		*/
	}
	btree_set_node_key(lower, slot, key);
	btree_set_node_ptr(lower, slot, ptr);
	btree_set_header_nritems(lower, nritems + 1);

	return 0;
}

/*
 * adjust the pointers going up the tree, starting at #level
 * making sure the right key of each node points to #key.
 * This is used after shifting pointers to the left, so it stops
 * fixing up pointers when a given leaf/node is not in slot 0 of the
 * higher levels
 *
 * If this fails to write a tree block, it returns -1, but continues
 * fixing up the blocks in ram so the tree is consistent.
 */
int fixup_low_keys(struct btree_root *root, struct btree_path *path,
		btree_key_t *key, int level)
{
	int i;
	int ret = 0;
	void *t;

	for (i = level; i < MAX_LEVEL; i++) {
		int tslot = path->slots[i];
		if (!path->nodes[i])
			break;
		t = path->nodes[i];
		btree_set_node_key(t, tslot, key);
		if (tslot != 0)
			break;
	}
	return ret;
}

/*
 * delete the pointer from a given node
 * */
int del_ptr(struct btree_root *root, struct btree_path *path, 
		int level, int slot)
{
	void *parent = path->nodes[level];
	int nritems;
	int ret = 0;
	int wret;

	/* delete the slot */
	nritems = btree_header_nritems(parent);
	if (slot != nritems - 1) {
		copy_node(parent, parent, slot, slot + 1, nritems - slot - 1);
	}
	nritems--;
	btree_set_header_nritems(parent, nritems);

	/* if the tree is empty after the deletion */
	if (nritems == 0 && parent == root->node) {
		/* turn the root into a leaf */
		btree_set_header_level(root->node, 0);
	} else if (slot == 0) {
		btree_key_t key;

		btree_node_key(parent, &key, 0);
		wret = fixup_low_keys(root, path, &key, level + 1);
		if (wret)
			ret = wret;
	}
	return ret;
}

/*
 * push data from src to dst.
 *
 * return 0 if some ptrs were pushed, < 0 if there were errors, > 0 if
 * there was no room in dst. 
 *
 * empty == 1 means we should empty the src node.
 * */
int push_node_left(struct btree_root *root, void *dst, void *src, int empty)
{
	int push_items = 0;
	int src_nritems;
	int dst_nritems;
	int ret = 0;

	src_nritems = btree_header_nritems(src);
	dst_nritems = btree_header_nritems(dst);
	/* free slots in dst */
	push_items = MAX_KEYS_PER_NODE - dst_nritems;

	if (!empty && src_nritems <= 8)
		return 1;

	if (push_items <= 0)
		return 1;

	if (empty) {
		/* push all pointers in src if there was enough space */
		push_items = min(src_nritems, push_items);
		if (push_items < src_nritems) {
			/* leave at least 8 pointers in the node if
			 * we aren't going to empty it.
			 * */
			if (src_nritems - push_items < 8) {
				if (push_items <= 8)
					return 1;
				push_items -= 8;
			}
		}
	} else
		push_items = min(src_nritems - 8, push_items);

	/* move pointers */
	copy_node(dst, src, dst_nritems, 0, push_items);

	if (push_items < src_nritems) 
		copy_node(src, src, 0, push_items, src_nritems - push_items);

	btree_set_header_nritems(src, src_nritems - push_items);
	btree_set_header_nritems(dst, dst_nritems + push_items);

	return ret;
}

/*
 * push data from src to dst, at most 1/2 of the contents of src.
 *
 * return 0 if some ptrs were pushed, < 0 if there were errors, > 0 if
 * there was no room in dst. 
 * */
int balance_node_right(struct btree_root *root, void *dst, void *src)
{
	int push_items = 0;
	int max_push;
	int src_nritems;
	int dst_nritems;
	int ret = 0;

	src_nritems = btree_header_nritems(src);
	dst_nritems = btree_header_nritems(dst);
	/* space left in dst */
	push_items = MAX_KEYS_PER_NODE - dst_nritems;
	if (push_items <= 0)
		return 1;

	/* TODO: why? */
	if (src_nritems < 4)
		return 1;

	/* push no more than 1/2 of the pointers */
	max_push = src_nritems / 2 + 1;
	/* leave no empty node */
	if (max_push >= src_nritems)
		return 1;

	if (max_push < push_items)
		push_items = max_push;

	/* move existing pointers in dst */
	copy_node(dst, dst, push_items, 0, dst_nritems);

	/* move pointers from src to dst */
	copy_node(dst, src, 0, src_nritems - push_items, push_items);

	btree_set_header_nritems(src, src_nritems - push_items);
	btree_set_header_nritems(dst, dst_nritems + push_items);

	return ret;
}

int push_nodes_for_insert(struct btree_root *root,
		struct btree_path *path, int level)
{
	void *right = NULL;
	void *mid;
	void *left = NULL;
	void *parent = NULL;
	int ret = 0;
	int wret;
	int pslot;
	int orig_slot = path->slots[level];

	/* for leaves */
	if (level == 0)
		return 1;

	mid = path->nodes[level];

	if (level < MAX_LEVEL - 1)
		parent = path->nodes[level + 1];
	pslot = path->slots[level + 1];

	/* for root */
	if (!parent)
		return 1;

	left = btree_node_ptr(parent, pslot - 1);
	/* first, try to make some room in the middle buffer */
	if (left) {
		unsigned int left_nr;

		left_nr = btree_header_nritems(left);
		if (left_nr >= MAX_KEYS_PER_NODE - 1) {
			wret = 1;
		} else {
			wret = push_node_left(root, left, mid, 0);
		}

		if (wret < 0)
			ret = wret;
		if (wret == 0) {
			btree_key_t key;
			orig_slot += left_nr;
			btree_node_key(mid, &key, 0);
			btree_set_node_key(parent, pslot, &key);

			if (btree_header_nritems(left) > orig_slot) {
				path->nodes[level] = left;
				path->slots[level + 1] -= 1;
				path->slots[level] = orig_slot;
			} else {
				orig_slot -= btree_header_nritems(left);
				path->slots[level] = orig_slot;
			}

			return 0;
		} /* end if wret ==0 */
	} /* end if left */

	right = btree_node_ptr(parent, pslot + 1);
	/*
	 * then try to empty the right most buffer into the middle
	 */
	if (right) {
		unsigned int right_nr;

		right_nr = btree_header_nritems(right);
		if (right_nr > MAX_KEYS_PER_NODE - 1) {
			wret = 1;
		} else {
			wret = balance_node_right(root, right, mid);
		}
		if (wret < 0)
			ret = wret;
		if (wret == 0) {
			btree_key_t key;

			btree_node_key(right, &key, 0);
			btree_set_node_key(parent, pslot + 1, &key);

			if (btree_header_nritems(mid) <= orig_slot) {
				path->nodes[level] = right;
				path->slots[level + 1] += 1;
				path->slots[level] = orig_slot 
					- btree_header_nritems(mid);
			} else {
			}
			return 0;
		} /* end if wret == 0 */
	} /* end if right */

	return 1;
}

/* 
 * split an index node into two.
 *
 * */
int split_node(struct btree_root *root, struct btree_path *path, int level)
{
	void *c, *split;
	btree_key_t key;
	int mid;
	int ret;
	int wret;
	int c_nritems;

	//printf("splitting node... \n");
	c = path->nodes[level];
	/* if splitting root node */
	if (c == root->node) {
		ret = insert_new_root(root, path, level + 1);
		if (ret)
			return ret;
	} else {
		ret = push_nodes_for_insert(root, path, level);
		if (ret < 0)
			return ret;
		c = path->nodes[level];
		if (!ret && btree_header_nritems(c) < MAX_KEYS_PER_NODE)
			return 0;
	}

	/* split from here */
	c_nritems = btree_header_nritems(c);
	mid = (c_nritems + 1) / 2;
	btree_node_key(c, &key, mid);

	/* allocate a new node */
	split = btree_new_node(btree_header_level(c));
	btree_set_header_level(split, btree_header_level(c));

	/* copy data to new node */
	copy_node(split, c, 0, mid, c_nritems - mid);
	btree_set_header_nritems(split, c_nritems - mid);
	btree_set_header_nritems(c, mid);

	/* insert a pointer for the new node */
	ret = insert_ptr(root, path, &key, split, 
			path->slots[level + 1] + 1, level + 1);

	/* check if we should change path */
	if (path->slots[level] >= mid) {
		path->slots[level] -= mid;
		path->nodes[level] = split;
		path->slots[level + 1] += 1;
	}

	return ret;
}

/*
 * */
int __push_leaf_right(struct btree_root *root, struct btree_path *path,
		int data_size, int empty, struct btree_leaf *right,
		int free_space, int left_nritems, int min_slot)
{
	struct btree_leaf *left = path->nodes[0];
	struct btree_node *upper = path->nodes[1];
	btree_key_t key;
	int slot;
	int i;
	int push_space = 0;
	int push_items = 0;
	struct btree_item *item;
	int nr;
	int right_nritems;
	int data_end;
	int this_item_size;

	if (empty)
		nr = 0;
	else
		nr = max(1, min_slot);

	if (path->slots[0] >= left_nritems)
		push_space += data_size;

	/* count how many items to push */
	slot = path->slots[1];
#if 0
	/* not needed at present */
	i = left_nritems - 1;
	while (i >= nr) {
		//item = btree_item_nr(left, i);

		if (!empty && push_items > 0) {
			if (path->slots[0] > i)
				break;
			/* TODO: ???? */
			if (path->slots[0] == i) {
				int space = btree_leaf_free_space(left);
				if (space + push_space * 2 > free_space)
					break;
			}
		}

		/* slots[0] is where the new items will go */
		if (path->slots[0] == i)
			push_space += data_size;

		/* FIXME */
		if (push_items > free_space)
			break;

		push_items++;

		/* reach the first item in #left */
		if (i == 0)
			break;

		i--;
	}
#else
	push_items = min(left_nritems - nr, free_space);
#endif
	
	if (push_items == 0)
		return 1;

	/* push left to right */
	right_nritems = btree_header_nritems(right);
	//printf(" @push_leaf_right(): left_nritems = %d, right_nritems = %d, push_items = %d\n", left_nritems, right_nritems, push_items);

	/* make room in the right */
	copy_leaf(right, right, push_items, 0, right_nritems);

	/* move from the left */
	copy_leaf(right, left, 0, left_nritems - push_items, push_items);

	right_nritems += push_items;
	btree_set_header_nritems(right, right_nritems);
	left_nritems -= push_items;
	btree_set_header_nritems(left, left_nritems);

	/* update parent node */
	btree_item_key(right, &key, 0);
	btree_set_node_key(upper, slot + 1, &key);

	/* fixup the leaf pointer in the path */
	if (path->slots[0] >= left_nritems) {
		path->slots[0] -= left_nritems;
		path->nodes[0] = right;
		path->slots[1] += 1;
	}

	return 0;
}

/*
 * try pushing items to the right node to make some space for insertion.
 *
 * items starting from #min_slot are pushed.
 *
 * return 0 if succeed, or 1 if failed.
 * */
int push_leaf_right(struct btree_root *root, struct btree_path *path, 
		int min_data_size, int data_size, int empty, int min_slot)
{
	struct btree_leaf *left = path->nodes[0];
	struct btree_leaf *right;
	struct btree_node *upper;
	int slot;
	int free_space;
	int left_nritems;
	int ret;

	if (!path->nodes[1])
		return 1;

	slot = path->slots[1];
	upper = path->nodes[1];
	if (slot >= btree_header_nritems(upper) - 1)
		return 1;

	right = btree_node_ptr(upper, slot + 1);
	if (right == NULL)
		return 1;

	/* no enough space in the right leaf */
	free_space = btree_leaf_free_space(right);
	if (free_space < data_size)
		return 1;

	left_nritems = btree_header_nritems(left);
	if (left_nritems == 0)
		return 1;

	return __push_leaf_right(root, path, min_data_size, empty,
			right, free_space, left_nritems, min_slot);
}

/*
 * push some data in the path leaf to the left, trying to free up at
 * least data_size bytes.  returns zero if the push worked, nonzero otherwise
 *
 * max_slot can put a limit on how far into the leaf we'll push items.  The
 * item at 'max_slot' won't be touched.  Use (u32)-1 to make us do all the
 * items
 */
int __push_leaf_left(struct btree_root *root, struct btree_path *path,
		int data_size, int empty, struct btree_leaf *left,
		int free_space, unsigned int right_nritems, 
		unsigned int max_slot)
{
	btree_key_t key;
	void *right = path->nodes[0];
	int i;
	int push_space = 0;
	int push_items = 0;
	struct btree_item *item;
	int old_left_nritems;
	int nr;
	int ret = 0;
	int wret;
	int this_item_size;
	int old_left_item_size;

	//printf("@__push_leaf_left()...\n");
	if (empty)
		nr = min(right_nritems, max_slot);
	else
		nr = min(right_nritems - 1, max_slot);

	//printf(" $$ right_nritems = %d, max_slot = %u\n", right_nritems, max_slot);

	/* counting slots & space required for push */
	/* not necessary at present */
#if 0
	for (i = 0; i < nr; i++) {
		item = btree_item_nr(right, i);

		if (!empty && push_items > 0) {
		}
	}
#else
	push_items = min(free_space, nr);
	//printf("push_items = %d \n", push_items);
#endif

	if (push_items == 0)
		return 1;

	/* copy items to #left */
	copy_leaf(left, right, btree_header_nritems(left), 0, push_items);

	old_left_nritems = btree_header_nritems(left);
	/* set data offset for copied items 
	 * not needed at present.
	 * */
	/*
	for (i = old_left_nritems; i < old_left_nritems + push_items; i++) {
	} */
	btree_set_header_nritems(left, old_left_nritems + push_items);

	/* fixup the right node */
	if (push_items < right_nritems) {
		copy_leaf(right, right, 0, push_items, 
				btree_header_nritems(right) - push_items);
	}
	right_nritems -= push_items;
	btree_set_header_nritems(right, right_nritems);
	/* fix data offset, not needed 
	for (i = 0; i < right_nritems; i++) {
	}*/

	btree_item_key(right, &key, 0);
	wret = fixup_low_keys(root, path, &key, 1);
	if (wret)
		ret = wret;

	/* fixup the leaf pointer in #path */
	if (path->slots[0] < push_items) {
		path->slots[0] += old_left_nritems;
		path->nodes[0] = left;
		path->slots[1] -= 1;
	} else {
		path->slots[0] -= push_items;
	}

	return ret;
}

/*
 * push some data in the path leaf to the left, trying to free up at
 * least data_size bytes.  returns zero if the push worked, nonzero otherwise
 *
 * max_slot can put a limit on how far into the leaf we'll push items.  The
 * item at 'max_slot' won't be touched.  Use (u32)-1 to make us push all the
 * items
 */
int push_leaf_left(struct btree_root *root, struct btree_path *path, 
		int min_data_size, int data_size, int empty, 
		unsigned int max_slot)
{
	struct btree_leaf *right = path->nodes[0];
	struct btree_leaf *left;
	int slot;
	int free_space;
	int right_nritems;
	int ret = 0;

	slot = path->slots[1];
	if (slot == 0)
		return 1;
	if (!path->nodes[1])
		return 1;

	right_nritems = btree_header_nritems(right);
	if (right_nritems == 0)
		return 1;

	left = btree_node_ptr(path->nodes[1], slot - 1);
	if (left == NULL)
		return 1;

	free_space = btree_leaf_free_space(left);
	if (free_space < data_size) {
		return 1;
	}

	return __push_leaf_left(root, path, min_data_size, empty, left, 
			free_space, right_nritems, max_slot);
}

/*
 * TODO: finish this function
 *
 * node level balancing, used to make sure nodes are in proper order for
 * item deletion.  We balance from the top down, so we have to make sure
 * that a deletion won't leave an node completely empty later on.
 */
int balance_level(struct btree_root *root, struct btree_path *path, int level)
{
	void *right = NULL;
	void *mid;
	void *left = NULL;
	void *parent = NULL;
	int ret = 0;
	int wret;
	int pslot;
	int orig_slot = path->slots[level];
	void *orig_ptr;

	//printf(" @balance_level() \n");

	/* no need for balancing leaves. */
	if (level == 0)
		return 0;

	mid = path->nodes[level];
	orig_ptr = btree_node_ptr(mid, orig_slot);

	if (level < MAX_LEVEL - 1)
		parent = path->nodes[level + 1];
	pslot = path->slots[level + 1];

	/*
	 * deal with the case where there is only one pointer in the root
	 * by promoting the node below to a root
	 */
	if (!parent) {	/* balancing root level */
		void *child;

		if (btree_header_nritems(mid) != 1)
			return 0;

		/* promote the child to a root */
		child = btree_node_ptr(mid, 0);
		root->node = child;

		path->nodes[level] = NULL;

		return 0;
	} /* end if !parent */

	if (btree_header_nritems(mid) > MAX_KEYS_PER_NODE / 4)
		return 0;

	/* FIXME: why? */
	btree_header_nritems(mid);

	/**/
	left  = btree_node_ptr(parent, pslot - 1);
	right = btree_node_ptr(parent, pslot + 1);

	/* first, try to make some room in the middle buffer */
	if (left) {
		orig_slot += btree_header_nritems(left);
		wret = push_node_left(root, left, mid, 1);
		if (wret < 0)
			ret = wret;
		btree_header_nritems(mid);
	}

	/*
	 * then try to empty the right most buffer into the middle
	 */
	if (right) {
		wret = push_node_left(root, mid, right, 1);
		if (wret < 0 && wret != -ENOSPC)
			ret = wret;
		if (btree_header_nritems(right) == 0) {
			wret = del_ptr(root, path, level + 1, pslot + 1);
			if (wret)
				ret = wret;
			right = NULL;
		} else {
			btree_key_t right_key;
			btree_node_key(right, &right_key, 0);
			btree_set_node_key(parent,  pslot + 1, &right_key);
		}
	} /* end if right */

	if (btree_header_nritems(mid) == 1) {
		wret = balance_node_right(root, mid, left);
		if (wret < 0) {
			ret = wret;
			goto enospc;
		}
		if (wret == 1) {
			wret = push_node_left(root, left, mid, 1);
			if (wret < 0)
				ret = wret;
		}
	}
	if (btree_header_nritems(mid) == 0) {
		wret = del_ptr(root, path, level + 1, pslot);
		if (wret)
			ret = wret;
		mid = NULL;
	} else {
		btree_key_t mid_key;
		btree_node_key(mid, &mid_key, 0);
		btree_set_node_key(parent, pslot, &mid_key);
	}

	/* update the path */
	if (left) {
		if (btree_header_nritems(left) > orig_slot) {
			path->nodes[level] = left;
			path->slots[level + 1] -= 1;
			path->slots[level] = orig_slot;
		} else {
			orig_slot -= btree_header_nritems(left);
			path->slots[level] = orig_slot;
		}
	}

enospc:
	return ret;
}

/*
 * does any balancing required.
 *
 * */
int setup_nodes_for_search(struct btree_root *root, struct btree_path *path, 
		struct btree_node *b, int level, int ins)
{
	int ret;

	/* NOTE: why -3 here? */
	//if (ins > 0 && btree_header_nritems(b) >= MAX_KEYS_PER_NODE - 3) {
	if (ins > 0 && btree_header_nritems(b) >= MAX_KEYS_PER_NODE) {
		/* split any full node when inserting */
		ret = split_node(root, path, level);
		if (ret)
			goto done;
		b = path->nodes[level];
	} else if (ins < 0 && btree_header_nritems(b) < MAX_KEYS_PER_NODE / 2) {
		/* when deleting */
		ret = balance_level(root, path, level);
		if (ret)
			goto done;
		b = path->nodes[level];
		/* drop the path if node deleted 
		 * force the search to start over
		 * */
		if (!b) {
			btree_release_path(path);
			goto again;
		}
	}
	return 0;

again:
	ret = -EAGAIN;
done:
	return ret;
}

/*
 * search for a key in the tree.
 *
 * ins > 0 means that we are searching for insertion, 
 * and the nodes will be split when searching.
 */
int btree_search(struct btree_root *root, btree_key_t *key,
		struct btree_path *path, int ins)
{
	int ret;
	int err;
	int level, slot, dec;
	void *buffer;
	int lowest_level = 0;

again:
	buffer  = root->node;
	while (buffer) {
		level = btree_header_level(buffer);
		path->nodes[level] = buffer;

		/*
		printf(" @btree_search(): search node ");
		if (level)
			print_node(buffer);
		else
			print_leaf(buffer);
		printf("\n");
		*/

		/* search this level */
		ret = bin_search(buffer, key, level, &slot);
		//printf(" @btree_search(): ret = %d, slot = %d\n", ret, slot);
	
		if (level != 0)	{	// for index nodes
			/* FIXME: why? */
			if (ret && slot > 0) {
				dec = 1;
				slot -= 1;
			}

			path->slots[level] = slot;
			err = setup_nodes_for_search(root, path,
					buffer, level, ins);
			/* restart the search */
			if (err == -EAGAIN)
				goto again;
			if (err) {
				ret = err;
				goto done;
			}
			buffer = path->nodes[level];
			slot = path->slots[level];

			if (level == 0) {
				if (dec)
					path->slots[level]++;
				goto done;
			}

			/* goto next level */
			buffer = btree_node_ptr(buffer, slot);
		} else {		// for leaf node
			path->slots[level] = slot;

			/* if no space for insertion */
			if (ins > 0 &&
 			     btree_leaf_free_space(buffer) < ins) {
				/*
				printf(" @btree_search(): ");
				print_leaf(buffer);
				printf("\n");
				*/
				err = split_leaf(root, key, path, ins, !ret);
				if (err) {
					ret = err;
					goto done;
				}
			}

			goto done;
		}
	}
	ret = 1;

done:
	return ret;
}

/*
 * this is a helper for btrfs_insert_empty_items, the main goal here is
 * to save stack depth by doing the bulk of the work in a function
 * that doesn't call btrfs_search_slot
 */
int setup_items_for_insert(struct btree_root *root, struct btree_path *path,
		btree_key_t *key, int *data_size, int total_data,
		int total_size, int nr)
{
	struct btree_item *item;
	int i;
	int nritems;
	unsigned int data_end;
	int ret;
	struct btree_leaf *leaf;
	int slot;

	leaf = path->nodes[0];
	slot = path->slots[0];

	nritems = btree_header_nritems(leaf);

	/*
	if (btree_leaf_free_space(root, leaf) < total_size) {
	} */

	if (slot != nritems) {
		/* shift items */
		copy_leaf(leaf, leaf, slot + nr, slot, nritems - slot);
	} /* if slot != nritems */

	/* setup the item for the new data */
	for (i = 0; i < nr; i++) {
		btree_set_item_key(leaf, key + i, slot + i);
	}

	btree_set_header_nritems(leaf, nritems + nr);

	ret = 0;
	if (slot == 0) {
		ret = fixup_low_keys(root, path, key, 1);
	}

	return ret;
}

/*
 * 
 * */
int btree_insert_empty_items(struct btree_root *root, struct btree_path *path,
		btree_key_t *key, int *data_size, int nr)
{
	int ret = 0;
	int slot;
	int i;
	int total_size = 0;
	int total_data = 0;

	/* FIXME: */
	total_size = nr;

	ret = btree_search(root, key, path, total_size);
	/*
	printf(" @insert_empty_items() ");
	print_leaf(path->nodes[0]);
	printf(" slot = %d\n", path->slots[0]);
	*/
	if (ret == 0)
		return -EEXIST;
	if (ret < 0)
		return ret;

	slot = path->slots[0];

	ret = setup_items_for_insert(root, path, key, data_size,
			total_data, total_size, nr);

	return ret;
}

int btree_insert_empty_item(struct btree_root *root, struct btree_path *path,
		btree_key_t *key, int data_size)
{
	return btree_insert_empty_items(root, path, key, &data_size, 1);
}

/* 
 * insert an item(key, data) into the tree.
 * This does all the path init required, making room in the tree if needed.
 *
 * FIXME: #data is current limited to int, so #data_size is unused.
 *
 * @param root: tree root
 * @param key : 
 * @param data: 
 */
int btree_insert_item(struct btree_root *root, btree_key_t *key,
		void *data, int data_size)
{
	int ret = 0;
	struct btree_path *path;
	struct btree_leaf *leaf;
	int slot;

	path = btree_alloc_path();
	if (!path)
		return -ENOMEM;
	ret = btree_insert_empty_item(root, path, key, data_size);
	if (!ret) {
		leaf = path->nodes[0];
		slot = path->slots[0];
		leaf->items[slot].data = *(int *)data;
	}

	btree_free_path(path);
	return ret;
}

int btree_del_leaf(struct btree_root *root, 
		struct btree_path *path,
		struct btree_leaf *leaf)
{
	int ret;

	//printf(" @btree_del_leaf() \n");

	ret = del_ptr(root, path, 1, path->slots[1]);
	if (ret)
		return ret;

	/* free leaf */
	free(leaf);

	return 0;
}

/* 
 * delete the item at the leaf level in path.  If that empties
 * the leaf, remove it from the tree
 *
 * @param root: tree root
 * @param path: path to the leaf node contains the item
 * @param slot: position of the first item to delete
 * @param nr  : number of items to delete
 */
int btree_del_items(struct btree_root *root, struct btree_path *path,
		int slot, int nr)
{
	struct btree_leaf *leaf;
	struct btree_item *item;
	int last_off;
	int dsize = 0;
	int ret = 0;
	int wret;
	int i;
	int nritems;

	leaf = path->nodes[0];
	//last_off = btree_item_offset_nr();

	/* count data size of removed items */
#if 0
	for (i = 0; i < nr; i++)
		dsize += btree_item_size_nr(leaf, slot + 1);
#endif

	nritems = btree_header_nritems(leaf);
	//printf(" @btree_del_items() slot = %d, nritems = %d, nr = %d\n", nritems, slot,nr);

	if (slot + nr != nritems) {
		copy_leaf(leaf, leaf, slot, slot + nr, nritems - slot - nr);
	}
	btree_set_header_nritems(leaf, nritems - nr);
	nritems -= nr;

	/* delete the leaf if we've emptied it */
	if (nritems == 0) {
		if (leaf == root->node) {
			btree_set_header_level(leaf, 0);
		} else {
			ret = btree_del_leaf(root, path, leaf);
		}
	} else {
		/* fixup low keys if we deleted the first few keys in the leaf*/
		if (slot == 0) {
			btree_key_t key;
			btree_item_key(leaf, &key, 0);
			wret = fixup_low_keys(root, path, &key, 1);
			if (wret)
				ret = wret;
		}

		/* delete the leaf if it's mostly empty */
		if (nritems < MAX_KEYS_PER_NODE / 2) {
			/* push_leaf_left fixes the path.
			 * make sure the path still points to our leaf
			 * for possible call to del_ptr below
			 */
			slot = path->slots[1];
			wret = push_leaf_left(root, path, 1, 1, 1,
					(unsigned int)-1);
			if (wret < 0 && wret != -ENOSPC)
				ret = wret;

			if (path->nodes[0] == leaf &&
				btree_header_nritems(leaf)) {
				wret = push_leaf_right(root, path, 1, 1, 1, 0);
				if (wret < 0 && wret != -ENOSPC)
					ret = wret;
			}

			if (btree_header_nritems(leaf) == 0) {
				path->slots[1] = slot;
				ret = btree_del_leaf(root, path, leaf);
			} else {
			}
		}
	}

	return ret;
}

/*
 * root: tree root
 * path: path to the item
 */
int btree_del_item(struct btree_root *root, struct btree_path *path)
{
	return btree_del_items(root, path, path->slots[0], 1);
}

struct btree_root *btree_new_tree(void)
{
	struct btree_root *root;
	struct btree_leaf *leaf;

	leaf = btree_new_node(0);
	root = malloc(sizeof(struct btree_root));

	root->node = leaf;

	return root;
}

void print_leaf(struct btree_leaf *leaf)
{
	int i;

	for (i = 0; i < leaf->header.nritems; i++)
		printf("%d ", leaf->items[i].key);
	printf("| ");
}

void print_node(struct btree_node *node)
{
	int i;

	for (i = 0; i < node->header.nritems; i++)
		printf("%d ", node->ptrs[i].key);
	printf("| ");
}

#define Q_MAX_LEN	256

struct queue {
	int start;
	int len;
	void *q[Q_MAX_LEN];
};

struct queue *new_queue()
{
	struct queue *q;

	q = malloc(sizeof(struct queue));
	q->start = 0;
	q->len = 0;

	return q;
}

void enqueue(struct queue *q, void *d)
{
	int tail = q->start + q->len;

	if (tail >= Q_MAX_LEN)
		tail -= Q_MAX_LEN;

	q->q[tail] = d;
	q->len++;
}

void *dequeue(struct queue *q)
{
	void *ret;

	if (!q->len)
		return NULL;
	ret = q->q[q->start];
	q->len--;
	q->start++;
	if (q->start >= Q_MAX_LEN)
		q->start -= Q_MAX_LEN;

	return ret;
}

void *qhead(struct queue *q)
{
	return q->q[q->start];
}

int qempty(struct queue *q)
{
	return q->len == 0;
}

void print_level(struct queue *q, int level)
{
	void *node;
	int l;
	int i;

	while (1) {
		if (qempty(q))
			break;

		node = qhead(q);
		l = btree_header_level(node);

		/* finish this level */
		if (l != level)
			break;

		node = dequeue(q);

		if (l) {
			print_node(node);
			/* put the pointers into the queue */
			for (i = 0; i < btree_header_nritems(node); i++) {
				enqueue(q, btree_node_ptr(node, i));
			}
		} else
			print_leaf(node);
	}

	printf("\n");
}

void print_tree(struct btree_root *root)
{
	void *node;
	int level, last_level;
	struct queue *q = new_queue();

	enqueue(q, root->node);

	printf("Tree:\n");

	while (1) {
		if (qempty(q))
			break;

		node = qhead(q);
		level = btree_header_level(node);
		
		printf(" L %d: ", level);
		print_level(q, level);
	}
}

void print_path(struct btree_path *p)
{
}

int main(void)
{
	struct btree_root *root;
	struct btree_path *path;
	int d = 10;
	btree_key_t keys[] = {3, 4, 9, 2, 5, 1, 7, 13, 21, 47, 
				23, 18, 33, 6, 12, 24, 19, 17, 26};
	int i, nr = sizeof(keys) / sizeof(btree_key_t);

	root = btree_new_tree();

	for (i = 0; i < nr; i++) {
		printf("\nInserting key %d ...\n", keys[i]);
		btree_insert_item(root, &keys[i], &d, sizeof(d));
		print_tree(root);
	}

	path = btree_alloc_path();
	for (i = 0; i < nr; i++) {
		printf("\nDeleting key %d ...\n", keys[i]);
		btree_search(root, &keys[i], path, -1);
		btree_del_item(root, path);
		print_tree(root);
	}

	return 0;	
}
