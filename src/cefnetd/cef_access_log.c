/*
 * cef_access_log.c
 *
 * Access log buffer of cefnetd.  See cef_access_log.h for the design.
 */

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "cef_access_log.h"

/****************************************************************************************
 Static Function Declarations
 ****************************************************************************************/

static int
cef_access_log_buf_init (
	CefT_AccessLog_Buf* buf,
	uint32_t capacity,
	uint32_t name_max
);

static void
cef_access_log_buf_free (
	CefT_AccessLog_Buf* buf
);

static void
cef_access_log_buf_clear (
	CefT_AccessLog_Buf* buf
);

static uint32_t
cef_access_log_hash (
	uint16_t faceid,
	const unsigned char* name,
	uint16_t name_len
);

static int32_t
cef_access_log_buf_find (
	const CefT_AccessLog_Buf* buf,
	uint32_t hashv,
	uint16_t faceid,
	const unsigned char* name,
	uint16_t name_len
);

static void
cef_access_log_lru_unlink (
	CefT_AccessLog_Buf* buf,
	int32_t idx
);

static void
cef_access_log_lru_push_tail (
	CefT_AccessLog_Buf* buf,
	int32_t idx
);

static void
cef_access_log_hash_unlink (
	CefT_AccessLog_Buf* buf,
	int32_t idx
);

static int32_t
cef_access_log_buf_alloc (
	CefT_AccessLog_Buf* buf
);

static int
cef_access_log_swap_locked (
	CefT_AccessLog* al
);

/****************************************************************************************
 Functions
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the access log buffers
----------------------------------------------------------------------------------------*/
CefT_AccessLog*
cef_access_log_create (
	uint32_t buf_size,
	uint32_t name_max,
	uint32_t swap_pct
) {
	CefT_AccessLog* al;
	uint64_t th;

	if (buf_size < 1 || buf_size > CefC_AccessLog_Max_BufSize || name_max < 1) {
		return (NULL);
	}
	if (swap_pct < 1) {
		swap_pct = 1;
	} else if (swap_pct > 100) {
		swap_pct = 100;
	}

	al = (CefT_AccessLog*) calloc (1, sizeof (CefT_AccessLog));
	if (al == NULL) {
		return (NULL);
	}
	if (cef_access_log_buf_init (&al->buf[0], buf_size, name_max) < 0 ||
		cef_access_log_buf_init (&al->buf[1], buf_size, name_max) < 0) {
		cef_access_log_buf_free (&al->buf[0]);
		cef_access_log_buf_free (&al->buf[1]);
		free (al);
		return (NULL);
	}

	th = ((uint64_t) buf_size * swap_pct + 99) / 100;
	if (th < 1) {
		th = 1;
	}
	al->swap_threshold = (uint32_t) th;
	al->active = 0;
	al->other_state = CefC_AccessLog_State_Empty;
	pthread_mutex_init (&al->mutex, NULL);
	pthread_cond_init (&al->cond, NULL);

	return (al);
}

/*--------------------------------------------------------------------------------------
	Destroys the access log buffers
----------------------------------------------------------------------------------------*/
void
cef_access_log_destroy (
	CefT_AccessLog* al
) {
	if (al == NULL) {
		return;
	}
	pthread_cond_destroy (&al->cond);
	pthread_mutex_destroy (&al->mutex);
	cef_access_log_buf_free (&al->buf[0]);
	cef_access_log_buf_free (&al->buf[1]);
	free (al);
}

/*--------------------------------------------------------------------------------------
	Records one returned Data
----------------------------------------------------------------------------------------*/
void
cef_access_log_record (
	CefT_AccessLog* al,
	uint16_t faceid,
	const unsigned char* name,
	uint16_t name_len,
	int new_access,
	uint64_t now
) {
	CefT_AccessLog_Buf* buf;
	CefT_AccessLog_Entry* ent;
	uint32_t hashv;
	int32_t idx;

	if (al == NULL || name == NULL) {
		return;
	}

	pthread_mutex_lock (&al->mutex);
	buf = &al->buf[al->active];

	if (name_len == 0 || name_len > buf->name_max) {
		/* Never truncate the Name: it would be aggregated with another content */
		buf->skipped_long_name++;
		pthread_mutex_unlock (&al->mutex);
		return;
	}

	hashv = cef_access_log_hash (faceid, name, name_len);
	idx = cef_access_log_buf_find (buf, hashv, faceid, name, name_len);

	if (idx != CefC_AccessLog_Idx_None) {
		/* Aggregates into the existing entry */
		ent = &buf->entries[idx];
		ent->last_ts = now;
		ent->chunk_count++;
		if (new_access) {
			ent->access_count++;
		}
		cef_access_log_lru_unlink (buf, idx);
		cef_access_log_lru_push_tail (buf, idx);
	} else {
		/* Creates a new entry (overwrites the least recently accessed one if full) */
		idx = cef_access_log_buf_alloc (buf);
		ent = &buf->entries[idx];
		ent->first_ts = now;
		ent->last_ts = now;
		ent->access_count = new_access ? 1 : 0;
		ent->chunk_count = 1;
		ent->hashv = hashv;
		ent->faceid = faceid;
		ent->name_len = name_len;
		memcpy (&buf->names[(size_t) idx * buf->name_max], name, name_len);

		ent->hash_next = buf->buckets[hashv & (buf->bucket_num - 1)];
		buf->buckets[hashv & (buf->bucket_num - 1)] = idx;
		cef_access_log_lru_push_tail (buf, idx);
	}

	if (buf->used >= al->swap_threshold) {
		cef_access_log_swap_locked (al);
	}
	pthread_mutex_unlock (&al->mutex);
}

/*--------------------------------------------------------------------------------------
	Acquires the buffer to transfer
----------------------------------------------------------------------------------------*/
CefT_AccessLog_Buf*
cef_access_log_acquire (
	CefT_AccessLog* al,
	int wait_ms
) {
	CefT_AccessLog_Buf* buf = NULL;
	struct timespec ts;

	if (al == NULL) {
		return (NULL);
	}

	pthread_mutex_lock (&al->mutex);
	if (al->other_state != CefC_AccessLog_State_Ready && wait_ms > 0) {
		clock_gettime (CLOCK_REALTIME, &ts);
		ts.tv_sec += wait_ms / 1000;
		ts.tv_nsec += (long) (wait_ms % 1000) * 1000000L;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		while (al->other_state != CefC_AccessLog_State_Ready) {
			if (pthread_cond_timedwait (&al->cond, &al->mutex, &ts) == ETIMEDOUT) {
				break;
			}
		}
	}
	if (al->other_state == CefC_AccessLog_State_Ready) {
		al->other_state = CefC_AccessLog_State_InUse;
		/* The active buffer cannot change while the other buffer is not empty */
		buf = &al->buf[1 - al->active];
	}
	pthread_mutex_unlock (&al->mutex);

	return (buf);
}

/*--------------------------------------------------------------------------------------
	Clears the acquired buffer and returns it for accumulation
----------------------------------------------------------------------------------------*/
void
cef_access_log_release (
	CefT_AccessLog* al,
	CefT_AccessLog_Buf* buf
) {
	if (al == NULL || buf == NULL) {
		return;
	}

	pthread_mutex_lock (&al->mutex);
	if (al->other_state != CefC_AccessLog_State_InUse || buf != &al->buf[1 - al->active]) {
		pthread_mutex_unlock (&al->mutex);
		return;
	}
	pthread_mutex_unlock (&al->mutex);

	/* The buffer is owned by the caller, so it is cleared without the lock */
	cef_access_log_buf_clear (buf);

	pthread_mutex_lock (&al->mutex);
	al->other_state = CefC_AccessLog_State_Empty;
	pthread_mutex_unlock (&al->mutex);
}

/*--------------------------------------------------------------------------------------
	Swaps the accumulation buffer and the other buffer (the mutex must be held)
----------------------------------------------------------------------------------------*/
static int
cef_access_log_swap_locked (
	CefT_AccessLog* al
) {
	if (al->other_state != CefC_AccessLog_State_Empty) {
		/* The transfer side is still busy: keep accumulating (old entries are overwritten) */
		return (0);
	}
	al->active = 1 - al->active;
	al->other_state = CefC_AccessLog_State_Ready;
	pthread_cond_signal (&al->cond);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Initializes a buffer
----------------------------------------------------------------------------------------*/
static int
cef_access_log_buf_init (
	CefT_AccessLog_Buf* buf,
	uint32_t capacity,
	uint32_t name_max
) {
	uint32_t bn = 1;

	memset (buf, 0, sizeof (CefT_AccessLog_Buf));
	while (bn < capacity * 2) {
		bn <<= 1;
	}

	buf->entries = (CefT_AccessLog_Entry*) calloc (capacity, sizeof (CefT_AccessLog_Entry));
	buf->names = (unsigned char*) calloc (capacity, name_max);
	buf->buckets = (int32_t*) calloc (bn, sizeof (int32_t));
	if (buf->entries == NULL || buf->names == NULL || buf->buckets == NULL) {
		cef_access_log_buf_free (buf);
		return (-1);
	}
	buf->capacity = capacity;
	buf->name_max = name_max;
	buf->bucket_num = bn;
	cef_access_log_buf_clear (buf);

	return (0);
}

static void
cef_access_log_buf_free (
	CefT_AccessLog_Buf* buf
) {
	free (buf->entries);
	free (buf->names);
	free (buf->buckets);
	memset (buf, 0, sizeof (CefT_AccessLog_Buf));
}

/*--------------------------------------------------------------------------------------
	Removes all entries and statistics of a buffer
----------------------------------------------------------------------------------------*/
static void
cef_access_log_buf_clear (
	CefT_AccessLog_Buf* buf
) {
	uint32_t i;

	for (i = 0; i < buf->bucket_num; i++) {
		buf->buckets[i] = CefC_AccessLog_Idx_None;
	}
	/* All entries are chained as the free list */
	for (i = 0; i < buf->capacity; i++) {
		buf->entries[i].hash_next =
			(i + 1 < buf->capacity) ? (int32_t) (i + 1) : CefC_AccessLog_Idx_None;
	}
	buf->free_head = (buf->capacity > 0) ? 0 : CefC_AccessLog_Idx_None;
	buf->lru_head = CefC_AccessLog_Idx_None;
	buf->lru_tail = CefC_AccessLog_Idx_None;
	buf->used = 0;
	buf->evicted = 0;
	buf->skipped_long_name = 0;
}

/*--------------------------------------------------------------------------------------
	FNV-1a hash of (Face-ID, Name)
----------------------------------------------------------------------------------------*/
static uint32_t
cef_access_log_hash (
	uint16_t faceid,
	const unsigned char* name,
	uint16_t name_len
) {
	uint32_t h = 2166136261u;
	uint16_t i;

	h = (h ^ (uint32_t) (faceid & 0xff)) * 16777619u;
	h = (h ^ (uint32_t) (faceid >> 8)) * 16777619u;
	for (i = 0; i < name_len; i++) {
		h = (h ^ name[i]) * 16777619u;
	}

	return (h);
}

static int32_t
cef_access_log_buf_find (
	const CefT_AccessLog_Buf* buf,
	uint32_t hashv,
	uint16_t faceid,
	const unsigned char* name,
	uint16_t name_len
) {
	int32_t idx = buf->buckets[hashv & (buf->bucket_num - 1)];

	while (idx != CefC_AccessLog_Idx_None) {
		const CefT_AccessLog_Entry* ent = &buf->entries[idx];
		if (ent->hashv == hashv && ent->faceid == faceid && ent->name_len == name_len &&
			memcmp (&buf->names[(size_t) idx * buf->name_max], name, name_len) == 0) {
			return (idx);
		}
		idx = ent->hash_next;
	}

	return (CefC_AccessLog_Idx_None);
}

static void
cef_access_log_lru_unlink (
	CefT_AccessLog_Buf* buf,
	int32_t idx
) {
	CefT_AccessLog_Entry* ent = &buf->entries[idx];

	if (ent->lru_prev != CefC_AccessLog_Idx_None) {
		buf->entries[ent->lru_prev].lru_next = ent->lru_next;
	} else {
		buf->lru_head = ent->lru_next;
	}
	if (ent->lru_next != CefC_AccessLog_Idx_None) {
		buf->entries[ent->lru_next].lru_prev = ent->lru_prev;
	} else {
		buf->lru_tail = ent->lru_prev;
	}
	ent->lru_prev = CefC_AccessLog_Idx_None;
	ent->lru_next = CefC_AccessLog_Idx_None;
}

static void
cef_access_log_lru_push_tail (
	CefT_AccessLog_Buf* buf,
	int32_t idx
) {
	CefT_AccessLog_Entry* ent = &buf->entries[idx];

	ent->lru_prev = buf->lru_tail;
	ent->lru_next = CefC_AccessLog_Idx_None;
	if (buf->lru_tail != CefC_AccessLog_Idx_None) {
		buf->entries[buf->lru_tail].lru_next = idx;
	} else {
		buf->lru_head = idx;
	}
	buf->lru_tail = idx;
}

static void
cef_access_log_hash_unlink (
	CefT_AccessLog_Buf* buf,
	int32_t idx
) {
	uint32_t b = buf->entries[idx].hashv & (buf->bucket_num - 1);
	int32_t* pp = &buf->buckets[b];

	while (*pp != CefC_AccessLog_Idx_None) {
		if (*pp == idx) {
			*pp = buf->entries[idx].hash_next;
			return;
		}
		pp = &buf->entries[*pp].hash_next;
	}
}

/*--------------------------------------------------------------------------------------
	Gets a free slot.  If the buffer is full, the least recently accessed entry
	(the head of the LRU list) is removed and reused.
	The returned slot is not linked to the hash table and the LRU list.
----------------------------------------------------------------------------------------*/
static int32_t
cef_access_log_buf_alloc (
	CefT_AccessLog_Buf* buf
) {
	int32_t idx;

	if (buf->free_head != CefC_AccessLog_Idx_None) {
		idx = buf->free_head;
		buf->free_head = buf->entries[idx].hash_next;
		buf->used++;
	} else {
		idx = buf->lru_head;
		cef_access_log_hash_unlink (buf, idx);
		cef_access_log_lru_unlink (buf, idx);
		buf->evicted++;
	}
	buf->entries[idx].hash_next = CefC_AccessLog_Idx_None;
	buf->entries[idx].lru_prev = CefC_AccessLog_Idx_None;
	buf->entries[idx].lru_next = CefC_AccessLog_Idx_None;

	return (idx);
}
