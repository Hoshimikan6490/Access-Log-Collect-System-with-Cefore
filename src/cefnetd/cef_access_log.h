/*
 * cef_access_log.h
 *
 * Access log buffer of cefnetd.
 *
 * A router which is the closest to the Consumer records, for each downstream Face and
 * each Contents Name, how many times the Contents were returned.  The records are
 * aggregated in a fixed-size buffer.  When the buffer is full, the entry which was
 * accessed least recently (the oldest last_ts) is overwritten.
 *
 * Two buffers are used alternately.  One is for accumulation (written by cefnetd), and
 * the other is for transfer (read by the transfer thread).
 *
 *     accumulation buffer --(swap)--> READY --(acquire)--> IN_USE --(release)--> EMPTY
 *
 * Thread safety:
 *   - cef_access_log_record() and cef_access_log_flush() may be called from any thread
 *     (they are serialized by a mutex).
 *   - A buffer returned by cef_access_log_acquire() is owned by the caller until
 *     cef_access_log_release() is called; it can be read without any lock.
 */

#ifndef __CEF_ACCESS_LOG_HEADER__
#define __CEF_ACCESS_LOG_HEADER__

/****************************************************************************************
 Include Files
 ****************************************************************************************/
#include <stdint.h>
#include <pthread.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/

#define CefC_AccessLog_Default_BufSize		4096	/* Entries per buffer				*/
#define CefC_AccessLog_Max_BufSize			1048576
#define CefC_AccessLog_Default_NameMax		256		/* Max bytes of a stored Name		*/
#define CefC_AccessLog_Default_SwapPct		80		/* Usage (%) which triggers a swap	*/

#define CefC_AccessLog_Idx_None				(-1)

/* State of the buffer which is not used for accumulation */
#define CefC_AccessLog_State_Empty			0
#define CefC_AccessLog_State_Ready			1		/* Filled, waiting for transfer		*/
#define CefC_AccessLog_State_InUse			2		/* Being read by the transfer side	*/

/****************************************************************************************
 Structure Declarations
 ****************************************************************************************/

/* One aggregated record */
typedef struct {
	uint64_t	first_ts;			/* Time of the first record (us)					*/
	uint64_t	last_ts;			/* Time of the last record (us)						*/
	uint64_t	access_count;		/* Number of accesses (counted at chunk 0)			*/
	uint64_t	chunk_count;		/* Number of Data (all chunks) returned				*/
	uint32_t	hashv;
	int32_t		hash_next;			/* Next entry in the same hash bucket / free list	*/
	int32_t		lru_prev;			/* Older entry										*/
	int32_t		lru_next;			/* Newer entry										*/
	uint16_t	faceid;				/* Downstream Face-ID								*/
	uint16_t	name_len;			/* Length of the Name (without the chunk number)	*/
} CefT_AccessLog_Entry;

/* Fixed-size aggregation buffer */
typedef struct {
	CefT_AccessLog_Entry*	entries;	/* [capacity]									*/
	unsigned char*			names;		/* [capacity * name_max]						*/
	int32_t*				buckets;	/* [bucket_num]									*/
	uint32_t	capacity;
	uint32_t	name_max;
	uint32_t	bucket_num;				/* Power of 2									*/
	uint32_t	used;
	int32_t		lru_head;				/* Oldest entry									*/
	int32_t		lru_tail;				/* Newest entry									*/
	int32_t		free_head;
	uint64_t	evicted;				/* Entries overwritten because the buffer was full	*/
	uint64_t	skipped_long_name;		/* Records skipped because the Name was too long	*/
} CefT_AccessLog_Buf;

typedef struct {
	CefT_AccessLog_Buf	buf[2];
	int					active;			/* Index of the accumulation buffer				*/
	int					other_state;	/* CefC_AccessLog_State_* of the other buffer	*/
	uint32_t			swap_threshold;	/* Number of entries which triggers a swap		*/
	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
} CefT_AccessLog;

/****************************************************************************************
 Function Declarations
 ****************************************************************************************/

/*--------------------------------------------------------------------------------------
	Creates the access log buffers
----------------------------------------------------------------------------------------*/
CefT_AccessLog*								/* Returns NULL if it fails					*/
cef_access_log_create (
	uint32_t buf_size,						/* Number of entries per buffer				*/
	uint32_t name_max,						/* Max bytes of a stored Name				*/
	uint32_t swap_pct						/* Usage (%) which triggers a swap			*/
);

/*--------------------------------------------------------------------------------------
	Destroys the access log buffers
----------------------------------------------------------------------------------------*/
void
cef_access_log_destroy (
	CefT_AccessLog* al
);

/*--------------------------------------------------------------------------------------
	Records one returned Data
----------------------------------------------------------------------------------------*/
void
cef_access_log_record (
	CefT_AccessLog* al,
	uint16_t faceid,						/* Downstream Face-ID						*/
	const unsigned char* name,				/* Name without the chunk number			*/
	uint16_t name_len,
	int new_access,							/* 1: count this Data as a new access		*/
	uint64_t now							/* Present time (us)						*/
);

/*--------------------------------------------------------------------------------------
	Swaps the buffers even if the threshold is not reached
----------------------------------------------------------------------------------------*/
int											/* Returns 1 if swapped, 0 otherwise		*/
cef_access_log_flush (
	CefT_AccessLog* al
);

/*--------------------------------------------------------------------------------------
	Acquires the buffer to transfer
----------------------------------------------------------------------------------------*/
CefT_AccessLog_Buf*							/* Returns NULL if no buffer is ready		*/
cef_access_log_acquire (
	CefT_AccessLog* al,
	int wait_ms								/* 0: no wait, >0: wait up to wait_ms		*/
);

/*--------------------------------------------------------------------------------------
	Clears the acquired buffer and returns it for accumulation
----------------------------------------------------------------------------------------*/
void
cef_access_log_release (
	CefT_AccessLog* al,
	CefT_AccessLog_Buf* buf
);

/*--------------------------------------------------------------------------------------
	Gets the Name of an entry of the acquired buffer
----------------------------------------------------------------------------------------*/
static inline const unsigned char*
cef_access_log_entry_name (
	const CefT_AccessLog_Buf* buf,
	int32_t idx
) {
	return (&buf->names[(size_t) idx * buf->name_max]);
}

/*
 * Iterates the entries of an acquired buffer from the oldest to the newest:
 *   for (i = buf->lru_head; i != CefC_AccessLog_Idx_None; i = buf->entries[i].lru_next)
 */

#endif // __CEF_ACCESS_LOG_HEADER__
