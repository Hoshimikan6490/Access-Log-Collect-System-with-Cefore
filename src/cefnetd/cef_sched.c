/*
 * Copyright (c) 2016-2023, National Institute of Information and Communications
 * Technology (NICT). All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the NICT nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NICT AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE NICT OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * cef_sched.c
 */

#define __CEF_SCHED_SOURECE__

/****************************************************************************************
 Include Files
 ****************************************************************************************/

#include "cef_netd.h"
#include <cefore/cef_client.h>

/****************************************************************************************
 Macros
 ****************************************************************************************/


/****************************************************************************************
 Structures Declaration
 ****************************************************************************************/

/****************************************************************************************
 State Variables
 ****************************************************************************************/


/****************************************************************************************
 Static Function Declaration
 ****************************************************************************************/

static int
cefnetd_packet_reparse (
	unsigned char* msg,
	uint16_t payload_len,
	uint16_t header_len,
	const CefT_CcnMsg_OptHdr* src_poh,
	CefT_CcnMsg_OptHdr* poh,
	CefT_CcnMsg_MsgBdy* pm,
	int target_type
);
static void
cefnetd_interest_forward_core (
	CefT_Netd_Handle* hdl,
	uint16_t faceids[],
	uint16_t faceid_num,
	int peer_faceid,
	unsigned char* msg,
	uint16_t payload_len,
	uint16_t header_len,
	CefT_CcnMsg_MsgBdy* pm,
	CefT_CcnMsg_OptHdr* poh,
	CefT_Pit_Entry* pe,
	CefT_Fib_Entry* fe
);

/*
 * Parses the tagged packet into poh/pm, which the caller zero-initializes.
 * Every offset (name_f, lifetime_f, ...) is then taken from new_msg by the parser, so
 * no list of offset fields has to be maintained here.  The caller's own pm/poh
 * (which describe the original msg) are left untouched.
 * The message hash does not depend on the header, so it is copied from src_poh
 * instead of being calculated again.
 */
static int										/* Returns a negative value if it fails 	*/
cefnetd_packet_reparse (
	unsigned char* msg,						/* tagged message							*/
	uint16_t payload_len,
	uint16_t header_len,
	const CefT_CcnMsg_OptHdr* src_poh,		/* Parsed Option Header of the original		*/
	CefT_CcnMsg_OptHdr* poh,				/* [out] Parsed Option Header of msg		*/
	CefT_CcnMsg_MsgBdy* pm,					/* [out] Parsed message of msg				*/
	int target_type
) {
	if (src_poh->MsgHash_len) {
		poh->MsgHash_len = src_poh->MsgHash_len;
		poh->MsgHash = src_poh->MsgHash;
	}
	return (cef_frame_message_parse (msg, payload_len, header_len, poh, pm, target_type));
}

/****************************************************************************************
 ****************************************************************************************/
/*
 * Builds a copy of msg with the LOG_TAG TLV added into new_msg.
 * msg is never modified, because it usually lives in the per-face receive buffer
 * together with the following packets.  new_msg must hold CefC_Max_Msg_Size bytes
 * and must not overlap msg.
 * Returns 1 if the tag was added (the packet is in new_msg and header_len/payload_len
 * are updated), otherwise 0 (new_msg is not valid and the caller keeps using msg).
 */
int
cefnetd_packet_add_log_tag (
	const unsigned char* msg,
	unsigned char* new_msg,
	uint16_t* header_len,
	uint16_t* payload_len,
	const unsigned char* log_tag,
	uint16_t log_tag_len,
	int overwrite
) {
	const struct fixed_hdr* in_hdr = (const struct fixed_hdr*) msg;
	struct fixed_hdr* fix_hdr;
	const struct tlv_hdr* rd_hdr;
	struct tlv_hdr* tlv_hdr;
	const uint16_t pen_len = 3;
	const unsigned char pen[] = {
		(CefC_NICT_PEN >> 16) & 0xff,
		(CefC_NICT_PEN >> 8) & 0xff,
		CefC_NICT_PEN & 0xff
	};
	uint16_t add_len = CefC_S_TLF + log_tag_len;
	uint16_t old_torg_len = 0;
	uint16_t torg_pos = 0;
	uint16_t log_tag_pos = 0;
	uint16_t old_log_tag_len = 0;
	uint16_t index;
	uint16_t packet_len;
	uint16_t insert_pos;
	uint16_t insert_len;
	uint16_t skip_len = 0;
	uint16_t shift_from;
	int delta;
	int has_log_tag = 0;
	int has_own_torg = 0;

  // if log tag is empty or NULL, return 0
	if (log_tag_len == 0 || log_tag == NULL) {
		return (0);
	}

  // check if the message has its own T-ORG TLV
	index = CefC_S_Fix_Header;
	while (index + CefC_S_TLF <= *header_len) {
		uint16_t torg_len;
		rd_hdr = (const struct tlv_hdr*) &msg[index];
		torg_len = ntohs (rd_hdr->length);
		if (torg_len > *header_len - index - CefC_S_TLF) {
			break;
		}
		if (ntohs (rd_hdr->type) == CefC_T_OPT_ORG
			&& torg_len >= pen_len
			&& memcmp (&msg[index + CefC_S_TLF], pen, pen_len) == 0) {
			torg_pos = index;
			old_torg_len = torg_len;
			has_own_torg = 1;
			break;
		}
		index += CefC_S_TLF + torg_len;
	}
	if (has_own_torg) {
		uint16_t org_value_pos = torg_pos + CefC_S_TLF + pen_len;
		uint16_t org_value_len = old_torg_len - pen_len;
		index = 0;
		while (index + CefC_S_TLF <= org_value_len) {
			uint16_t sub_len;
			rd_hdr = (const struct tlv_hdr*) &msg[org_value_pos + index];
			sub_len = ntohs (rd_hdr->length);
			if (sub_len > org_value_len - index - CefC_S_TLF) {
				break;
			}
			if (ntohs (rd_hdr->type) == CefC_T_LOG_TAG) {
				/* An existing non-empty tag is kept unless the caller asks to replace it */
				if (sub_len > 0 && !overwrite) {
					return (0);
				}
				log_tag_pos = org_value_pos + index;
				old_log_tag_len = sub_len;
				has_log_tag = 1;
				break;
			}
			index += CefC_S_TLF + sub_len;
		}
	}

  // check if the message has enough space to add LOG_TAG TLV
	packet_len = ntohs (in_hdr->pkt_len);
	if (has_own_torg) {
		if (has_log_tag) {
			/* Only the value of the existing LOG_TAG TLV is replaced */
			insert_pos = log_tag_pos + CefC_S_TLF;
			skip_len   = old_log_tag_len;
			insert_len = log_tag_len;
		} else {
			insert_pos = torg_pos + CefC_S_TLF + old_torg_len;
			insert_len = add_len;
		}
	} else {
		insert_pos = *header_len;
		insert_len = CefC_S_TLF + pen_len + add_len;
	}
	delta = (int) insert_len - (int) skip_len;
	if (delta > 0
		&& (packet_len > CefC_Max_Msg_Size - delta
			|| *header_len > CefC_Max_Header_Size - delta)) {
		return (0);
	}

  // add LOG_TAG TLV (without value of Log Tag) to the copied message
	shift_from = insert_pos + skip_len;
	memcpy (new_msg, msg, insert_pos);
	memcpy (&new_msg[insert_pos + insert_len], &msg[shift_from], packet_len - shift_from);
	if (has_own_torg) {
		tlv_hdr = (struct tlv_hdr*) &new_msg[torg_pos];
		tlv_hdr->length = htons (old_torg_len + delta);
		index = has_log_tag ? log_tag_pos : insert_pos;
	} else {
		tlv_hdr = (struct tlv_hdr*) &new_msg[insert_pos];
		tlv_hdr->type = htons (CefC_T_OPT_ORG);
		tlv_hdr->length = htons (pen_len + add_len);
		memcpy (&new_msg[insert_pos + CefC_S_TLF], pen, pen_len);
		index = insert_pos + CefC_S_TLF + pen_len;
	}
  // add LOG_TAG TLV (with value of Log Tag) to the message
	tlv_hdr = (struct tlv_hdr*) &new_msg[index];
	tlv_hdr->type = htons (CefC_T_LOG_TAG);
	tlv_hdr->length = htons (log_tag_len);
	memcpy (&new_msg[index + CefC_S_TLF], log_tag, log_tag_len);
	*header_len += delta;
	fix_hdr = (struct fixed_hdr*) new_msg;
	fix_hdr->hdr_len = (uint8_t) *header_len;
	fix_hdr->pkt_len = htons (*header_len + *payload_len);
	return (1);
}

/*--------------------------------------------------------------------------------------
	Forwards the specified Interest
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_interest_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	if (fe != NULL) {

		/* Forwards the Interest to next node 		*/
		if (pm->hoplimit < 1) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Not forwarded due to hop limit.\n");
#endif // CefC_Debug
			return (1);
		}

	} else {
		/* Forwards the Interest to local process, if it matches the Interest Filter 	*/
		// TBD: interest filter
	}

	if (!cef_face_is_local_face (peer_faceid)) {
		/* Updates Hoplimit 		*/
		pm->hoplimit--;
		if (pm->hoplimit < 1) {
#ifdef CefC_Debug
			cef_dbg_write (CefC_Dbg_Fine, "Not forwarded due to hop limit.\n");
#endif // CefC_Debug
			return (1);
		}
		msg[CefC_O_Fix_HopLimit] = pm->hoplimit;
	}
	if (hdl->access_log_f && hdl->log_tag_buf != NULL) {
		/*
		 * msg points into the receive buffer which also holds the following
		 * packets, so the tagged Interest is built in a separate buffer.
		 */
		unsigned char* tagged_msg = hdl->log_tag_buf;
		CefT_CcnMsg_MsgBdy tagged_pm = { 0 };
		CefT_CcnMsg_OptHdr tagged_poh = { 0 };
		uint16_t tagged_header_len = header_len;
		uint16_t tagged_payload_len = payload_len;

		/* pm/poh of the caller keep describing the original msg */
		if (cefnetd_packet_add_log_tag (msg, tagged_msg, &tagged_header_len, &tagged_payload_len,
				(unsigned char*) hdl->log_tag_name,
				(uint16_t) strlen (hdl->log_tag_name), 0)
			&& cefnetd_packet_reparse (tagged_msg, tagged_payload_len, tagged_header_len,
				poh, &tagged_poh, &tagged_pm, CefC_PT_INTEREST) >= 0) {
			cefnetd_interest_forward_core (hdl, faceids, faceid_num, peer_faceid,
				tagged_msg, tagged_payload_len, tagged_header_len,
				&tagged_pm, &tagged_poh, pe, fe);
			return (1);
		}
	}

	cefnetd_interest_forward_core (hdl, faceids, faceid_num, peer_faceid,
		msg, payload_len, header_len, pm, poh, pe, fe);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Passes the Interest to the forwarding strategy
----------------------------------------------------------------------------------------*/
static void
cefnetd_interest_forward_core (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* message to forward						*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	CefT_FwdStrtgy_Param		fwdstr = { 0 };

	if (hdl->fwd_strtgy_hdl->fwd_int) {

		/* Set parameters */
		fwdstr.hdl_cefnetd     = (void *)hdl;
		fwdstr.faceids         = faceids;
		fwdstr.faceid_num      = faceid_num;
		fwdstr.peer_faceid     = peer_faceid;
		fwdstr.msg             = msg;
		fwdstr.payload_len     = payload_len;
		fwdstr.header_len      = header_len;
		fwdstr.pm              = pm;
		fwdstr.poh             = poh;
		if ( poh ){
			fwdstr.tx_prio     = poh->tx_prio;
			/* In transmit threads, the default value of 0 is treated as a special value of 1. */
			/* If less than 0, it will not be transmit. */
			fwdstr.tx_copies   = poh->tx_copies;
			fwdstr.tx_routes   = poh->tx_routes;
		}
		fwdstr.pe              = pe;

		if (pm->chunk_num_f){
			uint16_t name_len_wo_chunk = pm->name_len;
			name_len_wo_chunk -= (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);

			/* Find for PIT without chunk number (Anker PIT) */
			fwdstr.pe_refer        =
				(CefT_Pit_Entry*) cef_lhash_tbl_item_get (hdl->pit, pm->name, name_len_wo_chunk);

			if ( fwdstr.pe_refer == NULL ){
				/* Find PIT with lower chunk number */
				fwdstr.pe_refer    = cef_pit_entry_search_with_anychunk (hdl->pit, pm, poh, 0);
			}
		}

		fwdstr.fe              = fe;
		fwdstr.cnt_send_frames = &(hdl->stat_send_interest);
		fwdstr.cnt_send_types  = hdl->stat_send_interest_types;

		/* Forwards the Interest according to Forwarding Strategy. */
		hdl->fwd_strtgy_hdl->fwd_int(&fwdstr);
	}
}
/*--------------------------------------------------------------------------------------
	Forwards the specified ccninfo request
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_ccninforeq_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	int peer_faceid, 						/* Face-ID to reply to the origin of 		*/
											/* transmission of the message(s)			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh, 				/* Parsed Option Header						*/
	CefT_Pit_Entry* pe, 					/* PIT entry matching this Interest 		*/
	CefT_Fib_Entry* fe						/* FIB entry matching this Interest 		*/
) {
	int fulldiscovery_authNZ = 0;
	CefT_FwdStrtgy_Param		fwdstr = { 0 };

	/* Ccninfo Full discovery authentication & authorization */
	if (hdl->ccninfo_full_discovery == 2 /* Authentication and Authorization */
		&& poh->ccninfo_flag & CefC_CtOp_FullDisCover) {
		fulldiscovery_authNZ = cefnetd_ccninfo_fulldiscovery_authNZ(
													hdl->ccninfousr_id_len,
													hdl->ccninfousr_node_id,
													hdl->ccninfo_rcvdpub_key_bi_len,
													hdl->ccninfo_rcvdpub_key_bi);
	}

	/* Set parameters */
	fwdstr.hdl_cefnetd     = (void *)hdl;
	fwdstr.faceids         = faceids;
	fwdstr.faceid_num      = faceid_num;
	fwdstr.peer_faceid     = peer_faceid;
	fwdstr.msg             = msg;
	fwdstr.payload_len     = payload_len;
	fwdstr.header_len      = header_len;
	fwdstr.pm              = pm;
	fwdstr.poh             = poh;
	fwdstr.pe              = pe;
	fwdstr.fe              = fe;

	/* Forwards the CcninfoReq according to Forwarding Strategy. */
	cef_forward_ccninforeq(&fwdstr, fulldiscovery_authNZ, hdl->ccninfo_full_discovery);

	return (1);
}

/*--------------------------------------------------------------------------------------
	Forwards the specified Content Object
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_object_forward (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh 				/* Parsed Option Header						*/
) {
	CefT_FwdStrtgy_Param		fwdstr = { 0 };
	uint16_t					name_len;

	if (hdl->fwd_strtgy_hdl->fwd_cob) {

		/* Set parameters */
		fwdstr.hdl_cefnetd     = (void *)hdl;
		fwdstr.faceids         = faceids;
		fwdstr.faceid_num      = faceid_num;
		fwdstr.msg             = msg;
		fwdstr.payload_len     = payload_len;
		fwdstr.header_len      = header_len;
		fwdstr.pm              = pm;
		fwdstr.poh             = poh;
		if ( poh ){
			fwdstr.tx_prio     = poh->tx_prio;
			/* In transmit threads, the default value of 0 is treated as a special value of 1. */
			/* If less than 0, it will not be transmit. */
			fwdstr.tx_copies   = poh->tx_copies;
		}
		fwdstr.cnt_send_frames = &(hdl->stat_send_frames);

		/* Searches a FIB entry matching the Interest requested this ContentObject */
		if (pm->chunk_num_f) {
			name_len = pm->name_len - (CefC_S_Type + CefC_S_Length + CefC_S_ChunkNum);
		} else {
			/* Symbolic Interest	*/
			name_len = pm->name_len;
		}

		fwdstr.fe = cef_fib_entry_search (hdl->fib, pm->name, name_len);

		/* Forwards the ContentObject according to Forwarding Strategy. */
		hdl->fwd_strtgy_hdl->fwd_cob(&fwdstr);

	}

	return (1);
}

/*--------------------------------------------------------------------------------------
	Forwards the specified Content Object with the Log Tag of each Face
----------------------------------------------------------------------------------------*/
int											/* Returns a negative value if it fails 	*/
cefnetd_object_forward_with_log_tag (
	CefT_Netd_Handle* hdl,					/* cefnetd handle							*/
	uint16_t faceids[], 					/* Face-IDs to forward						*/
	uint16_t faceid_num, 					/* Number of Face-IDs to forward			*/
	const unsigned char* const tags[],		/* Log Tag for each Face-ID					*/
	const uint16_t tag_lens[],				/* Length of Log Tag for each Face-ID		*/
	unsigned char* msg, 					/* received message to handle				*/
	uint16_t payload_len, 					/* Payload Length of this message			*/
	uint16_t header_len,					/* Header Length of this message			*/
	CefT_CcnMsg_MsgBdy* pm, 				/* Parsed message 							*/
	CefT_CcnMsg_OptHdr* poh 				/* Parsed Option Header						*/
) {
	uint16_t group[CefC_Fib_UpFace_Max];
	uint8_t done[CefC_Fib_UpFace_Max];
	/*
	 * msg points into the receive buffer which also holds the following
	 * packets, so the tagged Object is built in a separate buffer.
	 */
	unsigned char* tagged_msg = hdl->log_tag_buf;
	uint16_t i, j, group_num;

	if (faceid_num > CefC_Fib_UpFace_Max) {
		faceid_num = CefC_Fib_UpFace_Max;
	}
	memset (done, 0, sizeof (done));

	for (i = 0; i < faceid_num; i++) {
		CefT_CcnMsg_MsgBdy tagged_pm = { 0 };
		CefT_CcnMsg_OptHdr tagged_poh = { 0 };
		uint16_t tagged_header_len = header_len;
		uint16_t tagged_payload_len = payload_len;
		int tagged_f = 0;

		if (done[i]) {
			continue;
		}

		/* Faces which get the same Log Tag are sent together */
		group_num = 0;
		for (j = i; j < faceid_num; j++) {
			if (!done[j] && tag_lens[j] == tag_lens[i] &&
				(tag_lens[i] == 0 || memcmp (tags[j], tags[i], tag_lens[i]) == 0)) {
				group[group_num++] = faceids[j];
				done[j] = 1;
			}
		}

		if (tag_lens[i] > 0 && tagged_msg != NULL) {
			tagged_f = cefnetd_packet_add_log_tag (msg, tagged_msg,
				&tagged_header_len, &tagged_payload_len, tags[i], tag_lens[i], 1)
				&& cefnetd_packet_reparse (tagged_msg, tagged_payload_len, tagged_header_len,
					poh, &tagged_poh, &tagged_pm, CefC_PT_OBJECT) >= 0;
		}
		if (tagged_f) {
			/* pm/poh of the caller keep describing the original msg */
			cefnetd_object_forward (hdl, group, group_num, tagged_msg,
				tagged_payload_len, tagged_header_len, &tagged_pm, &tagged_poh);
		} else {
			cefnetd_object_forward (hdl, group, group_num, msg,
				payload_len, header_len, pm, poh);
		}
	}

	return (1);
}
