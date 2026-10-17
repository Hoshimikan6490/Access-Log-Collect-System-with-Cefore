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

/****************************************************************************************
 ****************************************************************************************/
static int
cefnetd_interest_add_log_tag (
	CefT_Netd_Handle* hdl,
	unsigned char* msg,
	uint16_t* header_len,
	uint16_t* payload_len,
	CefT_CcnMsg_OptHdr* poh
) {
	struct fixed_hdr* fix_hdr = (struct fixed_hdr*) msg;
	struct tlv_hdr* tlv_hdr;
	const uint16_t pen_len = 3;
	const unsigned char pen[] = {
		(CefC_NICT_PEN >> 16) & 0xff,
		(CefC_NICT_PEN >> 8) & 0xff,
		CefC_NICT_PEN & 0xff
	};
	uint16_t log_tag_len = (uint16_t) strlen (hdl->local_sock_id);
	uint16_t add_len = CefC_S_TLF + log_tag_len;
	uint16_t old_torg_len = 0;
	uint16_t torg_pos = 0;
	uint16_t log_tag_pos = 0;
	uint16_t index;
	uint16_t packet_len;
	int has_empty_log_tag = 0;
	int has_own_torg = 0;

  // if LOCAL_SOCK_ID is not set or poh is NULL, return 0
	if (log_tag_len == 0 || poh == NULL) {
		return (0);
	}

  // check if the message has its own T-ORG TLV
	index = CefC_S_Fix_Header;
	while (index + CefC_S_TLF <= *header_len) {
		uint16_t torg_len;
		tlv_hdr = (struct tlv_hdr*) &msg[index];
		torg_len = ntohs (tlv_hdr->length);
		if (torg_len > *header_len - index - CefC_S_TLF) {
			break;
		}
		if (ntohs (tlv_hdr->type) == CefC_T_OPT_ORG
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
			tlv_hdr = (struct tlv_hdr*) &msg[org_value_pos + index];
			sub_len = ntohs (tlv_hdr->length);
			if (sub_len > org_value_len - index - CefC_S_TLF) {
				break;
			}
			if (ntohs (tlv_hdr->type) == CefC_T_LOG_TAG) {
				if (sub_len > 0) {
					return (0);
				}
				log_tag_pos = org_value_pos + index;
				has_empty_log_tag = 1;
				break;
			}
			index += CefC_S_TLF + sub_len;
		}
	}

  // check if the message has enough space to add LOG_TAG TLV
	packet_len = ntohs (fix_hdr->pkt_len);
	if (has_own_torg) {
		uint16_t insert_len = has_empty_log_tag ? log_tag_len : add_len;
		if (packet_len > CefC_Max_Msg_Size - insert_len
			|| *header_len > CefC_Max_Header_Size - insert_len) {
			return (0);
		}
	} else {
		uint16_t new_torg_len = CefC_S_TLF + pen_len + add_len;
		if (packet_len > CefC_Max_Msg_Size - new_torg_len
			|| *header_len > CefC_Max_Header_Size - new_torg_len) {
			return (0);
		}
	}

  // add LOG_TAG TLV (without value of Log Tag) to the message
	if (has_own_torg) {
		uint16_t insert_len = has_empty_log_tag ? log_tag_len : add_len;
		uint16_t insert_pos = has_empty_log_tag
			? log_tag_pos + CefC_S_TLF
			: torg_pos + CefC_S_TLF + old_torg_len;
		memmove (&msg[insert_pos + insert_len], &msg[insert_pos], packet_len - insert_pos);
		tlv_hdr = (struct tlv_hdr*) &msg[torg_pos];
		tlv_hdr->length = htons (old_torg_len + insert_len);
		index = has_empty_log_tag ? log_tag_pos : insert_pos;
	} else {
		uint16_t insert_pos = *header_len;
		uint16_t new_torg_len = CefC_S_TLF + pen_len + add_len;
		memmove (&msg[insert_pos + new_torg_len], &msg[insert_pos], packet_len - insert_pos);
		tlv_hdr = (struct tlv_hdr*) &msg[insert_pos];
		tlv_hdr->type = htons (CefC_T_OPT_ORG);
		tlv_hdr->length = htons (pen_len + add_len);
		memcpy (&msg[insert_pos + CefC_S_TLF], pen, pen_len);
		index = insert_pos + CefC_S_TLF + pen_len;
	}

  // add LOG_TAG TLV (with value of Log Tag) to the message
	tlv_hdr = (struct tlv_hdr*) &msg[index];
	tlv_hdr->type = htons (CefC_T_LOG_TAG);
	tlv_hdr->length = htons (log_tag_len);
	memcpy (&msg[index + CefC_S_TLF], hdl->local_sock_id, log_tag_len);
	if (has_own_torg) {
		*header_len += add_len;
	} else {
		uint16_t new_torg_len = CefC_S_TLF + pen_len + add_len;
		*header_len += new_torg_len;
	}
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
	CefT_FwdStrtgy_Param		fwdstr = { 0 };

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
	cefnetd_interest_add_log_tag (hdl, msg, &header_len, &payload_len, poh);

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

	return (1);
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
