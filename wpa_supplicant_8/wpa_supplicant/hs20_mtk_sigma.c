/*! \file   "Hs20_mtk_sigma.c"
*    \brief  For HS20-SIGMA
*
*    This file provided the macros and functions library support for the
*    protocol layer hotspot 2.0 related function.
*
*/

/*******************************************************************************
* Copyright (c) 2007 MediaTek Inc.
*
* All rights reserved. Copying, compilation, modification, distribution
* or any other use whatsoever of this material is strictly prohibited
* except in accordance with a Software License Agreement with
* MediaTek Inc.
********************************************************************************
*/

/*******************************************************************************
* LEGAL DISCLAIMER
*
* BY OPENING THIS FILE, BUYER HEREBY UNEQUIVOCALLY ACKNOWLEDGES AND
* AGREES THAT THE SOFTWARE/FIRMWARE AND ITS DOCUMENTATIONS ("MEDIATEK
* SOFTWARE") RECEIVED FROM MEDIATEK AND/OR ITS REPRESENTATIVES ARE
* PROVIDED TO BUYER ON AN "AS-IS" BASIS ONLY. MEDIATEK EXPRESSLY
* DISCLAIMS ANY AND ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT
* LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
* PARTICULAR PURPOSE OR NONINFRINGEMENT. NEITHER DOES MEDIATEK PROVIDE
* ANY WARRANTY WHATSOEVER WITH RESPECT TO THE SOFTWARE OF ANY THIRD PARTY
* WHICH MAY BE USED BY, INCORPORATED IN, OR SUPPLIED WITH THE MEDIATEK
* SOFTWARE, AND BUYER AGREES TO LOOK ONLY TO SUCH THIRD PARTY FOR ANY
* WARRANTY CLAIM RELATING THERETO. MEDIATEK SHALL ALSO NOT BE RESPONSIBLE
* FOR ANY MEDIATEK SOFTWARE RELEASES MADE TO BUYER'S SPECIFICATION OR TO
* CONFORM TO A PARTICULAR STANDARD OR OPEN FORUM.
*
* BUYER'S SOLE AND EXCLUSIVE REMEDY AND MEDIATEK'S ENTIRE AND CUMULATIVE
* LIABILITY WITH RESPECT TO THE MEDIATEK SOFTWARE RELEASED HEREUNDER WILL
* BE, AT MEDIATEK'S OPTION, TO REVISE OR REPLACE THE MEDIATEK SOFTWARE AT
* ISSUE, OR REFUND ANY SOFTWARE LICENSE FEES OR SERVICE CHARGE PAID BY
* BUYER TO MEDIATEK FOR SUCH MEDIATEK SOFTWARE AT ISSUE.
*
* THE TRANSACTION CONTEMPLATED HEREUNDER SHALL BE CONSTRUED IN ACCORDANCE
* WITH THE LAWS OF THE STATE OF CALIFORNIA, USA, EXCLUDING ITS CONFLICT
* OF LAWS PRINCIPLES.  ANY DISPUTES, CONTROVERSIES OR CLAIMS ARISING
* THEREOF AND RELATED THERETO SHALL BE SETTLED BY ARBITRATION IN SAN
* FRANCISCO, CA, UNDER THE RULES OF THE INTERNATIONAL CHAMBER OF COMMERCE
* (ICC).
********************************************************************************
*/

/*
** $Log: Hs20_mtk_sigma.c $
 *
 */

  /*******************************************************************************
 *						   C O M P I L E R	 F L A G S
 ********************************************************************************
 */

 /*******************************************************************************
 *					  E X T E R N A L	R E F E R E N C E S
 ********************************************************************************
 */

#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "includes.h"
#include <linux/wireless.h>

#include "common.h"
#include "eloop.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/gas.h"
#include "common/wpa_ctrl.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "config.h"
#include "bss.h"
#include "gas_query.h"
#include "interworking.h"
#include "hs20_supplicant.h"
#include "mediatek_driver_nl80211.h"


/*******************************************************************************
*								C O N S T A N T S
********************************************************************************
*/

/*******************************************************************************
*							   D A T A	 T Y P E S
********************************************************************************
*/

/*******************************************************************************
*							  P U B L I C	D A T A
********************************************************************************
*/

/*******************************************************************************
*							 P R I V A T E	 D A T A
********************************************************************************
*/

/*******************************************************************************
*								   M A C R O S
********************************************************************************
*/

/*******************************************************************************
*					 F U N C T I O N   D E C L A R A T I O N S
********************************************************************************
*/

/*******************************************************************************
*								F U N C T I O N S
********************************************************************************
*/

#ifdef CONFIG_MTK_HS20R1_SIGMA
int sigma_hs20_init (struct wpa_supplicant *wpa_s)
{
	struct hs20_sigma *sigma;
	struct sigma_cmd_sta_cred_list *prCredLst;

	if(wpa_s->global->sigma == NULL) {
		wpa_hs20_printf(MSG_INFO, "HS20 SIGMA: sigma_init");

		sigma = os_zalloc(sizeof(struct hs20_sigma));
		if (sigma == NULL) {
			return -1;
		}

#if 0
	    //sigma->cred_count = 0;
	    prCredLst = os_zalloc(sizeof(struct sigma_cmd_sta_cred_list));
		if (prCredLst == NULL) {
			return -1;
		}
		prCredLst->prNext = NULL;
		prCredLst->cred_count = 0;
		sigma->prCredLst = prCredLst;
#endif

	    sigma->is_running= 0;
		wpa_s->global->sigma = sigma;

	}
	else {
		wpa_hs20_printf(MSG_INFO, "HS20 SIGMA: sigma is already init");
	}

	return 0;
}

void sigma_hs20_deinit(struct wpa_supplicant *wpa_s)
{
	size_t i;
	struct hs20_credential *prCredTmp;

	wpa_hs20_printf(MSG_INFO, "HS20 SIGMA: sigma_deinit");

	if(wpa_s->global->sigma != NULL) {
#if 0
		if (sigma->bssid_pool) {
			for (i = 0; i < sigma->bssid_pool_count; i++) {
				os_free(sigma->bssid_pool[i]);
			}
			os_free(sigma->bssid_pool);
			sigma->bssid_pool_count = 0;
			sigma->bssid_pool = NULL;
		}

		if (wpa_s->bss_pool) {
			os_free(wpa_s->bss_pool);
			wpa_s->bss_pool = NULL;
		}


		if (sigma->prCredLst) {
			sigma->prCredLst->cred_count = 0;
			while(sigma->prCredLst->prNext != NULL){
				prCredTmp = sigma->prCredLst->prNext->prNext;
				os_free(sigma->prCredLst->prNext);
				sigma->prCredLst->prNext = prCredTmp;
			}
			os_free(sigma->prCredLst);
			sigma->prCredLst = NULL;
		}
#endif
		os_free(wpa_s->global->sigma);
		wpa_s->global->sigma = NULL;
	}
	else {
		wpa_hs20_printf(MSG_INFO, "HS20 SIGMA: sigma is already deinit");
	}
}


/************
UCC: HS2-5.1
CAPI: sta_scan
************/
int sigma_hs20_add_scan_info(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen)
{
	char *str;
	int ret = 3;

	wpa_hs20_printf(MSG_INFO, "[%s] Add Scan info...", __func__);

	for(;;)
	{
		str = strtok_r(NULL, " ", &cmd);
		if(str == NULL || str[0] == '\0')
			break;

		if(os_strncmp(str, "-h", 2) == 0){
			if(hwaddr_aton(str+2, wpa_s->conf->hessid) == -1){
				ret = -1;
			}
			wpa_hs20_printf(MSG_INFO, "[%s] Set hessid : " MACSTR, __func__, MAC2STR(wpa_s->conf->hessid));
		}
		else if(os_strncmp(str, "-a", 2) == 0){
			wpa_s->conf->access_network_type = atoi(str+2);
			if(wpa_s->conf->access_network_type > 15 || wpa_s->conf->access_network_type < 0){
				ret = -1;
			}
			wpa_hs20_printf(MSG_INFO, "[%s] Set access_network_type : %d", __func__, wpa_s->conf->access_network_type);
		}
	}


	if (!wpa_s->conf->update_config) {
		wpa_hs20_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Not allowed "
			   "to update configuration (update_config=0)");
		return -1;
	}

	ret = wpa_config_write(wpa_s->confname, wpa_s->conf);
	if (ret) {
		wpa_hs20_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Failed to "
			   "update configuration");
	} else {
		wpa_hs20_printf(MSG_DEBUG, "CTRL_IFACE: SAVE_CONFIG - Configuration"
			   " updated");
	}


	return ret;
}

/************
UCC: Almost all
CAPI: get_curr_assoc
************/
int sigma_get_current_assoc(struct wpa_supplicant *wpa_s, char *cmd, char *buf, size_t buflen)
{
    struct wpa_ssid *cur_ssid = wpa_s->current_ssid;

	char *pos, *end;
	int ret = -1;
	int i = 0;

	pos = buf;
	end = buf + buflen;

	if((cur_ssid != NULL) && (wpa_s->wpa_state == WPA_COMPLETED)){
		ret = os_snprintf(pos, end - pos, "ssid=%s\nbssid=" MACSTR "\n", cur_ssid->ssid, MAC2STR(wpa_s->bssid));
	}

	return ret;
}

#endif
