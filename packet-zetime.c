/* packet-zetime.c
 *
 * Routines for ZeTime protocol packet disassembly
 * By Angelos Drossos <develangel@mail.drossos.de>
 * Copyright 2019 Angelos Drossos
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-bluetooth.h>

static int proto_zetime = -1;

static gint ett_zetime = -1;

static int hf_zetime_preamble = -1;
static int hf_zetime_pdu_type = -1;
static int hf_zetime_msg_type = -1;
static int hf_zetime_payload_length = -1;
static int hf_zetime_payload = -1;
static int hf_zetime_end = -1;

static int hf_zetime_packet_number = -1;
static int hf_zetime_timestamp = -1;
static int hf_zetime_steps = -1;
static int hf_zetime_calories_burnt = -1;
static int hf_zetime_meters_walked = -1;
static int hf_zetime_activity_minutes = -1;

#define zetime_pdu_type_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_PDU_TYPE_RECEIPT, 0x01, "Receipt") \
    XXX(ZETIME_PDU_TYPE_SERIALNUMBER, 0x02, "Serial Number") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x03, 0x03, "UNKNOWN 0x03") \
    XXX(ZETIME_PDU_TYPE_TIMESYNC, 0x04, "Time Synchronization") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x0b, 0x0b, "UNKNOWN 0x0b") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x0c, 0x0c, "UNKNOWN 0x0c") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x18, 0x18, "UNKNOWN 0x18") \
    XXX(ZETIME_PDU_TYPE_INFOAVAIL, 0x52, "Information Availability") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x53, 0x53, "UNKNOWN 0x53") \
    XXX(ZETIME_PDU_TYPE_ACTIVITYREPORT, 0x54, "Activity Report") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0x5a, 0x5a, "UNKNOWN 0x5a") \
    XXX(ZETIME_PDU_TYPE_HEARTRATEFREQ, 0x61, "Heart Rate Frequency") \
    XXX(ZETIME_PDU_TYPE_CALMONVIEW, 0x98, "Calendar Month View") \
    XXX(ZETIME_PDU_TYPE_CALDAYVIEW, 0x99, "Calendar Day View") \
    XXX(ZETIME_PDU_TYPE_UNKNOWN_0xe2, 0xe2, "UNKNOWN 0xe2")

VALUE_STRING_ENUM(zetime_pdu_type);
VALUE_STRING_ARRAY(zetime_pdu_type);

#define zetime_msg_type_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_MSG_TYPE_RECEIPT, 0x70, "Request") \
    XXX(ZETIME_MSG_TYPE_NOTIFICATION, 0x71, "Notification") \
    XXX(ZETIME_MSG_TYPE_RESPONSE, 0x80, "Response") \
    XXX(ZETIME_MSG_TYPE_CONFIRMATION, 0x81, "Confirmation") \

VALUE_STRING_ENUM(zetime_msg_type);
VALUE_STRING_ARRAY(zetime_msg_type);

static gint
dissect_preamble(tvbuff_t *tvb, gint offset, proto_tree *zetime_tree)
{
    const gint len = 1;
    proto_tree_add_item(zetime_tree, hf_zetime_preamble, tvb, offset, len,
                        ENC_NA);
    return len;
}

#define ZETIME_CMD_END_LEN 1

static gint
dissect_end(tvbuff_t *tvb, gint offset, proto_tree *zetime_tree)
{
    proto_tree_add_item(zetime_tree, hf_zetime_end, tvb, offset,
                        ZETIME_CMD_END_LEN, ENC_NA);
    return ZETIME_CMD_END_LEN;
}

static gint
dissect_pdu_type(tvbuff_t *tvb, gint offset, proto_tree *zetime_tree,
                 proto_item *ti, packet_info *pinfo, guint *valueRet)
{
    const gint len = 1;
    guint value = 0;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_pdu_type, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN, &value);
    proto_item_append_text(ti, ", %s", val_to_str(value,
                           zetime_pdu_type,
                           "UNKNOWN PDU TYPE (0x%02x)"));
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(value,
                 zetime_pdu_type,
                 "UNKNOWN PDU TYPE (0x%02x)"));

    if (valueRet) {
        *valueRet = value;
    }
    return len;
}

static gint
dissect_msg_type(tvbuff_t *tvb, gint offset, proto_tree *zetime_tree,
                 proto_item *ti, packet_info *pinfo _U_, guint *valueRet)
{
    const gint len = 1;
    guint value = 0;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_msg_type, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN, &value);
    proto_item_append_text(ti, ", %s", val_to_str(value,
                           zetime_msg_type,
                           "UNKNOWN MSG TYPE (0x%02x)"));

    if (valueRet) {
        *valueRet = value;
    }
    return len;
}

static gint
dissect_payload_length(tvbuff_t *tvb, gint offset, proto_tree *zetime_tree,
                       gint *payload_len)
{
    const gint len = 2;
    guint plen = 0;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_payload_length, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN,
                                 &plen);
    if (payload_len) {
        *payload_len = plen;
    }
    return len;
}

static gint
dissect_packet_number(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 2;
    proto_tree_add_item(tree, hf_zetime_packet_number, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static gint
dissect_timestamp(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 4;
    proto_tree_add_item(tree, hf_zetime_timestamp, tvb, offset, len, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
    return len;
}

static gint
dissect_steps(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 4;
    proto_tree_add_item(tree, hf_zetime_steps, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static gint
dissect_calories_burnt(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 4;
    proto_tree_add_item(tree, hf_zetime_calories_burnt, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static gint
dissect_meters_walked(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 4;
    proto_tree_add_item(tree, hf_zetime_meters_walked, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static gint
dissect_activity_minutes(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    const gint len = 4;
    proto_tree_add_item(tree, hf_zetime_activity_minutes, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_payload_unknown(tvbuff_t *tvb, packet_info *pinfo _U_,
                                proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_zetime_payload, tvb, 0, -1, ENC_NA);
    return tvb_captured_length(tvb);
}

static guint
dissect_activity_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                                proto_tree *tree, void *data _U_)
{
    gint offset = 0;
    offset += dissect_packet_number(tvb, offset, tree);
    offset += dissect_timestamp(tvb, offset, tree);
    offset += dissect_steps(tvb, offset, tree);
    offset += dissect_calories_burnt(tvb, offset, tree);
    offset += dissect_meters_walked(tvb, offset, tree);
    offset += dissect_activity_minutes(tvb, offset, tree);
    return offset;
}

static int
dissect_zetime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_,
               void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZeTime");
    col_clear(pinfo->cinfo, COL_INFO);

    /* General message composition
     *
     * +----------+----------+----------+----------------+----------+-------+
     * | PREAMBLE | PDU TYPE | MSG TYPE | payload length | payload  |  END  |
     * |  1 Byte  |  1 Byte  |  1 Byte  |    2 Bytes     | X Bytes  |  1 B  |
     * |  fixed   |   enum   |   enum   |    number      | variable | fixed |
     * +----------+----------+----------+----------------+----------+-------+
     *
     */

    proto_item *ti = proto_tree_add_item(tree, proto_zetime, tvb, 0, -1,
                                         ENC_NA);
    proto_tree *zetime_tree = proto_item_add_subtree(ti, ett_zetime);

    guint pdu_type = 0;
    guint msg_type = 0;
    gint payload_len = 0;
    gint offset = 0;

    offset += dissect_preamble(tvb, offset, zetime_tree);
    offset += dissect_pdu_type(tvb, offset, zetime_tree, ti, pinfo, &pdu_type);
    offset += dissect_msg_type(tvb, offset, zetime_tree, ti, pinfo, &msg_type);
    offset += dissect_payload_length(tvb, offset, zetime_tree, &payload_len);

    const gboolean fragmented = tvb_captured_length_remaining(tvb, offset)
                              < payload_len + ZETIME_CMD_END_LEN;
    {
        tvbuff_t *const payload_tvb = tvb_new_subset_length_caplen(tvb, offset, 
                                      fragmented ? -1 : payload_len, payload_len);
        switch (pdu_type) {
        case ZETIME_PDU_TYPE_RECEIPT:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_SERIALNUMBER:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x03:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_TIMESYNC:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x0b:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x0c:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x18:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_INFOAVAIL:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x53:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_ACTIVITYREPORT:
            offset += dissect_activity_response(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0x5a:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_HEARTRATEFREQ:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_CALMONVIEW:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_CALDAYVIEW:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        case ZETIME_PDU_TYPE_UNKNOWN_0xe2:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        default:
            offset += dissect_payload_unknown(payload_tvb, pinfo, zetime_tree, data);
            break;
        }
    }

    if (!fragmented) {
        offset += dissect_end(tvb, offset, zetime_tree);
    }

    return offset;
}

static int
dissect_zetime_uuid16_write(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_write(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid16_ack(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_ack(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid16_reply(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_reply(tvbuff_t *tvb, packet_info *pinfo,
                          proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid16_notify(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_notify(tvbuff_t *tvb, packet_info *pinfo,
                           proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid16_8005(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_8005(tvbuff_t *tvb, packet_info *pinfo,
                         proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid16_heart_rate(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

static int
dissect_zetime_uuid128_heart_rate(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree _U_, void *data _U_)
{
    return dissect_zetime(tvb, pinfo, tree, data);
}

void
proto_register_zetime(void)
{
    static hf_register_info hf[] = {
        { &hf_zetime_preamble,
            { "PREAMBLE", "zetime.preamble",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_pdu_type,
            { "PDU Type", "zetime.pdu_type",
            FT_UINT8, BASE_DEC,
            VALS(zetime_pdu_type), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_msg_type,
            { "MSG Type", "zetime.msg_type",
            FT_UINT8, BASE_HEX,
            VALS(zetime_msg_type), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_payload_length,
            { "Payload Length", "zetime.payload_length",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_payload,
            { "Payload", "zetime.payload",
            FT_BYTES, BASE_NO_DISPLAY_VALUE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_end,
            { "END", "zetime.end",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_packet_number,
            { "Packet Number", "zetime.packet_number",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_timestamp,
            { "Timestamp", "zetime.timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_steps,
            { "Steps", "zetime.steps",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calories_burnt,
            { "Calories burnt", "zetime.calories_burnt",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_meters_walked,
            { "Meters walked", "zetime.meters_walked",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_activity_minutes,
            { "Minutes of activity", "zetime.activity_minutes",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_zetime
    };

    proto_zetime = proto_register_protocol (
        "ZeTime Protocol", /* name */
        "ZeTime",          /* short name */
        "zetime"           /* abbrev */
    );

    proto_register_field_array(proto_zetime, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_zetime(void)
{
    const struct uuid_dissectors_t {
        const gchar * const uuid;
              gchar * const short_name;

        int (* const dissect_func)(tvbuff_t *tvb, packet_info *pinfo,
                                   proto_tree *tree, void *data);
    } uuid_dissectors[] = {
        /*
         * uuid characteristics
         */
        { "8001", "ZeTime Write", dissect_zetime_uuid16_write },
        { "00008001-0000-1000-8000-00805f9b34fb", "ZeTime Write", dissect_zetime_uuid128_write },
        { "8002", "ZeTime Ack", dissect_zetime_uuid16_ack },
        { "00008002-0000-1000-8000-00805f9b34fb", "ZeTime Ack", dissect_zetime_uuid128_ack },
        { "8003", "ZeTime Reply", dissect_zetime_uuid16_reply },
        { "00008003-0000-1000-8000-00805f9b34fb", "ZeTime Reply", dissect_zetime_uuid128_reply },
        { "8004", "ZeTime Notify", dissect_zetime_uuid16_notify },
        { "00008004-0000-1000-8000-00805f9b34fb", "ZeTime Notify", dissect_zetime_uuid128_notify },
        { "8005", "ZeTime 8005", dissect_zetime_uuid16_8005 },
        { "00008005-0000-1000-8000-00805f9b34fb", "ZeTime 8005", dissect_zetime_uuid128_8005 },
        { "2a37", "ZeTime Heart Rate", dissect_zetime_uuid16_heart_rate },
        { "00002a37-0000-1000-8000-00805f9b34fb", "ZeTime Heart Rate", dissect_zetime_uuid128_heart_rate },

        /* 2902 config descriptor is already defined in packet-btatt */

        /*
         * uuid services
         */
        { "6006", "ZeTime Service Base", NULL },
        { "00006006-0000-1000-8000-00805f9b34fb", "ZeTime Service Base", NULL },
        { "7006", "ZeTime Service Extend", NULL },
        { "00007006-0000-1000-8000-00805f9b34fb", "ZeTime Service Extend", NULL },
        { "180d", "ZeTime Service Heart Rate", NULL },
        { "0000180d-0000-1000-8000-00805f9b34fb", "ZeTime Service Heart Rate", NULL },

        { NULL, NULL, NULL } /* end of list */
    };
    for (gint i = 0; uuid_dissectors[i].uuid; ++i) {
        wmem_tree_insert_string(bluetooth_uuids, uuid_dissectors[i].uuid,
                                uuid_dissectors[i].short_name, 0);

        if (uuid_dissectors[i].dissect_func) {
            dissector_handle_t handle = create_dissector_handle(
                                            uuid_dissectors[i].dissect_func,
                                            proto_zetime);
            dissector_add_string("bluetooth.uuid", uuid_dissectors[i].uuid,
                                 handle);
        }
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
