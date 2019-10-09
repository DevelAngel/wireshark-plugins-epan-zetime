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
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/unit_strings.h>
#include <epan/dissectors/packet-bluetooth.h>

#include <assert.h>

static int proto_zetime = -1;

static gint ett_zetime = -1;
static gint ett_zetime_msg_fragment = -1;
static gint ett_zetime_msg_fragments = -1;

static expert_field ei_zetime_preamble_mismatch = EI_INIT;
static expert_field ei_zetime_end_mismatch = EI_INIT;
static expert_field ei_zetime_ack_mismatch = EI_INIT;

static int hf_zetime_preamble = -1;
static int hf_zetime_pdu_type = -1;
static int hf_zetime_action = -1;
static int hf_zetime_payload_length = -1;
static int hf_zetime_payload = -1;
static int hf_zetime_payload_unkown = -1;
static int hf_zetime_end = -1;
static int hf_zetime_ack = -1;

static int hf_zetime_error_code = -1;
static int hf_zetime_watch_id = -1;
static int hf_zetime_version_type = -1;
static int hf_zetime_version_info = -1;
static int hf_zetime_battery_power_level = -1;
static int hf_zetime_language = -1;
static int hf_zetime_packet_number = -1;
static int hf_zetime_timestamp = -1;
static int hf_zetime_steps = -1;
static int hf_zetime_calories_burnt = -1;
static int hf_zetime_meters_walked = -1;
static int hf_zetime_activity_minutes = -1;
static int hf_zetime_heart_rate = -1;

static int hf_zetime_available_steps = -1;
static int hf_zetime_available_sleep = -1;
static int hf_zetime_available_heart_rate = -1;

static int hf_zetime_datetime_year = -1;
static int hf_zetime_datetime_month = -1;
static int hf_zetime_datetime_day = -1;
static int hf_zetime_datetime_hour = -1;
static int hf_zetime_datetime_minute = -1;
static int hf_zetime_datetime_second = -1;
static int hf_zetime_timezone_hour = -1;
static int hf_zetime_timezone_minute = -1;

static int hf_zetime_calendar_event_type = -1;
static int hf_zetime_calendar_event_year = -1;
static int hf_zetime_calendar_event_month = -1;
static int hf_zetime_calendar_event_day = -1;
static int hf_zetime_calendar_event_hour = -1;
static int hf_zetime_calendar_event_minute = -1;
static int hf_zetime_calendar_event_title = -1;

static int hf_zetime_msg_fragments = -1;
static int hf_zetime_msg_fragment = -1;
static int hf_zetime_msg_fragment_overlap = -1;
static int hf_zetime_msg_fragment_overlap_conflicts = -1;
static int hf_zetime_msg_fragment_multiple_tails = -1;
static int hf_zetime_msg_fragment_too_long_fragment = -1;
static int hf_zetime_msg_fragment_error = -1;
static int hf_zetime_msg_fragment_count = -1;
static int hf_zetime_msg_reassembled_in = -1;
static int hf_zetime_msg_reassembled_length = -1;
static int hf_zetime_msg_reassembled_data = -1;

static const fragment_items zetime_msg_frag_items = {
    /* Fragment subtrees */
    &ett_zetime_msg_fragment,
    &ett_zetime_msg_fragments,

    /* Fragment fields */
    &hf_zetime_msg_fragments,
    &hf_zetime_msg_fragment,
    &hf_zetime_msg_fragment_overlap,
    &hf_zetime_msg_fragment_overlap_conflicts,
    &hf_zetime_msg_fragment_multiple_tails,
    &hf_zetime_msg_fragment_too_long_fragment,
    &hf_zetime_msg_fragment_error,
    &hf_zetime_msg_fragment_count,
    &hf_zetime_msg_reassembled_in,
    &hf_zetime_msg_reassembled_length,
    &hf_zetime_msg_reassembled_data,

    /* Tag */
    "Message fragments"
};

static reassembly_table zetime_msg_reassembly_table;

#define zetime_pdu_type_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_PDU_TYPE_RESPOND, 0x01, "Respond") \
    XXX(ZETIME_PDU_TYPE_WATCH_ID, 0x02, "Watch ID") \
    XXX(ZETIME_PDU_TYPE_DEVICE_VERSION, 0x03, "Device Version") \
    XXX(ZETIME_PDU_TYPE_DATE_TIME, 0x04, "Time Synchronization") \
    XXX(ZETIME_PDU_TYPE_BATTERY_POWER, 0x08, "Battery Power") \
    XXX(ZETIME_PDU_TYPE_LANGUAGE_SETTINGS, 0x0b, "Language Settings") \
    XXX(ZETIME_PDU_TYPE_AVAILABLE_DATA, 0x52, "Available Data") \
    XXX(ZETIME_PDU_TYPE_DELETE_STEP_COUNT, 0x53, "Step Count Deletion") \
    XXX(ZETIME_PDU_TYPE_GET_STEP_COUNT, 0x54, "Step Count") \
    XXX(ZETIME_PDU_TYPE_DELETE_HEARTRATE_DATA, 0x5a, "Heart Rate Data Deletion") \
    XXX(ZETIME_PDU_TYPE_GET_HEARTRATE_EXDATA, 0x61, "Heart Rate Exdata") \
    XXX(ZETIME_PDU_TYPE_PUSH_CALENDAR_DAY, 0x99, "Push Calendar Day") \

VALUE_STRING_ENUM(zetime_pdu_type);
VALUE_STRING_ARRAY(zetime_pdu_type);

#define zetime_action_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_ACTION_REQUEST, 0x70, "Request") \
    XXX(ZETIME_ACTION_SEND, 0x71, "Send") \
    XXX(ZETIME_ACTION_RESPONSE, 0x80, "Response") \
    XXX(ZETIME_ACTION_CONFIRMATION, 0x81, "Confirmation") \

VALUE_STRING_ENUM(zetime_action);
VALUE_STRING_ARRAY(zetime_action);

#define zetime_version_type_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_VERSION_TYPE_HW, 0x00, "Hardware Version") \
    XXX(ZETIME_VERSION_TYPE_OTHER, 0x02, "Other Version") \
    XXX(ZETIME_VERSION_TYPE_FW, 0x05, "Firmware Version") \

VALUE_STRING_ENUM(zetime_version_type);
VALUE_STRING_ARRAY(zetime_version_type);

#define zetime_error_code_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_ERROR_CODE_NONE, 0x00, "no error") \
    XXX(ZETIME_ERROR_CODE_GENERAL, 0x01, "general error") \

VALUE_STRING_ENUM(zetime_error_code);
VALUE_STRING_ARRAY(zetime_error_code);

#define zetime_language_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_LANGUAGE_EN,      0, "EN") \
    XXX(ZETIME_LANGUAGE_ZH,      1, "ZH") \
    XXX(ZETIME_LANGUAGE_TWHKMO,  2, "TW/HK/MO") \
    XXX(ZETIME_LANGUAGE_KO,      3, "KO") \
    XXX(ZETIME_LANGUAGE_TH,      4, "TH") \
    XXX(ZETIME_LANGUAGE_JA,      5, "JA") \
    XXX(ZETIME_LANGUAGE_FR,      6, "FR") \
    XXX(ZETIME_LANGUAGE_ES,      7, "ES") \
    XXX(ZETIME_LANGUAGE_DE,      8, "DE") \
    XXX(ZETIME_LANGUAGE_IT,      9, "IT") \
    XXX(ZETIME_LANGUAGE_PL,     10, "PL") \
    XXX(ZETIME_LANGUAGE_PT,     11, "PT") \
    XXX(ZETIME_LANGUAGE_RU,     12, "RU") \
    XXX(ZETIME_LANGUAGE_NL,     13, "NL") \
    XXX(ZETIME_LANGUAGE_RO,     32, "RO") \
    XXX(ZETIME_LANGUAGE_HU,     33, "HU") \

VALUE_STRING_ENUM(zetime_language);
VALUE_STRING_ARRAY(zetime_language);

/* ZeTime App btsnoop:
 * push calendar day with payload = 0x04000000000000000000
 * which has calendar event type = 0x04
 */
#define zetime_calendar_event_type_VALUE_STRING_LIST(XXX)    \
    XXX(ZETIME_CALENDAR_EVENT_TYPE_UNKNOWN, 0x01, "unknown") \
    XXX(ZETIME_CALENDAR_EVENT_TYPE_SUNRISE, 0x02, "sunrise") \
    XXX(ZETIME_CALENDAR_EVENT_TYPE_SUNSET, 0x03, "sunset") \
    XXX(ZETIME_CALENDAR_EVENT_TYPE_TEST, 0x04, "test") \

VALUE_STRING_ENUM(zetime_calendar_event_type);
VALUE_STRING_ARRAY(zetime_calendar_event_type);

#define ZETIME_FIELD_LEN_PREAMBLE       ((guint) 1)
#define ZETIME_FIELD_LEN_END            ((guint) 1)
#define ZETIME_FIELD_LEN_ACK            ((guint) 1)
#define ZETIME_FIELD_LEN_PDU_TYPE       ((guint) 1)
#define ZETIME_FIELD_LEN_ACTION         ((guint) 1)
#define ZETIME_FIELD_LEN_PAYLOAD_LEN    ((guint) 2)

#define ZETIME_MSG_HEADER_LEN \
        (ZETIME_FIELD_LEN_PREAMBLE + ZETIME_FIELD_LEN_PDU_TYPE \
        + ZETIME_FIELD_LEN_ACTION + ZETIME_FIELD_LEN_PAYLOAD_LEN)
#define ZETIME_MSG_FOOTER_LEN \
        (ZETIME_FIELD_LEN_END)

#define ZETIME_FIELD_VALUE_PREAMBLE  0x6f
#define ZETIME_FIELD_VALUE_END       0x8f
#define ZETIME_FIELD_VALUE_ACK       0x03

static guint
dissect_preamble_ex(tvbuff_t *tvb, guint offset, proto_tree *tree,
                    packet_info *pinfo)
{
    const guint len = ZETIME_FIELD_LEN_PREAMBLE;
    guint value = 0;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf_zetime_preamble,
                tvb, offset, len, ENC_LITTLE_ENDIAN, &value);
    if (value != ZETIME_FIELD_VALUE_PREAMBLE) {
        expert_add_info(pinfo, ti, &ei_zetime_preamble_mismatch);
    }
    return len;
}

static guint
dissect_end_ex(tvbuff_t *tvb, guint offset, proto_tree *tree,
               packet_info *pinfo)
{
    const guint len = ZETIME_FIELD_LEN_END;
    guint value = 0;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf_zetime_end,
                tvb, offset, len, ENC_LITTLE_ENDIAN, &value);
    if (value != ZETIME_FIELD_VALUE_END) {
        expert_add_info(pinfo, ti, &ei_zetime_end_mismatch);
    }
    return len;
}

static guint
dissect_ack_ex(tvbuff_t *tvb, guint offset, proto_tree *tree,
               packet_info *pinfo)
{
    const guint len = ZETIME_FIELD_LEN_ACK;
    guint value = 0;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf_zetime_ack,
                tvb, offset, len, ENC_LITTLE_ENDIAN, &value);
    if (value != ZETIME_FIELD_VALUE_ACK) {
        expert_add_info(pinfo, ti, &ei_zetime_ack_mismatch);
    }
    return len;
}

static guint
dissect_pdu_type_ex(tvbuff_t *tvb, guint offset, proto_tree *zetime_tree,
                    proto_item *ti, packet_info *pinfo, guint *valueRet)
{
    const guint len = ZETIME_FIELD_LEN_PDU_TYPE;
    guint value = 0;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_pdu_type, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN, &value);
    if (ti) {
        proto_item_append_text(ti, ", %s", val_to_str(value,
                               zetime_pdu_type,
                               "UNKNOWN PDU TYPE (0x%02x)"));
    }
    if (pinfo) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(value,
                     zetime_pdu_type,
                     "UNKNOWN PDU TYPE (0x%02x)"));
    }

    if (valueRet) {
        *valueRet = value;
    }
    return len;
}

static guint
dissect_action(tvbuff_t *tvb, guint offset, proto_tree *zetime_tree,
                 proto_item *ti, packet_info *pinfo _U_, guint *valueRet)
{
    const guint len = ZETIME_FIELD_LEN_ACTION;
    guint value = 0;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_action, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN, &value);
    proto_item_append_text(ti, ", %s", val_to_str(value,
                           zetime_action,
                           "UNKNOWN ACTION (0x%02x)"));

    if (valueRet) {
        *valueRet = value;
    }
    return len;
}

static guint
dissect_payload_length(tvbuff_t *tvb, guint offset, proto_tree *zetime_tree,
                       guint *payload_len)
{
    const guint len = ZETIME_FIELD_LEN_PAYLOAD_LEN;
    proto_tree_add_item_ret_uint(zetime_tree, hf_zetime_payload_length, tvb,
                                 offset, len, ENC_LITTLE_ENDIAN,
                                 payload_len);
    return len;
}

static guint
dissect_error_code(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_error_code, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_watch_id(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = tvb_captured_length_remaining(tvb, offset);
    proto_tree_add_item(tree, hf_zetime_watch_id, tvb, offset, len, ENC_NA);
    return len;
}

static guint
dissect_version_type(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_version_type, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_version_info(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = tvb_captured_length_remaining(tvb, offset);
    proto_tree_add_item(tree, hf_zetime_version_info, tvb, offset, len, ENC_NA);
    return len;
}

static guint
dissect_battery_power_level(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    const guint levelLow = 25; // TODO: proto setting
    guint level = 0;
    proto_item *ti = proto_tree_add_item_ret_uint(tree, hf_zetime_battery_power_level, tvb, offset, len, ENC_LITTLE_ENDIAN, &level);
    proto_item_append_text(ti, " (%s)", (level <= levelLow ? "low" : "normal"));
    return len;
}

static guint
dissect_language(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_language, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_year(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_datetime_year, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_month(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_datetime_month, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_day(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_datetime_day, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_hour(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_datetime_hour, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_minute(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_datetime_minute, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_datetime_second(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_datetime_second, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_timezone_hour(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_timezone_hour, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_timezone_minute(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_timezone_minute, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_packet_number(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_packet_number, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_timestamp(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 4;
    proto_tree_add_item(tree, hf_zetime_timestamp, tvb, offset, len, ENC_LITTLE_ENDIAN | ENC_TIME_SECS);
    return len;
}

static guint
dissect_steps(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 4;
    proto_tree_add_item(tree, hf_zetime_steps, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calories_burnt(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 4;
    proto_tree_add_item(tree, hf_zetime_calories_burnt, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_meters_walked(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 4;
    proto_tree_add_item(tree, hf_zetime_meters_walked, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_activity_minutes(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 4;
    proto_tree_add_item(tree, hf_zetime_activity_minutes, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_heart_rate(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_heart_rate, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_available_steps(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_available_steps, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_available_sleep(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_available_sleep, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_available_heart_rate(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_available_heart_rate, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_type(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_calendar_event_type, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_year(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_calendar_event_year, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_month(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_calendar_event_month, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_day(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1;
    proto_tree_add_item(tree, hf_zetime_calendar_event_day, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_hour(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_calendar_event_hour, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_minute(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 2;
    proto_tree_add_item(tree, hf_zetime_calendar_event_minute, tvb, offset, len, ENC_LITTLE_ENDIAN);
    return len;
}

static guint
dissect_calendar_event_title(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    const guint len = 1; // length of string length field
    const guint8 strlen = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_zetime_calendar_event_title, tvb, offset, len, ENC_LITTLE_ENDIAN|ENC_UTF_8);
    return len + strlen;
}

static guint
dissect_payload_unknown(tvbuff_t *tvb, packet_info *pinfo _U_,
                        proto_tree *tree, void *data _U_)
{
    proto_tree_add_item(tree, hf_zetime_payload_unkown, tvb, 0, -1, ENC_NA);
    return tvb_captured_length(tvb);
}

static guint
dissect_payload_unknown_ex(tvbuff_t *tvb, packet_info *pinfo,
                        proto_tree *tree, void *data _U_)
{
    col_append_str(pinfo->cinfo, COL_INFO, " [UNKNOWN PAYLOAD]");

    return dissect_payload_unknown(tvb, pinfo, tree, data);
}

static guint
dissect_payload_zeros(tvbuff_t *tvb, packet_info *pinfo _U_,
                proto_tree *tree, void *data _U_, guint expected_len)
{
    // payload should contain only zeros
    proto_tree_add_item(tree, hf_zetime_payload, tvb, 0, expected_len, ENC_NA);
    return expected_len;
}

static guint
dissect_respond_confirmation(tvbuff_t *tvb, packet_info *pinfo _U_,
                proto_tree *tree, void *data _U_)
{
    guint offset = 0;

    // Describe in info column which message was confirmed (or not)
    col_clear(pinfo->cinfo, COL_INFO);
    offset += dissect_pdu_type_ex(tvb, offset, tree, NULL, pinfo, NULL);
    col_append_str(pinfo->cinfo, COL_INFO, " Confirmation");

    offset += dissect_error_code(tvb, offset, tree);
    return offset;
}

static guint
dissect_watch_id_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_watch_id(tvb, offset, tree);
    return offset;
}

static guint
dissect_device_version_request(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_version_type(tvb, offset, tree);
    return offset;
}

static guint
dissect_device_version_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_version_type(tvb, offset, tree);
    offset += dissect_version_info(tvb, offset, tree);
    return offset;
}

static guint
dissect_battery_power_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                       proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_battery_power_level(tvb, offset, tree);
    return offset;
}

static guint
dissect_language_settings_send(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_language(tvb, offset, tree);
    return offset;
}

static guint
dissect_date_time_send(tvbuff_t *tvb, packet_info *pinfo _U_,
                       proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_datetime_year(tvb, offset, tree);
    offset += dissect_datetime_month(tvb, offset, tree);
    offset += dissect_datetime_day(tvb, offset, tree);
    offset += dissect_datetime_hour(tvb, offset, tree);
    offset += dissect_datetime_minute(tvb, offset, tree);
    offset += dissect_datetime_second(tvb, offset, tree);
    // unknown 3 byte data
    offset += dissect_payload_unknown(tvb_new_subset_length(tvb, offset, 3),
                                      pinfo, tree, data);
    offset += dissect_timezone_hour(tvb, offset, tree);
    offset += dissect_timezone_minute(tvb, offset, tree);
    return offset;
}

static guint
dissect_available_data_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                                proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_available_steps(tvb, offset, tree);
    offset += dissect_available_sleep(tvb, offset, tree);
    offset += dissect_available_heart_rate(tvb, offset, tree);
    // unkown 2 byte data, should be zeros
    offset += dissect_payload_unknown(tvb_new_subset_length(tvb, offset, 2),
                                      pinfo, tree, data);
    return offset;
}

static guint
dissect_get_step_count_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                                proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_packet_number(tvb, offset, tree);
    offset += dissect_timestamp(tvb, offset, tree);
    offset += dissect_steps(tvb, offset, tree);
    offset += dissect_calories_burnt(tvb, offset, tree);
    offset += dissect_meters_walked(tvb, offset, tree);
    offset += dissect_activity_minutes(tvb, offset, tree);
    return offset;
}

static guint
dissect_get_heartrate_exdata_response(tvbuff_t *tvb, packet_info *pinfo _U_,
                                      proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    do {
        offset += dissect_packet_number(tvb, offset, tree);
        offset += dissect_timestamp(tvb, offset, tree);
        offset += dissect_heart_rate(tvb, offset, tree);
    } while(offset < tvb_captured_length(tvb));
    return offset;
}

static guint
dissect_push_calendar_day_send(tvbuff_t *tvb, packet_info *pinfo _U_,
                               proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    offset += dissect_calendar_event_type(tvb, offset, tree);
    offset += dissect_calendar_event_year(tvb, offset, tree);
    offset += dissect_calendar_event_month(tvb, offset, tree);
    offset += dissect_calendar_event_day(tvb, offset, tree);
    offset += dissect_calendar_event_hour(tvb, offset, tree);
    offset += dissect_calendar_event_minute(tvb, offset, tree);
    offset += dissect_calendar_event_title(tvb, offset, tree);
    return offset;
}

static gboolean
has_zetime_msg_header(tvbuff_t *tvb)
{
    const guint tvb_len = tvb_captured_length(tvb);
    const guint header_len = ZETIME_MSG_HEADER_LEN;
    if (tvb_len < header_len) {
        // packet has not enough data for the message header
        return FALSE;
    }

    // check preamble value
    {
        const guint value = tvb_get_guint8(tvb, 0);
        if (value != ZETIME_FIELD_VALUE_PREAMBLE) {
            // preamble field in header has not the correct value
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
has_zetime_msg_nofragmentation(tvbuff_t *tvb)
{
    const guint tvb_len = tvb_captured_length(tvb);
    if (!has_zetime_msg_header(tvb)) {
        return FALSE;
    }

    // check end value
    {
        assert(tvb_len >= 1);
        const guint value = tvb_get_guint8(tvb, tvb_len - 1);
        if (value != ZETIME_FIELD_VALUE_END) {
            // end field in footer has not the correct value
            return FALSE;
        }
    }

    // check packet len
    {
        const guint header_len = ZETIME_MSG_HEADER_LEN;
        const guint footer_len = ZETIME_MSG_FOOTER_LEN;
        const guint offset = ZETIME_FIELD_LEN_PREAMBLE
                           + ZETIME_FIELD_LEN_PDU_TYPE
                           + ZETIME_FIELD_LEN_ACTION;
        const guint payload_len = tvb_get_letohs(tvb, offset); // 16bit unsigned
        if (tvb_len != header_len + payload_len + footer_len) {
            // packet has not the correct length
            return FALSE;
        }
    }

    return TRUE;
}

static guint
dissect_zetime_msg_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   proto_item *ti,
                   guint *pdu_type, guint *action, guint *payload_len)
{
    guint offset = 0;
    offset += dissect_preamble_ex(tvb, offset, tree, pinfo);
    offset += dissect_pdu_type_ex(tvb, offset, tree, ti, pinfo, pdu_type);
    offset += dissect_action(tvb, offset, tree, ti, pinfo, action);
    offset += dissect_payload_length(tvb, offset, tree, payload_len);
    return offset;
}

static guint
dissect_zetime_msg_footer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint offset = 0;
    offset += dissect_end_ex(tvb, offset, tree, pinfo);
    return offset;
}

static guint
dissect_zetime_msg_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   proto_item *ti _U_, void *data _U_,
                   guint pdu_type, guint action)
{
    guint offset = 0;
    switch (pdu_type) {
    case ZETIME_PDU_TYPE_RESPOND:
        switch (action) {
        case ZETIME_ACTION_CONFIRMATION:
            offset += dissect_respond_confirmation(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_WATCH_ID:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_watch_id_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_DEVICE_VERSION:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_device_version_request(tvb, pinfo, tree, data);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_device_version_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_DATE_TIME:
        switch (action) {
        case ZETIME_ACTION_SEND:
            offset += dissect_date_time_send(tvb, pinfo, tree, data);
            break;
        case ZETIME_ACTION_CONFIRMATION: // confirmation as RESPOND (0x01)
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_BATTERY_POWER:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_battery_power_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_LANGUAGE_SETTINGS:
        switch (action) {
        case ZETIME_ACTION_SEND:
            offset += dissect_language_settings_send(tvb, pinfo, tree, data);
            break;
        case ZETIME_ACTION_CONFIRMATION: // confirmation as RESPOND (0x01)
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_AVAILABLE_DATA:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_available_data_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_DELETE_STEP_COUNT:
        switch (action) {
        case ZETIME_ACTION_SEND:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_CONFIRMATION: // confirmation as RESPOND (0x01)
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_GET_STEP_COUNT:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 2);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_get_step_count_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_DELETE_HEARTRATE_DATA:
        switch (action) {
        case ZETIME_ACTION_SEND:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_CONFIRMATION: // confirmation as RESPOND (0x01)
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_GET_HEARTRATE_EXDATA:
        switch (action) {
        case ZETIME_ACTION_REQUEST:
            offset += dissect_payload_zeros(tvb, pinfo, tree, data, 1);
            break;
        case ZETIME_ACTION_RESPONSE:
            offset += dissect_get_heartrate_exdata_response(tvb, pinfo, tree, data);
            break;
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    case ZETIME_PDU_TYPE_PUSH_CALENDAR_DAY:
        switch (action) {
        case ZETIME_ACTION_SEND:
            offset += dissect_push_calendar_day_send(tvb, pinfo, tree, data);
            break;
        case ZETIME_ACTION_CONFIRMATION: // confirmation as RESPOND (0x01)
        default:
            // unkown action
            offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
            break;
        }
        break;
    default:
        offset += dissect_payload_unknown_ex(tvb, pinfo, tree, data);
        break;
    }
    return offset;
}

static guint
dissect_zetime_msg_complete(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   proto_item *ti, void *data _U_)
{
    const guint header_len = ZETIME_MSG_HEADER_LEN;
    const guint footer_len = ZETIME_MSG_FOOTER_LEN;

    guint offset = 0;
    guint pdu_type = 0;
    guint action = 0;
    guint payload_len = 0;

    tvbuff_t *header_tvb = tvb_new_subset_length(tvb, offset, header_len);
    offset += dissect_zetime_msg_header(header_tvb, pinfo, tree, ti,
                    &pdu_type, &action, &payload_len);

    tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, payload_len);
    offset += dissect_zetime_msg_payload(payload_tvb, pinfo, tree, ti, data,
                    pdu_type, action);

    tvbuff_t *footer_tvb = tvb_new_subset_length(tvb, offset, footer_len);
    offset += dissect_zetime_msg_footer(footer_tvb, pinfo, tree);

    return offset;
}

static guint
dissect_zetime_msg_incomplete(tvbuff_t *tvb, packet_info *pinfo)
{
    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_add_str(pinfo->cinfo, COL_INFO, "Sent fragment");
            break;
        case P2P_DIR_RECV:
            col_add_str(pinfo->cinfo, COL_INFO, "Rcvd fragment");
            break;
        default:
            col_add_str(pinfo->cinfo, COL_INFO, "Fragment with unknown direction");
            break;
    }

    return tvb_captured_length(tvb);
}

static guint
get_zetime_frag_id(packet_info *pinfo)
{
    return pinfo->p2p_dir;
}

static gboolean
find_zetime_reassembled_msg(tvbuff_t **new_tvb, tvbuff_t *tvb,
                packet_info *pinfo, proto_tree *tree)
{
    const guint frag_id = get_zetime_frag_id(pinfo);
    fragment_head *frag_msg = NULL;
    frag_msg = fragment_get_reassembled_id(&zetime_msg_reassembly_table,
                                           pinfo, frag_id);
    if (frag_msg) {
        // msg was already completely reassembled
        assert(new_tvb);
        *new_tvb = process_reassembled_data(tvb, 0, pinfo,
                        "Reassembled ZeTime packet", frag_msg,
                        &zetime_msg_frag_items, /*update_col_infop*/ NULL,
                        tree);
        return TRUE;
    }

    return FALSE;
}

static gboolean
add_zetime_msg_fragment_first(tvbuff_t **new_tvb, tvbuff_t *tvb,
                packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!has_zetime_msg_header(tvb)) {
        // incomplete or invalid header
        return FALSE;
    }

    guint payload_len = 0;
    guint offset = dissect_zetime_msg_header(tvb, pinfo, tree, NULL,
                    NULL, NULL, &payload_len);

    const guint footer_len = ZETIME_MSG_FOOTER_LEN;
    const gboolean fragmented = tvb_captured_length_remaining(tvb, offset)
                              < ((gint)(payload_len + footer_len));
    if (fragmented) {
        const guint frag_id = get_zetime_frag_id(pinfo);
        const guint tot_len = offset + payload_len + footer_len;
        fragment_head *frag_msg = NULL;
        frag_msg = fragment_add_check(&zetime_msg_reassembly_table,
                            tvb, 0,
                            pinfo, frag_id, data,
                            0, tvb_captured_length(tvb),
                            TRUE);
        fragment_set_tot_len(&zetime_msg_reassembly_table,
                             pinfo, frag_id, data,
                             tot_len);
        assert(new_tvb);
        *new_tvb = process_reassembled_data(tvb, 0, pinfo,
                        "Reassembled ZeTime packet", frag_msg,
                        &zetime_msg_frag_items, /*update_col_infop*/ NULL,
                        tree);
        pinfo->fragmented = TRUE;
        return TRUE;
    }

    return FALSE;
}

static gboolean
add_zetime_msg_fragment_next(tvbuff_t **new_tvb, tvbuff_t *tvb,
                packet_info *pinfo, proto_tree *tree, void *data, gboolean *more_fragsRet)
{
    const guint frag_id = get_zetime_frag_id(pinfo);
    fragment_head *frag_msg = NULL;
    frag_msg = fragment_get(&zetime_msg_reassembly_table, pinfo, frag_id, data);
    if (!frag_msg) {
        // no reassembling running
        return FALSE;
    }

    // reassembling is running -> find last fragment
    for (; frag_msg->next; frag_msg = frag_msg->next);
    const guint frag_offset = frag_msg->offset + frag_msg->len;
    const guint frag_len = tvb_captured_length(tvb);
    const guint tot_len = fragment_get_tot_len(&zetime_msg_reassembly_table,
                        pinfo, frag_id, data);
    if (frag_offset + frag_len > tot_len) {
        /* Fragmentation cannot be completed for previous packets
         * because at least one packet is missing or has wrong length.
         * But without unique frag_id, they will be added to the next
         * fragmented message, hopefully starting with this packet.
         */
        return FALSE;
    }

    const gboolean more_frags = (frag_offset + frag_len < tot_len) ? TRUE
                                                                   : FALSE;
    frag_msg = fragment_add_check(&zetime_msg_reassembly_table,
                        tvb, 0,
                        pinfo, frag_id, data,
                        frag_offset, frag_len,
                        more_frags);
    assert(new_tvb);
    *new_tvb = process_reassembled_data(tvb, 0, pinfo,
                    "Reassembled ZeTime packet", frag_msg,
                    &zetime_msg_frag_items, /*update_col_infop*/ NULL,
                    tree);
    pinfo->fragmented = TRUE;
    if (more_fragsRet) {
        *more_fragsRet = more_frags;
    }
    return TRUE;
}

static tvbuff_t *
reassemble_zetime_msg(tvbuff_t *const tvb, packet_info *pinfo, proto_tree *tree,
                      void *data)
{
    /* Fragmented message composition
     *
     * +----------+----------+----------+----------------+----------+ packet
     * | PREAMBLE | PDU TYPE |  ACTION  | payload length | payload  | 1
     * |  1 Byte  |  1 Byte  |  1 Byte  |    2 Bytes     | X Bytes  |
     * |  fixed   |   enum   |   enum   |    number      | variable |
     * +----------+----------+----------+----------------+----------+
     * +------------------------------------------------------------+ packet
     * |                        payload                             | 2..(n-1)
     * |                        X Bytes                             |
     * |                        variable                            |
     * +------------------------------------------------------------+
     * +----------+-------+ packet
     * | payload  |  END  | n
     * |  X Bytes |  1 B  |
     * | variable | fixed |
     * +----------+-------+
     *
     */
    if (tvb_captured_length(tvb) != tvb_reported_length(tvb)) {
        return NULL;
    }

    gboolean more_frags = FALSE;
    tvbuff_t *new_tvb = NULL;
    if (has_zetime_msg_nofragmentation(tvb)) {
        // no reassembling needed
        new_tvb = tvb;
    } else if (find_zetime_reassembled_msg(&new_tvb, tvb, pinfo, tree)) {
    } else if (add_zetime_msg_fragment_next(&new_tvb, tvb, pinfo, tree, data, &more_frags)) {
    } else if (add_zetime_msg_fragment_first(&new_tvb, tvb, pinfo, tree, data)) {
    } else {
        // fallback: no reassembling possible -> misformed packet?
        new_tvb = tvb;
    }

    return new_tvb;
}

static int
dissect_zetime_msg(tvbuff_t *const tvb, packet_info *pinfo, proto_tree *tree,
                   proto_item *ti, void *data)
{
    /* General message composition
     *
     * +----------+----------+----------+----------------+----------+-------+
     * | PREAMBLE | PDU TYPE |  ACTION  | payload length | payload  |  END  |
     * |  1 Byte  |  1 Byte  |  1 Byte  |    2 Bytes     | X Bytes  |  1 B  |
     * |  fixed   |   enum   |   enum   |    number      | variable | fixed |
     * +----------+----------+----------+----------------+----------+-------+
     *
     */

    tvbuff_t *ntvb = reassemble_zetime_msg(tvb, pinfo, tree, data);
    return (ntvb) ? dissect_zetime_msg_complete(ntvb, pinfo, tree, ti, data)
                  : dissect_zetime_msg_incomplete(tvb, pinfo);
}

static int
dissect_zetime_ack(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   proto_item *ti, void *data _U_)
{
    if (1 != tvb_reported_length(tvb)) {
        return 0;
    }

    // check ack value
    {
        const guint value = tvb_get_guint8(tvb, 0);
        if (value != ZETIME_FIELD_VALUE_ACK) {
            return 0;
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", "Ack");
    proto_item_append_text(ti, ", %s", "Ack");

    guint offset = 0;
    offset += dissect_ack_ex(tvb, offset, tree, pinfo);
    return offset;
}

static int
dissect_zetime(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               void *data)
{
    const gboolean save_fragmented = pinfo->fragmented;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ZeTime");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_zetime, tvb, 0, -1,
                                         ENC_NA);
    proto_tree *zetime_tree = proto_item_add_subtree(ti, ett_zetime);

    int offset = dissect_zetime_ack(tvb, pinfo, zetime_tree, ti, data);
    if (0 == offset) {
        offset = dissect_zetime_msg(tvb, pinfo, zetime_tree, ti, data);
    }

    pinfo->fragmented = save_fragmented; // restore
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
            { "Preamble", "zetime.preamble",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_pdu_type,
            { "PDU Type", "zetime.pdu_type",
            FT_UINT8, BASE_DEC,
            VALS(zetime_pdu_type), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_action,
            { "Action", "zetime.action",
            FT_UINT8, BASE_HEX,
            VALS(zetime_action), 0x0,
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
        { &hf_zetime_payload_unkown,
            { "Unknown Payload", "zetime.payload_unkown",
            FT_BYTES, BASE_NO_DISPLAY_VALUE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_end,
            { "End", "zetime.end",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_ack,
            { "Ack", "zetime.ack",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_error_code,
            { "Error Code", "zetime.error_code",
            FT_UINT8, BASE_DEC_HEX,
            VALS(zetime_error_code), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_watch_id,
            { "Watch ID (S/N)", "zetime.watch_id",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_version_type,
            { "Version Type", "zetime.version_type",
            FT_UINT8, BASE_DEC,
            VALS(zetime_version_type), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_version_info,
            { "Version Type", "zetime.version_info",
            FT_STRING, STR_ASCII,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_battery_power_level,
            { "Level", "zetime.battery_power.level",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
            &units_percent, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_language,
            { "Language", "zetime.language",
            FT_UINT8, BASE_DEC,
            VALS(zetime_language), 0x0,
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
        { &hf_zetime_heart_rate,
            { "Heart Rate", "zetime.heart_rate",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING,
            &units_bpm, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_available_steps,
            { "Steps", "zetime.available.steps",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_available_sleep,
            { "Sleep", "zetime.available.sleep",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_available_heart_rate,
            { "Sleep", "zetime.available.heart_rate",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_year,
            { "Year", "zetime.datetime.year",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_month,
            { "Month", "zetime.datetime.month",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_day,
            { "Day of Month", "zetime.datetime.day",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_hour,
            { "Hour", "zetime.datetime.hour",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_minute,
            { "Minute", "zetime.datetime.minute",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_datetime_second,
            { "Second", "zetime.datetime.second",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_timezone_hour,
            { "TimeZone Hour", "zetime.timezone.hour",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_timezone_minute,
            { "TimeZone Minute", "zetime.timezone.minute",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_type,
            { "Calendar Event Type", "zetime.calendar_event.type",
            FT_UINT8, BASE_DEC,
            VALS(zetime_calendar_event_type), 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_year,
            { "Year", "zetime.calendar_event.year",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_month,
            { "Month", "zetime.calendar_event.month",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_day,
            { "Day of Month", "zetime.calendar_event.day",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_hour,
            { "Hour", "zetime.calendar_event.hour",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_minute,
            { "Minute", "zetime.calendar_event.minute",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_zetime_calendar_event_title,
            { "Title", "zetime.calendar_event.title",
            FT_UINT_STRING, STR_UNICODE,
            NULL, 0x0,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragments,
	    { "Message fragments", "zetime.fragments",
	    FT_NONE, BASE_NONE,
            NULL, 0x00, NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment,
	    { "Message fragment", "zetime.fragment",
	    FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_overlap,
	    { "Message fragment overlap", "zetime.fragment.overlap",
	    FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_overlap_conflicts,
	    { "Message fragment overlapping with conflicting data",
	    "zetime.fragment.overlap.conflicts",
	    FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_multiple_tails,
	    { "Message has multiple tail fragments",
	    "zetime.fragment.multiple_tails",
	    FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_too_long_fragment,
	    { "Message fragment too long", "zetime.fragment.too_long_fragment",
	    FT_BOOLEAN, 0,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_error,
	    { "Message defragmentation error", "zetime.fragment.error",
	    FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_fragment_count,
	    { "Message fragment count", "zetime.fragment.count",
	    FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_reassembled_in,
	    { "Reassembled in", "zetime.reassembled.in",
	    FT_FRAMENUM, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_reassembled_length,
	    { "Reassembled length", "zetime.reassembled.length",
	    FT_UINT32, BASE_DEC,
            NULL, 0x00,
            NULL, HFILL }
        },
	{ &hf_zetime_msg_reassembled_data,
	    { "Reassembled data", "zetime.reassembled.data",
	    FT_BYTES, BASE_NONE,
            NULL, 0x00,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_zetime,
        &ett_zetime_msg_fragment,
        &ett_zetime_msg_fragments,
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_zetime_preamble_mismatch,
            { "zetime.preamble.mismatch",
            PI_MALFORMED, PI_ERROR,
            "preamble is not 0x6f", EXPFILL }
        },
        { &ei_zetime_end_mismatch,
            { "zetime.end.mismatch",
            PI_MALFORMED, PI_ERROR,
            "end is not 0x8f", EXPFILL }
        },
        { &ei_zetime_ack_mismatch,
            { "zetime.ack.mismatch",
            PI_MALFORMED, PI_ERROR,
            "ack is not 0x03", EXPFILL }
        },
    };

    proto_zetime = proto_register_protocol (
        "ZeTime Protocol", /* name */
        "ZeTime",          /* short name */
        "zetime"           /* abbrev */
    );

    proto_register_field_array(proto_zetime, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_module_t *const expert_zetime = expert_register_protocol(proto_zetime);
    expert_register_field_array(expert_zetime, ei, array_length(ei));

    /* Fragments */
    reassembly_table_register(&zetime_msg_reassembly_table,
                              &addresses_reassembly_table_functions);
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
    for (guint i = 0; uuid_dissectors[i].uuid; ++i) {
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
