#pragma once

constexpr int MAX_DEVICES = 128;
constexpr int PACKET_SIZE = 65536;
constexpr int MAX_PACKETS_AMOUNT = 100;
constexpr int DEFAULT_LISTVIEW_COLUMN_WIDTH = 100;

enum ui_id {
    id_cb_devices = 201,
    id_lb_devices = 202,
    id_btn_start = 203,
    id_btn_stop = 204,
    id_btn_pause = 205,
    id_lv_packets = 206,
};

