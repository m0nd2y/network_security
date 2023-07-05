#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct Dot11Hdr final {
	u_int16_t	frame_control_;
	u_int16_t	duration_;
	Mac			dest_addr;
	Mac			src_addr;
	Mac			bssid;
	u_int16_t	seq_ctrl_;

	u_int8_t	protocol_ver() const { return frame_control_ & 0x3; }
	u_int8_t	type() const { return (frame_control_ >> 2) & 0x3; }
	u_int8_t	subtype() const { return (frame_control_ >> 4) & 0xF; }
	u_int8_t	to_ds() const { return (frame_control_ >> 8) & 0x1; }
	u_int8_t	from_ds() const { return (frame_control_ >> 9) & 0x1; }
	u_int16_t	frame_control() const { return ntohs(frame_control_); }
	u_int16_t	duration() const { return ntohs(duration_); }
	u_int16_t	seq_ctrl() const { return ntohs(seq_ctrl_); }
};

#pragma pack(pop)
