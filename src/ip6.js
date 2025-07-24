
export class Ip6 extends DataView {
	get version() {
		return super.getUint8(0) >> 4;
	}
	set version(val) {
		super.setUint8(0, ((val & 0x0F) << 4) | (0x0F & super.getUint8(0)));
	}
	get traffic_class() {
		return (super.getUint16(0) & 0x0FF0) >> 4;
	}
	set traffic_class(val) {
		super.setUint16(0, (super.getUint16(0) & 0xF00F) | ((val & 0xFF) << 4));
	}
	get flow_label() {
		super.getUint32(0) & 0x000FFFFF;
	}
	set flow_label(val) {
		super.setUint32(0, (super.getUint32(0) & 0xFFF00000) | (val & 0xFFFFF));
	}
	get payload_length() {
		super.getUint16(4);
	}
	set payload_length(val) {
		super.setUint16(4, val);
	}
	get next_header() {
		super.getUint8(6);
	}
	set next_header(val) {
		super.setUint8(6, val);
	}
	get hop_limit() {
		super.getUint8(7);
	}
	set hop_limit(val) {
		super.setUint8(7, val);
	}
	get src() {
		return new Uint8Array(this.buffer, this.byteOffset + 8, 16);
	}
	get dst() {
		return new Uint8Array(this.buffer, this.byteOffset + 24, 16)
	}
}
