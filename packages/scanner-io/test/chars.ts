// Invisible and bidi characters, built from code points so that none of them
// sits in the source as a literal (the formatter turns escapes into literals).
const ch = (code: number): string => String.fromCharCode(code);

export const LINE_SEPARATOR = ch(0x2028);
export const PARAGRAPH_SEPARATOR = ch(0x2029);
export const RIGHT_TO_LEFT_OVERRIDE = ch(0x202e);
export const LEFT_TO_RIGHT_ISOLATE = ch(0x2066);
export const BYTE_ORDER_MARK = ch(0xfeff);
export const NONCHARACTER = ch(0xffff);
