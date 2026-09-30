package com.github.guoyyit.multisigaggregationjava.core;

public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xff;
            out[i * 2] = DIGITS[v >>> 4];
            out[i * 2 + 1] = DIGITS[v & 0x0f];
        }
        return new String(out);
    }

    public static byte[] decode(String hex) {
        if (hex == null) {
            return null;
        }
        String input = hex.startsWith("0x") ? hex.substring(2) : hex;
        if ((input.length() & 1) != 0) {
            throw new IllegalArgumentException("hex 字符串长度必须为偶数");
        }
        byte[] out = new byte[input.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(input.charAt(i * 2), 16);
            int low = Character.digit(input.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("hex 字符串含非法字符");
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }
}
