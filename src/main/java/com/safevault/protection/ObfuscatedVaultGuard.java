package com.safevault.protection;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

public class ObfuscatedVaultGuard {

    // Рівень 1 (Аналог first.py з Додатку А): відкрита перевірка без захисту
    public boolean verifyPlainBaseline(String candidate) {
        String expected = "2026_КБЗІ-23-1_Bereziuk_Oleksandr_варіант: 02";
        return expected.equals(candidate);
    }

    // Рівень 2 (Аналог second.py з Додатку А): перейменування ідентифікаторів та XOR-маскування байтів
    private static final byte[] _0x3d11 = new byte[]{
            (byte) 0x68, (byte) 0x0C, (byte) 0x43, (byte) 0x2F, (byte) 0x31, (byte) 0x92, (byte) 0xB7, (byte) 0x55,
            (byte) 0xCB, (byte) 0xEC, (byte) 0xE6, (byte) 0xC9, (byte) 0xE8, (byte) 0x6F, (byte) 0x1F, (byte) 0xB6,
            (byte) 0x77, (byte) 0x0D, (byte) 0x2E, (byte) 0x5B, (byte) 0x0B, (byte) 0x30, (byte) 0x48, (byte) 0xFF,
            (byte) 0x33, (byte) 0x49, (byte) 0x1A, (byte) 0x46, (byte) 0x21, (byte) 0x2E, (byte) 0x48, (byte) 0xEE,
            (byte) 0x29, (byte) 0x5D, (byte) 0x1F, (byte) 0x7D, (byte) 0x1C, (byte) 0x1D, (byte) 0xFD, (byte) 0x37,
            (byte) 0x8A, (byte) 0x8C, (byte) 0xA0, (byte) 0x99, (byte) 0xBF, (byte) 0xD4, (byte) 0xFD, (byte) 0x35,
            (byte) 0x8A, (byte) 0x81, (byte) 0xA0, (byte) 0x9B, (byte) 0x54, (byte) 0x62, (byte) 0x1D, (byte) 0xB7
    };
    private static final byte[] _0x5f20 = new byte[]{
            (byte) 0x5A, (byte) 0x3C, (byte) 0x71, (byte) 0x19, (byte) 0x6E, (byte) 0x42, (byte) 0x2D, (byte) 0x85
    };

    public boolean _0x4a91_verifyXorMasked(String _0x8b2e) {
        if (_0x8b2e == null) return false;
        byte[] _0x1c4d = _0x8b2e.getBytes(StandardCharsets.UTF_8);
        if (_0x1c4d.length != _0x3d11.length) return false;
        int _0xacc = 0;
        for (int _0xi = 0; _0xi < _0x3d11.length; _0xi++) {
            byte _0xdec = (byte) (_0x3d11[_0xi] ^ _0x5f20[_0xi % _0x5f20.length]);
            _0xacc |= (_0x1c4d[_0xi] ^ _0xdec);
        }
        return _0xacc == 0;
    }

    // Рівень 3 (Аналог third.py + fourth.py): Control-Flow Flattening + Opaque Predicates + AES-256-GCM + Reflection
    private static final String _0x2a01 = "3f8a1c4e9b2d7056a1c4e9f23b6d8014";
    private static final String _0x2a02 = "5e7a9c2f4b8d10367c9e2a4f6b8d0135";
    private static final String _0x9e02_iv = "112233445566778899aabbcc";
    private static final String _0x7c88_ct =
            "81CC05CA15E653A2FB38205D96B7523B041DD44D83AFFD1D726DE081E29A5EA7" +
                    "391495D16F7D1F378D1ACB80D8B8F8F7ED6B83485A2387F094E7759C7C0E20B7" +
                    "7EAEF69152D20908";

    public boolean _0x7f3a_verifyProtected(String _0xinput) {
        int _0xstate = 0x11;
        boolean _0xres = false;
        byte[] _0xrec = null;

        // Диспетчер скінченного автомата (Control-Flow Flattening)
        while (_0xstate != 0xFF) {
            switch (_0xstate) {
                case 0x11 -> {
                    // Крок 1: Перевірка середовища на наявність налагоджувача
                    if (AntiDebugAndIntegrityGuard.isDebuggerOrAgentAttached()) {
                        _0xstate = 0x99;
                    } else {
                        _0xstate = (_0xstate * 2) + 3; // Перехід у стан 0x25 (37)
                    }
                }
                case 0x25 -> {
                    // Крок 2: Непрозора умова (Opaque Predicate: добуток двох послідовних чисел завжди парний)
                    int _0xjunk = (_0xinput != null) ? _0xinput.length() : 0;
                    if (((_0xjunk * (_0xjunk + 1)) & 1) == 0) {
                        _0xrec = new byte[_0x3d11.length];
                        for (int _0xk = 0; _0xk < _0x3d11.length; _0xk++) {
                            _0xrec[_0xk] = (byte) (_0x3d11[_0xk] ^ _0x5f20[_0xk % _0x5f20.length]);
                        }
                        _0xstate = (_0xstate ^ 0x0F) + 10; // Перехід у стан 0x34 (52)
                    } else {
                        // Недосяжна фіктивна гілка (сміттєвий код для заплутування декомпілятора)
                        _0xstate = 0x77;
                    }
                }
                case 0x34 -> {
                    // Крок 3: Динамічне розшифрування еталона AES-256-GCM та непрямий виклик через Reflection
                    try {
                        byte[] _0xkey = HexFormat.of().parseHex(_0x2a01 + _0x2a02);
                        byte[] _0xiv = HexFormat.of().parseHex(_0x9e02_iv);
                        byte[] _0xct = HexFormat.of().parseHex(_0x7c88_ct);

                        Cipher _0xc = Cipher.getInstance("AES/GCM/NoPadding");
                        _0xc.init(Cipher.DECRYPT_MODE, new SecretKeySpec(_0xkey, "AES"), new GCMParameterSpec(128, _0xiv));
                        byte[] _0xplain = _0xc.doFinal(_0xct);

                        if (_0xinput != null && _0xrec != null) {
                            byte[] _0xcand = _0xinput.getBytes(StandardCharsets.UTF_8);
                            Method _0xm = MessageDigest.class.getMethod("isEqual", byte[].class, byte[].class);
                            boolean _0xm1 = (boolean) _0xm.invoke(null, _0xplain, _0xcand);
                            boolean _0xm2 = (boolean) _0xm.invoke(null, _0xrec, _0xcand);
                            _0xres = _0xm1 && _0xm2;
                        }
                    } catch (Exception _0xe) {
                        _0xres = false;
                    }
                    _0xstate = 0xFF;
                }
                case 0x77 -> {
                    // Фіктивний стан для ускладнення графа потоку керування (CFG)
                    _0xres = (_0xrec != null && _0xrec.length == -1);
                    _0xstate = 0xFF;
                }
                case 0x99 -> throw new SecurityException("403 Forbidden: Виявлено налагоджувач! Виконання зупинено.");
                default -> _0xstate = 0xFF;
            }
        }
        return _0xres;
    }
}