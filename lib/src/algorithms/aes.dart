part of encrypt;

/// Wraps the AES Algorithm.
class AES implements Algorithm {
  final Key key;
  final AESMode mode;
  final String? padding;
  late final BlockCipher _cipher;
  final StreamCipher? _streamCipher;

  AES(this.key, {this.mode = AESMode.sic, this.padding = 'PKCS7'})
      : _streamCipher = padding == null && _streamable.contains(mode)
            ? StreamCipher('AES/${_modes[mode]}')
            : null {
    if (mode == AESMode.gcm) {
      _cipher = GCMBlockCipher(AESEngine());
    } else {
      _cipher = padding != null
          ? PaddedBlockCipher('AES/${_modes[mode]}/$padding')
          : BlockCipher('AES/${_modes[mode]}');
    }
  }

  @override
  Encrypted encrypt(Uint8List bytes, {IV? iv, Uint8List? associatedData}) {
    if (mode != AESMode.ecb && iv == null) {
      throw StateError('IV is required.');
    }

    if (_streamCipher != null) {
      _streamCipher!
        ..reset()
        ..init(true, _buildParams(iv, associatedData: associatedData));

      return Encrypted(_streamCipher!.process(bytes));
    }

    _cipher
      ..reset()
      ..init(true, _buildParams(iv, associatedData: associatedData));

    if (padding != null) {
      return Encrypted(_cipher.process(bytes));
    }

    return Encrypted(_processBlocks(bytes));
  }

  @override
  Uint8List decrypt(Encrypted encrypted, {IV? iv, Uint8List? associatedData}) {
    if (mode != AESMode.ecb && iv == null) {
      throw StateError('IV is required.');
    }

    if (_streamCipher != null) {
      _streamCipher!
        ..reset()
        ..init(false, _buildParams(iv, associatedData: associatedData));

      return _streamCipher!.process(encrypted.bytes);
    }

    _cipher
      ..reset()
      ..init(false, _buildParams(iv, associatedData: associatedData));

    if (padding != null) {
      return _cipher.process(encrypted.bytes);
    }

    return _processBlocks(encrypted.bytes);
  }

  Uint8List _processBlocks(Uint8List input) {
    var output = Uint8List(input.lengthInBytes);

    for (int offset = 0; offset < input.lengthInBytes;) {
      offset += _cipher.processBlock(input, offset, output, offset);
    }

    return output;
  }

  CipherParameters _buildParams(IV? iv, {Uint8List? associatedData}) {
    if (mode == AESMode.ecb || iv == null) {
      if (padding != null) {
        return PaddedBlockCipherParameters(KeyParameter(key.bytes), null);
      } else {
        return KeyParameter(key.bytes);
      }
    }

    if (mode == AESMode.gcm) {
      return AEADParameters(
        KeyParameter(key.bytes),
        128,
        iv.bytes,
        associatedData ?? Uint8List.fromList([]),
      );
    }

    if (padding != null) {
      return _paddedParams(iv);
    }

    return ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes);
  }

  PaddedBlockCipherParameters _paddedParams(IV iv) {
    if (mode == AESMode.ecb) {
      return PaddedBlockCipherParameters(KeyParameter(key.bytes), null);
    }

    return PaddedBlockCipherParameters(
        ParametersWithIV<KeyParameter>(KeyParameter(key.bytes), iv.bytes),
        null);
  }

  // ============================================================
  // Fast CTR-only decryption for GCM (skips tag verification)
  // ============================================================

  /// Fast CTR-only decryption for GCM mode, skipping tag verification.
  ///
  /// GCM = AES-CTR (encryption) + GHASH (tag). This skips the
  /// per-block GHASH accumulation AND the tag check — providing
  /// roughly 2x speedup over the standard GCM path.
  ///
  /// Only for trusted local files where tampering is not a concern.
  ///
  /// Requires [iv] to be a 16-byte IV (WhatsApp crypt15 format).
  Uint8List decryptGcmCtr(Encrypted encrypted, IV iv) {
    if (mode != AESMode.gcm) {
      throw StateError('decryptGcmCtr only supports AESMode.gcm');
    }
    return _gcmCtrDecrypt(encrypted.bytes, iv.bytes);
  }

  Uint8List _gcmCtrDecrypt(Uint8List ciphertext, Uint8List iv) {
    // --- Step 1: H = AES_ENC_K(0^128) ---
    final aesEngine = AESEngine();
    aesEngine.init(true, KeyParameter(key.bytes));
    final h = Uint8List(16);
    aesEngine.processBlock(Uint8List(16), 0, h, 0);

    // --- Step 2: J0 = GHASH_H(IV || 0^8 || [len(IV)*8]_64) ---
    // For 16-byte IV: standard NIST GCM derivation
    final ghashIn = Uint8List(32);
    ghashIn.setRange(0, 16, iv);
    ghashIn[31] = 0x80; // length in bits = 128

    var j0 = _gfMul(ghashIn.sublist(0, 16), h);
    j0 = _gfMul(_xor16(j0, ghashIn.sublist(16, 32)), h);

    // --- Step 3: First counter = J0 + 1 ---
    final counter = Uint8List.fromList(j0);
    _inc32(counter);

    // --- Step 4: CTR decrypt (drop 16-byte tag at end) ---
    final ct = ciphertext.sublist(0, ciphertext.length - 16);
    final out = Uint8List(ct.length);
    final ks = Uint8List(16);

    for (int offset = 0; offset < ct.length; offset += 16) {
      aesEngine.processBlock(counter, 0, ks, 0);
      final n = (ct.length - offset) < 16 ? (ct.length - offset) : 16;
      for (int i = 0; i < n; i++) {
        out[offset + i] = ct[offset + i] ^ ks[i];
      }
      _inc32(counter);
    }
    return out;
  }

  // --- GCM counter helpers ---
  void _inc32(Uint8List c) {
    final v = ((c[12] & 0xFF) << 24) |
        ((c[13] & 0xFF) << 16) |
        ((c[14] & 0xFF) << 8) |
        (c[15] & 0xFF);
    final next = (v + 1) & 0xFFFFFFFF;
    c[12] = (next >> 24) & 0xFF;
    c[13] = (next >> 16) & 0xFF;
    c[14] = (next >> 8) & 0xFF;
    c[15] = next & 0xFF;
  }

  Uint8List _xor16(Uint8List a, Uint8List b) {
    final out = Uint8List(16);
    for (int i = 0; i < 16; i++) {
      out[i] = a[i] ^ b[i];
    }
    return out;
  }

  Uint8List _gfMul(Uint8List x, Uint8List y) {
    final z = Uint8List(16);
    final v = Uint8List.fromList(y);
    for (int i = 0; i < 128; i++) {
      final byteIdx = i ~/ 8;
      final bitIdx = 7 - (i % 8);
      if (((x[byteIdx] >> bitIdx) & 1) != 0) {
        for (int j = 0; j < 16; j++) {
          z[j] ^= v[j];
        }
      }
      int carry = 0;
      for (int j = 0; j < 16; j++) {
        final nc = v[j] & 1;
        v[j] = (v[j] >> 1) | (carry << 7);
        carry = nc;
      }
      if (carry != 0) v[0] ^= 0xe1;
    }
    return z;
  }
}

enum AESMode {
  cbc,
  cfb64,
  ctr,
  ecb,
  ofb64Gctr,
  ofb64,
  sic,
  gcm,
}

const Map<AESMode, String> _modes = {
  AESMode.cbc: 'CBC',
  AESMode.cfb64: 'CFB-64',
  AESMode.ctr: 'CTR',
  AESMode.ecb: 'ECB',
  AESMode.ofb64Gctr: 'OFB-64/GCTR',
  AESMode.ofb64: 'OFB-64',
  AESMode.sic: 'SIC',
  AESMode.gcm: 'GCM',
};

const List<AESMode> _streamable = [
  AESMode.sic,
  AESMode.ctr,
];
