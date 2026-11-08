part of encrypt;

/// Wraps Algorithms in a unique Container.
class Encrypter {
  final Algorithm algo;

  Encrypter(this.algo);

  /// Calls [encrypt] on the wrapped Algorithm using a raw binary.
  Encrypted encryptBytes(List<int> input, {IV? iv, Uint8List? associatedData}) {
    if (input is Uint8List) {
      return algo.encrypt(input, iv: iv, associatedData: associatedData);
    }

    return algo.encrypt(
      Uint8List.fromList(input),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Calls [encrypt] on the wrapped Algorithm.
  Encrypted encrypt(
    String input, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return encryptBytes(
      convert.utf8.encode(input),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Calls [decrypt] on the wrapped Algorithm without UTF-8 decoding.
  ///
  /// Returns [Uint8List] instead of `List<int>` for performance.
  /// On the Dart VM, `List<int>` boxes every byte (~28 bytes/byte), so
  /// a 1.4 MB decryption allocates ~39 MB of garbage. `Uint8List` uses
  /// contiguous byte storage, eliminating boxing overhead (~8x faster).
  ///
  /// When [verifyTag] is `false` and the wrapped algorithm is AES in GCM
  /// mode, the GCM tag verification (and per-block GHASH accumulation)
  /// is skipped — an additional ~2x speedup. Only use for trusted local
  /// files where tampering is not a concern.
  Uint8List decryptBytes(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
    bool verifyTag = true,
  }) {
    if (!verifyTag) {
      if (algo is AES && (algo as AES).mode == AESMode.gcm) {
        return (algo as AES).decryptGcmCtr(encrypted, iv!);
      }
      throw UnsupportedError(
        'verifyTag: false is only supported for AES in GCM mode',
      );
    }
    return algo.decrypt(encrypted, iv: iv, associatedData: associatedData);
  }

  /// Calls [decrypt] on the wrapped Algorithm.
  String decrypt(
    Encrypted encrypted, {
    IV? iv,
    Uint8List? associatedData,
  }) {
    return convert.utf8.decode(
      decryptBytes(encrypted, iv: iv, associatedData: associatedData),
      allowMalformed: true,
    );
  }

  /// Sugar for `decrypt(Encrypted.fromBase16(encoded))`.
  String decrypt16(String encoded, {IV? iv, Uint8List? associatedData}) {
    return decrypt(
      Encrypted.fromBase16(encoded),
      iv: iv,
      associatedData: associatedData,
    );
  }

  /// Sugar for `decrypt(Encrypted.fromBase64(encoded))`.
  String decrypt64(String encoded, {IV? iv, Uint8List? associatedData}) {
    return decrypt(
      Encrypted.fromBase64(encoded),
      iv: iv,
      associatedData: associatedData,
    );
  }
}
