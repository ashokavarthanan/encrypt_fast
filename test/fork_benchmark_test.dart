import 'dart:typed_data';
import 'package:encrypt_fast/encrypt.dart';
import 'package:test/test.dart';

void main() {
  group('encrypt_fast fork', () {
    test('decryptBytes returns Uint8List (backward compatible)', () {
      final key = Key.fromUtf8('12345678901234567890123456789012');
      final iv = IV.fromUtf8('1234567890123456');
      final encrypter = Encrypter(AES(key, mode: AESMode.gcm));

      final plaintext = Uint8List(1400000);
      for (int i = 0; i < plaintext.length; i++) {
        plaintext[i] = i & 0xFF;
      }

      final encrypted = encrypter.encryptBytes(plaintext, iv: iv);

      // Warmup
      for (int i = 0; i < 3; i++) {
        encrypter.decryptBytes(encrypted, iv: iv);
      }

      // Test 1: Return type is Uint8List
      final decrypted = encrypter.decryptBytes(encrypted, iv: iv);
      expect(decrypted, isA<Uint8List>(),
          reason: 'decryptBytes must return Uint8List for performance');
      expect(decrypted, plaintext, reason: 'Decryption must be lossless');

      // Test 2: Backward compat — List<int> assignment still works
      List<int> listResult = encrypter.decryptBytes(encrypted, iv: iv);
      expect(listResult.length, plaintext.length);

      // Test 3: verifyTag:false works and produces same output
      final fastDecrypted =
          encrypter.decryptBytes(encrypted, iv: iv, verifyTag: false);
      expect(fastDecrypted, plaintext);
    });

    test('verifyTag:false throws for non-AES algorithms', () {
      final key = Key.fromUtf8('12345678901234567890123456789012');
      final salsa = Salsa20(key);
      final encrypter = Encrypter(salsa);
      final iv = IV.fromLength(8);
      final encrypted = encrypter.encrypt('hello', iv: iv);

      expect(
        () => encrypter.decryptBytes(encrypted, iv: iv, verifyTag: false),
        throwsA(isA<UnsupportedError>()),
      );
    });

    test('benchmark: Uint8List vs verifyTag:false', () {
      final key = Key.fromUtf8('12345678901234567890123456789012');
      final iv = IV.fromUtf8('1234567890123456');
      final encrypter = Encrypter(AES(key, mode: AESMode.gcm));

      final plaintext = Uint8List(1400000);
      for (int i = 0; i < plaintext.length; i++) {
        plaintext[i] = i & 0xFF;
      }
      final encrypted = encrypter.encryptBytes(plaintext, iv: iv);

      // Warmup
      for (int i = 0; i < 5; i++) {
        encrypter.decryptBytes(encrypted, iv: iv);
        encrypter.decryptBytes(encrypted, iv: iv, verifyTag: false);
      }

      // Benchmark verifyTag:true
      final sw1 = Stopwatch()..start();
      for (int i = 0; i < 3; i++) {
        encrypter.decryptBytes(encrypted, iv: iv);
      }
      sw1.stop();
      final avg1 = sw1.elapsedMilliseconds / 3;

      // Benchmark verifyTag:false
      final sw2 = Stopwatch()..start();
      for (int i = 0; i < 3; i++) {
        encrypter.decryptBytes(encrypted, iv: iv, verifyTag: false);
      }
      sw2.stop();
      final avg2 = sw2.elapsedMilliseconds / 3;

      print('verifyTag=true  avg: ${avg1} ms');
      print('verifyTag=false avg: ${avg2} ms');
      print('Speedup: ${(avg1 / avg2).toStringAsFixed(2)}x');

      // Sanity check
      expect(avg2, lessThan(avg1),
          reason: 'verifyTag:false should be faster than verifyTag:true');
    });
  });
}
