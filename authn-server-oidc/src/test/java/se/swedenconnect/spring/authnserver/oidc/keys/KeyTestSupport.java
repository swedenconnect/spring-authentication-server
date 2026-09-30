/*
 * Copyright 2026 Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.swedenconnect.spring.authnserver.oidc.keys;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

/**
 * Creates credentials for the key tests. Key pairs are cached per name, so the same name gives the same key.
 *
 * @author Martin Lindström
 */
public final class KeyTestSupport {

  /** The key pairs, by name. */
  private static final Map<String, KeyPair> KEY_PAIRS = new ConcurrentHashMap<>();

  /**
   * Gets a credential with an RSA key.
   *
   * @param name the name, deciding which key pair is used
   * @param bits the key length
   * @return a credential
   */
  public static PkiCredential rsa(final String name, final int bits) {
    return credential(name, KEY_PAIRS.computeIfAbsent(name + "-rsa-" + bits, n -> generate("RSA", bits, null)));
  }

  /**
   * Gets a credential with an EC key.
   *
   * @param name the name, deciding which key pair is used
   * @param curve the curve, for example {@code secp256r1}
   * @return a credential
   */
  public static PkiCredential ec(final String name, final String curve) {
    return credential(name, KEY_PAIRS.computeIfAbsent(name + "-ec-" + curve, n -> generate("EC", 0, curve)));
  }

  /**
   * Gets a credential with an Ed25519 key.
   *
   * @param name the name
   * @return a credential
   */
  public static PkiCredential ed25519(final String name) {
    return credential(name, KEY_PAIRS.computeIfAbsent(name + "-ed25519", n -> generate("Ed25519", 0, null)));
  }

  private static PkiCredential credential(final String name, final KeyPair keyPair) {
    final BasicCredential credential = new BasicCredential(keyPair);
    credential.setName(name);
    return credential;
  }

  private static KeyPair generate(final String algorithm, final int bits, final String curve) {
    try {
      final KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
      if (curve != null) {
        generator.initialize(new ECGenParameterSpec(curve));
      }
      else if (bits > 0) {
        generator.initialize(bits);
      }
      return generator.generateKeyPair();
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  // Hidden constructor
  private KeyTestSupport() {
  }

}
