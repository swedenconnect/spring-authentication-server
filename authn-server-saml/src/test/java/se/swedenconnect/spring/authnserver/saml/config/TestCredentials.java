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
package se.swedenconnect.spring.authnserver.saml.config;

import java.io.InputStream;
import java.security.KeyStore;

import org.springframework.core.io.ClassPathResource;

import se.swedenconnect.security.credential.KeyStoreCredential;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.security.credential.factory.KeyStoreFactory;

/**
 * Credentials for the tests.
 *
 * @author Martin Lindström
 */
final class TestCredentials {

  /** The keystore holding the credentials sign, encrypt and metadata. */
  private static final KeyStore KEY_STORE;

  static {
    try (final InputStream is = new ClassPathResource("credentials/idp-credentials.p12").getInputStream()) {
      KEY_STORE = KeyStoreFactory.loadKeyStore(is, "secret".toCharArray(), "PKCS12", null);
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static final PkiCredential SIGN = load("sign");

  static final PkiCredential ENCRYPT = load("encrypt");

  static final PkiCredential METADATA = load("metadata");

  private static PkiCredential load(final String alias) {
    try {
      final KeyStoreCredential credential = new KeyStoreCredential(KEY_STORE, alias, "secret".toCharArray());
      credential.setName(alias);
      return credential;
    }
    catch (final Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private TestCredentials() {
  }

}
