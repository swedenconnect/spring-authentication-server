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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.io.IOException;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.LoggerFactory;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;

/**
 * Support for the tests of the validation of clients from the configuration and client repositories.
 *
 * @author Martin Lindström
 */
abstract class ClientTestSupport {

  static final String CLIENT_ID = "https://client.example.com";

  static final String REDIRECT_URI = CLIENT_ID + "/callback";

  static final String JWKS_URI = CLIENT_ID + "/jwks";

  static final String OTHER_JWKS_URI = CLIENT_ID + "/other-jwks";

  static final PkiCredential KEY = KeyTestSupport.rsa("client-key", 2048);

  static final PkiCredential NEW_KEY = KeyTestSupport.rsa("client-new-key", 2048);

  /**
   * Creates metadata of a valid client that authenticates with {@code private_key_jwt}, without keys.
   *
   * @return the metadata
   */
  static OIDCClientMetadata metadata() {
    final OIDCClientMetadata metadata = new OIDCClientMetadata();
    metadata.setName("The Client");
    metadata.setRedirectionURI(URI.create(REDIRECT_URI));
    metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
    return metadata;
  }

  /**
   * Creates metadata of a valid client with keys at {@link #JWKS_URI}.
   *
   * @return the metadata
   */
  static OIDCClientMetadata jwksUriMetadata() {
    final OIDCClientMetadata metadata = metadata();
    metadata.setJWKSetURI(URI.create(JWKS_URI));
    return metadata;
  }

  /**
   * Creates the JWK Set of a public key.
   *
   * @param credential the key
   * @param kid the key ID
   * @return the JWK Set
   */
  static JWKSet keys(final PkiCredential credential, final String kid) {
    return new JWKSet(new RSAKey.Builder((RSAPublicKey) credential.getPublicKey()).keyID(kid).build());
  }

  /**
   * Adds a list appender to a logger.
   *
   * @param type the class of the logger
   * @return the appender
   */
  static ListAppender<ILoggingEvent> appender(final Class<?> type) {
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    ((Logger) LoggerFactory.getLogger(type)).addAppender(appender);
    return appender;
  }

  /**
   * Removes a list appender from a logger.
   *
   * @param type the class of the logger
   * @param appender the appender
   */
  static void remove(final Class<?> type, final ListAppender<ILoggingEvent> appender) {
    ((Logger) LoggerFactory.getLogger(type)).detachAppender(appender);
  }

  /**
   * A {@link ClientKeysFetcher} that answers with the keys of the test and records the fetches.
   */
  static class StubKeysFetcher implements ClientKeysFetcher {

    /** The JWK Sets by {@code jwks_uri}. A URI without a JWK Set cannot be fetched. */
    final Map<String, JWKSet> jwks = new ConcurrentHashMap<>();

    /** The URIs that have been fetched. */
    final List<String> calls = new ArrayList<>();

    /** The signed JWK Set URIs that have been fetched. */
    final List<String> signedCalls = new ArrayList<>();

    @Override
    public synchronized JWKSet fetchJwks(final URI jwksUri) throws IOException {
      this.calls.add(jwksUri.toString());
      final JWKSet keys = this.jwks.get(jwksUri.toString());
      if (keys == null) {
        throw new IOException("HTTP status 503");
      }
      return keys;
    }

    @Override
    public synchronized SignedJWT fetchSignedJwks(final URI signedJwksUri) throws IOException {
      this.signedCalls.add(signedJwksUri.toString());
      throw new IOException("HTTP status 503");
    }
  }

  /**
   * A clock that the test moves forward itself.
   */
  static class TestClock extends Clock {

    /** The current time. */
    private volatile Instant instant = Instant.now().truncatedTo(ChronoUnit.SECONDS);

    /**
     * Moves the clock forward.
     *
     * @param duration how far to move it
     */
    void advance(final Duration duration) {
      this.instant = this.instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(final ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return this.instant;
    }
  }

}
