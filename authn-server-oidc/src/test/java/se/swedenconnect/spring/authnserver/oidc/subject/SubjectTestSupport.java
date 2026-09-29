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
package se.swedenconnect.spring.authnserver.oidc.subject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * Fixtures for the {@code sub} tests.
 *
 * @author Martin Lindström
 */
final class SubjectTestSupport {

  /** The OpenID Provider issuer identifier. */
  static final String ISSUER = "https://op.example.com";

  /** The personal identity number of the test user. */
  static final String IDENTITY_NUMBER = "197705232382";

  /** A server secret. */
  static final byte[] SECRET = "the-server-secret".getBytes(StandardCharsets.UTF_8);

  /**
   * Creates the test user.
   *
   * @return an {@link AuthenticatedUser}
   */
  static AuthenticatedUser user() {
    return user(IDENTITY_NUMBER);
  }

  /**
   * Creates a user with the supplied personal identity number.
   *
   * @param identityNumber the personal identity number
   * @return an {@link AuthenticatedUser}
   */
  static AuthenticatedUser user(final String identityNumber) {
    return new AuthenticatedUser(
        List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, identityNumber),
            GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3", Instant.now(),
        "192.168.1.14");
  }

  /**
   * Creates an OpenID Connect requester.
   *
   * @param clientId the client identifier
   * @return a {@link Requester}
   */
  static Requester client(final String clientId) {
    return new Requester(AuthenticationProtocol.OIDC, clientId);
  }

  /**
   * Serializes and deserializes the supplied object.
   *
   * @param <T> the type of the object
   * @param object the object to serialize
   * @return the deserialized object
   * @throws Exception for serialization errors
   */
  @SuppressWarnings("unchecked")
  static <T extends Serializable> T roundTrip(final T object) throws Exception {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(object);
    }
    try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }

  // Hidden constructor
  private SubjectTestSupport() {
  }

}
