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
package se.swedenconnect.spring.authnserver.service;

import java.io.IOException;
import java.net.ServerSocket;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Base class for the tests that start the service with the complete profile. The service runs on free ports, the same
 * for all test classes so that they share one running service, and the base URL, SAML entity ID and OIDC issuer follow
 * the port.
 *
 * @author Martin Lindström
 */
@SpringBootTest(classes = ReferenceApplication.class, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@ActiveProfiles("complete")
abstract class AbstractCompleteProfileTest {

  /** The HTTPS port. */
  static final int PORT = freePort();

  /** The management port. */
  static final int MANAGEMENT_PORT = freePort();

  /** The base URL of the server. */
  static final String BASE_URL = "https://localhost:" + PORT;

  /** The SAML entity ID of the server. */
  static final String ENTITY_ID = BASE_URL + "/saml";

  @DynamicPropertySource
  static void ports(final DynamicPropertyRegistry registry) {
    registry.add("server.port", () -> PORT);
    registry.add("management.server.port", () -> MANAGEMENT_PORT);
    registry.add("authn-server.base-url", () -> BASE_URL);
    registry.add("authn-server.saml.entity-id", () -> ENTITY_ID);
    registry.add("authn-server.oidc.issuer", () -> BASE_URL);
  }

  private static int freePort() {
    try (final ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
    catch (final IOException e) {
      throw new IllegalStateException(e);
    }
  }

}
