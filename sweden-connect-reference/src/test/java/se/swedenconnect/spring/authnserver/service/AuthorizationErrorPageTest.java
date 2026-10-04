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

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLEncoder;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.actuate.audit.AuditEventRepository;

/**
 * Tests that an authorization request that must not be redirected to the client, OAuth 2.0 (RFC 6749), Section
 * 4.1.2.1, shows the error page with HTTP status 400, and is audited once.
 *
 * @author Martin Lindström
 */
class AuthorizationErrorPageTest extends AbstractCompleteProfileTest {

  /** The audit event type of an error shown to the user. */
  private static final String UNRECOVERABLE = "authn_unrecoverable_error";

  @Autowired
  private AuditEventRepository auditEvents;

  @Test
  void anUnknownClientShowsTheErrorPage() throws Exception {
    final Instant start = Instant.now();
    final Map<String, String> request = request();
    request.put("client_id", "https://unknown.test.local");

    final HttpResponse<String> response = new TestBrowser().get(authorizeUrl(request));

    assertErrorPage(response, 400, "The service that sent you here is not known.");
    assertThat(this.auditEvents.find("https://unknown.test.local", start, UNRECOVERABLE)).hasSize(1);
  }

  @Test
  void aMissingClientIdShowsTheErrorPage() throws Exception {
    final Map<String, String> request = request();
    request.remove("client_id");
    assertErrorPage(new TestBrowser().get(authorizeUrl(request)), 400,
        "The request from the service that sent you here is invalid.");
  }

  @Test
  void aMissingOrUnregisteredRedirectUriShowsTheErrorPage() throws Exception {
    final Instant start = Instant.now();
    final Map<String, String> request = request();
    request.put("redirect_uri", "https://evil.test.local/callback");
    assertErrorPage(new TestBrowser().get(authorizeUrl(request)), 400,
        "The request from the service that sent you here has an invalid return address.");

    request.remove("redirect_uri");
    assertErrorPage(new TestBrowser().get(authorizeUrl(request)), 400,
        "The request from the service that sent you here has an invalid return address.");
    assertThat(this.auditEvents.find(OidcFlowTest.CLIENT_ID, start, UNRECOVERABLE)).hasSize(2);
  }

  @Test
  void thePageIsInTheLanguageOfTheUser() throws Exception {
    final Map<String, String> request = request();
    request.put("client_id", "https://unknown.test.local");
    request.put("lang", "sv");
    assertErrorPage(new TestBrowser().get(authorizeUrl(request)), 400, "E-tjänsten som skickade dig hit är okänd.");
  }

  @Test
  void aRequestThatDoesNotAcceptHtmlStillGetsTheErrorPage() throws Exception {
    final Map<String, String> request = request();
    request.put("client_id", "https://unknown.test.local");
    for (final String accept : new String[] { "application/json", "*/*" }) {
      final HttpResponse<String> response = new TestBrowser().get(authorizeUrl(request), accept);
      assertErrorPage(response, 400, "The service that sent you here is not known.");
    }
  }

  /**
   * Asserts that the response is the error page with the status and message, and no redirect.
   */
  static void assertErrorPage(final HttpResponse<String> response, final int status, final String message) {
    assertThat(response.statusCode()).isEqualTo(status);
    assertThat(response.headers().firstValue("Location")).isEmpty();
    assertThat(response.headers().firstValue("Content-Type")).hasValueSatisfying(
        type -> assertThat(type).startsWith("text/html"));
    assertThat(response.body()).contains(message).doesNotContain("\"status\"");
  }

  private static Map<String, String> request() {
    final Map<String, String> request = new LinkedHashMap<>();
    request.put("response_type", "code");
    request.put("client_id", OidcFlowTest.CLIENT_ID);
    request.put("redirect_uri", OidcFlowTest.REDIRECT_URI);
    request.put("scope", "openid");
    request.put("state", "state-1");
    return request;
  }

  private static String authorizeUrl(final Map<String, String> request) {
    return BASE_URL + "/oidc/authorize?" + request.entrySet().stream()
        .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
  }

}
