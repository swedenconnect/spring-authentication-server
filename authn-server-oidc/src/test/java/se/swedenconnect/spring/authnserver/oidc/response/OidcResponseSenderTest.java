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
package se.swedenconnect.spring.authnserver.oidc.response;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.nimbusds.oauth2.sdk.ErrorObject;

/**
 * Tests for {@link OidcResponseSender} and {@link DefaultResponsePage}.
 *
 * @author Martin Lindström
 */
class OidcResponseSenderTest {

  private final OidcResponseSender sender = new OidcResponseSender();

  @Test
  void aQueryResponseIsAddedToTheQueryOfTheRedirectUri() throws Exception {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.sender.sendError(new MockHttpServletRequest(), response,
        new OidcResponseTarget("client", "https://rp.example.com/cb?x=1", "query", "a b&c"),
        new ErrorObject("invalid_request", "Missing value"));
    assertThat(response.getRedirectedUrl()).isEqualTo(
        "https://rp.example.com/cb?x=1&error=invalid_request&error_description=Missing%20value&state=a%20b%26c");
  }

  @Test
  void aResponseWithoutStateHasNoStateParameter() throws Exception {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.sender.send(new MockHttpServletRequest(), response,
        new OidcResponseTarget("client", "https://rp.example.com/cb", "query", null), Map.of("code", "abc"));
    assertThat(response.getRedirectedUrl()).isEqualTo("https://rp.example.com/cb?code=abc");
  }

  @Test
  void aFormPostResponseIsAnEscapedPage() throws Exception {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.sender.sendError(new MockHttpServletRequest(), response,
        new OidcResponseTarget("client", "https://rp.example.com/cb", "form_post", "<s>"),
        new ErrorObject("access_denied", null));
    assertThat(response.getRedirectedUrl()).isNull();
    assertThat(response.getContentType()).startsWith("text/html");
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-cache, no-store");
    assertThat(response.getContentAsString())
        .contains("action=\"https://rp.example.com/cb\" method=\"POST\"")
        .contains("name=\"error\" value=\"access_denied\"")
        .contains("name=\"state\" value=\"&lt;s&gt;\"")
        .doesNotContain("error_description");
  }

  @Test
  void aCustomResponsePageIsUsed() throws Exception {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    this.sender.setResponsePage((req, resp, destination, parameters) ->
        resp.getWriter().write(destination + " " + parameters));
    this.sender.sendError(new MockHttpServletRequest(), response,
        new OidcResponseTarget("client", "https://rp.example.com/cb", "form_post", null),
        new ErrorObject("access_denied", null));
    assertThat(response.getContentAsString()).isEqualTo("https://rp.example.com/cb {error=access_denied}");
  }

  @Test
  void theTargetIsKeptOnTheRequest() {
    final MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(OidcResponseTarget.fromRequest(request)).isNull();
    final OidcResponseTarget target = new OidcResponseTarget("client", "https://rp.example.com/cb", "query", null);
    OidcResponseTarget.setOnRequest(request, target);
    assertThat(OidcResponseTarget.fromRequest(request)).isSameAs(target);
    assertThat(target.isFormPost()).isFalse();
  }

}
