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
package se.swedenconnect.spring.authnserver.service.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.http.Cookie;

/**
 * Tests for {@link CookieGenerator}.
 *
 * @author Martin Lindström
 */
class CookieGeneratorTest {

  @Test
  void theCookieIsWrittenAndRead() {
    final CookieGenerator generator = new CookieGenerator("selectedUser", "/idp", Duration.ofDays(1));
    final MockHttpServletResponse response = new MockHttpServletResponse();
    generator.addCookie("value", response);
    assertThat(response.getHeader("Set-Cookie"))
        .contains("selectedUser=value", "Path=/idp", "Max-Age=86400", "Secure", "HttpOnly");

    final MockHttpServletRequest request = new MockHttpServletRequest();
    assertThat(generator.getValue(request)).isNull();
    request.setCookies(new Cookie("other", "x"), new Cookie("selectedUser", "value"));
    assertThat(generator.getValue(request)).isEqualTo("value");
    assertThat(generator.getName()).isEqualTo("selectedUser");
  }

  @Test
  void withoutAContextPathTheCookieIsForTheWholeServer() {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    new CookieGenerator("c", "", Duration.ofDays(1)).addCookie("v", response);
    assertThat(response.getHeader("Set-Cookie")).contains("Path=/");
  }

  @Test
  void theCookieIsCleared() {
    final MockHttpServletResponse response = new MockHttpServletResponse();
    new CookieGenerator("c", null, Duration.ofDays(1)).clearCookie(response);
    assertThat(response.getHeader("Set-Cookie")).contains("c=", "Max-Age=0");
  }

}
