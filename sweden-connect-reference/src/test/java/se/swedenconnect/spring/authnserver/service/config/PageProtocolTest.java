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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Locale;
import java.util.ResourceBundle;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;

/**
 * Tests for {@link PageProtocol}.
 *
 * @author Martin Lindström
 */
class PageProtocolTest {

  @Test
  void theValueIsTheLowerCaseProtocol() {
    assertThat(PageProtocol.value(AuthenticationProtocol.SAML)).isEqualTo("saml");
    assertThat(PageProtocol.value(AuthenticationProtocol.OIDC)).isEqualTo("oidc");
  }

  @Test
  void aProtocolIsRequired() {
    assertThatThrownBy(() -> PageProtocol.value(null)).isInstanceOf(NullPointerException.class);
  }

  @Test
  void everyProtocolHasItsTextsInEveryLanguage() {
    for (final Locale locale : new Locale[] { Locale.ENGLISH, Locale.of("sv") }) {
      final ResourceBundle messages = ResourceBundle.getBundle("messages", locale);
      for (final String key : new String[] { "idp.msg.title", "idp.msg.heading" }) {
        assertThat(messages.getString(key)).isNotBlank();
      }
      for (final AuthenticationProtocol protocol : AuthenticationProtocol.values()) {
        for (final String key : new String[] { "idp.msg.title", "idp.msg.heading", "idp.msg.help.1.title" }) {
          assertThat(messages.getString(key + "." + PageProtocol.value(protocol))).isNotBlank();
        }
      }
    }
  }

}
