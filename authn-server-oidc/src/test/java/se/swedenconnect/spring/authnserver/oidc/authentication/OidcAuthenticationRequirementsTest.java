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
package se.swedenconnect.spring.authnserver.oidc.authentication;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestData;
import se.swedenconnect.spring.authnserver.oidc.response.OidcResponseTarget;

/**
 * Tests for {@link OidcAuthenticationRequirements} and {@link OidcAuthnRequestData}.
 *
 * @author Martin Lindström
 */
class OidcAuthenticationRequirementsTest {

  @Test
  void theRequirementsSurviveSerialization() throws Exception {
    final OidcAuthenticationRequirements requirements = requirements();
    final OidcAuthenticationRequirements copy = roundTrip(requirements);
    assertThat(copy).isEqualTo(requirements).hasSameHashCodeAs(requirements);
    assertThat(copy.getScopes()).containsExactly("openid", "profile");
    assertThat(copy.getLoginHint()).isEqualTo("hint");
    assertThat(copy.getUiLocales()).containsExactly("sv");
    assertThat(copy.getIdTokenHintSubject()).isEqualTo("sub");
  }

  @Test
  void theLoginHintAndSubjectAreNotLogged() {
    final String s = requirements().toString();
    assertThat(s).contains("scopes=[openid, profile]", "ui-locales=[sv]", "login-hint=<present>",
        "id-token-hint=<present>").doesNotContain("hint]", "=sub");
  }

  @Test
  void theGenericRequirementsAreCopied() {
    final AuthenticationRequirements generic = new AuthenticationRequirements();
    generic.setMaxAuthnAge(Duration.ZERO);
    final OidcAuthenticationRequirements requirements = new OidcAuthenticationRequirements(generic);
    assertThat(requirements.isForceAuthn()).isTrue();
    assertThat(requirements.getScopes()).isEmpty();
    requirements.setScopes(null);
    requirements.setUiLocales(null);
    assertThat(requirements.getUiLocales()).isEmpty();
    assertThat(requirements).isNotEqualTo(requirements());
  }

  @Test
  void theRequestDataSurvivesSerialization() throws Exception {
    final OidcAuthnRequestData data = new OidcAuthnRequestData(
        new OidcResponseTarget("client", "https://rp.example.com/cb", "query", "s"), "nonce", "challenge", "S256",
        List.of("openid"), "{\"id_token\":{}}", List.of("http://id.elegnamnden.se/loa/1.0/loa3"));
    assertThat(roundTrip(data)).isEqualTo(data);
  }

  private static OidcAuthenticationRequirements requirements() {
    final OidcAuthenticationRequirements requirements = new OidcAuthenticationRequirements();
    requirements.setScopes(List.of("openid", "profile"));
    requirements.setLoginHint("hint");
    requirements.setUiLocales(List.of("sv"));
    requirements.setIdTokenHintSubject("sub");
    return requirements;
  }

  @SuppressWarnings("unchecked")
  private static <T extends Serializable> T roundTrip(final T object) throws Exception {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(object);
    }
    try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }

}
