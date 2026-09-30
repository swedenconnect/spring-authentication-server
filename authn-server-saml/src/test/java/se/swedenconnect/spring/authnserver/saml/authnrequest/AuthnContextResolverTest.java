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
package se.swedenconnect.spring.authnserver.saml.authnrequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.core.StatusCode;

import se.swedenconnect.opensaml.saml2.core.build.RequestedAuthnContextBuilder;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;

/**
 * Tests for {@link AuthnContextResolver}.
 *
 * @author Martin Lindström
 */
class AuthnContextResolverTest extends OpenSamlTestBase {

  private static final String LOA2 = "http://id.elegnamnden.se/loa/1.0/loa2";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  @Test
  void nothingRequestedGivesNothing() {
    assertThat(new AuthnContextResolver().resolve(null, "log")).isEmpty();
  }

  @Test
  void exactComparisonGivesTheRequestedUris() {
    assertThat(new AuthnContextResolver().resolve(request(AuthnContextComparisonTypeEnumeration.EXACT, LOA3, LOA4),
        "log")).containsExactly(LOA3, LOA4);
    assertThat(new AuthnContextResolver().resolve(request(null, LOA3), "log")).containsExactly(LOA3);
  }

  @Test
  void otherComparisonsNeedAMapping() {
    for (final AuthnContextComparisonTypeEnumeration c : List.of(AuthnContextComparisonTypeEnumeration.MINIMUM,
        AuthnContextComparisonTypeEnumeration.BETTER, AuthnContextComparisonTypeEnumeration.MAXIMUM)) {
      assertThatThrownBy(() -> new AuthnContextResolver().resolve(request(c, LOA3), "log"))
          .isInstanceOfSatisfying(SamlErrorStatusException.class,
              e -> assertThat(e.getStatus().subStatusCode()).isEqualTo(StatusCode.REQUEST_UNSUPPORTED));
    }
  }

  @Test
  void theMappingsResolveTheRequestedUris() {
    final AuthnContextResolver resolver = new AuthnContextResolver();
    resolver.setMinimumMapping(Map.of(LOA2, List.of(LOA2, LOA3, LOA4), LOA3, List.of(LOA3, LOA4)));
    resolver.setBetterMapping(Map.of(LOA2, List.of(LOA3, LOA4), LOA3, List.of(LOA4)));
    resolver.setMaximumMapping(Map.of(LOA4, List.of(LOA2, LOA3, LOA4)));

    assertThat(resolver.resolve(request(AuthnContextComparisonTypeEnumeration.MINIMUM, LOA3), "log"))
        .containsExactly(LOA3, LOA4);
    assertThat(resolver.resolve(request(AuthnContextComparisonTypeEnumeration.BETTER, LOA2, LOA3), "log"))
        .containsExactly(LOA4);
    assertThat(resolver.resolve(request(AuthnContextComparisonTypeEnumeration.MAXIMUM, LOA4), "log"))
        .containsExactly(LOA2, LOA3);
  }

  @Test
  void aUriWithoutMappingIsAnError() {
    final AuthnContextResolver resolver = new AuthnContextResolver();
    resolver.setMinimumMapping(Map.of(LOA3, List.of(LOA3, LOA4)));
    assertThatThrownBy(() -> resolver.resolve(request(AuthnContextComparisonTypeEnumeration.MINIMUM, LOA2), "log"))
        .isInstanceOf(SamlErrorStatusException.class);
  }

  private static RequestedAuthnContext request(final AuthnContextComparisonTypeEnumeration comparison,
      final String... uris) {
    return RequestedAuthnContextBuilder.builder().comparison(comparison).authnContextClassRefs(uris).build();
  }

}
