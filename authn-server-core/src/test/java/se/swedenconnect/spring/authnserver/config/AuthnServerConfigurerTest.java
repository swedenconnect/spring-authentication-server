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
package se.swedenconnect.spring.authnserver.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.Mockito.mock;

import jakarta.annotation.Nonnull;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.authentication.provider.AbstractUserAuthenticationProvider;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryBackend;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.ConfigurableRequesterAcceptance;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;
import se.swedenconnect.spring.authnserver.sso.SsoPolicy;
import se.swedenconnect.spring.authnserver.subject.AbstractSubjectIdentifierGenerator;

/**
 * Test cases for {@link AuthnServerConfigurer} and {@link AbstractProtocolConfigurer}.
 *
 * @author Martin Lindström
 */
class AuthnServerConfigurerTest {

  private static final String BASE_URL = "https://idp.example.com/auth";

  /** A protocol configurer with one endpoint. */
  static class TestProtocolConfigurer extends AbstractProtocolConfigurer<TestProtocolConfigurer> {

    boolean initialized = false;

    boolean configured = false;

    private RequestMatcher matcher;

    TestProtocolConfigurer() {
      super("/test");
    }

    @Override
    public @Nonnull AuthenticationProtocol getProtocol() {
      return AuthenticationProtocol.SAML;
    }

    @Override
    protected void init(final @Nonnull HttpSecurity http) {
      this.initialized = true;
      this.matcher = PathPatternRequestMatcher.pathPattern(this.getEndpointPath("/endpoint"));
    }

    @Override
    protected void configure(final @Nonnull HttpSecurity http) {
      this.configured = true;
    }

    @Override
    protected @Nonnull RequestMatcher getRequestMatcher() {
      return this.matcher;
    }
  }

  /** A provider for checking the single sign-on policies. */
  static class TestProvider extends AbstractUserAuthenticationProvider {

    @Override
    public @Nonnull String getName() {
      return "test";
    }

    @Override
    public @Nonnull List<String> getSupportedAuthnContextUris() {
      return List.of();
    }

    @Override
    protected @Nonnull Authentication authenticate(final @Nonnull UserAuthenticationInputToken token,
        final @Nonnull List<String> authnContextUris) {
      throw new UnsupportedOperationException();
    }
  }

  @Test
  void theDefaultsApply() {
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer();
    assertThat(configurer.getBaseUrl()).isNull();
    assertThat(configurer.getClockSkew()).isEqualTo(Duration.ofSeconds(30));
    assertThat(configurer.isSupportsUserMessage()).isFalse();
    assertThat(configurer.getSubjectIdentifierSecret()).isNull();
    assertThat(configurer.getSubjectIdentifierHashAlgorithm())
        .isEqualTo(AbstractSubjectIdentifierGenerator.DEFAULT_HASH_ALGORITHM);
    assertThat(configurer.getAuthnFlowMaxAge()).isEqualTo(Duration.ofMinutes(30));
    assertThat(configurer.getSsoPolicy().isEnabled()).isTrue();
    assertThat(configurer.getSsoPolicy().getTimeLimit()).isEqualTo(SsoPolicy.DEFAULT_TIME_LIMIT);
  }

  @Test
  void theBaseUrlIsRequired() {
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer();
    assertThatIllegalArgumentException().isThrownBy(() -> configurer.init(mock(HttpSecurity.class)))
        .withMessageContaining("Missing base URL")
        .withMessageContaining("authn-server.base-url");
  }

  @Test
  void anInvalidBaseUrlIsRejected() {
    for (final String url : List.of("https://idp.example.com/", "ftp://idp.example.com", "not a url",
        "https://idp.example.com?a=b")) {
      final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(url);
      assertThatIllegalArgumentException().as(url).isThrownBy(() -> configurer.init(mock(HttpSecurity.class)));
    }
  }

  @Test
  void invalidSharedValuesAreRejected() {
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .clockSkew(Duration.ofSeconds(-1)).init(mock(HttpSecurity.class)));
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .subjectIdentifierHashAlgorithm("NO-SUCH-ALG").init(mock(HttpSecurity.class)));
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .subjectIdentifierSecret(new byte[0]).init(mock(HttpSecurity.class)));
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .authnFlowMaxAge(Duration.ZERO).init(mock(HttpSecurity.class)));
  }

  @Test
  void theProtocolConfigurersAreInitializedAndConfigured() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer();
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(protocol);
    final HttpSecurity http = mock(HttpSecurity.class);

    configurer.init(http);
    assertThat(protocol.initialized).isTrue();
    configurer.configure(http);
    assertThat(protocol.configured).isTrue();

    assertThat(protocol.getEndpointPath("/endpoint")).isEqualTo("/test/endpoint");
    assertThat(protocol.getEndpointUrl("/endpoint")).isEqualTo(BASE_URL + "/test/endpoint");
  }

  @Test
  void theEndpointsMatcherMatchesTheProtocolEndpoints() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer();
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(protocol);
    final RequestMatcher matcher = configurer.getEndpointsMatcher();

    assertThatIllegalStateException().isThrownBy(() -> matcher.matches(request("/test/endpoint")));

    configurer.init(mock(HttpSecurity.class));
    assertThat(matcher.matches(request("/test/endpoint"))).isTrue();
    assertThat(matcher.matches(request("/other"))).isFalse();
  }

  @Test
  void changingTheProtocolPathMovesTheEndpoints() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer().path("/moved");
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(protocol);
    configurer.init(mock(HttpSecurity.class));

    assertThat(configurer.getEndpointsMatcher().matches(request("/moved/endpoint"))).isTrue();
    assertThat(configurer.getEndpointsMatcher().matches(request("/test/endpoint"))).isFalse();
    assertThat(protocol.getEndpointUrl("/endpoint")).isEqualTo(BASE_URL + "/moved/endpoint");
  }

  @Test
  void anEmptyProtocolPathPlacesTheEndpointsUnderTheBaseUrl() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer().path("");
    new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(protocol).init(mock(HttpSecurity.class));
    assertThat(protocol.getEndpointUrl("/endpoint")).isEqualTo(BASE_URL + "/endpoint");
  }

  @Test
  void anInvalidProtocolPathIsRejected() {
    for (final String path : List.of("test", "/test/")) {
      final AuthnServerConfigurer configurer =
          new AuthnServerConfigurer().baseUrl(BASE_URL).protocol(new TestProtocolConfigurer().path(path));
      assertThatIllegalArgumentException().as(path).isThrownBy(() -> configurer.init(mock(HttpSecurity.class)));
    }
  }

  @Test
  void withoutProtocolsTheEndpointsMatcherMatchesNothing() {
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL);
    configurer.init(mock(HttpSecurity.class));
    assertThat(configurer.getEndpointsMatcher().matches(request("/test/endpoint"))).isFalse();
  }

  @Test
  void theSharedValuesApplyWhenTheProtocolHasNoValueOfItsOwn() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer();
    final SsoPolicy shared = SsoPolicy.none();
    new AuthnServerConfigurer()
        .baseUrl(BASE_URL)
        .ssoPolicy(shared)
        .clockSkew(Duration.ofSeconds(10))
        .supportsUserMessage(true)
        .subjectIdentifierSecret("shared".getBytes(StandardCharsets.UTF_8))
        .subjectIdentifierHashAlgorithm("SHA-512")
        .protocol(protocol);

    assertThat(protocol.getSsoPolicy()).isSameAs(shared);
    assertThat(protocol.getClockSkew()).isEqualTo(Duration.ofSeconds(10));
    assertThat(protocol.isSupportsUserMessage()).isTrue();
    assertThat(protocol.getSubjectIdentifierSecret()).isEqualTo("shared".getBytes(StandardCharsets.UTF_8));
    assertThat(protocol.getSubjectIdentifierHashAlgorithm()).isEqualTo("SHA-512");
  }

  @Test
  void aProtocolValueWinsOverTheSharedValue() {
    final SsoPolicy own = SsoPolicy.forSessionLifetime();
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer()
        .ssoPolicy(own)
        .clockSkew(Duration.ofSeconds(5))
        .supportsUserMessage(false)
        .subjectIdentifierSecret("protocol".getBytes(StandardCharsets.UTF_8))
        .subjectIdentifierHashAlgorithm("SHA-384");
    new AuthnServerConfigurer()
        .baseUrl(BASE_URL)
        .ssoPolicy(SsoPolicy.none())
        .clockSkew(Duration.ofSeconds(10))
        .supportsUserMessage(true)
        .subjectIdentifierSecret("shared".getBytes(StandardCharsets.UTF_8))
        .protocol(protocol);

    assertThat(protocol.getSsoPolicy()).isSameAs(own);
    assertThat(protocol.getClockSkew()).isEqualTo(Duration.ofSeconds(5));
    assertThat(protocol.isSupportsUserMessage()).isFalse();
    assertThat(protocol.getSubjectIdentifierSecret()).isEqualTo("protocol".getBytes(StandardCharsets.UTF_8));
    assertThat(protocol.getSubjectIdentifierHashAlgorithm()).isEqualTo("SHA-384");
  }

  @Test
  void invalidProtocolValuesAreRejected() {
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .protocol(new TestProtocolConfigurer().clockSkew(Duration.ofSeconds(-1))).init(mock(HttpSecurity.class)));
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .protocol(new TestProtocolConfigurer().subjectIdentifierHashAlgorithm("NO-SUCH-ALG"))
        .init(mock(HttpSecurity.class)));
    assertThatIllegalArgumentException().isThrownBy(() -> new AuthnServerConfigurer().baseUrl(BASE_URL)
        .protocol(new TestProtocolConfigurer().subjectIdentifierSecret(new byte[0]))
        .init(mock(HttpSecurity.class)));
  }

  @Test
  void theSsoPoliciesAreGivenToTheProviders() {
    final TestProvider provider = new TestProvider();
    final SsoPolicy samlPolicy = SsoPolicy.forSessionLifetime();
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
        .baseUrl(BASE_URL)
        .ssoPolicy(SsoPolicy.none())
        .authenticationProvider(provider)
        .protocol(new TestProtocolConfigurer().ssoPolicy(samlPolicy));
    configurer.init(mock(HttpSecurity.class));

    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML)).isSameAs(samlPolicy);
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.OIDC).isEnabled()).isFalse();

    final SsoPolicy own = SsoPolicy.defaultPolicy();
    provider.setSsoPolicy(own);
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML)).isSameAs(own);
  }

  @Test
  void theSharedSsoPolicyAppliesWhenTheProtocolHasNone() {
    final TestProvider provider = new TestProvider();
    final SsoPolicy shared = SsoPolicy.none();
    new AuthnServerConfigurer()
        .baseUrl(BASE_URL)
        .ssoPolicy(shared)
        .authenticationProvider(provider)
        .protocol(new TestProtocolConfigurer())
        .init(mock(HttpSecurity.class));
    assertThat(provider.getSsoPolicy(AuthenticationProtocol.SAML)).isSameAs(shared);
  }

  @Test
  void protocolConfigurersAreReachedByType() {
    final TestProtocolConfigurer protocol = new TestProtocolConfigurer();
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().protocol(protocol);

    assertThat(configurer.getProtocolConfigurer(TestProtocolConfigurer.class)).isSameAs(protocol);
    assertThat(configurer.getProtocolConfigurers()).containsExactly(protocol);

    configurer.protocol(TestProtocolConfigurer.class, c -> c.path("/customized"));
    assertThat(protocol.getPath()).isEqualTo("/customized");

    final TestProtocolConfigurer replacement = new TestProtocolConfigurer();
    configurer.protocol(replacement);
    assertThat(configurer.getProtocolConfigurers()).containsExactly(replacement);
  }

  @Test
  void customizingAnUnregisteredProtocolFails() {
    assertThatIllegalStateException().isThrownBy(
        () -> new AuthnServerConfigurer().protocol(TestProtocolConfigurer.class, c -> c.path("/x")));
    assertThat(new AuthnServerConfigurer().getProtocolConfigurer(TestProtocolConfigurer.class)).isNull();
  }

  @Test
  void anUnregisteredProtocolConfigurerHasNoServer() {
    assertThatIllegalStateException().isThrownBy(() -> new TestProtocolConfigurer().getServer());
  }

  @Test
  void theClientRegistryIsBuiltFromTheBackends() throws Exception {
    final RequesterRecord record = new RequesterRecord(
        new Requester(AuthenticationProtocol.SAML, "https://sp"), List.of(), List.of(), Set.of(), "md");
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .clientRegistryBackend(backend(record));
    assertThatIllegalStateException().isThrownBy(configurer::getClientRegistry);

    configurer.init(mock(HttpSecurity.class));
    assertThat(configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, "https://sp")).isSameAs(record);
    assertThat(configurer.getClientRegistry().lookup(AuthenticationProtocol.SAML, "https://other")).isNull();
  }

  @Test
  void anAssignedClientRegistryIsUsed() {
    final ClientRegistry registry = mock(ClientRegistry.class);
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .clientRegistry(registry)
        .protocol(new BackendRequiringProtocolConfigurer());
    configurer.init(mock(HttpSecurity.class));
    assertThat(configurer.getClientRegistry()).isSameAs(registry);
  }

  @Test
  void aProtocolThatNeedsABackendFailsWithoutOne() {
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer().baseUrl(BASE_URL)
        .protocol(new BackendRequiringProtocolConfigurer());
    assertThatIllegalArgumentException().isThrownBy(() -> configurer.init(mock(HttpSecurity.class)))
        .withMessageContaining("No client registry backend for SAML requesters");

    configurer.clientRegistryBackend(backend(null));
    configurer.init(mock(HttpSecurity.class));
  }

  @Test
  void theRequesterAcceptanceDefaultsToAcceptAll() {
    final AuthnServerConfigurer configurer = new AuthnServerConfigurer();
    assertThat(configurer.getRequesterAcceptance()).isSameAs(RequesterAcceptance.acceptAll());

    final ConfigurableRequesterAcceptance configurable = configurer.configurableRequesterAcceptance();
    assertThat(configurer.configurableRequesterAcceptance()).isSameAs(configurable);
    assertThat(configurer.getRequesterAcceptance()).isSameAs(configurable);

    configurer.requesterAcceptance((record, registry) -> false);
    assertThatIllegalStateException().isThrownBy(configurer::configurableRequesterAcceptance);
  }

  /** A protocol configurer that needs a client registry backend. */
  static class BackendRequiringProtocolConfigurer extends TestProtocolConfigurer {

    @Override
    protected boolean requiresClientRegistryBackend() {
      return true;
    }
  }

  private static ClientRegistryBackend backend(final RequesterRecord record) {
    return new ClientRegistryBackend() {

      @Override
      public @Nonnull String getName() {
        return "test";
      }

      @Override
      public @Nonnull AuthenticationProtocol getProtocol() {
        return AuthenticationProtocol.SAML;
      }

      @Override
      public RequesterRecord lookup(final @Nonnull String identifier) {
        return record != null && record.getIdentifier().equals(identifier) ? record : null;
      }
    };
  }

  private static MockHttpServletRequest request(final String path) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    return request;
  }

}
