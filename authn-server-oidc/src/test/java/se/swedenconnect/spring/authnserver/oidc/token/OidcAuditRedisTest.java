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
package se.swedenconnect.spring.authnserver.oidc.token;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.Filter;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.security.credential.PkiCredential;
import se.swedenconnect.spring.audit.AuditApplicationListener;
import se.swedenconnect.spring.audit.AuditEvent;
import se.swedenconnect.spring.audit.tracing.CorrelationIDHolder;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.redirect.RedirectForAuthenticationToken;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.oidc.RedisTestNodes;
import se.swedenconnect.spring.authnserver.oidc.audit.AuditCollector;
import se.swedenconnect.spring.authnserver.oidc.client.ConfigurationClientBackend;
import se.swedenconnect.spring.authnserver.oidc.client.OidcClientRecord;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.keys.KeyTestSupport;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;

/**
 * Tests that one authentication flow, handled by two server instances that share the session, the authorization codes
 * and the access tokens in Redis, is audited under one correlation ID.
 * <p>
 * The session is moved between the instances by Java serialization, as a session kept in Redis is.
 * </p>
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class OidcAuditRedisTest {

  private static final String BASE_URL = "https://op.example.com";

  private static final String CLIENT = "https://rsa.example.com";

  private static final String REDIRECT_URI = "https://rp.example.com/callback";

  private static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  private static final String AUTHN_PATH = "/authn/login";

  private static final String RESUME_PATH = "/authn/resume";

  private static final PkiCredential OP_RSA = KeyTestSupport.rsa("op-rsa", 2048);

  private static final PkiCredential CLIENT_RSA = KeyTestSupport.rsa("client-rsa", 2048);

  @Container
  private static final GenericContainer<?> REDIS = RedisTestNodes.container();

  private static LettuceConnectionFactory redisA;

  private static LettuceConnectionFactory redisB;

  /** The Redis connection of the instance being created. */
  private static StringRedisTemplate currentRedis;

  /** The provider of the instance being created. */
  private static OidcCodeFlowTest.TestRedirectProvider currentProvider;

  private final List<AnnotationConfigWebApplicationContext> contexts = new ArrayList<>();

  @Configuration
  @EnableWebSecurity
  static class InstanceConfiguration {

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http) throws Exception {
      final StringRedisTemplate redis = currentRedis;
      final OIDCClientMetadata metadata = new OIDCClientMetadata();
      metadata.setRedirectionURI(URI.create(REDIRECT_URI));
      metadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
      metadata.setJWKSet(new JWKSet(
          new RSAKey.Builder((RSAPublicKey) CLIENT_RSA.getPublicKey()).keyID("rsa-key").build()));

      final AuthnServerConfigurer configurer = new AuthnServerConfigurer()
          .baseUrl(BASE_URL)
          .clientRegistryBackend(new ConfigurationClientBackend(List.of(OidcClientRecord.of(CLIENT, metadata))))
          .authenticationProvider(currentProvider)
          .protocol(new OidcProviderConfigurer()
              .signingKeys(List.of(SigningKey.activeDefault(OP_RSA)))
              .scopes(List.of("openid", "profile"))
              .authnRequestProcessor(c -> c
                  .authorizationCodeStore(new RedisAuthorizationCodeStore(redis))
                  .accessTokenStore(new RedisAccessTokenStore(redis))));
      AuthnServerConfigurer.applyDefaultSecurity(http, configurer);
      return http.build();
    }

    @Bean
    AuditApplicationListener auditApplicationListener(final ApplicationContext context) {
      return AuditCollector.listener(context);
    }

    @Bean
    AuditCollector auditCollector() {
      return new AuditCollector();
    }
  }

  @BeforeAll
  static void init() {
    redisA = RedisTestNodes.connect(REDIS);
    redisB = RedisTestNodes.connect(REDIS);
  }

  @AfterAll
  static void close() {
    redisA.destroy();
    redisB.destroy();
  }

  @AfterEach
  void closeContexts() {
    this.contexts.forEach(AnnotationConfigWebApplicationContext::close);
  }

  @Test
  void aFlowHandledByTwoInstancesIsAuditedUnderOneCorrelationId() throws Exception {
    final OidcCodeFlowTest.TestRedirectProvider providerA = new OidcCodeFlowTest.TestRedirectProvider(LOA3);
    final OidcCodeFlowTest.TestRedirectProvider providerB = new OidcCodeFlowTest.TestRedirectProvider(LOA3);
    final AnnotationConfigWebApplicationContext instanceA = this.start(redisA, providerA);
    final AnnotationConfigWebApplicationContext instanceB = this.start(redisB, providerB);

    // Instance A receives the request and sends the user to the module ...
    MockHttpSession session = new MockHttpSession();
    final MockHttpServletRequest authorize = new MockHttpServletRequest("GET", "/oidc/authorize");
    Map.of("client_id", CLIENT, "response_type", "code", "scope", "openid", "redirect_uri", REDIRECT_URI,
        "state", "state-1").forEach(authorize::addParameter);
    final MockHttpServletResponse redirect = send(instanceA, authorize, session, new MockFilterChain());
    final String authnId = redirect.getRedirectedUrl().substring(redirect.getRedirectedUrl().indexOf('=') + 1);
    assertThat(CorrelationIDHolder.get()).isNull();

    // ... whose pages are served by instance B ...
    session = transfer(session);
    final AtomicReference<String> moduleCorrelationId = new AtomicReference<>();
    send(instanceB, appRequest(AUTHN_PATH, authnId), session, new MockFilterChain(new HttpServlet() {
      @Override
      protected void service(final HttpServletRequest request, final HttpServletResponse response) {
        moduleCorrelationId.set(CorrelationIDHolder.get().getValue());
      }
    }));
    final MockHttpServletRequest completion = appRequest(AUTHN_PATH, authnId);
    completion.setSession(session);
    providerB.getAuthenticatorRepository().complete(new UserAuthentication(user()), completion);

    // ... and B resumes the flow and issues the code
    session = transfer(session);
    final MockHttpServletResponse resumed = send(instanceB, appRequest(RESUME_PATH, authnId), session,
        new MockFilterChain());
    final String code = UriComponentsBuilder.fromUriString(resumed.getRedirectedUrl()).build()
        .getQueryParams().getFirst("code");
    assertThat(code).isNotNull();

    // The client redeems the code at instance A, and calls UserInfo at instance B
    final MockHttpServletRequest token = new MockHttpServletRequest("POST", "/oidc/token");
    token.setScheme("https");
    token.setServerName("op.example.com");
    token.setServerPort(443);
    token.setContentType("application/x-www-form-urlencoded");
    Map.of("grant_type", "authorization_code", "code", code, "redirect_uri", REDIRECT_URI,
        "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion", clientAssertion()).forEach(token::addParameter);
    final MockHttpServletResponse tokenResponse = send(instanceA, token, new MockHttpSession(), new MockFilterChain());
    assertThat(tokenResponse.getStatus()).as(tokenResponse.getContentAsString()).isEqualTo(200);
    final String accessToken =
        (String) JSONObjectUtils.parse(tokenResponse.getContentAsString()).get("access_token");

    final MockHttpServletRequest userInfo = new MockHttpServletRequest("GET", "/oidc/userinfo");
    userInfo.addHeader("Authorization", "Bearer " + accessToken);
    assertThat(send(instanceB, userInfo, new MockHttpSession(), new MockFilterChain()).getStatus()).isEqualTo(200);
    assertThat(CorrelationIDHolder.get()).isNull();

    // Every event, whichever instance produced it, is audited under the same correlation ID
    final List<AuditEvent> eventsA = instanceA.getBean(AuditCollector.class).getEvents();
    final List<AuditEvent> eventsB = instanceB.getBean(AuditCollector.class).getEvents();
    assertThat(eventsA).extracting(AuditEvent::getType)
        .containsExactly("authn_request_received", "authn_request_accepted", "authn_success_response");
    assertThat(eventsB).extracting(AuditEvent::getType)
        .containsExactly("authn_user_authenticated", "authn_authorization_response", "authn_userinfo_delivered");
    final String flow = eventsA.getFirst().getCorrelationId().getValue();
    assertThat(eventsA).allSatisfy(e -> assertThat(e.getCorrelationId().getValue()).isEqualTo(flow));
    assertThat(eventsB).allSatisfy(e -> assertThat(e.getCorrelationId().getValue()).isEqualTo(flow));
    assertThat(moduleCorrelationId.get()).isEqualTo(flow);
    assertThat(eventsB).allSatisfy(e -> assertThat(e.getPrincipal()).isEqualTo(CLIENT));
  }

  private AnnotationConfigWebApplicationContext start(final LettuceConnectionFactory redis,
      final OidcCodeFlowTest.TestRedirectProvider provider) {
    currentRedis = new StringRedisTemplate(redis);
    currentProvider = provider;
    final AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
    context.setServletContext(new MockServletContext());
    context.register(InstanceConfiguration.class);
    context.refresh();
    this.contexts.add(context);
    return context;
  }

  private static MockHttpServletResponse send(final AnnotationConfigWebApplicationContext instance,
      final MockHttpServletRequest request, final MockHttpSession session, final MockFilterChain chain)
      throws Exception {
    request.setSession(session);
    final MockHttpServletResponse response = new MockHttpServletResponse();
    instance.getBean("springSecurityFilterChain", Filter.class).doFilter(request, response, chain);
    return response;
  }

  private static MockHttpServletRequest appRequest(final String path, final String authnId) {
    final MockHttpServletRequest request = new MockHttpServletRequest("GET", path);
    request.setServletPath(path);
    request.addParameter(RedirectForAuthenticationToken.AUTHN_ID_PARAMETER, authnId);
    return request;
  }

  /**
   * Moves a session to another instance, by serializing its attributes as a session kept in Redis is.
   */
  private static MockHttpSession transfer(final MockHttpSession session) throws Exception {
    final MockHttpSession copy = new MockHttpSession(null, session.getId());
    for (final String name : Collections.list(session.getAttributeNames())) {
      final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
      try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
        out.writeObject(session.getAttribute(name));
      }
      try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
        copy.setAttribute(name, in.readObject());
      }
    }
    return copy;
  }

  private static String clientAssertion() throws Exception {
    final Instant now = Instant.now();
    final SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("rsa-key").build(),
        new JWTClaimsSet.Builder()
            .issuer(CLIENT)
            .subject(CLIENT)
            .audience(BASE_URL + "/oidc/token")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(60)))
            .jwtID(UUID.randomUUID().toString())
            .build());
    jwt.sign(new RSASSASigner(CLIENT_RSA.getPrivateKey()));
    return jwt.serialize();
  }

  private static AuthenticatedUser user() {
    return new AuthenticatedUser(List.of(
        GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
        GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Kalle")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, LOA3, Instant.now(), "127.0.0.1");
  }

}
