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
package se.swedenconnect.spring.authnserver.autoconfigure.storage;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.storage.ReplayCache;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.session.autoconfigure.SessionAutoConfiguration;
import org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurer;
import se.swedenconnect.spring.authnserver.config.AuthnServerConfigurerAdapter;
import se.swedenconnect.spring.authnserver.oidc.client.federation.CachedClientRecord;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.RedisFederationCache;
import se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarks;
import se.swedenconnect.spring.authnserver.oidc.federation.RedisProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenData;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeData;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.oidc.token.InMemoryAccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisAccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisAuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay.RedisReplayCache;

/**
 * Tests for {@link AuthnServerStorageAutoConfiguration}, against a Redis container.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class AuthnServerStorageAutoConfigurationTest {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, DataRedisAutoConfiguration.class, SessionAutoConfiguration.class,
          SessionDataRedisAutoConfiguration.class, SamlAutoConfiguration.class, OidcAutoConfiguration.class,
          AuthnServerAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class))
      .withPropertyValues(StorageTestProperties.SERVER)
      .withPropertyValues("spring.data.redis.host=" + REDIS.getHost(),
          "spring.data.redis.port=" + REDIS.getFirstMappedPort());

  /** Captures the configurer. */
  @Configuration
  static class CaptureConfiguration {

    static final AtomicReference<AuthnServerConfigurer> CONFIGURER = new AtomicReference<>();

    @Bean
    @Order(10)
    AuthnServerConfigurerAdapter captureAdapter() {
      return (http, configurer) -> CONFIGURER.set(configurer);
    }
  }

  @BeforeEach
  void flush() {
    final LettuceConnectionFactory factory =
        new LettuceConnectionFactory(REDIS.getHost(), REDIS.getFirstMappedPort());
    factory.afterPropertiesSet();
    factory.start();
    try {
      new StringRedisTemplate(factory).execute(c -> {
        c.serverCommands().flushAll();
        return null;
      }, true);
    }
    finally {
      factory.destroy();
    }
  }

  @Test
  void withTheDefaultNothingIsKeptInRedis() {
    this.runner.withUserConfiguration(CaptureConfiguration.class)
        .withConfiguration(AutoConfigurations.of(SessionAutoConfiguration.class))
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(RedisStorage.class);
          assertThat(context).doesNotHaveBean(ReplayCache.class);
          assertThat(context).doesNotHaveBean(AuthorizationCodeStore.class);
          assertThat(context).doesNotHaveBean(AccessTokenStore.class);
          assertThat(context).doesNotHaveBean(ClientAssertionReplayCache.class);
          assertThat(context).doesNotHaveBean(ProviderTrustMarkStore.class);
          assertThat(context).getBean(FederationCache.class).isInstanceOf(InMemoryFederationCache.class);
          assertThat(oidc().getAccessTokenStore().getClass().getSimpleName()).isEqualTo("InMemoryAccessTokenStore");
        });
  }

  @Test
  void withRedisEveryStoreAndTheSessionAreKeptInRedis() {
    this.runner.withUserConfiguration(CaptureConfiguration.class)
        .withPropertyValues("authn-server.storage.type=redis")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(ReplayCache.class).isInstanceOf(RedisReplayCache.class);
          assertThat(context).getBean(AuthorizationCodeStore.class).isInstanceOf(RedisAuthorizationCodeStore.class);
          assertThat(context).getBean(AccessTokenStore.class).isInstanceOf(RedisAccessTokenStore.class);
          assertThat(context).getBean(ClientAssertionReplayCache.class)
              .isInstanceOf(RedisClientAssertionReplayCache.class);
          assertThat(context).getBean(FederationCache.class).isInstanceOf(RedisFederationCache.class);
          assertThat(context).getBean(ProviderTrustMarkStore.class).isInstanceOf(RedisProviderTrustMarkStore.class);
          assertThat(context).getBean(SessionRepository.class).isInstanceOf(RedisSessionRepository.class);
          assertThat(oidc().getAccessTokenStore()).isSameAs(context.getBean(AccessTokenStore.class));

          // Everything is written under the key prefix
          context.getBean(AccessTokenStore.class).save(token("t1"));
          final Session session = createSession(context);
          final StringRedisTemplate redis = template(context);
          assertThat(redis.keys("*")).allMatch(k -> k.startsWith("authn-server:"))
              .contains("authn-server:oidc:access-token:t1", "authn-server:sessions:" + session.getId());
        });
  }

  @Test
  void theKeyPrefixIsConfigurable() {
    this.runner.withPropertyValues("authn-server.storage.type=redis", "authn-server.redis.key-prefix=other")
        .run(context -> {
          assertThat(context).hasNotFailed();
          context.getBean(AccessTokenStore.class).save(token("t1"));
          final Session session = createSession(context);
          assertThat(template(context).keys("*")).allMatch(k -> k.startsWith("other:"))
              .contains("other:oidc:access-token:t1", "other:sessions:" + session.getId());
        });
  }

  @Test
  void anAssignedSessionNamespaceIsKept() {
    this.runner.withPropertyValues("authn-server.storage.type=redis", "spring.session.data.redis.namespace=sess")
        .run(context -> {
          assertThat(context).hasNotFailed();
          final Session session = createSession(context);
          assertThat(template(context).keys("*")).contains("sess:sessions:" + session.getId());
        });
  }

  @Test
  void theServerSetsUpTheSessionWhenSpringBootDoesNot() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, DataRedisAutoConfiguration.class, SamlAutoConfiguration.class,
            OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class,
            AuthnServerStorageAutoConfiguration.class))
        .withClassLoader(new FilteredClassLoader("org.springframework.boot.session."))
        .withPropertyValues(StorageTestProperties.SERVER)
        .withPropertyValues("spring.data.redis.host=" + REDIS.getHost(),
            "spring.data.redis.port=" + REDIS.getFirstMappedPort(), "authn-server.storage.type=redis")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(SessionRepository.class).isInstanceOf(RedisSessionRepository.class);
          assertThat(context).hasBean("springSessionRepositoryFilter");
          final Session session = createSession(context);
          assertThat(template(context).keys("*")).contains("authn-server:sessions:" + session.getId());
        });
  }

  @Test
  void aStoreOverriddenToRedisIsTheOnlyOneInRedis() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, DataRedisAutoConfiguration.class, SamlAutoConfiguration.class,
            OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class,
            AuthnServerStorageAutoConfiguration.class))
        .withClassLoader(new FilteredClassLoader("org.springframework.session."))
        .withPropertyValues(StorageTestProperties.SERVER)
        .withPropertyValues("spring.data.redis.host=" + REDIS.getHost(),
            "spring.data.redis.port=" + REDIS.getFirstMappedPort(), "authn-server.oidc.storage.access-tokens=redis")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(AccessTokenStore.class).isInstanceOf(RedisAccessTokenStore.class);
          assertThat(context).doesNotHaveBean(AuthorizationCodeStore.class);
          assertThat(context).doesNotHaveBean(ReplayCache.class);
          assertThat(context).getBean(FederationCache.class).isInstanceOf(InMemoryFederationCache.class);
          assertThat(context).doesNotHaveBean(SessionRepository.class);
        });
  }

  @Test
  void aStoreOverriddenToMemoryStaysInMemory() {
    this.runner.withPropertyValues("authn-server.storage.type=redis", "authn-server.saml.replay.type=memory",
            "authn-server.oidc.storage.authorization-codes=MEMORY", "authn-server.oidc.storage.trust-marks=memory",
            "authn-server.oidc.storage.federation-cache=memory")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(ReplayCache.class);
          assertThat(context).doesNotHaveBean(AuthorizationCodeStore.class);
          assertThat(context).doesNotHaveBean(ProviderTrustMarkStore.class);
          assertThat(context).getBean(FederationCache.class).isInstanceOf(InMemoryFederationCache.class);
          assertThat(context).getBean(AccessTokenStore.class).isInstanceOf(RedisAccessTokenStore.class);
          assertThat(context).getBean(SessionRepository.class).isInstanceOf(RedisSessionRepository.class);
        });
  }

  @Test
  void aStoreBeanOfTheApplicationIsKept() {
    final AccessTokenStore own = new InMemoryAccessTokenStore();
    this.runner.withPropertyValues("authn-server.storage.type=redis")
        .withBean(AccessTokenStore.class, () -> own)
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).getBean(AccessTokenStore.class).isSameAs(own);
        });
  }

  @Test
  void twoInstancesSharingRedisSeeTheSameState() {
    this.runner.withPropertyValues("authn-server.storage.type=redis").run(first -> {
      assertThat(first).hasNotFailed();
      this.runner.withPropertyValues("authn-server.storage.type=redis").run(second -> {
        assertThat(second).hasNotFailed();

        first.getBean(AuthorizationCodeStore.class).save(code("c1"));
        assertThat(second.getBean(AuthorizationCodeStore.class).redeem("c1").replay()).isFalse();
        assertThat(first.getBean(AuthorizationCodeStore.class).redeem("c1").replay()).isTrue();

        final AccessTokenData token = token("t1");
        first.getBean(AccessTokenStore.class).save(token);
        assertThat(second.getBean(AccessTokenStore.class).get("t1")).isEqualTo(token);

        assertThat(first.getBean(ReplayCache.class).check("ctx", "_id", Instant.now().plusSeconds(60))).isTrue();
        assertThat(second.getBean(ReplayCache.class).check("ctx", "_id", Instant.now().plusSeconds(60))).isFalse();

        final Instant expiresAt = Instant.now().plusSeconds(60);
        assertThat(first.getBean(ClientAssertionReplayCache.class).register("rp", "jti", expiresAt)).isTrue();
        assertThat(second.getBean(ClientAssertionReplayCache.class).register("rp", "jti", expiresAt)).isFalse();

        first.getBean(FederationCache.class)
            .put(CachedClientRecord.notFound("rp", Instant.now(), Duration.ofMinutes(1)));
        assertThat(second.getBean(FederationCache.class).get("rp")).isNotNull();

        first.getBean(ProviderTrustMarkStore.class).put("type", ProviderTrustMarkStore.Entry.EMPTY
            .failed("down", Instant.now(), Instant.now().plusSeconds(60)));
        assertThat(second.getBean(ProviderTrustMarks.class).getStates()).isNotEmpty();
        assertThat(second.getBean(ProviderTrustMarkStore.class).get("type").failures()).isEqualTo(1);

        final Session session = createSession(first);
        assertThat(second.getBean(SessionRepository.class).findById(session.getId())).isNotNull();
      });
    });
  }

  @Test
  void redisThatCannotBeReachedFailsStartup() {
    this.runner.withPropertyValues("authn-server.storage.type=redis", "spring.data.redis.port=1",
            "spring.data.redis.connect-timeout=1s")
        .run(context -> assertThat(context).hasFailed().getFailure()
            .hasStackTraceContaining(
                "authn-server.storage.type is set to 'redis', but the Redis connection does not work"));
  }

  private static OidcProviderConfigurer oidc() {
    return CaptureConfiguration.CONFIGURER.get().getProtocolConfigurer(OidcProviderConfigurer.class);
  }

  @SuppressWarnings("unchecked")
  private static Session createSession(final AssertableWebApplicationContext context) {
    final SessionRepository<Session> repository = context.getBean(SessionRepository.class);
    final Session session = repository.createSession();
    session.setAttribute("a", "b");
    repository.save(session);
    return session;
  }

  private static StringRedisTemplate template(final AssertableWebApplicationContext context) {
    return new StringRedisTemplate(context.getBean(RedisConnectionFactory.class));
  }

  private static AccessTokenData token(final String value) {
    final Instant now = Instant.parse("2026-10-01T10:00:00Z");
    return new AccessTokenData(value, "rp", "sub", List.of("openid"), "{}", now, Instant.now().plusSeconds(300),
        false, null);
  }

  private static AuthorizationCodeData code(final String code) {
    final Instant now = Instant.now();
    return new AuthorizationCodeData(code, "rp", "https://rp.example.com/cb", null, null, null, List.of("openid"),
        "sub", now, "http://id.elegnamnden.se/loa/1.0/loa3", "{}", "{}", now, now.plusSeconds(60),
        now.plusSeconds(300), null);
  }

}
