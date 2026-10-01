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

import java.time.Clock;
import java.util.List;

import org.jspecify.annotations.NonNull;
import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ResourceLoader;
import org.springframework.data.redis.connection.RedisConnection;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.session.SessionRepository;
import org.springframework.session.config.SessionRepositoryCustomizer;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration;
import org.springframework.util.ClassUtils;

import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerConfigurationProperties;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationServiceStateStore;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.InMemoryFederationServiceStateStore;
import se.swedenconnect.spring.authnserver.oidc.client.federation.RedisFederationCache;
import se.swedenconnect.spring.authnserver.oidc.client.federation.RedisFederationServiceStateStore;
import se.swedenconnect.spring.authnserver.oidc.federation.ProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.federation.RedisProviderTrustMarkStore;
import se.swedenconnect.spring.authnserver.oidc.token.AccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.ClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.oidc.token.RedisAccessTokenStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisAuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.oidc.token.RedisClientAssertionReplayCache;
import se.swedenconnect.spring.authnserver.redis.RedisKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientStore;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay.RedisReplayCache;

/**
 * Autoconfiguration of where the server keeps its state: the HTTP session and the stores of the protocols.
 * <p>
 * The shared setting, {@value StorageSettings#SHARED}, chooses "memory" or "redis" for the HTTP session and all
 * stores, and each store may be overridden by a setting of its own, see {@link StorageSettings}. With "memory" nothing
 * is added, and the protocols use their in-memory stores.
 * </p>
 * <p>
 * For each store that is kept in Redis, a bean of the store type is declared, unless the application declares one.
 * When the shared setting is "redis", the HTTP session is kept in Redis by Spring Session, set up by Spring Boot when
 * its session module is present and by this class otherwise, with the key prefix as the default namespace.
 * </p>
 * <p>
 * The record of known clients follows the shared setting. In memory, it and the federation cache are kept in the
 * cache directory, {@code authn-server.cache-directory}, when one is given, so that they survive a restart.
 * </p>
 * <p>
 * Startup fails when something is to be kept in Redis and Spring Data Redis or a working Redis connection is missing,
 * and when the HTTP session is to be kept in Redis and Spring Session for Redis is missing.
 * </p>
 *
 * @author Martin Lindström
 */
@AutoConfiguration(afterName = { "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration",
    "org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration" },
    beforeName = { "se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration",
        "se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration" })
@EnableConfigurationProperties({ AuthnServerRedisProperties.class, AuthnServerConfigurationProperties.class })
@Import(RedisClientConfiguration.class)
public class AuthnServerStorageAutoConfiguration {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnServerStorageAutoConfiguration.class);

  /** The class that tells whether Spring Data Redis is on the classpath. */
  static final String SPRING_DATA_REDIS_CLASS = "org.springframework.data.redis.core.StringRedisTemplate";

  /** The class that tells whether Spring Session for Redis is on the classpath. */
  static final String SPRING_SESSION_REDIS_CLASS = "org.springframework.session.data.redis.RedisSessionRepository";

  /** The Spring Boot autoconfiguration that sets up Spring Session for Redis. */
  static final String BOOT_SESSION_REDIS_AUTOCONFIGURATION =
      "org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration";

  /** The Spring Session property for the namespace. */
  static final String SESSION_NAMESPACE_PROPERTY = "spring.session.data.redis.namespace";

  /**
   * Constructor checking the storage settings, and that the dependencies that they need are on the classpath.
   *
   * @param environment the environment
   * @param resourceLoader gives the class loader of the application
   * @throws IllegalArgumentException for an invalid storage setting
   * @throws IllegalStateException if a dependency is missing
   */
  public AuthnServerStorageAutoConfiguration(final @NonNull Environment environment,
      final @NonNull ResourceLoader resourceLoader) {
    StorageSettings.validate(environment);
    final List<String> redisSettings = StorageSettings.redisSettings(environment);
    if (redisSettings.isEmpty()) {
      return;
    }
    final ClassLoader classLoader = resourceLoader.getClassLoader();
    if (!ClassUtils.isPresent(SPRING_DATA_REDIS_CLASS, classLoader)) {
      throw new IllegalStateException(("%s set to 'redis', but Spring Data Redis is not on the classpath - "
          + "add spring-boot-starter-data-redis").formatted(describe(redisSettings)));
    }
    if (StorageSettings.shared(environment) == StorageType.REDIS
        && !ClassUtils.isPresent(SPRING_SESSION_REDIS_CLASS, classLoader)) {
      throw new IllegalStateException(("%s is 'redis', which keeps the HTTP session in Redis, but Spring Session for "
          + "Redis is not on the classpath - add spring-boot-starter-session-data-redis")
          .formatted(StorageSettings.SHARED));
    }
    log.info("Keeping state in Redis according to {}", redisSettings);
  }

  /**
   * Describes the settings that keep something in Redis, for error messages.
   *
   * @param settings the settings
   * @return a description
   */
  static @NonNull String describe(final @NonNull List<String> settings) {
    return settings.size() == 1 ? settings.getFirst() + " is" : String.join(", ", settings) + " are";
  }

  /**
   * Creates the record of known clients in memory, kept in the cache directory when one is given.
   *
   * @param properties the shared properties
   * @return an {@link InMemoryKnownClientStore}
   */
  @Bean
  @ConditionalOnMissingBean(KnownClientStore.class)
  @ConditionalOnStorageType(StorageType.MEMORY)
  KnownClientStore authnServerKnownClientStore(final AuthnServerConfigurationProperties properties) {
    return new InMemoryKnownClientStore(properties.getCachePath(AuthnServerConfigurationProperties.KNOWN_CLIENTS_FILE));
  }

  /**
   * The record of known clients in Redis.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = SPRING_DATA_REDIS_CLASS)
  @ConditionalOnStorageType(StorageType.REDIS)
  static class RedisKnownClientsConfiguration {

    /**
     * Creates the record of known clients.
     *
     * @param storage the Redis storage
     * @return a {@link RedisKnownClientStore}
     */
    @Bean
    @ConditionalOnMissingBean(KnownClientStore.class)
    KnownClientStore authnServerKnownClientStore(final RedisStorage storage) {
      return new RedisKnownClientStore(storage.getRedisTemplate(), storage.getKeyPrefix());
    }

  }

  /**
   * The Redis connection, when something is kept in Redis.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = SPRING_DATA_REDIS_CLASS)
  @ConditionalOnRedisInUse
  static class RedisConnectionConfiguration {

    /**
     * Creates what the Redis stores are created from, after checking that there is a Redis connection that works.
     *
     * @param connectionFactory the Redis connection factory
     * @param properties the Redis properties of the server
     * @param environment the environment
     * @return a {@link RedisStorage}
     * @throws IllegalStateException if there is no Redis connection, or it does not work
     */
    @Bean
    RedisStorage authnServerRedisStorage(final ObjectProvider<RedisConnectionFactory> connectionFactory,
        final AuthnServerRedisProperties properties, final Environment environment) {
      final String settings = describe(StorageSettings.redisSettings(environment));
      final RedisConnectionFactory factory = connectionFactory.getIfUnique();
      if (factory == null) {
        throw new IllegalStateException(("%s set to 'redis', but there is no Redis connection - add "
            + "spring-boot-starter-data-redis and configure the connection with spring.data.redis.*")
            .formatted(settings));
      }
      try (final RedisConnection connection = factory.getConnection()) {
        connection.ping();
      }
      catch (final RuntimeException e) {
        throw new IllegalStateException("%s set to 'redis', but the Redis connection does not work: %s"
            .formatted(settings, e.getMessage()), e);
      }
      log.info("Using Redis with the key prefix '{}'", properties.getKeyPrefix());
      return new RedisStorage(factory, properties.getKeyPrefix());
    }

  }

  /**
   * The SAML stores in Redis.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = { SPRING_DATA_REDIS_CLASS,
      "se.swedenconnect.spring.authnserver.saml.config.Saml2IdpConfigurer" })
  @ConditionalOnProperty(name = "authn-server.saml.enabled", havingValue = "true")
  static class SamlRedisStorageConfiguration {

    /**
     * Creates the replay cache.
     *
     * @param storage the Redis storage
     * @return a {@link RedisReplayCache}
     */
    @Bean
    @ConditionalOnMissingBean(ReplayCache.class)
    @ConditionalOnStorageType(store = StorageSettings.SAML_REPLAY, value = StorageType.REDIS)
    ReplayCache authnServerSamlReplayCache(final RedisStorage storage) {
      return new RedisReplayCache(storage.getRedisTemplate(), storage.getKeyPrefix());
    }

  }

  /**
   * The OIDC stores.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "se.swedenconnect.spring.authnserver.oidc.config.OidcProviderConfigurer")
  @ConditionalOnProperty(name = "authn-server.oidc.enabled", havingValue = "true")
  static class OidcStorageConfiguration {

    /**
     * Creates the federation cache in memory, for applications that set up the federation backend of the client
     * registry. It is kept in the cache directory when one is given.
     *
     * @param properties the shared properties
     * @return an {@link InMemoryFederationCache}
     */
    @Bean
    @ConditionalOnMissingBean(FederationCache.class)
    @ConditionalOnStorageType(store = StorageSettings.OIDC_FEDERATION_CACHE, value = StorageType.MEMORY)
    FederationCache authnServerFederationCache(final AuthnServerConfigurationProperties properties) {
      return new InMemoryFederationCache(
          properties.getCachePath(AuthnServerConfigurationProperties.OIDC_FEDERATION_CACHE_FILE), Clock.systemUTC());
    }

    /**
     * Creates the store of the state of the federation services in memory. It follows the federation cache.
     *
     * @return an {@link InMemoryFederationServiceStateStore}
     */
    @Bean
    @ConditionalOnMissingBean(FederationServiceStateStore.class)
    @ConditionalOnStorageType(store = StorageSettings.OIDC_FEDERATION_CACHE, value = StorageType.MEMORY)
    FederationServiceStateStore authnServerFederationServiceStateStore() {
      return new InMemoryFederationServiceStateStore();
    }

    /**
     * The OIDC stores in Redis.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = SPRING_DATA_REDIS_CLASS)
    static class OidcRedisStorageConfiguration {

      /**
       * Creates the authorization code store.
       *
       * @param storage the Redis storage
       * @return a {@link RedisAuthorizationCodeStore}
       */
      @Bean
      @ConditionalOnMissingBean(AuthorizationCodeStore.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_AUTHORIZATION_CODES, value = StorageType.REDIS)
      AuthorizationCodeStore authnServerAuthorizationCodeStore(final RedisStorage storage) {
        return new RedisAuthorizationCodeStore(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

      /**
       * Creates the access token store.
       *
       * @param storage the Redis storage
       * @return a {@link RedisAccessTokenStore}
       */
      @Bean
      @ConditionalOnMissingBean(AccessTokenStore.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_ACCESS_TOKENS, value = StorageType.REDIS)
      AccessTokenStore authnServerAccessTokenStore(final RedisStorage storage) {
        return new RedisAccessTokenStore(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

      /**
       * Creates the cache of used client assertions.
       *
       * @param storage the Redis storage
       * @return a {@link RedisClientAssertionReplayCache}
       */
      @Bean
      @ConditionalOnMissingBean(ClientAssertionReplayCache.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_CLIENT_ASSERTIONS, value = StorageType.REDIS)
      ClientAssertionReplayCache authnServerClientAssertionReplayCache(final RedisStorage storage) {
        return new RedisClientAssertionReplayCache(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

      /**
       * Creates the federation cache.
       *
       * @param storage the Redis storage
       * @return a {@link RedisFederationCache}
       */
      @Bean
      @ConditionalOnMissingBean(FederationCache.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_FEDERATION_CACHE, value = StorageType.REDIS)
      FederationCache authnServerFederationCache(final RedisStorage storage) {
        return new RedisFederationCache(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

      /**
       * Creates the store of the state of the federation services. It follows the federation cache.
       *
       * @param storage the Redis storage
       * @return a {@link RedisFederationServiceStateStore}
       */
      @Bean
      @ConditionalOnMissingBean(FederationServiceStateStore.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_FEDERATION_CACHE, value = StorageType.REDIS)
      FederationServiceStateStore authnServerFederationServiceStateStore(final RedisStorage storage) {
        return new RedisFederationServiceStateStore(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

      /**
       * Creates the store of the OpenID Provider's own trust marks.
       *
       * @param storage the Redis storage
       * @return a {@link RedisProviderTrustMarkStore}
       */
      @Bean
      @ConditionalOnMissingBean(ProviderTrustMarkStore.class)
      @ConditionalOnStorageType(store = StorageSettings.OIDC_TRUST_MARKS, value = StorageType.REDIS)
      ProviderTrustMarkStore authnServerProviderTrustMarkStore(final RedisStorage storage) {
        return new RedisProviderTrustMarkStore(storage.getRedisTemplate(), storage.getKeyPrefix());
      }

    }

  }

  /**
   * The HTTP session in Redis.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = { SPRING_DATA_REDIS_CLASS, SPRING_SESSION_REDIS_CLASS })
  @ConditionalOnStorageType(StorageType.REDIS)
  @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
  static class RedisSessionConfiguration {

    /**
     * Makes the key prefix the namespace of the sessions, unless {@value #SESSION_NAMESPACE_PROPERTY} is assigned.
     *
     * @param properties the Redis properties of the server
     * @param environment the environment
     * @return a {@link SessionRepositoryCustomizer}
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    SessionRepositoryCustomizer<RedisSessionRepository> authnServerSessionNamespaceCustomizer(
        final AuthnServerRedisProperties properties, final Environment environment) {
      return repository -> {
        if (!environment.containsProperty(SESSION_NAMESPACE_PROPERTY)) {
          repository.setRedisKeyNamespace(properties.getKeyPrefix());
        }
      };
    }

    /**
     * Makes the key prefix the namespace of the sessions, unless {@value #SESSION_NAMESPACE_PROPERTY} is assigned, for
     * the indexed repository.
     *
     * @param properties the Redis properties of the server
     * @param environment the environment
     * @return a {@link SessionRepositoryCustomizer}
     */
    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)
    SessionRepositoryCustomizer<RedisIndexedSessionRepository> authnServerIndexedSessionNamespaceCustomizer(
        final AuthnServerRedisProperties properties, final Environment environment) {
      return repository -> {
        if (!environment.containsProperty(SESSION_NAMESPACE_PROPERTY)) {
          repository.setRedisKeyNamespace(properties.getKeyPrefix());
        }
      };
    }

    /**
     * Sets up Spring Session for Redis, when Spring Boot's session module, which would otherwise do it, is missing.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnMissingClass(BOOT_SESSION_REDIS_AUTOCONFIGURATION)
    @ConditionalOnBean(RedisConnectionFactory.class)
    @ConditionalOnMissingBean(SessionRepository.class)
    @Import(RedisHttpSessionConfiguration.class)
    static class FallbackRedisSessionConfiguration {
    }

  }

}
