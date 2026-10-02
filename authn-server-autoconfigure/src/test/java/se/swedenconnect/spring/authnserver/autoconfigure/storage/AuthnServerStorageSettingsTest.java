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

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.session.autoconfigure.SessionAutoConfiguration;
import org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;

import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;

/**
 * Tests for the storage settings and the startup checks of {@link AuthnServerStorageAutoConfiguration} that need no
 * Redis.
 *
 * @author Martin Lindström
 */
class AuthnServerStorageSettingsTest {

  private static final String OIDC_KEY = StorageTestProperties.OIDC_KEY;

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, DataRedisAutoConfiguration.class, SessionAutoConfiguration.class,
          SessionDataRedisAutoConfiguration.class, SamlAutoConfiguration.class, OidcAutoConfiguration.class,
          AuthnServerAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class))
      .withPropertyValues(StorageTestProperties.SERVER);

  @Test
  void anInvalidStorageSettingFailsStartup() {
    this.runner.withPropertyValues("authn-server.oidc.storage.access-tokens=mongo")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("authn-server.oidc.storage.access-tokens").hasMessageContaining("mongo"));
    this.runner.withPropertyValues("authn-server.storage.type=disk")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("authn-server.storage.type"));
  }

  @Test
  void redisWithoutSpringDataRedisFailsStartup() {
    this.runner.withClassLoader(new FilteredClassLoader("org.springframework.data.redis."))
        .withPropertyValues("authn-server.oidc.storage.authorization-codes=redis")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("authn-server.oidc.storage.authorization-codes is set to 'redis'")
            .hasMessageContaining("Spring Data Redis"));
  }

  @Test
  void aRedisSessionWithoutSpringSessionFailsStartup() {
    this.runner.withClassLoader(new FilteredClassLoader("org.springframework.session.data.redis."))
        .withPropertyValues("authn-server.storage.type=redis")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("authn-server.storage.type").hasMessageContaining("Spring Session for Redis"));
  }

  @Test
  void redisWithoutAConnectionFailsStartup() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, SamlAutoConfiguration.class, OidcAutoConfiguration.class,
            AuthnServerAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class))
        .withPropertyValues(StorageTestProperties.SERVER)
        .withPropertyValues("authn-server.saml.replay.type=redis")
        .run(context -> assertThat(context).hasFailed().getFailure().rootCause()
            .hasMessageContaining("authn-server.saml.replay.type is set to 'redis'")
            .hasMessageContaining("no Redis connection"));
  }

  @Test
  void aProtocolThatIsNotEnabledDoesNotNeedRedis() {
    new WebApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
            ConvertersAutoConfiguration.class, OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class,
            AuthnServerStorageAutoConfiguration.class))
        .withPropertyValues("authn-server.base-url=" + StorageTestProperties.BASE_URL,
            "authn-server.oidc.enabled=true",
            "authn-server.oidc.clients[0].location=classpath:clients/oidc-clients.json",
            OIDC_KEY + "store.location=classpath:credentials/oidc-keys.p12",
            OIDC_KEY + "store.password=secret",
            OIDC_KEY + "store.type=PKCS12",
            OIDC_KEY + "key.alias=rsa-sign",
            OIDC_KEY + "key.key-password=secret",
            "authn-server.saml.replay.type=redis")
        .run(context -> {
          assertThat(context).hasNotFailed();
          assertThat(context).doesNotHaveBean(RedisStorage.class);
        });
  }

  @Test
  void theSessionModuleOfSpringBootIsOnlyImportedForRedis() {
    final String session = AuthnServerStorageAutoConfiguration.BOOT_SESSION_REDIS_AUTOCONFIGURATION;
    final String[] candidates = { session, DataRedisAutoConfiguration.class.getName() };
    final SessionStorageImportFilter filter = new SessionStorageImportFilter();
    assertThat(filter.match(candidates, null)).containsExactly(true, true);

    final MockEnvironment environment = new MockEnvironment();
    filter.setEnvironment(environment);
    assertThat(filter.match(candidates, null)).containsExactly(false, true);
    environment.setProperty("authn-server.storage.type", "redis");
    assertThat(filter.match(candidates, null)).containsExactly(true, true);
    environment.setProperty("authn-server.storage.type", "memory");
    assertThat(filter.match(candidates, null)).containsExactly(false, true);
    environment.setProperty("authn-server.storage.type", "invalid");
    assertThat(filter.match(candidates, null)).containsExactly(true, true);
  }

  @Test
  void theStorageSettingsAreRead() {
    final MockEnvironment environment = new MockEnvironment();
    assertThat(StorageSettings.shared(environment)).isEqualTo(StorageType.MEMORY);
    assertThat(StorageSettings.redisSettings(environment)).isEmpty();
    environment.setProperty("authn-server.oidc.enabled", "true");
    environment.setProperty(StorageSettings.OIDC_TRUST_MARKS, "redis");
    environment.setProperty(StorageSettings.SAML_REPLAY, "redis");
    assertThat(StorageSettings.redisSettings(environment)).containsExactly(StorageSettings.OIDC_TRUST_MARKS);
    assertThat(StorageSettings.forStore(environment, StorageSettings.OIDC_TRUST_MARKS)).isEqualTo(StorageType.REDIS);
    assertThat(StorageSettings.forStore(environment, StorageSettings.OIDC_ACCESS_TOKENS))
        .isEqualTo(StorageType.MEMORY);
    environment.setProperty(StorageSettings.SHARED, " Redis ");
    assertThat(StorageSettings.redisSettings(environment)).containsExactly(StorageSettings.SHARED);
    assertThat(StorageType.parse("", "x")).isNull();
    assertThat(AuthnServerStorageAutoConfiguration.describe(List.of("a", "b"))).isEqualTo("a, b are");
  }

}
