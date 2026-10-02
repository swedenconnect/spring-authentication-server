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
package se.swedenconnect.spring.authnserver.autoconfigure.actuate;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration;
import org.springframework.boot.session.autoconfigure.SessionAutoConfiguration;
import org.springframework.boot.session.data.redis.autoconfigure.SessionDataRedisAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationEvent;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import se.swedenconnect.security.credential.spring.autoconfigure.ConvertersAutoConfiguration;
import se.swedenconnect.security.credential.spring.autoconfigure.SpringCredentialBundlesAutoConfiguration;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.autoconfigure.AuthnServerAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.ConfiguredAuthnServer;
import se.swedenconnect.spring.authnserver.autoconfigure.oidc.OidcAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.saml.SamlAutoConfiguration;
import se.swedenconnect.spring.authnserver.autoconfigure.storage.AuthnServerStorageAutoConfiguration;
import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationClientBackend;
import se.swedenconnect.spring.authnserver.redis.RedisKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.InMemoryKnownClientStore;
import se.swedenconnect.spring.authnserver.registry.changes.KnownClientStore;

/**
 * Tests that clients that appear in and disappear from the client registry are reported across restarts, with the
 * state kept in the cache directory or in Redis.
 *
 * @author Martin Lindström
 */
@Testcontainers(disabledWithoutDocker = true)
class ClientChangesTest {

  @Container
  private static final GenericContainer<?> REDIS =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine")).withExposedPorts(6379);

  private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SpringCredentialBundlesAutoConfiguration.class,
          ConvertersAutoConfiguration.class, AuthnServerStorageAutoConfiguration.class, SamlAutoConfiguration.class,
          OidcAutoConfiguration.class, AuthnServerAutoConfiguration.class))
      .withUserConfiguration(ActuatorTestSupport.OidcBackendsConfiguration.class,
          ActuatorTestSupport.EventsConfiguration.class);

  @TempDir
  Path directory;

  @AfterEach
  void clear() {
    ActuatorTestSupport.RESOLVED.clear();
  }

  @Test
  void theCacheDirectoryKeepsTheKnownClientsAndTheFederationCacheAcrossARestart() throws Exception {
    final Path metadata = this.directory.resolve("metadata.xml");
    final Path cache = this.directory.resolve("cache");
    Files.writeString(metadata, ActuatorTestSupport.metadata(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.SP_TWO));
    final WebApplicationContextRunner server = this.runner.withPropertyValues(ActuatorTestSupport.server(metadata))
        .withPropertyValues("authn-server.cache-directory=" + cache);

    server.run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(context.getBean(KnownClientStore.class)).isInstanceOf(InMemoryKnownClientStore.class);
      ActuatorTestSupport.RESOLVED.put(ActuatorTestSupport.FEDERATION_CLIENT,
          ActuatorTestSupport.resolved(ActuatorTestSupport.FEDERATION_CLIENT));
      context.getBean(ConfiguredAuthnServer.class).getClientRegistry()
          .lookup(AuthenticationProtocol.OIDC, ActuatorTestSupport.FEDERATION_CLIENT);
      assertThat(events(context).added()).containsExactlyInAnyOrder(ActuatorTestSupport.SP_ONE,
          ActuatorTestSupport.SP_TWO, ActuatorTestSupport.PROPERTIES_CLIENT, ActuatorTestSupport.CONFIGURED_CLIENT,
          ActuatorTestSupport.FEDERATION_CLIENT);
    });
    assertThat(cache.resolve("known-clients.json")).exists();
    assertThat(cache.resolve("oidc/federation-cache.json")).exists();

    Files.writeString(metadata,
        ActuatorTestSupport.metadata(ActuatorTestSupport.SP_TWO, ActuatorTestSupport.SP_THREE));
    ActuatorTestSupport.RESOLVED.clear();
    server.run(context -> {
      assertThat(context).hasNotFailed();
      assertThat(events(context).added()).containsExactly(ActuatorTestSupport.SP_THREE);
      assertThat(events(context).removed()).containsExactly(ActuatorTestSupport.SP_ONE);
      final FederationClientBackend federation = context.getBean(ConfiguredAuthnServer.class)
          .getClientRegistryBackends(FederationClientBackend.class).getFirst();
      assertThat(federation.getClient(ActuatorTestSupport.FEDERATION_CLIENT)).isNotNull();
    });
  }

  @Test
  void withoutACacheDirectoryEveryStartIsAFirstStart() throws Exception {
    final Path metadata = this.directory.resolve("metadata.xml");
    Files.writeString(metadata, ActuatorTestSupport.metadata(ActuatorTestSupport.SP_ONE));
    final WebApplicationContextRunner server = this.runner.withPropertyValues(ActuatorTestSupport.server(metadata));

    for (int i = 0; i < 2; i++) {
      server.run(context -> assertThat(events(context).added())
          .containsExactlyInAnyOrder(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.PROPERTIES_CLIENT,
              ActuatorTestSupport.CONFIGURED_CLIENT));
    }
  }

  @Test
  void twoInstancesSharingRedisGiveOneEventForEachChange() throws Exception {
    final Path metadata = this.directory.resolve("metadata.xml");
    final Path cache = this.directory.resolve("cache");
    Files.writeString(metadata, ActuatorTestSupport.metadata(ActuatorTestSupport.SP_ONE, ActuatorTestSupport.SP_TWO));
    final WebApplicationContextRunner server = this.runner
        .withConfiguration(AutoConfigurations.of(DataRedisAutoConfiguration.class, SessionAutoConfiguration.class,
            SessionDataRedisAutoConfiguration.class))
        .withPropertyValues(ActuatorTestSupport.server(metadata))
        .withPropertyValues("authn-server.storage.type=redis", "authn-server.cache-directory=" + cache,
            "authn-server.redis.key-prefix=changes",
            "spring.data.redis.host=" + REDIS.getHost(), "spring.data.redis.port=" + REDIS.getFirstMappedPort());

    final List<ApplicationEvent> all = new ArrayList<>();
    server.run(a -> {
      assertThat(a).hasNotFailed();
      new StringRedisTemplate(a.getBean(RedisConnectionFactory.class)).delete("changes:known-clients");
    });
    server.run(a -> server.run(b -> {
      assertThat(a).hasNotFailed();
      assertThat(b).hasNotFailed();
      assertThat(a.getBean(KnownClientStore.class)).isInstanceOf(RedisKnownClientStore.class);
      all.addAll(events(a).events);
      all.addAll(events(b).events);
    }));
    assertThat(all).hasSize(4);

    Files.writeString(metadata,
        ActuatorTestSupport.metadata(ActuatorTestSupport.SP_TWO, ActuatorTestSupport.SP_THREE));
    all.clear();
    server.run(a -> server.run(b -> {
      final ActuatorTestSupport.EventCollector ea = events(a);
      final ActuatorTestSupport.EventCollector eb = events(b);
      assertThat(concat(ea.added(), eb.added())).containsExactly(ActuatorTestSupport.SP_THREE);
      assertThat(concat(ea.removed(), eb.removed())).containsExactly(ActuatorTestSupport.SP_ONE);

      ActuatorTestSupport.RESOLVED.put(ActuatorTestSupport.FEDERATION_CLIENT,
          ActuatorTestSupport.resolved(ActuatorTestSupport.FEDERATION_CLIENT));
      a.getBean(ConfiguredAuthnServer.class).getClientRegistry()
          .lookup(AuthenticationProtocol.OIDC, ActuatorTestSupport.FEDERATION_CLIENT);
      b.getBean(ConfiguredAuthnServer.class).getClientRegistryBackends(FederationClientBackend.class).getFirst()
          .update(ActuatorTestSupport.FEDERATION_CLIENT);
      assertThat(concat(ea.added(), eb.added())).containsExactly(ActuatorTestSupport.SP_THREE,
          ActuatorTestSupport.FEDERATION_CLIENT);
    }));
    assertThat(cache).doesNotExist();
  }

  private static ActuatorTestSupport.EventCollector events(
      final org.springframework.context.ApplicationContext context) {
    return context.getBean(ActuatorTestSupport.EventCollector.class);
  }

  private static List<String> concat(final List<String> a, final List<String> b) {
    final List<String> result = new ArrayList<>(a);
    result.addAll(b);
    return result;
  }

}
