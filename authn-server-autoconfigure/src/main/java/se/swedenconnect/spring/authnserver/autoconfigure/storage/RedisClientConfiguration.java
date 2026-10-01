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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.net.ssl.SSLParameters;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.data.redis.autoconfigure.ClientResourcesBuilderCustomizer;
import org.springframework.boot.data.redis.autoconfigure.DataRedisConnectionDetails;
import org.springframework.boot.data.redis.autoconfigure.DataRedisProperties;
import org.springframework.boot.data.redis.autoconfigure.JedisClientConfigurationBuilderCustomizer;
import org.springframework.boot.data.redis.autoconfigure.LettuceClientConfigurationBuilderCustomizer;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslOptions;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import io.lettuce.core.SslVerifyMode;
import io.lettuce.core.internal.HostAndPort;
import io.lettuce.core.resource.MappingSocketAddressResolver;

/**
 * Applies the settings of {@link AuthnServerRedisProperties} that Spring Boot does not have to the Redis client that
 * Spring Boot sets up: the TLS host name check and the Redis Cluster NAT translation.
 * <p>
 * The host name check means the same for both clients: with it, the server certificate must be issued by a trusted
 * issuer and match the host name; without it, only the issuer is checked. For Lettuce, turning it off is the
 * {@code CA} verification mode. For Jedis, which Spring Boot leaves without a host name check, the check is turned on
 * unless it has been turned off.
 * </p>
 * <p>
 * NAT translation is only supported with Lettuce. With Jedis, startup fails when it is configured.
 * </p>
 *
 * @author Martin Lindström
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(name = "org.springframework.boot.data.redis.autoconfigure.DataRedisProperties")
class RedisClientConfiguration {

  /**
   * The settings for the Lettuce client.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "io.lettuce.core.RedisClient")
  static class LettuceConfiguration {

    /**
     * Turns off the host name check, when that has been configured and TLS is used.
     *
     * @param properties the Redis properties of the server
     * @param redisProperties the Spring Boot Redis properties
     * @param connectionDetails the Redis connection details
     * @return a {@link LettuceClientConfigurationBuilderCustomizer}
     */
    @Bean
    LettuceClientConfigurationBuilderCustomizer authnServerLettuceClientCustomizer(
        final AuthnServerRedisProperties properties, final ObjectProvider<DataRedisProperties> redisProperties,
        final ObjectProvider<DataRedisConnectionDetails> connectionDetails) {
      return builder -> {
        if (properties.getSsl().isSkipHostnameVerification()
            && usesSsl(redisProperties.getIfAvailable(), connectionDetails.getIfAvailable())) {
          builder.useSsl().verifyPeer(SslVerifyMode.CA);
        }
      };
    }

    /**
     * Translates the addresses that the cluster nodes report, when that has been configured.
     *
     * @param properties the Redis properties of the server
     * @return a {@link ClientResourcesBuilderCustomizer}
     */
    @Bean
    ClientResourcesBuilderCustomizer authnServerLettuceNatCustomizer(final AuthnServerRedisProperties properties) {
      final Map<HostAndPort, HostAndPort> translation = natTranslation(properties);
      return builder -> {
        if (!translation.isEmpty()) {
          final Function<HostAndPort, HostAndPort> mapping = a -> translation.getOrDefault(a, a);
          builder.socketAddressResolver(MappingSocketAddressResolver.create(mapping));
        }
      };
    }

    /**
     * Reads the NAT translation entries.
     *
     * @param properties the Redis properties of the server
     * @return the translation, empty if none is configured
     * @throws IllegalArgumentException for an invalid entry
     */
    static @NonNull Map<HostAndPort, HostAndPort> natTranslation(final @NonNull AuthnServerRedisProperties properties) {
      final Map<HostAndPort, HostAndPort> translation = new HashMap<>();
      final List<AuthnServerRedisProperties.NatTranslation> entries = properties.getCluster().getNatTranslation();
      if (entries == null) {
        return translation;
      }
      for (int i = 0; i < entries.size(); i++) {
        final AuthnServerRedisProperties.NatTranslation entry = entries.get(i);
        final String name = "%s.cluster.nat-translation[%d]".formatted(AuthnServerRedisProperties.PREFIX, i);
        translation.put(parseAddress(entry.getFrom(), name + ".from"), parseAddress(entry.getTo(), name + ".to"));
      }
      return translation;
    }

    /**
     * Parses an address given as host:port.
     *
     * @param address the address
     * @param property the property, for the error message
     * @return a {@link HostAndPort}
     * @throws IllegalArgumentException if the address is missing or invalid
     */
    private static @NonNull HostAndPort parseAddress(final @Nullable String address, final @NonNull String property) {
      if (!StringUtils.hasText(address)) {
        throw new IllegalArgumentException("Missing value for " + property);
      }
      try {
        final HostAndPort result = HostAndPort.parse(address.trim());
        if (!result.hasPort()) {
          throw new IllegalArgumentException("no port");
        }
        return result;
      }
      catch (final IllegalArgumentException e) {
        throw new IllegalArgumentException(
            "Invalid value for %s: '%s' - expected host:port".formatted(property, address), e);
      }
    }

  }

  /**
   * The settings for the Jedis client.
   */
  @Configuration(proxyBeanMethods = false)
  @ConditionalOnClass(name = "redis.clients.jedis.Jedis")
  static class JedisConfiguration {

    /**
     * Applies the host name check when TLS is used, unless it has been turned off, and refuses NAT translation.
     *
     * @param properties the Redis properties of the server
     * @param redisProperties the Spring Boot Redis properties
     * @param connectionDetails the Redis connection details
     * @return a {@link JedisClientConfigurationBuilderCustomizer}
     */
    @Bean
    JedisClientConfigurationBuilderCustomizer authnServerJedisClientCustomizer(
        final AuthnServerRedisProperties properties, final ObjectProvider<DataRedisProperties> redisProperties,
        final ObjectProvider<DataRedisConnectionDetails> connectionDetails) {
      return builder -> {
        if (properties.getCluster().hasNatTranslation()) {
          throw new IllegalStateException(("%s.cluster.nat-translation is only supported with the Lettuce client, "
              + "and the Redis connection uses Jedis").formatted(AuthnServerRedisProperties.PREFIX));
        }
        final DataRedisConnectionDetails details = connectionDetails.getIfAvailable();
        if (!usesSsl(redisProperties.getIfAvailable(), details)) {
          return;
        }
        final SSLParameters parameters = new SSLParameters();
        final SslBundle bundle = details != null ? details.getSslBundle() : null;
        if (bundle != null) {
          final SslOptions options = bundle.getOptions();
          if (options.getCiphers() != null) {
            parameters.setCipherSuites(options.getCiphers());
          }
          if (options.getEnabledProtocols() != null) {
            parameters.setProtocols(options.getEnabledProtocols());
          }
        }
        if (!properties.getSsl().isSkipHostnameVerification()) {
          parameters.setEndpointIdentificationAlgorithm("HTTPS");
        }
        builder.useSsl().sslParameters(parameters);
      };
    }

  }

  /**
   * Tells whether the Redis connection uses TLS.
   *
   * @param redisProperties the Spring Boot Redis properties, or {@code null}
   * @param connectionDetails the Redis connection details, or {@code null}
   * @return {@code true} if TLS is used and {@code false} otherwise
   */
  static boolean usesSsl(final @Nullable DataRedisProperties redisProperties,
      final @Nullable DataRedisConnectionDetails connectionDetails) {
    if (connectionDetails != null && connectionDetails.getSslBundle() != null) {
      return true;
    }
    final String url = redisProperties != null ? redisProperties.getUrl() : null;
    return url != null && url.startsWith("rediss:");
  }

}
