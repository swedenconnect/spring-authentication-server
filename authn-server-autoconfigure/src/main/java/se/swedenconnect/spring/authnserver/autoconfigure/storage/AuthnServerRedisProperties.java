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

import java.util.List;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;

import se.swedenconnect.spring.authnserver.redis.RedisKeys;

/**
 * Configuration properties for the use of Redis. The connection itself is configured with Spring Boot's
 * {@code spring.data.redis.*} settings, and TLS key and trust stores with Spring Boot SSL bundles.
 *
 * @author Martin Lindström
 */
@ConfigurationProperties(AuthnServerRedisProperties.PREFIX)
public class AuthnServerRedisProperties {

  /** The property prefix. */
  public static final String PREFIX = "authn-server.redis";

  /**
   * The prefix that starts every key the server writes to Redis, and the default Spring Session namespace. Two
   * deployments that share one Redis are kept apart by giving them different prefixes. Defaults to "authn-server".
   */
  private String keyPrefix = RedisKeys.DEFAULT_PREFIX;

  /**
   * TLS settings that Spring Boot does not have.
   */
  private final SslProperties ssl = new SslProperties();

  /**
   * Redis Cluster settings that Spring Boot does not have.
   */
  private final ClusterProperties cluster = new ClusterProperties();

  /**
   * Gets the key prefix.
   *
   * @return the key prefix
   */
  public @NonNull String getKeyPrefix() {
    return this.keyPrefix;
  }

  /**
   * Assigns the key prefix.
   *
   * @param keyPrefix the key prefix
   */
  public void setKeyPrefix(final @NonNull String keyPrefix) {
    this.keyPrefix = keyPrefix;
  }

  /**
   * Gets the TLS settings.
   *
   * @return the TLS settings
   */
  public @NonNull SslProperties getSsl() {
    return this.ssl;
  }

  /**
   * Gets the cluster settings.
   *
   * @return the cluster settings
   */
  public @NonNull ClusterProperties getCluster() {
    return this.cluster;
  }

  /**
   * TLS settings.
   */
  public static class SslProperties {

    /**
     * Whether the check that the host name matches the Redis server certificate is skipped, for example when Redis
     * Cluster nodes are reached by IP address. The certificate is still checked against the trust store. Defaults to
     * false.
     */
    private boolean skipHostnameVerification = false;

    /**
     * Tells whether the host name check is skipped.
     *
     * @return whether the host name check is skipped
     */
    public boolean isSkipHostnameVerification() {
      return this.skipHostnameVerification;
    }

    /**
     * Assigns whether the host name check is skipped.
     *
     * @param skipHostnameVerification whether the host name check is skipped
     */
    public void setSkipHostnameVerification(final boolean skipHostnameVerification) {
      this.skipHostnameVerification = skipHostnameVerification;
    }
  }

  /**
   * Redis Cluster settings.
   */
  public static class ClusterProperties {

    /**
     * Translation of the addresses that the cluster nodes report into addresses that the server can reach, for a
     * cluster behind NAT. Only supported with the Lettuce client.
     */
    private List<NatTranslation> natTranslation;

    /**
     * Gets the NAT translation entries.
     *
     * @return the NAT translation entries, or {@code null}
     */
    public @Nullable List<NatTranslation> getNatTranslation() {
      return this.natTranslation;
    }

    /**
     * Assigns the NAT translation entries.
     *
     * @param natTranslation the NAT translation entries
     */
    public void setNatTranslation(final @Nullable List<NatTranslation> natTranslation) {
      this.natTranslation = natTranslation;
    }

    /**
     * Tells whether NAT translation is configured.
     *
     * @return {@code true} if there is at least one translation entry and {@code false} otherwise
     */
    public boolean hasNatTranslation() {
      return this.natTranslation != null && !this.natTranslation.isEmpty();
    }
  }

  /**
   * A NAT translation entry.
   */
  public static class NatTranslation {

    /**
     * The address that a cluster node reports, as host:port.
     */
    private String from;

    /**
     * The address that the server uses instead, as host:port.
     */
    private String to;

    /**
     * Gets the address to translate from.
     *
     * @return the address, or {@code null}
     */
    public @Nullable String getFrom() {
      return this.from;
    }

    /**
     * Assigns the address to translate from.
     *
     * @param from the address
     */
    public void setFrom(final @Nullable String from) {
      this.from = from;
    }

    /**
     * Gets the address to translate to.
     *
     * @return the address, or {@code null}
     */
    public @Nullable String getTo() {
      return this.to;
    }

    /**
     * Assigns the address to translate to.
     *
     * @param to the address
     */
    public void setTo(final @Nullable String to) {
      this.to = to;
    }
  }

}
