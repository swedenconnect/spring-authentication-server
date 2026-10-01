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

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;

/**
 * Reads the storage settings: the shared setting, {@value #SHARED}, and the settings that override it for one store.
 *
 * @author Martin Lindström
 */
public final class StorageSettings {

  /** The shared setting, for the HTTP session and every store that is not overridden. */
  public static final String SHARED = "authn-server.storage.type";

  /** The setting for the SAML replay cache. */
  public static final String SAML_REPLAY = "authn-server.saml.replay.type";

  /** The setting for the OIDC authorization codes. */
  public static final String OIDC_AUTHORIZATION_CODES = "authn-server.oidc.storage.authorization-codes";

  /** The setting for the OIDC access tokens. */
  public static final String OIDC_ACCESS_TOKENS = "authn-server.oidc.storage.access-tokens";

  /** The setting for the values of used OIDC client assertions. */
  public static final String OIDC_CLIENT_ASSERTIONS = "authn-server.oidc.storage.client-assertions";

  /** The setting for the federation cache. */
  public static final String OIDC_FEDERATION_CACHE = "authn-server.oidc.storage.federation-cache";

  /** The setting for the OpenID Provider's own trust marks. */
  public static final String OIDC_TRUST_MARKS = "authn-server.oidc.storage.trust-marks";

  /** The settings of the SAML stores. */
  static final List<String> SAML_STORES = List.of(SAML_REPLAY);

  /** The settings of the OIDC stores. */
  static final List<String> OIDC_STORES = List.of(OIDC_AUTHORIZATION_CODES, OIDC_ACCESS_TOKENS,
      OIDC_CLIENT_ASSERTIONS, OIDC_FEDERATION_CACHE, OIDC_TRUST_MARKS);

  /**
   * Gets the shared storage type.
   *
   * @param environment the environment
   * @return the storage type, {@link StorageType#MEMORY} by default
   * @throws IllegalArgumentException for an invalid value
   */
  public static @NonNull StorageType shared(final @NonNull Environment environment) {
    return Objects.requireNonNullElse(read(environment, SHARED), StorageType.MEMORY);
  }

  /**
   * Gets the storage type of a store: its own setting if assigned, and otherwise the shared setting.
   *
   * @param environment the environment
   * @param store the setting of the store, or an empty string for the shared setting
   * @return the storage type
   * @throws IllegalArgumentException for an invalid value
   */
  public static @NonNull StorageType forStore(final @NonNull Environment environment, final @NonNull String store) {
    if (store.isEmpty()) {
      return shared(environment);
    }
    return Objects.requireNonNullElseGet(read(environment, store), () -> shared(environment));
  }

  /**
   * Checks every storage setting.
   *
   * @param environment the environment
   * @throws IllegalArgumentException for an invalid value
   */
  public static void validate(final @NonNull Environment environment) {
    read(environment, SHARED);
    SAML_STORES.forEach(s -> read(environment, s));
    OIDC_STORES.forEach(s -> read(environment, s));
  }

  /**
   * Gets the settings that keep something in Redis: the shared setting, when it is "redis", and the settings of the
   * stores of the enabled protocols that are "redis" while the shared setting is not.
   *
   * @param environment the environment
   * @return the settings, empty if nothing is kept in Redis
   */
  public static @NonNull List<String> redisSettings(final @NonNull Environment environment) {
    final List<String> settings = new ArrayList<>();
    if (shared(environment) == StorageType.REDIS) {
      settings.add(SHARED);
      return settings;
    }
    final Binder binder = Binder.get(environment);
    if (binder.bind("authn-server.saml.enabled", Boolean.class).orElse(false)) {
      SAML_STORES.stream().filter(s -> read(environment, s) == StorageType.REDIS).forEach(settings::add);
    }
    if (binder.bind("authn-server.oidc.enabled", Boolean.class).orElse(false)) {
      OIDC_STORES.stream().filter(s -> read(environment, s) == StorageType.REDIS).forEach(settings::add);
    }
    return settings;
  }

  /**
   * Reads a setting.
   *
   * @param environment the environment
   * @param property the setting
   * @return the storage type, or {@code null} if not assigned
   */
  private static StorageType read(final @NonNull Environment environment, final @NonNull String property) {
    return StorageType.parse(Binder.get(environment).bind(property, String.class).orElse(null), property);
  }

  // Hidden constructor
  private StorageSettings() {
  }

}
