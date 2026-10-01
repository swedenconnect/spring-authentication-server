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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.AutoConfigurationImportFilter;
import org.springframework.boot.autoconfigure.AutoConfigurationMetadata;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;

/**
 * Keeps Spring Boot from putting the HTTP session in Redis when the shared storage setting,
 * {@value StorageSettings#SHARED}, is not "redis", so that the HTTP session always follows that setting, also when
 * Spring Session for Redis is on the classpath for some other reason.
 *
 * @author Martin Lindström
 */
public class SessionStorageImportFilter implements AutoConfigurationImportFilter, EnvironmentAware {

  /** The environment. */
  private @Nullable Environment environment;

  /** {@inheritDoc} */
  @Override
  public void setEnvironment(final @NonNull Environment environment) {
    this.environment = environment;
  }

  /** {@inheritDoc} */
  @Override
  public boolean @NonNull [] match(final @Nullable String @NonNull [] autoConfigurationClasses,
      final @Nullable AutoConfigurationMetadata autoConfigurationMetadata) {
    final boolean[] matches = new boolean[autoConfigurationClasses.length];
    for (int i = 0; i < autoConfigurationClasses.length; i++) {
      matches[i] = !AuthnServerStorageAutoConfiguration.BOOT_SESSION_REDIS_AUTOCONFIGURATION
          .equals(autoConfigurationClasses[i]) || this.isRedisSession();
    }
    return matches;
  }

  /**
   * Tells whether the HTTP session is to be kept in Redis. An invalid setting is let through; it is reported by
   * {@link AuthnServerStorageAutoConfiguration}.
   *
   * @return {@code true} if the HTTP session is kept in Redis and {@code false} otherwise
   */
  private boolean isRedisSession() {
    if (this.environment == null) {
      return true;
    }
    try {
      return StorageSettings.shared(this.environment) == StorageType.REDIS;
    }
    catch (final IllegalArgumentException e) {
      return true;
    }
  }

}
