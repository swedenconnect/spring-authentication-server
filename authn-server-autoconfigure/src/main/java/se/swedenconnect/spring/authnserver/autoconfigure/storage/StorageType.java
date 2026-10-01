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

import java.util.Locale;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * Where the server keeps a store, or its HTTP session.
 *
 * @author Martin Lindström
 */
public enum StorageType {

  /** In the memory of the node. */
  MEMORY,

  /** In Redis, shared by all nodes. */
  REDIS;

  /**
   * Parses the value of a storage setting.
   *
   * @param value the value, or {@code null}
   * @param property the name of the setting, for the error message
   * @return the storage type, or {@code null} if the value is {@code null} or empty
   * @throws IllegalArgumentException if the value is not "memory" or "redis"
   */
  public static @Nullable StorageType parse(final @Nullable String value, final @NonNull String property) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return StorageType.valueOf(value.trim().toUpperCase(Locale.ROOT));
    }
    catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("Invalid value for %s: '%s' - the supported values are 'memory' and 'redis'"
          .formatted(property, value));
    }
  }

}
