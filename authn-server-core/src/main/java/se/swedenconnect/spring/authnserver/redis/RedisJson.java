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
package se.swedenconnect.spring.authnserver.redis;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Writes and reads the JSON of the entries that the server keeps in Redis.
 * <p>
 * Entries are JSON so that an entry written by an older version can be read after a class has changed, for example
 * during a rolling upgrade. Properties that a class does not know are ignored, and a property that is missing gets
 * its default value.
 * </p>
 *
 * @author Martin Lindström
 */
public final class RedisJson {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(RedisJson.class);

  /** The mapper. */
  private static final JsonMapper MAPPER = JsonMapper.builder()
      .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
      .build();

  /**
   * Writes an entry as JSON.
   *
   * @param entry the entry
   * @return the JSON
   * @throws IllegalArgumentException if the entry cannot be written
   */
  public static @NonNull String write(final @NonNull Object entry) {
    try {
      return MAPPER.writeValueAsString(entry);
    }
    catch (final JacksonException e) {
      throw new IllegalArgumentException("Failed to write %s as JSON".formatted(entry.getClass().getSimpleName()), e);
    }
  }

  /**
   * Reads an entry. An entry that cannot be read is logged and treated as missing.
   *
   * @param key the Redis key of the entry, for the log
   * @param json the JSON, or {@code null}
   * @param type the type of the entry
   * @param <T> the type of the entry
   * @return the entry, or {@code null} if there is none or it cannot be read
   */
  public static <T> @Nullable T read(final @NonNull String key, final @Nullable String json,
      final @NonNull Class<T> type) {
    if (json == null) {
      return null;
    }
    try {
      return MAPPER.readValue(json, type);
    }
    catch (final JacksonException | IllegalArgumentException | NullPointerException e) {
      log.warn("The Redis entry '{}' could not be read as {} and is ignored: {}", key, type.getSimpleName(),
          e.getMessage());
      return null;
    }
  }

  // Hidden constructor
  private RedisJson() {
  }

}
