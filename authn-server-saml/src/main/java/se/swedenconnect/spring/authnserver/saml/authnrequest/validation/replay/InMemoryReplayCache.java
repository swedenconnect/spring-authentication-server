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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation.replay;

import jakarta.annotation.Nonnull;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.opensaml.storage.ReplayCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link ReplayCache} that keeps the seen message IDs in memory. It only protects the node it runs on, so a
 * deployment with several nodes needs a shared cache.
 *
 * @author Martin Lindström
 */
public class InMemoryReplayCache implements ReplayCache {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(InMemoryReplayCache.class);

  /** The cache, mapping each key to its expiration time in seconds since the epoch. */
  private final ConcurrentMap<String, Long> cache = new ConcurrentHashMap<>();

  /**
   * Checks the key and adds it if it is not present. Expired entries are removed first.
   */
  @Override
  public boolean check(final @Nonnull String context, final @Nonnull String key, final @Nonnull Instant expires) {
    final long now = Instant.now().getEpochSecond();
    this.cache.entrySet().removeIf(e -> e.getValue() < now);

    // The atomicity of putIfAbsent ensures that only one of any number of concurrent calls for the same key gets true.
    //
    final String cacheKey = context + ":" + key;
    if (this.cache.putIfAbsent(cacheKey, expires.getEpochSecond()) != null) {
      log.debug("Key '{}' was present in in-memory replay cache", key);
      return false;
    }
    log.trace("Key '{}' was not present in in-memory replay cache, adding it", key);
    return true;
  }

}
