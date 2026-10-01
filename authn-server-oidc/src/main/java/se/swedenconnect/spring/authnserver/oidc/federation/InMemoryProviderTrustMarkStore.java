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
package se.swedenconnect.spring.authnserver.oidc.federation;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * A {@link ProviderTrustMarkStore} that keeps the state in the memory of one node. It is the default.
 *
 * @author Martin Lindström
 */
public class InMemoryProviderTrustMarkStore implements ProviderTrustMarkStore {

  /** The state, by trust mark type. */
  private final Map<String, Entry> entries = new ConcurrentHashMap<>();

  /** {@inheritDoc} */
  @Override
  public @Nullable Entry get(final @NonNull String trustMarkType) {
    return this.entries.get(Objects.requireNonNull(trustMarkType, "trustMarkType must not be null"));
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull String trustMarkType, final @NonNull Entry entry) {
    this.entries.put(Objects.requireNonNull(trustMarkType, "trustMarkType must not be null"),
        Objects.requireNonNull(entry, "entry must not be null"));
  }

}
