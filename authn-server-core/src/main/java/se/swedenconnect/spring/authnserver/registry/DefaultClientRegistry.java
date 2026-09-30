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
package se.swedenconnect.spring.authnserver.registry;

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.Requester;

/**
 * The default {@link ClientRegistry}. It asks its backends in the order they were given and the first backend that
 * knows the requester wins.
 *
 * @author Martin Lindström
 */
public class DefaultClientRegistry implements ClientRegistry {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(DefaultClientRegistry.class);

  /** The backends, in the order they are asked. */
  private final List<ClientRegistryBackend> backends;

  /**
   * Constructor.
   *
   * @param backends the backends, in the order they are to be asked
   */
  public DefaultClientRegistry(final @NonNull List<ClientRegistryBackend> backends) {
    this.backends = List.copyOf(Objects.requireNonNull(backends, "backends must not be null"));
    if (this.backends.isEmpty()) {
      throw new IllegalArgumentException("backends must not be empty");
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord lookup(final @NonNull Requester requester) throws ClientRegistryException {
    Objects.requireNonNull(requester, "requester must not be null");
    for (final ClientRegistryBackend backend : this.backendsFor(requester)) {
      final RequesterRecord record = backend.lookup(requester.identifier());
      if (record != null) {
        log.debug("Requester '{}' was found by the '{}' backend", requester, backend.getName());
        return record;
      }
    }
    log.debug("No backend knows the requester '{}'", requester);
    return null;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable RequesterRecord requestMark(final @NonNull Requester requester, final @NonNull String mark)
      throws ClientRegistryException {
    Objects.requireNonNull(requester, "requester must not be null");
    Objects.requireNonNull(mark, "mark must not be null");
    for (final ClientRegistryBackend backend : this.backendsFor(requester)) {
      final RequesterRecord record = backend.requestMark(requester.identifier(), mark);
      if (record != null) {
        return record;
      }
    }
    log.debug("No backend knows the requester '{}'", requester);
    return null;
  }

  /**
   * Gets the backends that answer for the protocol of the supplied requester.
   *
   * @param requester the requester
   * @return the backends to ask, in order
   */
  private @NonNull List<ClientRegistryBackend> backendsFor(final @NonNull Requester requester) {
    return this.backends.stream()
        .filter(b -> b.getProtocol() == requester.protocol())
        .toList();
  }

}
