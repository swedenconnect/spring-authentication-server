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
package se.swedenconnect.spring.authnserver.oidc.client.federation;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.ParseException;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * A {@link FederationCache} that keeps its entries in the memory of one node. It is the default, and it is what a
 * single node deployment needs.
 * <p>
 * When a file is given, the entries are kept there too, so that they survive a restart. The file is read when the
 * cache is created, and entries that have expired are dropped. It is written a few seconds after a change, so that a
 * burst of changes gives one write, and when the cache is closed.
 * </p>
 *
 * @author Martin Lindström
 */
public class InMemoryFederationCache implements FederationCache, AutoCloseable {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(InMemoryFederationCache.class);

  /** How long after a change the file is written. */
  static final Duration WRITE_DELAY = Duration.ofSeconds(5);

  /** The mapper for the file. */
  private static final JsonMapper MAPPER = JsonMapper.builder()
      .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .disable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
      .build();

  /** The entries, keyed by {@code client_id}. */
  private final Map<String, CachedClientRecord> entries = new ConcurrentHashMap<>();

  /** The clock, so that tests can control time. */
  private final Clock clock;

  /** The file where the entries are kept, or {@code null}. */
  private final Path file;

  /** Writes the file, or {@code null} if there is no file. */
  private final ScheduledExecutorService writer;

  /** Whether a write of the file has been scheduled. Guarded by {@code this}. */
  private boolean writeScheduled = false;

  /**
   * Default constructor using the system clock.
   */
  public InMemoryFederationCache() {
    this(Clock.systemUTC());
  }

  /**
   * Constructor.
   *
   * @param clock the clock to use
   */
  public InMemoryFederationCache(final @NonNull Clock clock) {
    this(null, clock);
  }

  /**
   * Constructor for a cache that is kept in a file too.
   *
   * @param file the file where the entries are kept, or {@code null} to keep them in memory only
   * @param clock the clock to use
   */
  public InMemoryFederationCache(final @Nullable Path file, final @NonNull Clock clock) {
    this.clock = Objects.requireNonNull(clock, "clock must not be null");
    this.file = file;
    if (file != null) {
      this.read(file);
      this.writer = Executors.newSingleThreadScheduledExecutor(r -> {
        final Thread thread = new Thread(r, "federation-cache-writer");
        thread.setDaemon(true);
        return thread;
      });
    }
    else {
      this.writer = null;
    }
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable CachedClientRecord get(final @NonNull String clientId) {
    Objects.requireNonNull(clientId, "clientId must not be null");
    final CachedClientRecord record = this.entries.get(clientId);
    if (record == null) {
      return null;
    }
    if (record.isExpired(this.clock.instant())) {
      this.entries.remove(clientId, record);
      return null;
    }
    return record;
  }

  /** {@inheritDoc} */
  @Override
  public void put(final @NonNull CachedClientRecord record) {
    Objects.requireNonNull(record, "record must not be null");
    this.entries.put(record.clientId(), record);
    this.scheduleWrite();
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull Collection<CachedClientRecord> getEntries() {
    final Instant now = this.clock.instant();
    return this.entries.values().stream().filter(r -> !r.isExpired(now)).toList();
  }

  /** {@inheritDoc} */
  @Override
  public void remove(final @NonNull String clientId) {
    if (this.entries.remove(Objects.requireNonNull(clientId, "clientId must not be null")) != null) {
      this.scheduleWrite();
    }
  }

  /**
   * Removes every entry that has expired.
   */
  public void purgeExpired() {
    final Instant now = this.clock.instant();
    this.entries.values().removeIf(r -> r.isExpired(now));
  }

  /**
   * Gets the number of entries that the cache holds, expired entries that have not yet been dropped included.
   *
   * @return the number of entries
   */
  public int size() {
    return this.entries.size();
  }

  /**
   * Writes the file now, if there is one.
   */
  public synchronized void write() {
    this.writeScheduled = false;
    if (this.file == null) {
      return;
    }
    final Instant now = this.clock.instant();
    final List<StoredClientRecord> stored = this.entries.values().stream()
        .filter(r -> !r.isExpired(now))
        .map(StoredClientRecord::of)
        .toList();
    try {
      final Path directory = this.file.toAbsolutePath().getParent();
      Files.createDirectories(directory);
      final Path temporary = Files.createTempFile(directory, "federation-cache", ".tmp");
      Files.writeString(temporary, MAPPER.writeValueAsString(stored), StandardCharsets.UTF_8);
      Files.move(temporary, this.file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
      log.trace("Wrote {} federation cache entries to {}", stored.size(), this.file);
    }
    catch (final IOException | JacksonException e) {
      log.warn("Failed to write the federation cache to {}: {}", this.file, e.getMessage());
    }
  }

  /**
   * Writes the file, if there is one, and stops the writer.
   */
  @Override
  public void close() {
    if (this.writer != null) {
      this.writer.shutdownNow();
      this.write();
    }
  }

  /**
   * Schedules a write of the file, unless one is already scheduled or there is no file.
   */
  private synchronized void scheduleWrite() {
    if (this.writer == null || this.writeScheduled || this.writer.isShutdown()) {
      return;
    }
    this.writeScheduled = true;
    this.writer.schedule(this::write, WRITE_DELAY.toMillis(), TimeUnit.MILLISECONDS);
  }

  /**
   * Reads the entries of the file. Entries that have expired are dropped, and a file that cannot be read is logged and
   * ignored.
   *
   * @param path the file
   */
  private void read(final @NonNull Path path) {
    if (!Files.isRegularFile(path)) {
      return;
    }
    try {
      final StoredClientRecord[] stored =
          MAPPER.readValue(Files.readString(path, StandardCharsets.UTF_8), StoredClientRecord[].class);
      final Instant now = this.clock.instant();
      int expired = 0;
      for (final StoredClientRecord entry : stored) {
        try {
          final CachedClientRecord record = entry.toRecord();
          if (record.isExpired(now)) {
            expired++;
          }
          else {
            this.entries.put(record.clientId(), record);
          }
        }
        catch (final ParseException | RuntimeException e) {
          log.info("A federation cache entry in {} could not be read and is dropped: {}", path, e.getMessage());
        }
      }
      log.info("Read {} federation cache entries from {}, {} expired entries dropped", this.entries.size(), path,
          expired);
    }
    catch (final IOException | JacksonException e) {
      log.warn("The federation cache in {} could not be read and is not used: {}", path, e.getMessage());
    }
  }

}
