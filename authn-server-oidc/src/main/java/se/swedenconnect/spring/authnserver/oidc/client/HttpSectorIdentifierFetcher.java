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
package se.swedenconnect.spring.authnserver.oidc.client;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import com.nimbusds.jose.util.JSONArrayUtils;

/**
 * A {@link SectorIdentifierFetcher} that fetches the document with an HTTP GET request.
 * <p>
 * The URI comes from client metadata, so a call has a time limit and the body a size limit. Redirects are not
 * followed, and an answer other than 2xx means that the document cannot be fetched.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpSectorIdentifierFetcher implements SectorIdentifierFetcher {

  /** The default timeout, 5 seconds. */
  public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

  /** The default maximum size of the document, 100 KB. */
  public static final int DEFAULT_MAX_SIZE = 100 * 1024;

  /** The HTTP client. */
  private final HttpClient httpClient;

  /** The timeout of a request. */
  private final Duration timeout;

  /** The maximum size of the document, in bytes. */
  private final int maxSize;

  /**
   * Constructor using the default timeout and maximum size.
   */
  public HttpSectorIdentifierFetcher() {
    this(HttpClient.newBuilder()
        .connectTimeout(DEFAULT_TIMEOUT)
        .followRedirects(HttpClient.Redirect.NEVER)
        .build(), DEFAULT_TIMEOUT, DEFAULT_MAX_SIZE);
  }

  /**
   * Constructor. The HTTP client should not follow redirects.
   *
   * @param httpClient the HTTP client
   * @param timeout the timeout of a request
   * @param maxSize the maximum size of the document, in bytes
   */
  public HttpSectorIdentifierFetcher(final @NonNull HttpClient httpClient, final @NonNull Duration timeout,
      final int maxSize) {
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
    this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
    if (maxSize <= 0) {
      throw new IllegalArgumentException("maxSize must be positive");
    }
    this.maxSize = maxSize;
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable List<String> fetch(final @NonNull URI sectorIdentifierUri) throws IOException {
    final HttpRequest request = HttpRequest.newBuilder(sectorIdentifierUri)
        .timeout(this.timeout)
        .header("Accept", "application/json")
        .GET()
        .build();
    final HttpResponse<InputStream> response;
    try {
      response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching the document", e);
    }
    catch (final IllegalArgumentException e) {
      throw new IOException("Invalid URI - " + e.getMessage(), e);
    }
    final String body;
    try (final InputStream is = response.body()) {
      if (response.statusCode() < 200 || response.statusCode() > 299) {
        throw new IOException("HTTP status " + response.statusCode());
      }
      final byte[] bytes = is.readNBytes(this.maxSize + 1);
      if (bytes.length > this.maxSize) {
        throw new IOException("The document is larger than " + this.maxSize + " bytes");
      }
      body = new String(bytes, StandardCharsets.UTF_8).trim();
    }
    return parse(body);
  }

  /**
   * Parses the document.
   *
   * @param body the body of the answer
   * @return the strings of the JSON array, or {@code null} if the body is JSON but not an array of strings
   * @throws IOException if the body is not JSON
   */
  static @Nullable List<String> parse(final @NonNull String body) throws IOException {
    final List<Object> values;
    try {
      // Wrapped in an array, so that any JSON value parses and only a body that is not JSON fails
      final List<Object> wrapped = JSONArrayUtils.parse("[" + body + "]");
      if (wrapped.size() != 1) {
        throw new IOException("The document is not valid JSON");
      }
      if (!(wrapped.getFirst() instanceof final List<?> list)) {
        return null;
      }
      values = new ArrayList<>(list);
    }
    catch (final ParseException e) {
      throw new IOException("The document is not valid JSON", e);
    }
    final List<String> result = new ArrayList<>(values.size());
    for (final Object value : values) {
      if (!(value instanceof final String s)) {
        return null;
      }
      result.add(s);
    }
    return result;
  }

}
