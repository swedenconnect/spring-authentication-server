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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import jakarta.annotation.Nonnull;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

/**
 * A {@link RequestUriFetcher} that fetches the request object over HTTP with a GET request.
 * <p>
 * The response must have status 200, and its body may not be larger than the configured maximum size.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpRequestUriFetcher implements RequestUriFetcher {

  /** The default timeout, 5 seconds. */
  public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

  /** The default maximum size of a request object, 100 KB. */
  public static final int DEFAULT_MAX_SIZE = 100 * 1024;

  /** The HTTP client. */
  private final HttpClient httpClient;

  /** The timeout of a request. */
  private final Duration timeout;

  /** The maximum size of a request object, in bytes. */
  private final int maxSize;

  /**
   * Constructor using the default timeout and maximum size.
   */
  public HttpRequestUriFetcher() {
    this(HttpClient.newBuilder().connectTimeout(DEFAULT_TIMEOUT).build(), DEFAULT_TIMEOUT, DEFAULT_MAX_SIZE);
  }

  /**
   * Constructor.
   *
   * @param httpClient the HTTP client
   * @param timeout the timeout of a request
   * @param maxSize the maximum size of a request object, in bytes
   */
  public HttpRequestUriFetcher(final @Nonnull HttpClient httpClient, final @Nonnull Duration timeout,
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
  public @Nonnull String fetch(final @Nonnull URI requestUri) throws IOException {
    final HttpRequest request = HttpRequest.newBuilder(requestUri)
        .timeout(this.timeout)
        .header("Accept", "application/oauth-authz-req+jwt, application/jwt")
        .GET()
        .build();
    final HttpResponse<InputStream> response;
    try {
      response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while fetching request object", e);
    }
    try (final InputStream body = response.body()) {
      if (response.statusCode() != 200) {
        throw new IOException("Fetching request object gave HTTP status " + response.statusCode());
      }
      final byte[] bytes = body.readNBytes(this.maxSize + 1);
      if (bytes.length > this.maxSize) {
        throw new IOException("Request object is larger than " + this.maxSize + " bytes");
      }
      return new String(bytes, StandardCharsets.UTF_8).trim();
    }
  }

}
