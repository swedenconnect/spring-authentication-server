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
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Duration;
import java.util.Locale;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.SignedJWT;

import se.swedenconnect.spring.authnserver.oidc.client.federation.FederationCallEvent;

/**
 * A {@link ClientKeysFetcher} that fetches the keys with an HTTP GET request.
 * <p>
 * The URI comes from client metadata, so a call has a time limit and the body a size limit. Redirects are not
 * followed. Every fetch is published as a {@link FederationCallEvent} when an event publisher is assigned, so that it
 * shows in the health of the federation services as a call to the URI.
 * </p>
 *
 * @author Martin Lindström
 */
public class HttpClientKeysFetcher implements ClientKeysFetcher, ApplicationEventPublisherAware {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(HttpClientKeysFetcher.class);

  /** The content type of a signed JWK Set. */
  public static final String SIGNED_JWKS_CONTENT_TYPE = "application/jwk-set+jwt";

  /** The default timeout, 5 seconds. */
  public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

  /** The default maximum size of the answer, 100 KB. */
  public static final int DEFAULT_MAX_SIZE = 100 * 1024;

  /** The HTTP client. */
  private final HttpClient httpClient;

  /** The timeout of a request. */
  private final Duration timeout;

  /** The maximum size of the answer, in bytes. */
  private final int maxSize;

  /** Publishes how each fetch went, or {@code null}. */
  private ApplicationEventPublisher eventPublisher;

  /**
   * Constructor using the default timeout and maximum size.
   */
  public HttpClientKeysFetcher() {
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
   * @param maxSize the maximum size of the answer, in bytes
   */
  public HttpClientKeysFetcher(final @NonNull HttpClient httpClient, final @NonNull Duration timeout,
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
  public @NonNull JWKSet fetchJwks(final @NonNull URI jwksUri) throws IOException {
    final String body = this.get(jwksUri, "application/json", false);
    try {
      final JWKSet keys = JWKSet.parse(body);
      this.publish(jwksUri, FederationCallEvent.Outcome.SUCCESS, null);
      return keys;
    }
    catch (final ParseException e) {
      throw this.failure(jwksUri, FederationCallEvent.Outcome.ERROR_RESPONSE,
          "The answer is not a JWK Set - " + e.getMessage(), e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public @NonNull SignedJWT fetchSignedJwks(final @NonNull URI signedJwksUri) throws IOException {
    final String body = this.get(signedJwksUri, SIGNED_JWKS_CONTENT_TYPE, true);
    try {
      final SignedJWT jwt = SignedJWT.parse(body);
      this.publish(signedJwksUri, FederationCallEvent.Outcome.SUCCESS, null);
      return jwt;
    }
    catch (final ParseException e) {
      throw this.failure(signedJwksUri, FederationCallEvent.Outcome.ERROR_RESPONSE,
          "The answer is not a signed JWT - " + e.getMessage(), e);
    }
  }

  /**
   * Makes the GET request and reads the body.
   *
   * @param uri the URI
   * @param accept the content type asked for
   * @param signed whether a signed JWK Set is fetched, which must be answered with status 200 and its content type
   * @return the body
   * @throws IOException if the call fails or the answer is not accepted
   */
  private @NonNull String get(final @NonNull URI uri, final @NonNull String accept, final boolean signed)
      throws IOException {
    final HttpResponse<InputStream> response;
    try {
      response = this.httpClient.send(HttpRequest.newBuilder(uri)
          .timeout(this.timeout)
          .header("Accept", accept)
          .GET()
          .build(), HttpResponse.BodyHandlers.ofInputStream());
    }
    catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw this.failure(uri, FederationCallEvent.Outcome.UNREACHABLE, "Interrupted while fetching the keys", e);
    }
    catch (final IllegalArgumentException e) {
      throw this.failure(uri, FederationCallEvent.Outcome.ERROR_RESPONSE, "Invalid URI - " + e.getMessage(), e);
    }
    catch (final HttpTimeoutException e) {
      throw this.failure(uri, FederationCallEvent.Outcome.UNREACHABLE, "Timed out", e);
    }
    catch (final IOException e) {
      throw this.failure(uri, FederationCallEvent.Outcome.UNREACHABLE,
          Objects.requireNonNullElse(e.getMessage(), e.getClass().getSimpleName()), e);
    }
    try (final InputStream is = response.body()) {
      final int status = response.statusCode();
      if (signed ? status != 200 : status < 200 || status > 299) {
        throw this.failure(uri, FederationCallEvent.Outcome.ERROR_RESPONSE, "HTTP status " + status, null);
      }
      if (signed) {
        final String contentType = response.headers().firstValue("Content-Type").orElse("");
        if (!contentType.toLowerCase(Locale.ROOT).startsWith(SIGNED_JWKS_CONTENT_TYPE)) {
          throw this.failure(uri, FederationCallEvent.Outcome.ERROR_RESPONSE,
              "The content type is '%s', not %s".formatted(contentType, SIGNED_JWKS_CONTENT_TYPE), null);
        }
      }
      final byte[] bytes = is.readNBytes(this.maxSize + 1);
      if (bytes.length > this.maxSize) {
        throw this.failure(uri, FederationCallEvent.Outcome.ERROR_RESPONSE,
            "The answer is larger than " + this.maxSize + " bytes", null);
      }
      return new String(bytes, StandardCharsets.UTF_8).trim();
    }
  }

  /**
   * Publishes a failed fetch and creates the exception for it.
   *
   * @param uri the URI
   * @param outcome how the fetch went
   * @param error what went wrong
   * @param cause the cause, or {@code null}
   * @return an {@link IOException}
   */
  private @NonNull IOException failure(final @NonNull URI uri, final FederationCallEvent.@NonNull Outcome outcome,
      final @NonNull String error, final @Nullable Throwable cause) {
    this.publish(uri, outcome, error);
    return new IOException(error, cause);
  }

  /**
   * Publishes how a fetch went, if there is an event publisher. A failure to publish is logged and does not affect the
   * fetch.
   *
   * @param uri the URI
   * @param outcome how the fetch went
   * @param error what went wrong, or {@code null}
   */
  private void publish(final @NonNull URI uri, final FederationCallEvent.@NonNull Outcome outcome,
      final @Nullable String error) {
    if (this.eventPublisher == null) {
      return;
    }
    try {
      this.eventPublisher.publishEvent(
          new FederationCallEvent(FederationCallEvent.Call.CLIENT_KEYS, uri.toString(), null, outcome, error));
    }
    catch (final RuntimeException e) {
      log.warn("Failed to publish the outcome of a fetch of the client keys at {}: {}", uri, e.getMessage());
    }
  }

  /**
   * Assigns the publisher of the {@link FederationCallEvent}s. Without a publisher, nothing is published.
   *
   * @param eventPublisher the event publisher, or {@code null}
   */
  @Override
  public void setApplicationEventPublisher(final @Nullable ApplicationEventPublisher eventPublisher) {
    this.eventPublisher = eventPublisher;
  }

}
