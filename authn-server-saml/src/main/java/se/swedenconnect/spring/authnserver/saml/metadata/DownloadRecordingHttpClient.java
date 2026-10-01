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
package se.swedenconnect.spring.authnserver.saml.metadata;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;

import org.apache.hc.client5.http.classic.HttpClient;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.io.HttpClientResponseHandler;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * An {@link HttpClient} that records the outcome of every download of a metadata source, so that a failed download is
 * seen even when the resolver falls back to the metadata it already holds or to its backup file.
 *
 * @author Martin Lindström
 */
class DownloadRecordingHttpClient implements HttpClient {

  /** The client that makes the calls. */
  private final HttpClient client;

  /** Where the outcome is recorded. */
  private final DownloadRecord record;

  /** Whether a 404 answer is a normal answer, as it is for an MDQ query for an unknown entity. */
  private final boolean notFoundIsAnswer;

  /**
   * Constructor.
   *
   * @param client the client that makes the calls
   * @param record where the outcome is recorded
   * @param notFoundIsAnswer whether a 404 answer is a normal answer
   */
  DownloadRecordingHttpClient(final @NonNull HttpClient client, final @NonNull DownloadRecord record,
      final boolean notFoundIsAnswer) {
    this.client = Objects.requireNonNull(client, "client must not be null");
    this.record = Objects.requireNonNull(record, "record must not be null");
    this.notFoundIsAnswer = notFoundIsAnswer;
  }

  /** {@inheritDoc} */
  @Override
  @Deprecated
  public @Nullable HttpResponse execute(final @NonNull ClassicHttpRequest request) throws IOException {
    return this.recorded(this.call(() -> this.client.execute(request)));
  }

  /** {@inheritDoc} */
  @Override
  @Deprecated
  public @Nullable HttpResponse execute(final @NonNull ClassicHttpRequest request,
      final @Nullable HttpContext context) throws IOException {
    return this.recorded(this.call(() -> this.client.execute(request, context)));
  }

  /** {@inheritDoc} */
  @Override
  @Deprecated
  public @Nullable ClassicHttpResponse execute(final @Nullable HttpHost target,
      final @NonNull ClassicHttpRequest request) throws IOException {
    return this.recorded(this.call(() -> this.client.execute(target, request)));
  }

  /** {@inheritDoc} */
  @Override
  @Deprecated
  public @Nullable HttpResponse execute(final @Nullable HttpHost target, final @NonNull ClassicHttpRequest request,
      final @Nullable HttpContext context) throws IOException {
    return this.recorded(this.call(() -> this.client.execute(target, request, context)));
  }

  /** {@inheritDoc} */
  @Override
  public @Nullable ClassicHttpResponse executeOpen(final @Nullable HttpHost target,
      final @NonNull ClassicHttpRequest request, final @Nullable HttpContext context) throws IOException {
    return this.recorded(this.call(() -> this.client.executeOpen(target, request, context)));
  }

  /** {@inheritDoc} */
  @Override
  public <T> @Nullable T execute(final @NonNull ClassicHttpRequest request,
      final @NonNull HttpClientResponseHandler<? extends T> handler) throws IOException {
    return this.call(() -> this.client.execute(request, this.recording(handler)));
  }

  /** {@inheritDoc} */
  @Override
  public <T> @Nullable T execute(final @NonNull ClassicHttpRequest request, final @Nullable HttpContext context,
      final @NonNull HttpClientResponseHandler<? extends T> handler) throws IOException {
    return this.call(() -> this.client.execute(request, context, this.recording(handler)));
  }

  /** {@inheritDoc} */
  @Override
  public <T> @Nullable T execute(final @Nullable HttpHost target, final @NonNull ClassicHttpRequest request,
      final @NonNull HttpClientResponseHandler<? extends T> handler) throws IOException {
    return this.call(() -> this.client.execute(target, request, this.recording(handler)));
  }

  /** {@inheritDoc} */
  @Override
  public <T> @Nullable T execute(final @Nullable HttpHost target, final @NonNull ClassicHttpRequest request,
      final @Nullable HttpContext context, final @NonNull HttpClientResponseHandler<? extends T> handler)
      throws IOException {
    return this.call(() -> this.client.execute(target, request, context, this.recording(handler)));
  }

  /**
   * Makes a call, recording a failure if it throws.
   *
   * @param call the call
   * @param <T> the type of the result
   * @return the result
   * @throws IOException if the call fails
   */
  private <T> @Nullable T call(final @NonNull Call<T> call) throws IOException {
    try {
      return call.make();
    }
    catch (final IOException | RuntimeException e) {
      this.record.failure(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
      throw e;
    }
  }

  /**
   * Records the outcome of a response.
   *
   * @param response the response
   * @param <R> the type of the response
   * @return the response
   */
  private <R extends HttpResponse> @Nullable R recorded(final @Nullable R response) {
    if (response != null) {
      final int status = response.getCode();
      if (status == 200 || status == 304 || (status == 404 && this.notFoundIsAnswer)) {
        this.record.success();
      }
      else {
        this.record.failure("HTTP status " + status);
      }
    }
    return response;
  }

  /**
   * Wraps a response handler so that the outcome of the response is recorded.
   *
   * @param handler the handler
   * @param <T> the type of the result
   * @return the wrapped handler
   */
  private <T> @NonNull HttpClientResponseHandler<T> recording(
      final @NonNull HttpClientResponseHandler<? extends T> handler) {
    return response -> handler.handleResponse(this.recorded(response));
  }

  /**
   * A call that may throw an {@link IOException}.
   *
   * @param <T> the type of the result
   */
  @FunctionalInterface
  private interface Call<T> {

    /**
     * Makes the call.
     *
     * @return the result
     * @throws IOException for errors
     */
    T make() throws IOException;

  }

  /**
   * The outcome of the downloads of one metadata source.
   */
  static class DownloadRecord {

    /** When the latest download was made, or {@code null}. */
    private volatile Instant lastAttempt;

    /** When the latest successful download was made, or {@code null}. */
    private volatile Instant lastSuccess;

    /** Why the latest download failed, or {@code null} if it succeeded. */
    private volatile String lastError;

    /**
     * Records a successful download.
     */
    void success() {
      final Instant now = Instant.now();
      this.lastAttempt = now;
      this.lastSuccess = now;
      this.lastError = null;
    }

    /**
     * Records a failed download.
     *
     * @param error why it failed
     */
    void failure(final @NonNull String error) {
      this.lastAttempt = Instant.now();
      this.lastError = error;
    }

    /**
     * Gets when the latest download was made.
     *
     * @return the time, or {@code null} if none has been made
     */
    @Nullable Instant getLastAttempt() {
      return this.lastAttempt;
    }

    /**
     * Gets when the latest successful download was made.
     *
     * @return the time, or {@code null}
     */
    @Nullable Instant getLastSuccess() {
      return this.lastSuccess;
    }

    /**
     * Gets why the latest download failed.
     *
     * @return the error, or {@code null} if it succeeded or none has been made
     */
    @Nullable String getLastError() {
      return this.lastError;
    }

  }

}
