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
package se.swedenconnect.spring.authnserver.audit;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * What the audit knows about the HTTP request being processed: who the requester is and how far the processing has
 * come. The protocol modules update it as the request is processed, and an error event takes its requester and stage
 * from it.
 * <p>
 * It is kept as an attribute of the HTTP request.
 * </p>
 *
 * @author Martin Lindström
 */
public final class AuditRequestContext {

  /** The name of the request attribute. */
  public static final String REQUEST_ATTRIBUTE = AuditRequestContext.class.getName();

  /** The requester. */
  private AuditRequester requester = AuditRequester.unknown(null);

  /** The stage. */
  private AuditStage stage;

  /**
   * Gets the context of a request, and creates it if the request has none.
   *
   * @param request the HTTP request
   * @return the context
   */
  public static @NonNull AuditRequestContext get(final @NonNull HttpServletRequest request) {
    if (request.getAttribute(REQUEST_ATTRIBUTE) instanceof final AuditRequestContext context) {
      return context;
    }
    final AuditRequestContext context = new AuditRequestContext();
    request.setAttribute(REQUEST_ATTRIBUTE, context);
    return context;
  }

  /**
   * Gets the requester. Until a protocol module has assigned it, the requester is unknown.
   *
   * @return the requester
   */
  public @NonNull AuditRequester getRequester() {
    return this.requester;
  }

  /**
   * Assigns the requester.
   *
   * @param requester the requester
   * @return this context
   */
  public @NonNull AuditRequestContext setRequester(final @NonNull AuditRequester requester) {
    this.requester = Objects.requireNonNull(requester, "requester must not be null");
    return this;
  }

  /**
   * Gets the stage that the processing has reached.
   *
   * @return the stage, or {@code null} if no protocol module has assigned it
   */
  public @Nullable AuditStage getStage() {
    return this.stage;
  }

  /**
   * Assigns the stage that the processing has reached.
   *
   * @param stage the stage
   * @return this context
   */
  public @NonNull AuditRequestContext setStage(final @NonNull AuditStage stage) {
    this.stage = Objects.requireNonNull(stage, "stage must not be null");
    return this;
  }

}
