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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.audit.tracing.CorrelationID;
import se.swedenconnect.spring.audit.tracing.CorrelationIDHolder;

/**
 * Assigns the correlation ID of the current request, kept by spring-audit-support's {@link CorrelationIDHolder}.
 * <p>
 * One correlation ID is generated per authentication flow, when the authentication request arrives. Later requests of
 * the flow join it, using the ID kept with the authentication in progress, the authorization code or the access token.
 * A request that cannot be tied to a flow gets an ID of its own. The ID is cleared when the request ends, see
 * {@link AuthnAuditFilter}.
 * </p>
 *
 * @author Martin Lindström
 */
public final class FlowCorrelation {

  /**
   * Starts a new flow: a correlation ID is generated and assigned to the current request.
   *
   * @return the correlation ID
   */
  public static @NonNull String startFlow() {
    final CorrelationID id = CorrelationID.generate();
    CorrelationIDHolder.set(id);
    return id.getValue();
  }

  /**
   * Joins the current request to a flow. If no correlation ID is given, the request is not tied to a flow and gets a
   * correlation ID of its own, unless it already has one.
   *
   * @param correlationId the correlation ID of the flow, or {@code null}
   * @return the correlation ID of the current request
   */
  public static @NonNull String join(final @Nullable String correlationId) {
    if (StringUtils.hasText(correlationId)) {
      CorrelationIDHolder.set(CorrelationID.of(correlationId));
      return correlationId;
    }
    return ensure();
  }

  /**
   * Gets the correlation ID of the current request, and generates one if it has none.
   *
   * @return the correlation ID
   */
  public static @NonNull String ensure() {
    final CorrelationID current = CorrelationIDHolder.get();
    return current != null ? current.getValue() : startFlow();
  }

  /**
   * Gets the correlation ID of the current request.
   *
   * @return the correlation ID, or {@code null} if none has been assigned
   */
  public static @Nullable String current() {
    final CorrelationID current = CorrelationIDHolder.get();
    return current != null ? current.getValue() : null;
  }

  /**
   * Removes the correlation ID of the current request.
   */
  public static void clear() {
    CorrelationIDHolder.clear();
  }

  // Hidden constructor
  private FlowCorrelation() {
  }

}
