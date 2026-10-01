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
import org.springframework.context.ApplicationEventPublisher;

import se.swedenconnect.spring.authnserver.audit.events.AbstractAuthnEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnErrorResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnUnrecoverableErrorEvent;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Publishes the events of an authentication flow as Spring application events.
 * <p>
 * Every event is published under a correlation ID. If the current request has none, it cannot be tied to a flow, and
 * a correlation ID is generated for it, see {@link FlowCorrelation}.
 * </p>
 * <p>
 * Without an {@link ApplicationEventPublisher}, nothing is published.
 * </p>
 *
 * @author Martin Lindström
 */
public class AuthnEventPublisher {

  /** The application event publisher, or {@code null} if nothing is published. */
  private final ApplicationEventPublisher publisher;

  /**
   * Constructor.
   *
   * @param publisher the application event publisher, or {@code null} if nothing should be published
   */
  public AuthnEventPublisher(final @Nullable ApplicationEventPublisher publisher) {
    this.publisher = publisher;
  }

  /**
   * Gets a publisher that publishes nothing.
   *
   * @return an {@link AuthnEventPublisher}
   */
  public static @NonNull AuthnEventPublisher noop() {
    return new AuthnEventPublisher(null);
  }

  /**
   * Publishes an event.
   *
   * @param event the event
   */
  public void publish(final @NonNull AbstractAuthnEvent event) {
    Objects.requireNonNull(event, "event must not be null");
    if (this.publisher == null) {
      return;
    }
    FlowCorrelation.ensure();
    this.publisher.publishEvent(event);
  }

  /**
   * Publishes an {@link AuthnErrorResponseEvent} for an error that is sent to the requester. The requester and the
   * stage are taken from the {@link AuditRequestContext} of the request.
   *
   * @param request the HTTP request
   * @param response the protocol-specific data about the error response, or {@code null}
   * @param errorCode the error code of the protocol
   * @param errorDescription the error description, or {@code null}
   */
  public void publishErrorResponse(final @NonNull HttpServletRequest request,
      final @Nullable ProtocolAuditData response, final @NonNull String errorCode,
      final @Nullable String errorDescription) {
    final AuditRequestContext context = AuditRequestContext.get(request);
    this.publish(new AuthnErrorResponseEvent(context.getRequester(), response, context.getStage(), errorCode,
        errorDescription));
  }

  /**
   * Publishes an {@link AuthnUnrecoverableErrorEvent} for an error that is shown to the user. The requester and the
   * stage are taken from the {@link AuditRequestContext} of the request.
   *
   * @param request the HTTP request
   * @param error the error
   */
  public void publishUnrecoverableError(final @NonNull HttpServletRequest request,
      final @NonNull UnrecoverableErrorException error) {
    final AuditRequestContext context = AuditRequestContext.get(request);
    this.publish(new AuthnUnrecoverableErrorEvent(context.getRequester(), context.getStage(), error));
  }

}
