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
package se.swedenconnect.spring.authnserver.audit.transform;

import java.io.Serializable;
import java.util.List;

import org.jspecify.annotations.NonNull;

import se.swedenconnect.spring.audit.value.AuditValue;
import se.swedenconnect.spring.audit.value.AuditValueConstants;
import se.swedenconnect.spring.audit.value.StringAuditValue;
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.AuthnErrorResponseEvent;

/**
 * Transforms an {@link AuthnErrorResponseEvent} into an audit event of the type {@code authn_error_response}. The
 * data is the {@code requester} object, the protocol-specific {@code response} object, the {@code stage} that the
 * error came from, and the {@code error} object of spring-audit-support holding the error code and description of the
 * protocol.
 *
 * @author Martin Lindström
 */
public class AuthnErrorResponseEventTransformer extends AbstractAuthnEventTransformer<AuthnErrorResponseEvent> {

  /** The name of the member holding the stage. */
  public static final String STAGE = "stage";

  /**
   * Constructor.
   */
  public AuthnErrorResponseEventTransformer() {
    super(AuthnErrorResponseEvent.class, AuthnAuditTypes.AUTHN_ERROR_RESPONSE);
  }

  /**
   * Adds the {@code stage} and the {@code error} object.
   */
  @Override
  protected @NonNull List<AuditValue<? extends Serializable>> getDataFields(
      final @NonNull AuthnErrorResponseEvent event) {
    final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
    if (event.getStage() != null) {
      fields.add(new StringAuditValue(STAGE, event.getStage().getValue()));
    }
    fields.add(AuditValueConstants.error(event.getErrorCode(), event.getErrorDescription(), null, null));
    return fields;
  }

}
