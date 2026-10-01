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
import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.AuthnSuccessResponseEvent;

/**
 * Transforms an {@link AuthnSuccessResponseEvent} into an audit event of the type {@code authn_success_response}.
 * The data is the {@code requester} object, the protocol-specific {@code response} object, and the
 * {@code released_attributes} list holding the released attributes by their protocol names.
 *
 * @author Martin Lindström
 */
public class AuthnSuccessResponseEventTransformer extends AbstractAuthnEventTransformer<AuthnSuccessResponseEvent> {

  /** The name of the list of the released attributes. */
  public static final String RELEASED_ATTRIBUTES = "released_attributes";

  /**
   * Constructor.
   */
  public AuthnSuccessResponseEventTransformer() {
    super(AuthnSuccessResponseEvent.class, AuthnAuditTypes.AUTHN_SUCCESS_RESPONSE);
  }

  /**
   * Adds the {@code released_attributes} list.
   */
  @Override
  protected @NonNull List<AuditValue<? extends Serializable>> getDataFields(
      final @NonNull AuthnSuccessResponseEvent event) {
    final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
    fields.add(attributes(RELEASED_ATTRIBUTES, event.getReleasedAttributes()));
    return fields;
  }

}
