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
import se.swedenconnect.spring.authnserver.audit.events.AuthnUserInfoDeliveredEvent;

/**
 * Transforms an {@link AuthnUserInfoDeliveredEvent} into an audit event of the type {@code authn_userinfo_delivered}.
 * The data is the {@code requester} object, the protocol-specific {@code response} object, and the
 * {@code released_attributes} list holding the released claims.
 *
 * @author Martin Lindström
 */
public class AuthnUserInfoDeliveredEventTransformer
    extends AbstractAuthnEventTransformer<AuthnUserInfoDeliveredEvent> {

  /**
   * Constructor.
   */
  public AuthnUserInfoDeliveredEventTransformer() {
    super(AuthnUserInfoDeliveredEvent.class, AuthnAuditTypes.AUTHN_USERINFO_DELIVERED);
  }

  /**
   * Adds the {@code released_attributes} list.
   */
  @Override
  protected @NonNull List<AuditValue<? extends Serializable>> getDataFields(
      final @NonNull AuthnUserInfoDeliveredEvent event) {
    final List<AuditValue<? extends Serializable>> fields = super.getDataFields(event);
    fields.add(attributes(AuthnSuccessResponseEventTransformer.RELEASED_ATTRIBUTES, event.getReleasedAttributes()));
    return fields;
  }

}
