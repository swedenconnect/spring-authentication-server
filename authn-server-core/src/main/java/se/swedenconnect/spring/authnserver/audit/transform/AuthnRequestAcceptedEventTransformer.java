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

import se.swedenconnect.spring.authnserver.audit.AuthnAuditTypes;
import se.swedenconnect.spring.authnserver.audit.events.AuthnRequestAcceptedEvent;

/**
 * Transforms an {@link AuthnRequestAcceptedEvent} into an audit event of the type
 * {@code authn_request_accepted}. The data is the {@code requester} object and the protocol-specific
 * {@code authn_request} object.
 *
 * @author Martin Lindström
 */
public class AuthnRequestAcceptedEventTransformer extends AbstractAuthnEventTransformer<AuthnRequestAcceptedEvent> {

  /**
   * Constructor.
   */
  public AuthnRequestAcceptedEventTransformer() {
    super(AuthnRequestAcceptedEvent.class, AuthnAuditTypes.AUTHN_REQUEST_ACCEPTED);
  }

}
