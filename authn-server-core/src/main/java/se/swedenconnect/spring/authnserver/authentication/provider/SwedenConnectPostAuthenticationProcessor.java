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
package se.swedenconnect.spring.authnserver.authentication.provider;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;

/**
 * A {@link PostAuthenticationProcessor} that applies the rules of the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Swedish eID Framework</a> that do not depend on a
 * protocol.
 * <p>
 * It asserts that a sign message that had to be shown to the user actually was. The Deployment Profile, Section 7.1.1,
 * and the Signature Extension for OpenID Connect both require the operation to fail rather than complete with the
 * message unshown.
 * </p>
 *
 * @author Martin Lindström
 */
public class SwedenConnectPostAuthenticationProcessor implements PostAuthenticationProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SwedenConnectPostAuthenticationProcessor.class);

  /** {@inheritDoc} */
  @Override
  public void process(final @NonNull UserAuthentication authentication) throws AuthenticationErrorException {
    final AuthenticationRequirements requirements = authentication.getAuthnRequirements();
    if (requirements == null) {
      return;
    }
    final GenericSignMessage signMessage = requirements.getSignMessage();
    if (signMessage != null && signMessage.isMustShow()
        && !authentication.getAuthenticatedUser().isSignMessageDisplayed()) {
      log.info("Sign message was not displayed for '{}' - failing the operation",
          authentication.getAuthenticatedUser().getUsername());
      throw new AuthenticationErrorException(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED);
    }
  }

}
