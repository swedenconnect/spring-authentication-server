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
package se.swedenconnect.spring.authnserver.saml.authnrequest.validation;

import jakarta.annotation.Nonnull;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayChecker;
import se.swedenconnect.opensaml.saml2.response.replay.MessageReplayException;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.saml.authnrequest.Saml2AuthnRequestAuthenticationToken;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;

/**
 * Protects against replay: an authentication request whose ID has already been seen is rejected.
 *
 * @author Martin Lindström
 */
public class AuthnRequestReplayValidator implements AuthnRequestValidator {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(AuthnRequestReplayValidator.class);

  /** The replay checker. */
  private final MessageReplayChecker replayChecker;

  /**
   * Constructor.
   *
   * @param replayChecker the replay checker
   */
  public AuthnRequestReplayValidator(final @Nonnull MessageReplayChecker replayChecker) {
    this.replayChecker = Objects.requireNonNull(replayChecker, "replayChecker must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void validate(final @Nonnull Saml2AuthnRequestAuthenticationToken token) {
    try {
      this.replayChecker.checkReplay(token.getAuthnRequest().getID());
      log.debug("Replay check was successful [{}]", token.getLogString());
    }
    catch (final MessageReplayException e) {
      log.info("Replay of AuthnRequest was detected [{}]", token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.REPLAY_DETECTED);
    }
  }

}
