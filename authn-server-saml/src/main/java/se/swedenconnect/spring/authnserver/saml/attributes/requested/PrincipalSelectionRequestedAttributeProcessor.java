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
package se.swedenconnect.spring.authnserver.saml.attributes.requested;

import jakarta.annotation.Nonnull;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.sweid.saml2.authn.psc.MatchValue;
import se.swedenconnect.opensaml.sweid.saml2.authn.psc.PrincipalSelection;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes of the {@code PrincipalSelection} extension of the request, see <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/14_-_Principal_Selection_in_SAML_Authentication_Requests.html">Principal
 * Selection in SAML Authentication Requests</a>.
 * <p>
 * The extension tells the Identity Provider which user the requester expects, so each of its attributes becomes a
 * requested attribute carrying the given value. Such an attribute is never required. The requester is stating who the
 * user is, not asking for the attribute to be released.
 * </p>
 *
 * @author Martin Lindström
 */
public class PrincipalSelectionRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(PrincipalSelectionRequestedAttributeProcessor.class);

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<SamlRequestedAttribute> extractRequestedAttributes(
      final @Nonnull RequestedAttributeContext context) {

    final PrincipalSelection principalSelection = RequestExtensions.getExtension(
        context.authnRequest(), PrincipalSelection.DEFAULT_ELEMENT_NAME, PrincipalSelection.class);
    if (principalSelection == null) {
      return List.of();
    }
    final List<SamlRequestedAttribute> attributes = new ArrayList<>();
    for (final MatchValue matchValue : principalSelection.getMatchValues()) {
      if (matchValue.getName() == null || matchValue.getValue() == null) {
        log.info("Ignoring PrincipalSelection MatchValue that lacks a name or a value [{}]", context.getLogString());
        continue;
      }
      attributes.add(SamlRequestedAttribute.of(matchValue.getName(), null, false, List.of(matchValue.getValue())));
    }

    log.debug("Requested attributes from the PrincipalSelection extension: {} [{}]",
        attributes, context.getLogString());

    return attributes;
  }

}
