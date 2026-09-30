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
package se.swedenconnect.spring.authnserver.saml.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

import net.shibboleth.shared.xml.SerializeSupport;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;

/**
 * Sends a SAML response to the Service Provider with the HTTP POST binding, using a {@link ResponsePage}.
 *
 * @author Martin Lindström
 */
public class Saml2ResponseSender {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2ResponseSender.class);

  /** The response page. */
  private ResponsePage responsePage = new DefaultResponsePage();

  /**
   * Sends the response.
   *
   * @param httpServletRequest the HTTP request
   * @param httpServletResponse the HTTP response
   * @param destination the URL of the assertion consumer service
   * @param response the SAML response
   * @param relayState the relay state, or {@code null}
   * @throws UnrecoverableErrorException if the response cannot be sent
   */
  public void send(final @NonNull HttpServletRequest httpServletRequest,
      final @NonNull HttpServletResponse httpServletResponse, final @NonNull String destination,
      final @NonNull Response response, final @Nullable String relayState) throws UnrecoverableErrorException {

    final String encodedResponse = this.encodeResponse(response);
    try {
      this.responsePage.sendResponse(httpServletRequest, httpServletResponse, destination, encodedResponse,
          relayState);
    }
    catch (final IOException e) {
      log.error("Failed to send SAML Response to {} - {}", destination, e.getMessage(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to send Response message", e);
    }
  }

  /**
   * Assigns the response page. The default is a {@link DefaultResponsePage}.
   *
   * @param responsePage the response page
   */
  public void setResponsePage(final @NonNull ResponsePage responsePage) {
    this.responsePage = Objects.requireNonNull(responsePage, "responsePage must not be null");
  }

  /**
   * Marshalls and Base64 encodes the response.
   *
   * @param response the response
   * @return the encoded response
   * @throws UnrecoverableErrorException if the response cannot be marshalled
   */
  protected @NonNull String encodeResponse(final @NonNull Response response) throws UnrecoverableErrorException {
    try {
      final String xml = SerializeSupport.nodeToString(XMLObjectSupport.marshall(response));
      return Base64.getEncoder().encodeToString(xml.getBytes(StandardCharsets.UTF_8));
    }
    catch (final MarshallingException e) {
      log.error("Failed to encode Response message - {} [destination: '{}', in-response-to: '{}']",
          e.getMessage(), response.getDestination(), response.getInResponseTo(), e);
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to encode Response message", e);
    }
  }

}
