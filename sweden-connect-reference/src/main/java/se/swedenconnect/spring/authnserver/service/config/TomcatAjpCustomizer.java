/*
 * Copyright 2016-2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.service.config;

import java.util.Objects;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.ajp.AbstractAjpProtocol;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

/**
 * Adds a Tomcat AJP connector, when it is turned on.
 *
 * @author Martin Lindström
 */
public class TomcatAjpCustomizer implements WebServerFactoryCustomizer<TomcatServletWebServerFactory> {

  /** The AJP settings. */
  private final TomcatAjpProperties ajp;

  /**
   * Constructor.
   *
   * @param ajp the AJP settings
   */
  public TomcatAjpCustomizer(final @NonNull TomcatAjpProperties ajp) {
    this.ajp = Objects.requireNonNull(ajp, "ajp must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public void customize(final @NonNull TomcatServletWebServerFactory factory) {
    if (!this.ajp.isEnabled()) {
      return;
    }
    final Connector connector = new Connector("AJP/1.3");
    connector.setPort(this.ajp.getPort());
    connector.setAllowTrace(false);
    connector.setScheme("http");
    connector.setProperty("address", "0.0.0.0");
    connector.setProperty("allowedRequestAttributesPattern", ".*");

    final AbstractAjpProtocol<?> protocol = (AbstractAjpProtocol<?>) connector.getProtocolHandler();
    if (this.ajp.isSecretRequired()) {
      connector.setSecure(true);
      protocol.setSecretRequired(true);
      protocol.setSecret(this.ajp.getSecret());
    }
    else {
      connector.setSecure(false);
      protocol.setSecretRequired(false);
    }
    factory.addAdditionalConnectors(connector);
  }

}
