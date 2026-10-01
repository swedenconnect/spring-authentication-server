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
package se.swedenconnect.spring.authnserver.service.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.ajp.AbstractAjpProtocol;
import org.junit.jupiter.api.Test;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;

/**
 * Tests for {@link TomcatAjpCustomizer}.
 *
 * @author Martin Lindström
 */
class TomcatAjpCustomizerTest {

  @Test
  void noConnectorIsAddedWhenAjpIsOff() {
    final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
    new TomcatAjpCustomizer(new TomcatAjpProperties()).customize(factory);
    assertThat(factory.getAdditionalConnectors()).isEmpty();
  }

  @Test
  void anAjpConnectorIsAddedWhenAjpIsOn() {
    final TomcatAjpProperties ajp = new TomcatAjpProperties();
    ajp.setEnabled(true);
    ajp.setPort(8010);
    final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
    new TomcatAjpCustomizer(ajp).customize(factory);

    assertThat(factory.getAdditionalConnectors()).hasSize(1);
    final Connector connector = factory.getAdditionalConnectors().getFirst();
    assertThat(connector.getProtocol()).isEqualTo("AJP/1.3");
    assertThat(connector.getPort()).isEqualTo(8010);
    assertThat(connector.getSecure()).isFalse();
    assertThat(((AbstractAjpProtocol<?>) connector.getProtocolHandler()).getSecretRequired()).isFalse();
  }

  @Test
  void theSecretIsRequiredWhenConfigured() {
    final TomcatAjpProperties ajp = new TomcatAjpProperties();
    ajp.setEnabled(true);
    ajp.setSecretRequired(true);
    ajp.setSecret("secret");
    final TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
    new TomcatAjpCustomizer(ajp).customize(factory);

    final Connector connector = factory.getAdditionalConnectors().getFirst();
    assertThat(connector.getPort()).isEqualTo(8009);
    assertThat(connector.getSecure()).isTrue();
    final AbstractAjpProtocol<?> protocol = (AbstractAjpProtocol<?>) connector.getProtocolHandler();
    assertThat(protocol.getSecretRequired()).isTrue();
    assertThat(ajp.getSecret()).isEqualTo("secret");
    assertThat(ajp.isSecretRequired()).isTrue();
  }

}
