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
package se.swedenconnect.spring.authnserver.service.authn;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.registry.DisplayName;
import se.swedenconnect.spring.authnserver.registry.Logo;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Tests for {@link RequesterDisplay}.
 *
 * @author Martin Lindström
 */
class RequesterDisplayTest {

  @Test
  void theNameForTheLanguageIsUsedAndOtherwiseTheFirst() {
    final List<DisplayName> names = List.of(new DisplayName("sv", "Tjänsten"), new DisplayName("en", "The Service"));
    assertThat(RequesterDisplay.of(record(names, List.of()), "en").displayName()).isEqualTo("The Service");
    assertThat(RequesterDisplay.of(record(names, List.of()), "de").displayName()).isEqualTo("Tjänsten");
    assertThat(RequesterDisplay.of(record(List.of(), List.of()), "en"))
        .isEqualTo(new RequesterDisplay(null, null));
  }

  @Test
  void aLogoWiderThanItIsHighIsPreferred() {
    assertThat(logo(new Logo(null, "square", 256, 256), new Logo(null, "wide", 60, 200))).isEqualTo("wide");
  }

  @Test
  void aLogoOfMediumHeightIsUsed() {
    assertThat(logo(new Logo(null, "large", 256, 256), new Logo(null, "medium", 60, 60))).isEqualTo("medium");
  }

  @Test
  void theSmallestLargeLogoIsUsedBeforeTheLargestSmallLogo() {
    assertThat(logo(new Logo(null, "small", 30, 30), new Logo(null, "huge", 512, 512),
        new Logo(null, "large", 256, 256), new Logo(null, "smaller", 20, 20))).isEqualTo("large");
    assertThat(logo(new Logo(null, "smaller", 20, 20), new Logo(null, "small", 30, 30))).isEqualTo("small");
  }

  @Test
  void withoutSizesTheFirstLogoIsUsed() {
    assertThat(logo(Logo.of("first"), Logo.of("second"))).isEqualTo("first");
    assertThat(logo()).isNull();
  }

  @Test
  void theLogosOfTheLanguageAndThoseWithoutLanguageAreChosenAmong() {
    assertThat(logo(new Logo("sv", "sv-wide", 60, 200), new Logo("en", "en-medium", 60, 60)))
        .isEqualTo("en-medium");
    assertThat(logo(new Logo("sv", "sv-wide", 60, 200), Logo.of("plain"))).isEqualTo("plain");
    // No logo for the language, so all are chosen among
    assertThat(logo(new Logo("sv", "sv-wide", 60, 200), new Logo("de", "de", 300, 300))).isEqualTo("sv-wide");
  }

  private static String logo(final Logo... logos) {
    return RequesterDisplay.of(record(List.of(), List.of(logos)), "en").logoUrl();
  }

  private static RequesterRecord record(final List<DisplayName> names, final List<Logo> logos) {
    return new RequesterRecord(new Requester(AuthenticationProtocol.SAML, "https://sp.example.com"), names, logos,
        Set.of(), new Object());
  }

}
