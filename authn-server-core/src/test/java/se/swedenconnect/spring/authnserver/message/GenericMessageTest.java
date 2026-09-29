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
package se.swedenconnect.spring.authnserver.message;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;

/**
 * Tests for {@link LocalizedMessage}, {@link GenericMessage}, {@link GenericUserMessage} and
 * {@link GenericSignMessage}.
 *
 * @author Martin Lindström
 */
class GenericMessageTest {

  static final String TBS_DATA = Base64.getEncoder().encodeToString("document-hash".getBytes());

  @Test
  void aMessageIsHeldBase64EncodedAndDecodedOnDemand() {
    final LocalizedMessage message = LocalizedMessage.ofText("sv", "Jag godkänner");
    assertThat(message.language()).isEqualTo("sv");
    assertThat(message.message())
        .isEqualTo(Base64.getEncoder().encodeToString("Jag godkänner".getBytes(StandardCharsets.UTF_8)));
    assertThat(message.getText()).isEqualTo("Jag godkänner");
    assertThat(message.getPrimaryLanguage()).isEqualTo("sv");
  }

  @Test
  void thePrimaryLanguageIsThePartBeforeTheHyphen() {
    assertThat(LocalizedMessage.ofText("sv-SE", "Hej").getPrimaryLanguage()).isEqualTo("sv");
    assertThat(LocalizedMessage.ofText(null, "Hello").getPrimaryLanguage()).isNull();
  }

  @Test
  void aMessageThatIsNotBase64OrIsEmptyIsRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new LocalizedMessage("sv", "not base64 ***"))
        .withMessage("message must be Base64 encoded");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new LocalizedMessage("sv", ""))
        .withMessage("message must be set and not empty");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new LocalizedMessage(" ", "SGVq"))
        .withMessage("language must not be empty");
  }

  @Test
  void aUserMessageHoldsOneMessagePerLanguage() {
    final GenericUserMessage message = new GenericUserMessage(
        List.of(LocalizedMessage.ofText(null, "Sign in"), LocalizedMessage.ofText("sv", "Logga in"),
            LocalizedMessage.ofText("en-GB", "Sign in")),
        MessageMimeType.TEXT_MARKDOWN);

    assertThat(message.getMimeType()).isEqualTo(MessageMimeType.TEXT_MARKDOWN);
    assertThat(message.getMessages()).hasSize(3);
    assertThat(message.getDefaultMessage()).isNotNull()
        .satisfies(m -> assertThat(m.getText()).isEqualTo("Sign in"));
    assertThat(message.toString()).contains("user-message", "text/markdown");
  }

  @Test
  void theMessageForALanguageIsPickedByExactThenPrimaryThenDefault() {
    final GenericUserMessage message = new GenericUserMessage(
        List.of(LocalizedMessage.ofText(null, "default"), LocalizedMessage.ofText("sv", "svenska"),
            LocalizedMessage.ofText("en-GB", "british")),
        null);

    assertThat(textOf(message, "sv")).isEqualTo("svenska");
    assertThat(textOf(message, "SV")).isEqualTo("svenska");
    assertThat(textOf(message, "en-GB")).isEqualTo("british");
    assertThat(textOf(message, "sv-SE")).isEqualTo("svenska");
    assertThat(textOf(message, "en")).isEqualTo("british");
    assertThat(textOf(message, "de")).isEqualTo("default");
    assertThat(textOf(message, null)).isEqualTo("default");
  }

  @Test
  void thereIsNothingToShowWhenNoLanguageMatchesAndThereIsNoDefault() {
    final GenericUserMessage message = new GenericUserMessage(List.of(LocalizedMessage.ofText("sv", "svenska")), null);
    assertThat(message.getMessage("de")).isNull();
    assertThat(message.getMessage(null)).isNull();
    assertThat(message.getDefaultMessage()).isNull();
  }

  @Test
  void aMissingMimeTypeMeansPlainText() {
    assertThat(new GenericUserMessage(List.of(LocalizedMessage.ofText("sv", "Hej")), null).getMimeType())
        .isEqualTo(MessageMimeType.TEXT_PLAIN);
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void missingMessagesAreRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new GenericUserMessage(List.of(), null))
        .withMessage("messages must not be empty");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new GenericUserMessage(null, null))
        .withMessage("messages must not be null");
  }

  @Test
  void moreThanOneMessageWithoutALanguageIsRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new GenericUserMessage(
            List.of(LocalizedMessage.ofText(null, "one"), LocalizedMessage.ofText(null, "two")), null))
        .withMessage("At most one message may be without a language");
  }

  @Test
  void aRepeatedLanguageIsRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new GenericUserMessage(
            List.of(LocalizedMessage.ofText("sv", "en"), LocalizedMessage.ofText("SV", "två")), null))
        .withMessage("A language must not appear more than once among the messages");
  }

  @Test
  void aSignMessageAddsMustShowAndTheDataToBeSigned() {
    final GenericSignMessage message = new GenericSignMessage(
        List.of(LocalizedMessage.ofText("sv", "Jag godkänner")), MessageMimeType.TEXT_HTML, true, TBS_DATA);

    assertThat(message.isMustShow()).isTrue();
    assertThat(message.getTbsData()).isEqualTo(TBS_DATA);
    assertThat(message.getTbsDataBytes()).isEqualTo("document-hash".getBytes());
    assertThat(message.getMimeType()).isEqualTo(MessageMimeType.TEXT_HTML);
    assertThat(message.toString()).contains("sign-message", "must-show=true");
  }

  @Test
  void aSignMessageWithoutDataToBeSignedIsTheSamlCase() {
    final GenericSignMessage message = GenericSignMessage.ofText(null, "Jag godkänner");
    assertThat(message.isMustShow()).isTrue();
    assertThat(message.getTbsData()).isNull();
    assertThat(message.getTbsDataBytes()).isNull();
    assertThat(message.getDefaultMessage()).isNotNull();
  }

  @Test
  void dataToBeSignedThatIsNotBase64IsRejected() {
    final List<LocalizedMessage> messages = List.of(LocalizedMessage.ofText("sv", "Jag godkänner"));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new GenericSignMessage(messages, null, true, "not base64 ***"))
        .withMessage("tbsData must be Base64 encoded");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new GenericSignMessage(messages, null, true, ""))
        .withMessage("tbsData must not be empty");
  }

  @Test
  void theMessagesSurviveSerialization() throws Exception {
    final GenericUserMessage userMessage = new GenericUserMessage(
        List.of(LocalizedMessage.ofText(null, "Sign in"), LocalizedMessage.ofText("sv", "Logga in")),
        MessageMimeType.TEXT_MARKDOWN);
    final GenericUserMessage restoredUserMessage = SerializationTestSupport.roundTrip(userMessage);
    assertThat(restoredUserMessage).isEqualTo(userMessage);
    assertThat(textOf(restoredUserMessage, "sv")).isEqualTo("Logga in");

    final GenericSignMessage signMessage = new GenericSignMessage(
        List.of(LocalizedMessage.ofText("sv", "Jag godkänner")), MessageMimeType.TEXT_HTML, true, TBS_DATA);
    final GenericSignMessage restoredSignMessage = SerializationTestSupport.roundTrip(signMessage);
    assertThat(restoredSignMessage).isEqualTo(signMessage);
    assertThat(restoredSignMessage.isMustShow()).isTrue();
    assertThat(restoredSignMessage.getTbsDataBytes()).isEqualTo("document-hash".getBytes());
  }

  @Test
  void aSignMessageIsNeverEqualToAUserMessage() {
    final List<LocalizedMessage> messages = List.of(LocalizedMessage.ofText("sv", "Hej"));
    final GenericMessage userMessage = new GenericUserMessage(messages, MessageMimeType.TEXT_PLAIN);
    final GenericMessage signMessage = new GenericSignMessage(messages, MessageMimeType.TEXT_PLAIN, false, null);

    assertThat(userMessage).isNotEqualTo(signMessage);
    assertThat(signMessage).isNotEqualTo(userMessage);
    assertThat(userMessage).isEqualTo(new GenericUserMessage(messages, MessageMimeType.TEXT_PLAIN))
        .hasSameHashCodeAs(new GenericUserMessage(messages, MessageMimeType.TEXT_PLAIN));
    assertThat(signMessage)
        .isEqualTo(new GenericSignMessage(messages, MessageMimeType.TEXT_PLAIN, false, null))
        .isNotEqualTo(new GenericSignMessage(messages, MessageMimeType.TEXT_PLAIN, true, null))
        .isNotEqualTo(new GenericSignMessage(messages, MessageMimeType.TEXT_PLAIN, false, TBS_DATA));
  }

  private static String textOf(final GenericMessage message, final String language) {
    if (message == null) {
      return null;
    }
    final LocalizedMessage localized = message.getMessage(language);
    return localized != null ? localized.getText() : null;
  }

}
