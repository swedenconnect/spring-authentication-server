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
package se.swedenconnect.spring.authnserver.service.authn.model;

import java.util.List;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

/**
 * What the user picker shows.
 *
 * @author Martin Lindström
 */
public class UiModel {

  /** The display name of the requester, in the language of the page. */
  private String spDisplayName;

  /** The URL of the logotype of the requester. */
  private String spLogoUrl;

  /** The personal identity number of the user to pre-select. */
  private String selectedUser;

  /** Whether the pre-selected user is locked. */
  private boolean fixedSelectedUser = false;

  /** The levels of assurance to choose among. */
  private List<String> possibleAuthnContextUris = List.of();

  /** The level of assurance to pre-select. */
  private String selectedAuthnContextUri;

  /** Whether the requester is a signature service. */
  private boolean signature = false;

  /** The sign message, as HTML. */
  private String signMessage;

  /** The user message, as HTML. */
  private String userMessage;

  /**
   * Gets the display name of the requester.
   *
   * @return the display name, or {@code null}
   */
  public @Nullable String getSpDisplayName() {
    return this.spDisplayName;
  }

  /**
   * Assigns the display name of the requester.
   *
   * @param spDisplayName the display name
   */
  public void setSpDisplayName(final @Nullable String spDisplayName) {
    this.spDisplayName = spDisplayName;
  }

  /**
   * Gets the URL of the logotype of the requester.
   *
   * @return the URL, or {@code null}
   */
  public @Nullable String getSpLogoUrl() {
    return this.spLogoUrl;
  }

  /**
   * Assigns the URL of the logotype of the requester.
   *
   * @param spLogoUrl the URL
   */
  public void setSpLogoUrl(final @Nullable String spLogoUrl) {
    this.spLogoUrl = spLogoUrl;
  }

  /**
   * Gets the personal identity number of the user to pre-select.
   *
   * @return the personal identity number, or {@code null}
   */
  public @Nullable String getSelectedUser() {
    return this.selectedUser;
  }

  /**
   * Assigns the personal identity number of the user to pre-select.
   *
   * @param selectedUser the personal identity number
   */
  public void setSelectedUser(final @Nullable String selectedUser) {
    this.selectedUser = selectedUser;
  }

  /**
   * Tells whether the pre-selected user is locked, so that no other user can be chosen.
   *
   * @return {@code true} if the user is locked
   */
  public boolean isFixedSelectedUser() {
    return this.fixedSelectedUser;
  }

  /**
   * Assigns whether the pre-selected user is locked.
   *
   * @param fixedSelectedUser {@code true} if the user is locked
   */
  public void setFixedSelectedUser(final boolean fixedSelectedUser) {
    this.fixedSelectedUser = fixedSelectedUser;
  }

  /**
   * Gets the levels of assurance to choose among.
   *
   * @return the LoA URIs
   */
  public @NonNull List<String> getPossibleAuthnContextUris() {
    return this.possibleAuthnContextUris;
  }

  /**
   * Assigns the levels of assurance to choose among.
   *
   * @param possibleAuthnContextUris the LoA URIs
   */
  public void setPossibleAuthnContextUris(final @Nullable List<String> possibleAuthnContextUris) {
    this.possibleAuthnContextUris =
        possibleAuthnContextUris != null ? List.copyOf(possibleAuthnContextUris) : List.of();
  }

  /**
   * Gets the level of assurance to pre-select.
   *
   * @return the LoA URI, or {@code null}
   */
  public @Nullable String getSelectedAuthnContextUri() {
    return this.selectedAuthnContextUri;
  }

  /**
   * Assigns the level of assurance to pre-select.
   *
   * @param selectedAuthnContextUri the LoA URI
   */
  public void setSelectedAuthnContextUri(final @Nullable String selectedAuthnContextUri) {
    this.selectedAuthnContextUri = selectedAuthnContextUri;
  }

  /**
   * Tells whether the requester is a signature service.
   *
   * @return {@code true} for a signature service
   */
  public boolean isSignature() {
    return this.signature;
  }

  /**
   * Assigns whether the requester is a signature service.
   *
   * @param signature {@code true} for a signature service
   */
  public void setSignature(final boolean signature) {
    this.signature = signature;
  }

  /**
   * Gets the sign message as HTML.
   *
   * @return the HTML, or {@code null}
   */
  public @Nullable String getSignMessage() {
    return this.signMessage;
  }

  /**
   * Assigns the sign message as HTML.
   *
   * @param signMessage the HTML
   */
  public void setSignMessage(final @Nullable String signMessage) {
    this.signMessage = signMessage;
  }

  /**
   * Gets the user message as HTML.
   *
   * @return the HTML, or {@code null}
   */
  public @Nullable String getUserMessage() {
    return this.userMessage;
  }

  /**
   * Assigns the user message as HTML.
   *
   * @param userMessage the HTML
   */
  public void setUserMessage(final @Nullable String userMessage) {
    this.userMessage = userMessage;
  }

  /**
   * Tells whether the supplied user is the one to pre-select.
   *
   * @param id the personal identity number of the user
   * @return {@code true} if the user is to be pre-selected
   */
  public boolean isSelectedUser(final @Nullable String id) {
    return Objects.equals(id, this.selectedUser);
  }

  /**
   * Tells whether the supplied level of assurance is the one to pre-select.
   *
   * @param loa the LoA URI
   * @return {@code true} if the LoA is to be pre-selected
   */
  public boolean isSelectedLoa(final @Nullable String loa) {
    return Objects.equals(loa, this.selectedAuthnContextUri);
  }

}
