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

import org.jspecify.annotations.Nullable;
import org.springframework.util.StringUtils;

/**
 * What the user picker posts: the selected user and level of assurance, or the error to simulate.
 *
 * @author Martin Lindström
 */
public class SelectedUserModel {

  /** The personal identity number selected in the list. */
  private String personalIdentityNumber;

  /** A personal identity number entered in the advanced view. */
  private String customPersonalIdentityNumber;

  /** The level of assurance. */
  private String loa;

  /** The given name, entered in the advanced view. */
  private String givenName;

  /** The surname, entered in the advanced view. */
  private String surname;

  /** Whether the sign message was displayed. */
  private boolean signMessageDisplayed;

  /** The name of the error to simulate. */
  private String error;

  /** The error message to simulate. */
  private String errorMessage;

  /**
   * Gets the personal identity number of the selected user: the one selected in the list, or else the one entered in
   * the advanced view.
   *
   * @return the personal identity number, or {@code null}
   */
  public @Nullable String getPersonalIdentityNumber() {
    return StringUtils.hasText(this.personalIdentityNumber) && !"NONE".equals(this.personalIdentityNumber)
        ? this.personalIdentityNumber
        : StringUtils.hasText(this.customPersonalIdentityNumber) ? this.customPersonalIdentityNumber.trim() : null;
  }

  /**
   * Assigns the personal identity number selected in the list.
   *
   * @param personalIdentityNumber the personal identity number
   */
  public void setPersonalIdentityNumber(final @Nullable String personalIdentityNumber) {
    this.personalIdentityNumber = personalIdentityNumber;
  }

  /**
   * Assigns the personal identity number entered in the advanced view.
   *
   * @param customPersonalIdentityNumber the personal identity number
   */
  public void setCustomPersonalIdentityNumber(final @Nullable String customPersonalIdentityNumber) {
    this.customPersonalIdentityNumber = customPersonalIdentityNumber;
  }

  /**
   * Gets the level of assurance URI.
   *
   * @return the LoA URI
   */
  public @Nullable String getLoa() {
    return this.loa;
  }

  /**
   * Assigns the level of assurance URI.
   *
   * @param loa the LoA URI
   */
  public void setLoa(final @Nullable String loa) {
    this.loa = loa;
  }

  /**
   * Gets the given name.
   *
   * @return the given name
   */
  public @Nullable String getGivenName() {
    return this.givenName;
  }

  /**
   * Assigns the given name.
   *
   * @param givenName the given name
   */
  public void setGivenName(final @Nullable String givenName) {
    this.givenName = givenName;
  }

  /**
   * Gets the surname.
   *
   * @return the surname
   */
  public @Nullable String getSurname() {
    return this.surname;
  }

  /**
   * Assigns the surname.
   *
   * @param surname the surname
   */
  public void setSurname(final @Nullable String surname) {
    this.surname = surname;
  }

  /**
   * Tells whether the sign message was displayed.
   *
   * @return {@code true} if the sign message was displayed
   */
  public boolean isSignMessageDisplayed() {
    return this.signMessageDisplayed;
  }

  /**
   * Assigns whether the sign message was displayed.
   *
   * @param signMessageDisplayed {@code true} if the sign message was displayed
   */
  public void setSignMessageDisplayed(final boolean signMessageDisplayed) {
    this.signMessageDisplayed = signMessageDisplayed;
  }

  /**
   * Gets the name of the error to simulate, an {@code AuthenticationError} name.
   *
   * @return the error name
   */
  public @Nullable String getError() {
    return this.error;
  }

  /**
   * Assigns the name of the error to simulate.
   *
   * @param error the error name
   */
  public void setError(final @Nullable String error) {
    this.error = error;
  }

  /**
   * Gets the error message to simulate.
   *
   * @return the error message
   */
  public @Nullable String getErrorMessage() {
    return this.errorMessage;
  }

  /**
   * Assigns the error message to simulate.
   *
   * @param errorMessage the error message
   */
  public void setErrorMessage(final @Nullable String errorMessage) {
    this.errorMessage = errorMessage;
  }

  /**
   * Tells whether the tester entered a user of their own in the advanced view, that is, a personal identity number,
   * a given name and a surname.
   *
   * @return {@code true} if a user was entered, and {@code false} if one was selected in the list
   */
  public boolean isCustom() {
    return StringUtils.hasText(this.getPersonalIdentityNumber()) && StringUtils.hasText(this.givenName)
        && StringUtils.hasText(this.surname);
  }

}
