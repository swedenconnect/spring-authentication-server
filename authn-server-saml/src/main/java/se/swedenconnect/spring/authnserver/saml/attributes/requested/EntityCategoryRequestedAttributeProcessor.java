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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.saml2.attribute.AttributeTemplate;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeSet;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategory;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistry;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryRegistryImpl;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.ServiceEntityCategory;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlRequestedAttribute;

/**
 * Finds the attributes that the Service Provider asks for through the service entity categories it declares, see
 * <a href="https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
 * Categories for the Swedish eID Framework</a>.
 * <p>
 * Only categories that the Identity Provider itself declares are used, and every category brings the attributes of
 * its attribute set.
 * </p>
 * <p>
 * A Service Provider may declare several categories while the Identity Provider delivers according to only one of
 * them. An attribute is therefore required only when every declared category requires it. An attribute that one
 * category does not hold at all is never required.
 * </p>
 *
 * @author Martin Lindström
 */
public class EntityCategoryRequestedAttributeProcessor implements RequestedAttributeProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(EntityCategoryRequestedAttributeProcessor.class);

  /** The entity categories that the Identity Provider declares. */
  private final List<String> idpDeclaredEntityCategories;

  /** The entity categories that are known. */
  private EntityCategoryRegistry entityCategoryRegistry = getDefaultEntityCategoryRegistry();

  /**
   * Constructor.
   *
   * @param idpDeclaredEntityCategories the entity categories that the Identity Provider declares
   */
  public EntityCategoryRequestedAttributeProcessor(final @Nonnull Collection<String> idpDeclaredEntityCategories) {
    this.idpDeclaredEntityCategories = List.copyOf(
        Objects.requireNonNull(idpDeclaredEntityCategories, "idpDeclaredEntityCategories must not be null"));
  }

  /**
   * Assigns the registry of known entity categories. It defaults to the categories of the Swedish eID Framework, see
   * {@link #getDefaultEntityCategoryRegistry()}. Assign a registry of your own to add categories.
   *
   * @param entityCategoryRegistry the registry of known entity categories
   */
  public void setEntityCategoryRegistry(final @Nonnull EntityCategoryRegistry entityCategoryRegistry) {
    this.entityCategoryRegistry =
        Objects.requireNonNull(entityCategoryRegistry, "entityCategoryRegistry must not be null");
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull List<SamlRequestedAttribute> extractRequestedAttributes(
      final @Nonnull RequestedAttributeContext context) {

    final List<ServiceEntityCategory> categories =
        EntityDescriptorUtils.getEntityCategories(context.spMetadata()).stream()
            .distinct()
            .map(this.entityCategoryRegistry::getEntityCategory)
            .filter(Optional::isPresent)
            .map(Optional::get)
            .filter(ServiceEntityCategory.class::isInstance)
            .map(ServiceEntityCategory.class::cast)
            .filter(c -> this.idpDeclaredEntityCategories.contains(c.getUri()))
            .toList();

    if (categories.isEmpty()) {
      log.debug("No declared service entity category that this Identity Provider supports [{}]",
          context.getLogString());
      return List.of();
    }

    final Map<String, Candidate> candidates = new LinkedHashMap<>();
    for (final ServiceEntityCategory category : categories) {
      final AttributeSet attributeSet = category.getAttributeSet();
      if (attributeSet == null) {
        continue;
      }
      for (final AttributeTemplate template : attributeSet.getRequiredAttributes()) {
        candidates.computeIfAbsent(template.getName(), n -> new Candidate(template.getFriendlyName())).add(true);
      }
      for (final AttributeTemplate template : attributeSet.getRecommendedAttributes()) {
        candidates.computeIfAbsent(template.getName(), n -> new Candidate(template.getFriendlyName())).add(false);
      }
    }

    final List<SamlRequestedAttribute> attributes = new ArrayList<>(candidates.size());
    candidates.forEach((name, candidate) -> attributes.add(candidate.toRequestedAttribute(name, categories.size())));

    log.debug("Requested attributes from the service entity categories {}: {} [{}]",
        categories.stream().map(EntityCategory::getUri).toList(), attributes, context.getLogString());

    return attributes;
  }

  /**
   * Gets the entity categories of the Swedish eID Framework, see <a href=
   * "https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html">Entity
   * Categories for the Swedish eID Framework</a>.
   *
   * @return the entity categories of the Swedish eID Framework
   */
  public static @Nonnull List<EntityCategory> getDefaultEntityCategories() {
    return List.of(
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_PNR,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_PNR,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_PNR,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_NAME,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_NAME,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_NAME,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA2_ORGID,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA3_ORGID,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_LOA4_ORGID,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_EIDAS_NATURAL_PERSON,
        EntityCategoryConstants.SERVICE_ENTITY_CATEGORY_EIDAS_PNR_DELIVERY,
        EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_MOBILE_AUTH,
        EntityCategoryConstants.SERVICE_PROPERTY_CATEGORY_SCAL2,
        EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE,
        EntityCategoryConstants.SERVICE_TYPE_CATEGORY_PUBLIC_SECTOR_SP,
        EntityCategoryConstants.SERVICE_TYPE_CATEGORY_PRIVATE_SECTOR_SP,
        EntityCategoryConstants.SERVICE_CONTRACT_CATEGORY_SWEDEN_CONNECT,
        EntityCategoryConstants.SERVICE_CONTRACT_CATEGORY_EID_CHOICE_2017,
        EntityCategoryConstants.SERVICE_CONTRACT_CATEGORY_EID_AUTHZ_SYSTEM,
        EntityCategoryConstants.GENERAL_CATEGORY_SECURE_AUTHENTICATOR_BINDING,
        EntityCategoryConstants.GENERAL_CATEGORY_ACCEPTS_COORDINATION_NUMBER,
        EntityCategoryConstants.GENERAL_CATEGORY_SUPPORTS_USER_MESSAGE);
  }

  /**
   * Gets a registry holding the entity categories of the Swedish eID Framework.
   *
   * @return an {@link EntityCategoryRegistry}
   */
  public static @Nonnull EntityCategoryRegistry getDefaultEntityCategoryRegistry() {
    return new EntityCategoryRegistryImpl(getDefaultEntityCategories());
  }

  /**
   * An attribute found in the attribute set of at least one declared service entity category.
   */
  private static class Candidate {

    /** The attribute friendly name. */
    private final String friendlyName;

    /** The number of categories holding the attribute. */
    private int count = 0;

    /** Whether every category holding the attribute requires it. */
    private boolean alwaysRequired = true;

    /**
     * Constructor.
     *
     * @param friendlyName the attribute friendly name
     */
    Candidate(final String friendlyName) {
      this.friendlyName = friendlyName;
    }

    /**
     * Records that a category holds the attribute.
     *
     * @param required whether the category requires it
     */
    void add(final boolean required) {
      this.count++;
      this.alwaysRequired = this.alwaysRequired && required;
    }

    /**
     * Creates the requested attribute. It is required only when every declared category holds it and requires it.
     *
     * @param name the attribute name
     * @param numberOfCategories the number of declared categories
     * @return a {@link SamlRequestedAttribute}
     */
    @Nonnull SamlRequestedAttribute toRequestedAttribute(final @Nonnull String name, final int numberOfCategories) {
      return SamlRequestedAttribute.of(name, this.friendlyName,
          this.count == numberOfCategories && this.alwaysRequired);
    }

  }

}
