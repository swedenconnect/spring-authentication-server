![Logo](images/sweden-connect.png)

# Attributes

![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

-----

User authentication is implemented once and serves both SAML and OpenID Connect. The authentication step therefore
sees requested attributes, and produces user attributes, in a form that does not depend on the protocol. This page
describes that form, the mapping to and from SAML attributes and OpenID Connect claims, and how an application adds
attributes and mappings of its own.

## The generic attribute model

The model lives in `authn-server-core` and knows nothing about either protocol.

### Generic attribute

A `GenericAttribute` is an identifier and one or more values of the same Java type. Values are serializable, since the
authentication result is kept in the user session.

```java
GenericAttribute<String> surname = GenericAttribute.of(AttributeIdentifiers.SURNAME, "Lindeman");
GenericAttribute<LocalDate> dateOfBirth =
    GenericAttribute.of(AttributeIdentifiers.DATE_OF_BIRTH, LocalDate.of(1950, 6, 26));
```

An identifier is the prefix `attribute.` followed by a kebab-case name, for example
`attribute.personal-identity-number`. The identifiers of the built-in attributes are constants in
`AttributeIdentifiers`.

### Generic requested attribute

A `GenericRequestedAttribute` is what a requester asked for. It holds the identifier, whether the attribute is
essential ("required" in SAML, "essential" in OpenID Connect), the values that the requester will accept, and
protocol data.

Protocol data is data that only the protocol layer understands. The generic layer carries it and never looks at it.
The delivery target of an OpenID Connect claim, the ID token, the UserInfo endpoint or both, is such data:

```java
ClaimDeliveryTarget target = requested.getProtocolData(
    ClaimDeliveryTarget.PROTOCOL_DATA_KEY, ClaimDeliveryTarget.class);
```

The same attribute may be asked for in more than one place. Merging two requested attributes gives an attribute that
is essential if either of them was, and the protocol data of the second one replaces the data of the first, key by
key. Data that implements `MergeableProtocolData` decides the result for its key itself, which is how a claim asked
for in the ID token by one source and from the UserInfo endpoint by another ends up delivered in both places.

### Attribute definitions

An `AttributeDefinition` describes a generic attribute: its identifier, the Java type of its values, whether it may
hold more than one value, and a short description. The definitions of the built-in attributes are in
`BuiltInAttributeDefinitions`, and an `AttributeDefinitionRegistry` holds the ones an application knows about.

Values are typed where the specifications define a type. Dates, such as the date of birth, are `LocalDate`. Values
defined as seconds since epoch, such as the validity of a credential, are `Instant`. Values defined as booleans are
`Boolean`. Everything else is a `String`.

## Mapping

Mapping runs in both directions and is not one to one. One input may become several outputs, several inputs may
become one output, and the values may decide the result.

- A `FromProtocolAttributeMapper` maps a requested attribute from its protocol representation into the generic form.
  It is used for what a request or a metadata entry asked for. Such attributes usually carry no values, but they may.

- A `ToProtocolAttributeMapper` maps an attribute from the generic form into its protocol representation. It is used
  when the authentication step returns, so it maps attributes that have values.

A mapper declares the protocol names, or the generic identifiers, that it handles, and is called once per mapping
operation with the inputs that carry them. It is also given a context holding the attribute definitions and every
input of the operation, and, in the "to protocol" direction, the requested attributes.

An attribute that no mapper handles is left out of the result. That is not an error.

The SAML mappers are in `authn-server-saml` and work on the OpenSAML types. The OpenID Connect mappers are in
`authn-server-oidc` and work on the Nimbus types. The eIDAS attributes have a mapping of their own, see
[eIDAS attributes](#eidas-attributes) below.

```java
// SAML
SamlAttributeMapping saml = new SamlAttributeMapping();
List<GenericRequestedAttribute> requested = saml.toGenericFromRequestedAttributes(metadataRequestedAttributes);
List<Attribute> attributes = saml.toSaml(userAttributes, requested);

// OpenID Connect
OidcAttributeMapping oidc = new OidcAttributeMapping();
List<GenericRequestedAttribute> requested = oidc.toGenericFromClaimsRequest(claimsRequest);
List<UserClaim> claims = oidc.toClaims(userAttributes, requested);
```

## What a request asks for

The mapping above turns one requested attribute, or one claims request entry, into the generic form. Working out what
a whole request asks for is a step above that, and it has a resolver per protocol. The request processing calls the
resolver and puts the result in the authentication requirements, see
[Writing an authentication module](authentication-module.html).

### SAML

A Service Provider states what it needs in more than one place, and `SamlRequestedAttributeResolver` collects them
all:

- The `AttributeConsumingService` element of its metadata. The `AttributeConsumingServiceIndex` of the request picks
  the element, and without it the element marked as the default is used, failing that the one with the lowest index.
- The service entity categories it declares, which is the preferred way within the Swedish eID Framework.
- The `RequestedAttributes` extension of the request, both the one of the SAML protocol extension for requesting
  attributes and the eIDAS one.
- The `PrincipalSelection` extension, whose attributes become requested attributes carrying the given values. They
  are never essential. The requester is stating who the user is, not asking for the attribute to be released.

Each source has a `RequestedAttributeProcessor` of its own. An attribute that more than one source asks for appears
once in the result and is essential if any source said so.

```java
SamlRequestedAttributeResolver resolver = new SamlRequestedAttributeResolver(idpEntityCategories);
List<GenericRequestedAttribute> requested =
    resolver.resolve(new RequestedAttributeContext(authnRequest, spMetadata));
```

An eIDAS Proxy Service works with the eIDAS attribute names rather than the names of the Swedish eID Framework, so it
hands the mapping of `EidasAttributeMapping` to the constructor:

```java
SamlRequestedAttributeResolver resolver = new SamlRequestedAttributeResolver(
    new EidasAttributeMapping().getFromProtocolMapping(),
    SamlRequestedAttributeResolver.getDefaultProcessors(idpEntityCategories));
```

Pass a list of processors of your own to the same constructor to add a source, or to leave one out.

#### Entity categories

Only the categories that the Identity Provider itself declares are used, and every category brings the attributes of
its attribute set. The required attributes of the set are essential and the recommended ones are not.

A Service Provider may declare several categories while the Identity Provider delivers according to only one of them.
An attribute is therefore essential only when every declared category requires it, and an attribute that one of the
categories does not hold at all is never essential. This is the one exception to "essential if any source says so".

`EntityCategoryRequestedAttributeProcessor` knows the categories of
[Entity Categories for the Swedish eID Framework](https://docs.swedenconnect.se/technical-framework/latest/06_-_Entity_Categories_for_the_Swedish_eID_Framework.html).
To add a category of your own, hand it a registry holding the default categories and yours:

```java
List<EntityCategory> categories =
    new ArrayList<>(EntityCategoryRequestedAttributeProcessor.getDefaultEntityCategories());
categories.add(new ServiceEntityCategoryImpl("https://example.com/ec/own", loaUris, attributeSet));

EntityCategoryRequestedAttributeProcessor processor =
    new EntityCategoryRequestedAttributeProcessor(idpEntityCategories);
processor.setEntityCategoryRegistry(new EntityCategoryRegistryImpl(categories));
```

An entity category that is not in the registry, and one that is not a service entity category, asks for nothing.

### OpenID Connect

A client asks for claims by the scopes it requests and by the `claims` request parameter.
`OidcRequestedAttributeResolver` expands the scopes into the claims they stand for, merges the `claims` parameter in
and maps the result:

```java
OidcRequestedAttributeResolver resolver = new OidcRequestedAttributeResolver();
List<GenericRequestedAttribute> requested = resolver.resolve(scope, claimsRequest, logString);
```

A claim is essential if any source says so. Claims that are not user attributes, such as `sub`, `auth_time` and
`acr`, have no mapping and are left out, like any other claim that no mapper handles.

#### Where a claim is delivered

Section 4.2 of the Swedish OpenID Connect Profile decides this, and the answer is carried as the protocol data
`ClaimDeliveryTarget`:

- A claim of the `claims` parameter is delivered where the parameter says, `id_token` or `userinfo`.
- A claim of a scope is delivered where the scope definition says.
- Any other claim is delivered from the UserInfo endpoint.

When more than one source asks for the same claim the targets are combined. A claim asked for in the ID token by the
`claims` parameter is therefore also delivered from the UserInfo endpoint when a requested scope covers it, which is
what the profile requires.

#### The built-in scopes

`ScopeRegistry` holds the scopes that the OpenID Provider knows about, and `DefaultScopeRegistry` starts with the
built-in ones:

| Scope | Specification |
| :--- | :--- |
| `openid`, `profile`, `email`, `address`, `phone` | OpenID Connect Core, Section 5.4 |
| `https://id.oidc.se/scope/naturalPersonInfo` | Claims and Scopes Specification for the Swedish OpenID Connect Profile |
| `https://id.oidc.se/scope/naturalPersonNumber` | Claims and Scopes Specification for the Swedish OpenID Connect Profile |
| `https://id.oidc.se/scope/naturalPersonOrgId` | Claims and Scopes Specification for the Swedish OpenID Connect Profile |
| `https://id.oidc.se/scope/sign` | Signature Extension for OpenID Connect |
| `https://id.oidc.se/scope/signApproval` | Signature Extension for OpenID Connect |
| `https://id.swedenconnect.se/scope/eidasNaturalPersonIdentity` | OpenID Connect Claims and Scopes Specification for Sweden Connect |
| `https://id.swedenconnect.se/scope/eidasSwedishIdentity` | OpenID Connect Claims and Scopes Specification for Sweden Connect |

The `openid` scope asks for `sub`, and `signApproval` asks for no claims at all, so neither of them gives a requested
attribute. A scope that is not registered asks for nothing, which is not an error.

#### Adding a scope

A scope is an `OidcScopeValue`, which states its claims and, for each of them, whether it is essential and where it is
delivered by default. Register it, and a mapper for the claim if it is one of your own:

```java
ScopeRegistry scopes = new DefaultScopeRegistry();
scopes.register(new OidcScopeValue("https://example.com/scope/employee", new ClaimRequirement[] {
    ClaimRequirement.of("https://example.com/claim/employeeNumber", true, true, false) }));

OidcRequestedAttributeResolver resolver = new OidcRequestedAttributeResolver(oidcAttributeMapping, scopes);
```

The three flags of a `ClaimRequirement` are, in order, whether the claim is essential, whether it is delivered in the
ID token and whether it is delivered from the UserInfo endpoint. At least one of the two delivery flags must be set.
Registering a scope whose value is already registered replaces it, which is how a built-in scope is given a definition
of your own.

## Adding an attribute

Register a definition for it, and a mapper for each protocol it is to be released in.

```java
AttributeDefinitionRegistry definitions = new DefaultAttributeDefinitionRegistry();
definitions.register(AttributeDefinition.ofString("attribute.employee-number", "Employee number."));

SamlAttributeMapping saml = new SamlAttributeMapping(definitions);
AttributeTemplate template = new AttributeTemplate("urn:oid:1.2.3.4", "employeeNumber");
saml.getToProtocolMapping().register(new SamlToProtocolMapper("attribute.employee-number", template));
saml.getFromProtocolMapping().register(new SamlFromProtocolMapper("urn:oid:1.2.3.4", "attribute.employee-number"));

OidcAttributeMapping oidc = new OidcAttributeMapping(definitions);
oidc.getToProtocolMapping().register(
    new ClaimToProtocolMapper("attribute.employee-number", "https://example.com/claim/employeeNumber"));
oidc.getFromProtocolMapping().register(
    new ClaimFromProtocolMapper("https://example.com/claim/employeeNumber", "attribute.employee-number"));
```

`SamlToProtocolMapper`, `SamlFromProtocolMapper`, `ClaimToProtocolMapper` and `ClaimFromProtocolMapper` cover the
straightforward cases. Implement `ToProtocolAttributeMapper` or `FromProtocolAttributeMapper` directly when a
mapping needs more than that.

## Replacing a built-in mapper

Registering a mapper takes over every protocol name, or generic identifier, that it declares. Registering a mapper
for a name that a built-in mapper already held replaces it for that name.

```java
saml.getToProtocolMapping().register(new MyOwnSurnameMapper());
```

A mapper that produces a name that another mapper also produced is merged with it. SAML attributes with the same name
get the values of both, and claims that are JSON objects get the members of both.

Note that a built-in mapper handling several identifiers, such as the one building the OpenID Connect `address`
claim, is replaced for one identifier at a time. To take it over completely, register a mapper that declares every
identifier it declares.

## The built-in attributes

`Date` is a `LocalDate`, written as `YYYY-MM-DD` in SAML and in claims. `Instant` is written as an ISO-8601
timestamp in SAML and as seconds since epoch in claims, which is what the claim definitions call for.

A SAML attribute is given by its attribute name with the friendly name of the Attribute Specification for the Swedish
eID Framework below it. The friendly name is what the text below uses. A dash means that the attribute has no mapping
in that protocol.

Several generic attributes may map to the same SAML attribute or claim, and the cell then says how. "Joined with the
other name parts" means that this attribute is one of the parts that together make up the value, and the rules under
[Mapping rules](#mapping-rules) below say in what order. "The key `PoBox`" means that this attribute is one key of the
key-value list that the SAML attribute holds.

| Generic attribute | Type | SAML attribute | OpenID Connect claim |
| :--- | :--- | :--- | :--- |
| `attribute.surname` | String | `urn:oid:2.5.4.4`<br />`sn` | `family_name` |
| `attribute.given-name` | String | `urn:oid:2.5.4.42`<br />`givenName` | `given_name` |
| `attribute.middle-name` | String | - | `middle_name` |
| `attribute.display-name` | String | `urn:oid:2.16.840.1.113730.3.1.241`<br />`displayName` | `name` |
| `attribute.nickname` | String | - | `nickname` |
| `attribute.preferred-username` | String | - | `preferred_username` |
| `attribute.birth-name` | String | `urn:oid:1.2.752.201.3.8`<br />`birthName` | - |
| `attribute.birth-family-name` | String | `urn:oid:1.2.752.201.3.8`<br />`birthName`,<br />joined with the other name parts | `birth_family_name` |
| `attribute.birth-given-name` | String | `urn:oid:1.2.752.201.3.8`<br />`birthName`,<br />joined with the other name parts | `birth_given_name` |
| `attribute.birth-middle-name` | String | `urn:oid:1.2.752.201.3.8`<br />`birthName`,<br />joined with the other name parts | `birth_middle_name` |
| `attribute.`<br />`personal-identity-number` | String | `urn:oid:1.2.752.29.4.13`<br />`personalIdentityNumber` | `https://id.oidc.se/claim/`<br />`personalIdentityNumber` |
| `attribute.coordination-number` | String | `urn:oid:1.2.752.29.4.13`<br />`personalIdentityNumber` | `https://id.oidc.se/claim/`<br />`coordinationNumber` |
| `attribute.`<br />`coordination-number-level` | String | - | `https://id.oidc.se/claim/`<br />`coordinationNumberLevel` |
| `attribute.`<br />`previous-personal-identity-number` | String | `urn:oid:1.2.752.201.3.15`<br />`previousPersonalIdentityNumber` | - |
| `attribute.`<br />`previous-coordination-number` | String | `urn:oid:1.2.752.201.3.15`<br />`previousPersonalIdentityNumber` | `https://id.oidc.se/claim/`<br />`previousCoordinationNumber` |
| `attribute.`<br />`mapped-personal-identity-number` | String | `urn:oid:1.2.752.201.3.16`<br />`mappedPersonalIdentityNumber` | `https://id.swedenconnect.se/claim/`<br />`mappedPersonalIdentityNumber` |
| `attribute.`<br />`mapped-coordination-number` | String | `urn:oid:1.2.752.201.3.16`<br />`mappedPersonalIdentityNumber` | `https://id.swedenconnect.se/claim/`<br />`mappedCoordinationNumber` |
| `attribute.identity-binding` | String | `urn:oid:1.2.752.201.3.6`<br />`personalIdentityNumberBinding` | `https://id.swedenconnect.se/claim/`<br />`identityBinding` |
| `attribute.date-of-birth` | Date | `urn:oid:1.3.6.1.5.5.7.9.1`<br />`dateOfBirth` | `birthdate` |
| `attribute.place-of-birth` | String | `urn:oid:1.3.6.1.5.5.7.9.2`<br />`placeOfBirth` | `place_of_birth.locality`,<br />only when no part of the place of birth is known |
| `attribute.place-of-birth-country` | String | `urn:oid:1.3.6.1.5.5.7.9.2`<br />`placeOfBirth`,<br />joined with the other place parts | `place_of_birth.country` |
| `attribute.place-of-birth-region` | String | `urn:oid:1.3.6.1.5.5.7.9.2`<br />`placeOfBirth`,<br />joined with the other place parts | `place_of_birth.region` |
| `attribute.`<br />`place-of-birth-locality` | String | `urn:oid:1.3.6.1.5.5.7.9.2`<br />`placeOfBirth`,<br />joined with the other place parts | `place_of_birth.locality` |
| `attribute.gender` | String | `urn:oid:1.3.6.1.5.5.7.9.3`<br />`gender` | `gender` |
| `attribute.country-of-citizenship` | String,<br />multi-valued | `urn:oid:1.3.6.1.5.5.7.9.4`<br />`countryOfCitizenship` | `nationalities` |
| `attribute.country-of-residence` | String | `urn:oid:1.3.6.1.5.5.7.9.5`<br />`countryOfResidence` | - |
| `attribute.formatted-address` | String | - | `address.formatted` |
| `attribute.street-address` | String | `urn:oid:2.5.4.9`<br />`street` | `address.street_address` |
| `attribute.post-office-box` | String | `urn:oid:2.5.4.18`<br />`postOfficeBox` | `address.street_address` |
| `attribute.postal-code` | String | `urn:oid:2.5.4.17`<br />`postalCode` | `address.postal_code` |
| `attribute.locality` | String | `urn:oid:2.5.4.7`<br />`l` | `address.locality` |
| `attribute.region` | String | - | `address.region` |
| `attribute.country` | String | `urn:oid:2.5.4.6`<br />`c` | `address.country` |
| `attribute.eidas-address-po-box` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `PoBox` | `address.street_address` |
| `attribute.`<br />`eidas-address-locator-designator` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `LocatorDesignator` | `address.street_address` |
| `attribute.`<br />`eidas-address-locator-name` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `LocatorName` | `address.street_address` |
| `attribute.eidas-address-area` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `CvaddressArea` | `address.street_address` |
| `attribute.`<br />`eidas-address-thoroughfare` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `Thoroughfare` | `address.street_address` |
| `attribute.`<br />`eidas-address-post-name` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `PostName` | `address.locality` |
| `attribute.`<br />`eidas-address-admin-unit-first-line` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `AdminunitFirstline` | `address.country` |
| `attribute.`<br />`eidas-address-admin-unit-second-line` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `AdminunitSecondline` | `address.region` |
| `attribute.`<br />`eidas-address-post-code` | String | `urn:oid:1.2.752.201.3.9`<br />`eidasNaturalPersonAddress`,<br />the key `PostCode` | `address.postal_code` |
| `attribute.telephone-number` | String,<br />multi-valued | `urn:oid:2.5.4.20`<br />`telephoneNumber` | `phone_number` |
| `attribute.mobile-number` | String,<br />multi-valued | `urn:oid:0.9.2342.19200300.100.1.41`<br />`mobile` | `phone_number`, `msisdn` |
| `attribute.phone-number-verified` | Boolean | - | `phone_number_verified` |
| `attribute.email` | String,<br />multi-valued | `urn:oid:0.9.2342.19200300.100.1.3`<br />`mail` | `email` |
| `attribute.email-verified` | Boolean | - | `email_verified` |
| `attribute.organization-name` | String | `urn:oid:2.5.4.10`<br />`o` | `https://id.oidc.se/claim/`<br />`orgName` |
| `attribute.`<br />`organizational-unit-name` | String,<br />multi-valued | `urn:oid:2.5.4.11`<br />`ou` | `https://id.oidc.se/claim/`<br />`orgUnit` |
| `attribute.`<br />`organization-identifier` | String | `urn:oid:2.5.4.97`<br />`organizationIdentifier` | `https://id.oidc.se/claim/`<br />`orgNumber` |
| `attribute.`<br />`organizational-affiliation` | String,<br />multi-valued | `urn:oid:1.2.752.201.3.1`<br />`orgAffiliation` | `https://id.oidc.se/claim/`<br />`orgAffiliation` |
| `attribute.profile` | String | - | `profile` |
| `attribute.picture` | String | - | `picture` |
| `attribute.website` | String | - | `website` |
| `attribute.zone-info` | String | - | `zoneinfo` |
| `attribute.locale` | String | - | `locale` |
| `attribute.updated-at` | Instant | - | `updated_at` |
| `attribute.`<br />`eidas-person-identifier` | String | `urn:oid:1.2.752.201.3.7`<br />`eidasPersonIdentifier` | `https://id.swedenconnect.se/claim/`<br />`eidasPersonIdentifier` |
| `attribute.eidas-country` | String | `urn:oid:2.5.4.6`<br />`c`,<br />only when no country is known | `https://id.swedenconnect.se/claim/`<br />`eidasCountry` |
| `attribute.prid` | String | `urn:oid:1.2.752.201.3.4`<br />`prid` | `https://id.swedenconnect.se/claim/`<br />`prid` |
| `attribute.prid-persistence` | String | `urn:oid:1.2.752.201.3.5`<br />`pridPersistence` | `https://id.swedenconnect.se/claim/`<br />`pridPersistence` |
| `attribute.user-certificate` | String | `urn:oid:1.2.752.201.3.10`<br />`userCertificate` | `https://id.oidc.se/claim/`<br />`userCertificate` |
| `attribute.user-signature` | String | `urn:oid:1.2.752.201.3.11`<br />`userSignature` | `https://id.oidc.se/claim/`<br />`userSignature` |
| `attribute.`<br />`authentication-evidence` | String | `urn:oid:1.2.752.201.3.13`<br />`authServerSignature` | `https://id.oidc.se/claim/`<br />`authnEvidence` |
| `attribute.credential-valid-from` | Instant | - | `https://id.oidc.se/claim/`<br />`credentialValidFrom` |
| `attribute.credential-valid-to` | Instant | - | `https://id.oidc.se/claim/`<br />`credentialValidTo` |
| `attribute.device-ip` | String | - | `https://id.oidc.se/claim/`<br />`deviceIp` |
| `attribute.`<br />`authentication-provider` | String | - | `https://id.oidc.se/claim/`<br />`authnProvider` |
| `attribute.transaction-identifier` | String | `urn:oid:1.2.752.201.3.2`<br />`transactionIdentifier` | `txn` |
| `attribute.sad` | String | `urn:oid:1.2.752.201.3.12`<br />`sad` | - |
| `attribute.sign-message-digest` | String | `urn:oid:1.2.752.201.3.14`<br />`signMessageDigest` | - |
| `attribute.auth-context-params` | String | `urn:oid:1.2.752.201.3.3`<br />`authContextParams` | - |
| `attribute.employee-hsa-id` | String | `urn:oid:1.2.752.29.6.2.1`<br />`employeeHsaId` | - |

## Mapping rules

Several mappings need more than a name on each side.

### Personal identity numbers and coordination numbers

SAML uses `personalIdentityNumber` for both a Swedish personal identity number ("personnummer") and a coordination
number ("samordningsnummer"). OpenID Connect has a claim for each. The generic model follows OpenID Connect and has
an attribute for each.

- A requested SAML `personalIdentityNumber` becomes a request for both.
- Either attribute is released as SAML `personalIdentityNumber`. When both are present the personal identity number
  is used.
- When a value arrives in a form that does not say which kind it is, the number itself decides. A coordination number
  is issued with the day of the month increased by 60, see SKV 704 and SKV 707, so a day in the range 61 to 91 means
  a coordination number.

The same holds for `previousPersonalIdentityNumber` and for `mappedPersonalIdentityNumber`.
`previousPersonalIdentityNumber` reaches OpenID Connect only as `previousCoordinationNumber`, and so only when the
previous number is a coordination number.

### Birth name

SAML has one `birthName` attribute holding the full name. OpenID Connect has a claim for each part.

- SAML `birthName` gets the full birth name, or, when only the parts are known, the parts joined with a space in the
  order given name, middle name and family name.
- OpenID Connect gets the parts. A full birth name on its own is not split.

### Place of birth

- SAML `placeOfBirth` gets the free text place of birth, or, when only the parts are known, the parts joined with a
  comma and a space in the order locality, region and country, giving for example `Stockholm, SE`. Parts that are
  missing are skipped.
- The `place_of_birth` claim gets the parts in its `country`, `region` and `locality` fields. When the free text is
  the only thing known it is sent as `place_of_birth.locality`.

### Telephone numbers and e-mail

The claims `phone_number` and `email` hold one value each, while the SAML attributes may hold several.

- `email` gets the first mail value.
- `phone_number` gets the first mobile number, and the first telephone number when no mobile number is known.
- A requested `phone_number` becomes a request for both the telephone number and the mobile number.

More generally, a multi-valued attribute mapped to a claim that holds one value contributes its first value.

### Gender

The generic attribute uses the OpenID Connect values, `female` and `male`. The SAML values `M` and `F`, in either
case, are converted. The SAML value `U`, for an unspecified gender, is kept as the generic value `u` but has no claim
value and is not released in OpenID Connect.

### Country

The country and the eIDAS country are separate attributes.

- SAML `c` is released from the country, and from the eIDAS country when no country is known.
- `address.country` comes from the country, and the `eidasCountry` claim from the eIDAS country.

### The eIDAS address

The SAML attribute `eidasNaturalPersonAddress` holds the eIDAS `CurrentAddress` of a natural person as key-value
pairs separated by semicolons, where the key and the value are URL-encoded. Each key is a generic attribute of its
own, and a request for the SAML attribute is a request for all of them.

The attribute value is produced by OpenSAML, `CurrentAddressType.toSwedishEidString()`. Reading such a value back is
not supported there, so `EidasNaturalPersonAddress.parse()` does that.

### Transliteration

An eIDAS attribute value may be given twice, once in Latin script and once in the script of the member state, which
Section 2.4 of the eIDAS attribute specification calls transliteration. Section 3.3.3 of the Attribute Specification
for the Swedish eID Framework says that a value stating `LatinScript="false"` is not part of the converted attribute,
so such values are dropped when an attribute is read.

### The OpenID Connect address

Each part of the `address` claim is a generic attribute of its own, and a request for the claim is a request for all
of them, the parts of the eIDAS address included. The street address and the post office box both go into
`street_address`, which OpenID Connect Core allows to hold several lines. When both are known they are written on a
line each, the street address first.

The parts of the eIDAS address fill the claim too, since the OpenID Connect Claims and Scopes Specification for Sweden
Connect, Appendix A, maps the eIDAS `CurrentAddress` to `address`. `PostName` is the city, `AdminunitFirstline` the
country and `AdminunitSecondline` the level below that, which is what the eIDAS SAML Attribute Profile gives as the
equivalent of the country and region of residence.

`street_address` gets one line per part, in this order, skipping the parts that are missing:

1. `LocatorName`, a building, site or room name.
2. `Thoroughfare`, the street, followed by a space and `LocatorDesignator`, the building or apartment number, for
   example `Arcacia Avenue 22`. When only one of the two is known, that one alone is the line.
3. `CvaddressArea`.
4. `PoBox`.

When a generic address attribute and an eIDAS part would fill the same field of the claim, the generic attribute wins.
The two sets are never mixed within one field: a known generic street address or post office box means that
`street_address` holds those and none of the eIDAS lines.

## eIDAS attributes

eIDAS attributes are a third naming of the same information, used between the nodes of the eIDAS network. They are
mapped separately, by `EidasAttributeMapping` in `authn-server-saml`, and that is what an eIDAS Proxy Service uses:
it reads the requested attributes of an eIDAS authentication request and produces the eIDAS attributes of the
assertion it issues.

The mapping is kept apart from `SamlAttributeMapping` because the same generic attribute maps to a different
attribute in each of them. A surname is `urn:oid:2.5.4.4` in the Swedish eID Framework and
`http://eidas.europa.eu/attributes/naturalperson/CurrentFamilyName` in eIDAS, and one registry can hold only one
mapper per generic attribute. A server picks the mapping that fits what it is.

```java
EidasAttributeMapping eidas = new EidasAttributeMapping();
List<GenericRequestedAttribute> requested = eidas.toGenericFromRequestedAttributes(eidasRequestedAttributes);
List<Attribute> attributes = eidas.toEidas(userAttributes, requested);
```

There is no OpenID Connect counterpart. eIDAS attributes belong to SAML.

Only the attributes for natural persons are supported, see `EidasNaturalPersonAttributes`. The attributes for legal
persons, for representatives and for eJustice are not, and a request for one of them is left out like any other
attribute that no mapper handles.

eIDAS attributes do not use plain string values. Each has an XML type of its own, which is why an
`EidasAttributeTemplate` carries the type along with the name.

| eIDAS attribute | Value type | Generic attribute |
| :--- | :--- | :--- |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`PersonIdentifier` | `PersonIdentifierType` | `attribute.eidas-person-identifier` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`CurrentFamilyName` | `CurrentFamilyNameType` | `attribute.surname` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`CurrentGivenName` | `CurrentGivenNameType` | `attribute.given-name` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`DateOfBirth` | `DateOfBirthType` | `attribute.date-of-birth` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`BirthName` | `BirthNameType` | `attribute.birth-name` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`PlaceOfBirth` | `PlaceOfBirthType` | `attribute.place-of-birth` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`CountryOfBirth` | `CountryOfBirthType` | `attribute.place-of-birth-country` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`TownOfBirth` | `xs:string` | `attribute.place-of-birth-locality` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`CurrentAddress` | `CurrentAddressType` | the nine `attribute.eidas-address-*` attributes |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`Gender` | `GenderType` | `attribute.gender` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`Nationality` | `NationalityType` | `attribute.country-of-citizenship` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`CountryOfResidence` | `CountryOfResidenceType` | `attribute.country-of-residence` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`PhoneNumber` | `xs:string` | `attribute.telephone-number` |
| `http://eidas.europa.eu/`<br />`attributes/naturalperson/`<br />`EmailAddress` | `xs:string` | `attribute.email` |

Two values need converting. The gender is `Male`, `Female` or `Unspecified` in eIDAS and `male`, `female` or `u` in
the generic model, so nothing is lost, unlike in OpenID Connect where an unspecified gender has no claim value. The
address is the same `CurrentAddress` that the Swedish eID Framework carries as `eidasNaturalPersonAddress`, so the
nine parts are the same generic attributes in both mappings, and only the wrapping differs: a typed `CurrentAddress`
in eIDAS, the key-value string in the Swedish eID Framework.

## Attributes that exist in only one protocol

Not every attribute has a meaning in both protocols. An attribute with a mapping for only one of them is still a
generic attribute, and it is simply left out when the other protocol is used.

### SAML only

- `attribute.birth-name`
- `attribute.previous-personal-identity-number`
- `attribute.country-of-residence`
- `attribute.sad`
- `attribute.sign-message-digest`
- `attribute.auth-context-params`
- `attribute.employee-hsa-id`

### OpenID Connect only

- `attribute.middle-name`
- `attribute.nickname`
- `attribute.preferred-username`
- `attribute.coordination-number-level`
- `attribute.formatted-address`
- `attribute.region`
- `attribute.phone-number-verified`
- `attribute.email-verified`
- `attribute.profile`
- `attribute.picture`
- `attribute.website`
- `attribute.zone-info`
- `attribute.locale`
- `attribute.updated-at`
- `attribute.credential-valid-from`
- `attribute.credential-valid-to`
- `attribute.device-ip`
- `attribute.authentication-provider`

-----

Copyright &copy; 2026, [Sweden Connect](https://www.swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
