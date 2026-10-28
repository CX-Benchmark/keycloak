# Threat model — Keycloak (github.com/cx-benchmark/keycloak, main @ 1d7be35d)

## system

Covers the whole repository at HEAD `1d7be35d0764060a8143fc74b0aabf2442743be4`; paths are relative to its root. "Out of view" = not opened; "not verified" = read but could not confirm.

Keycloak is an identity and access management server: it authenticates users for other applications (OIDC/OAuth 2.0, SAML 2.0, optionally Docker registry auth and OID4VC), issues and signs tokens/assertions, brokers external identity providers, federates LDAP/Kerberos/SSSD directories, and serves admin and account web consoles. It is multi-tenant by **realm**; the administrative realm (`master` by default) administers all others. Within a realm, **organizations** (`ORGANIZATION` feature, per-realm toggle) group members, domains and IdPs.

Main components (production code):
- **Runtime/launcher**: Quarkus application in `quarkus/` — `config-api` (all CLI/env options and defaults, e.g. `HttpOptions`, `HostnameV2Options`, `ProxyOptions`), `runtime` (`KeycloakMain`, `KeycloakRecorder`, property mappers, vault factories), `deployment` (build steps, `KeycloakProcessor`), `server` (app packaging, `application.properties`), `dist` (zip/tar with `bin/kc.sh`, `conf/keycloak.conf`, `providers/`, `themes/`), `container/Dockerfile`.
- **HTTP root resources** (JAX-RS, `services/src/main/java/org/keycloak/services/resources/`): `RealmsResource` (`/realms`), `admin/AdminRoot` (`/admin`), `ThemeResource` (`/resources`), `WelcomeResource` (`/`), `ServerMetadataResource` (`/.well-known`), `LoadBalancerResource` (`/lb-check`); plus `rest/admin-v2/.../AdminRootV2` (`/admin/api`) and `quarkus/runtime/.../DebugHostnameSettingsResource`.
- **Protocols**: `services/src/main/java/org/keycloak/protocol/` (`oidc`, `saml`, `docker`, `oid4vc`, `oauth2/cimd`), registered in `services/src/main/resources/META-INF/services/org.keycloak.protocol.LoginProtocolFactory`. SAML XML parsing/signing in `saml-core/`, `saml-core-api/`.
- **Login and flows**: `services/.../authentication/` (authenticators, client authenticators, required actions, action tokens), `LoginActionsService`, `IdentityBrokerService`, `services/.../broker/` (OIDC/SAML brokers), `services/.../social/`.
- **Admin REST API v1** (`services/.../resources/admin/`, permissions in `admin/fgap/`), admin extensions (`rest/admin-ui-ext`, `federation/ldap/.../resources/admin`, `model/storage-services`, `ssf/services/admin`); **Admin API v2** (`rest/admin-v2`, preview feature).
- **Account REST API and console** (`services/.../resources/account/`), **dynamic client registration** (`services/.../clientregistration/`), **Authorization Services/UMA** (`services/.../authorization/`, policy providers in `authz/policy/common`).
- **SCIM** (`scim/`), **AuthZEN** (`authzen/`), **Shared Signals transmitter** (`ssf/`), **workflows** (`services/.../workflow`, `model/jpa/.../workflow`).
- **Storage**: `model/jpa` (Hibernate + Liquibase changelogs), `model/infinispan` (caches, sessions; ProtoStream-annotated entities), `model/storage*`; SPIs in `server-spi`, `server-spi-private`; shared types/JOSE/`TokenVerifier` in `core/`; feature flags and utilities in `common/`.
- **Crypto**: `crypto/default` (BouncyCastle), `crypto/fips1402` (BC-FIPS), `crypto/elytron`.
- **Federation**: `federation/ldap`, `kerberos`, `sssd`, `ipatuura`.
- **Front ends**: FreeMarker themes in `themes/` (login, email, account, welcome, admin index); React SPAs `js/apps/admin-ui`, `js/apps/account-ui` with `js/libs/ui-shared`; npm library `js/libs/keycloak-admin-client`.
- **CLI**: `integration/client-cli` (`kcadm`/`kcreg`), packaged into the server dist (`quarkus/dist/pom.xml` depends on `keycloak-client-cli-dist`). Java admin client: `integration/admin-client*`.
- **Kubernetes operator**: `operator/` (Quarkus Operator SDK; CRDs `Keycloak`, `KeycloakRealmImport` in `crds/v2beta1`, `KeycloakOIDCClient`/`KeycloakSAMLClient` in `crds/v2alpha1`).
- **SAML SP adapters** for WildFly/EAP: `adapters/saml`, packaged by `distribution/saml-adapters` and `distribution/galleon-feature-packs` (only listed).

Principals the code trusts:
- The **server operator**: CLI options, env vars, `conf/keycloak.conf`, vault files (`FilesPlainTextVaultProvider`/`FilesKeystoreVaultProvider`), the database, the `providers/` and `themes/` directories.
- **Provider JARs**: loaded in the single application class loader with full privileges (`docs/guides/server/configuration-provider.adoc`).
- **Master-realm administrators**: can administer every realm through the per-realm `{realm}-realm` client roles (`MgmtPermissions.hasOneAdminRole`).
- **Cluster peers** (Infinispan/JGroups) and the **database**.
- **Reverse proxy**, only when `proxy-headers` is set (forwarded headers are otherwise not honoured).

Feature gating (`common/src/main/java/org/keycloak/common/Profile.java`): `Type.DEFAULT` features are on; `PREVIEW` only with the preview profile; `EXPERIMENTAL` and `DISABLED_BY_DEFAULT` are off (`isEnabledByDefault`). Relevant defaults:
- **On**: `ACCOUNT_API`, `ADMIN_API`, `ADMIN_FINE_GRAINED_AUTHZ_V2`, `IMPERSONATION`, `TOKEN_EXCHANGE_STANDARD_V2`, `JWT_AUTHORIZATION_GRANT`, `CLIENT_AUTH_FEDERATED`, `KUBERNETES_SERVICE_ACCOUNTS`, `CIBA`, `PAR`, `DEVICE_FLOW`, `DPOP`, `ORGANIZATION`, `WORKFLOWS`, `SCIM_API` (also needs per-realm `isScimApiEnabled`), `PASSKEYS`, `KERBEROS` (if the JDK supports it), `TWITTER_BROKER`, `IDENTITY_BROKERING_API_V1`.
- **Preview**: `SCRIPTS`, `TOKEN_EXCHANGE` v1, `TOKEN_EXCHANGE_DELEGATION`, `PARAMETERIZED_SCOPES`, `CLIENT_ADMIN_API_V2`, `OID4VC_VCI`, `SPIFFE`.
- **Experimental**: `AUTHZEN`, `SSF`, `CIMD`, `OID4VC_VP`, `OID4VC_VCI_PREAUTH_CODE`, `CLIENT_AUTH_ABCA`, `IDENTITY_ASSERTION_JWT`, `RESOURCE_INDICATORS`, `TRANSIENT_USERS`.
- **Disabled by default**: `DOCKER`, `FIPS`, `STATELESS`, `IDENTITY_BROKERING_API_V2`.
- Endpoints check flags either through `EnvironmentDependentProviderFactory.isSupported` (e.g. `AuthZenRealmResourceProviderFactory`, `SsfRealmResourceProviderFactory`, `ScimRealmResourceFactory`) or through `ProfileHelper.requireFeature`/`Profile.isFeatureEnabled` at the resource (e.g. `RealmsResource.getAuthorizationService`, `AdminRoot.isAdminApiEnabled`).

Build, ship, deploy (from the repository's own files):
- Maven multi-module build (`pom.xml` modules, profiles `distribution`, `operator`, `testsuite`, `adapters`, `docs`). JS is built with pnpm/wireit (`js/package.json`) and packaged as Maven modules (`js/pom.xml`).
- Server image `quarkus/container/Dockerfile`: `ubi9-micro` base, `java-21-openjdk-headless`, runs as UID 1000, sets `KC_RUN_IN_CONTAINER=true`, exposes 8080/8443/9000. Operator image `operator/Dockerfile`: Java 25, UID 1000.
- `RELEASES.md` lists the published artifacts: dist on GitHub Releases, images on quay.io, the operator on OperatorHub, Maven artifacts on Maven Central. It also says client libraries are released separately from the server.
- `.github/workflows` run build, test, CodeQL, dependency scans and labelling. No job publishing release artifacts was found, so the release pipeline is out of view.

## adversaries

Network reachability defaults:
- **HTTP listener off** in production: `HttpOptions.HTTP_ENABLED` defaults false. `HttpPropertyMappers.isHttpEnabled` forces it on in dev mode (`start-dev`) and in non-server commands.
- **Bind address**: `HttpPropertyMappers.getHttpHost` returns `0.0.0.0` when running in a container (the Dockerfile sets `KC_RUN_IN_CONTAINER`), under WSL or in remote dev. It returns `localhost` in dev mode, and otherwise defers to the Quarkus default.
- **Admin on the same port**: the admin console and Admin API are served on the same listener as the public endpoints (`AdminRoot` under `/admin`). `docs/documentation/server_admin/topics/threat/admin.adoc` concedes this.

### A1 — Anonymous network attacker (internet-facing browser or HTTP client)
Reaches every route below; the middle column gives what each one requires.
- **Global request filters**:
  - `RejectNonNormalizedPathFilter` rejects non-normalized paths and `;` (registered by `KeycloakRecorder.rejectNonNormalizedPathFilter` unless the deprecated `http-accept-non-normalized-paths` is true).
  - `MisdirectedFilter` (421 on SNI/authority mismatch). Only when HTTPS is on and `proxy-headers` is unset.
  - `RejectSourceMapFilter` (404 for `*.js.map`).
- **Realm resolution**: every `/realms/{realm}/…` locator resolves the realm by name and returns 404 when it is missing (`RealmsResource.resolveRealmAndUpdateSession`).
- **Built-in public clients** (`RealmManager.setupAdminConsole`/`setupAdminCli`), present in every realm including master:
  - `security-admin-console`: PKCE S256, redirect `/admin/{realm}/console/*`, full scope, lightweight tokens.
  - `admin-cli`: direct access (password) grant on, standard flow off, full scope.
  - The password grant at `…/openid-connect/token` is therefore reachable for every realm, master included, wherever `/realms/master/` is exposed.

| Entry point | Access the code requires | Where enforced |
|---|---|---|
| `GET /`, `/welcome-content/{path}` | anonymous | `WelcomeResource` |
| `POST /` (create the initial admin) | anonymous, but only before any admin exists, only when `isLocal` holds, and only with a matching `WELCOME_STATE_CHECKER` cookie | `WelcomeResource.createUser`, `isLocal` (no `X-Forwarded-For`/`Forwarded` header, local remote and local addresses; false for HTTPS in prod when neither `proxy-headers` nor `proxy-protocol-enabled` is set), `csrfCheck` |
| `/resources/{version}/{type}/{theme}/{path}`, `/resources/{realm}/{themeType}/{locale}` | anonymous | `ThemeResource`; path confinement in `theme/ResourceLoader` (`normalize()` + `startsWith(root)`) |
| `/realms/{realm}` (public realm info), `/.well-known/{alias}`, `/.well-known/{provider}/realms/{realm}` | anonymous; CORS allow-all on well-known | `PublicRealmResource`, `RealmsResource.getWellKnownResponse`, `ServerMetadataResource` |
| `/realms/{realm}/clients/{client_id}/redirect` | anonymous; 303 to the client's configured root/base URL | `RealmsResource.getRedirect` |
| `…/protocol/openid-connect/auth`, `/registrations`, `/forgot-credentials`, `/login-status-iframe.html`, `/3p-cookies`, `/certs`, `/oauth/oob` | anonymous | `OIDCLoginProtocolService`, `AuthorizationEndpoint` |
| `…/openid-connect/auth` with `request_uri` | anonymous; makes the server fetch the URL if it matches the client's `request.uris` (wildcard matcher `RedirectUtils.verifyRedirectUri`) | `AuthorizationEndpointRequestParserProcessor` |
| `…/openid-connect/token` | client authentication via `AuthorizeClientUtil.authorizeClient` (`TokenEndpoint.checkClient`). **Exceptions**: UMA grant and pre-authorized-code grant (`UMA_GRANT_TYPE`, `PRE_AUTH_GRANT_TYPE`) skip `checkClient` | `TokenEndpoint`, grant types in `protocol/oidc/grants` |
| `…/token/introspect` | authenticated confidential client | `TokenIntrospectionEndpoint.authorizeClient` |
| `…/userinfo` | bearer access token | `UserInfoEndpoint` |
| `…/revoke` | client authentication | `TokenRevocationEndpoint` |
| `…/logout` | anonymous (browser RP-initiated logout); the refresh-token POST branch requires client authentication | `LogoutEndpoint`, `logoutToken` |
| `…/ext/par/request`, `…/ext/ciba/auth` | client authentication | `ParEndpoint.authorizeClient`, `BackchannelAuthenticationEndpoint.authorizeClient` |
| `…/ext/ciba/auth/callback` | bearer token decoded with `session.tokens().decode` | `BackchannelAuthenticationCallbackEndpoint.verifyAuthenticationRequest` |
| `/realms/{realm}/device` (user-code page) | anonymous; the device authorization request requires client authentication | `DeviceEndpoint` (line ~394) |
| `/realms/{realm}/protocol/saml` (GET/POST), `/descriptor`, `/clients/{client}` (IdP-initiated) | anonymous. The request signature is checked only when the client sets `SAML_CLIENT_SIGNATURE_ATTRIBUTE` (`SamlClient.requiresClientSignature`) | `SamlService` |
| SAML artifact resolve / SOAP | anonymous. Artifact lookup goes through the single-use store; the signature is checked only if the client requires it | `SamlService.artifactResolve` |
| `/realms/{realm}/login-actions/*` (authenticate, reset-credentials, registration, required-action, consent, first/post-broker-login, restart, action-token) | anonymous. State is bound to the `AUTH_SESSION_ID` cookie and tab/session codes; action tokens are verified with a realm key (`SignatureProvider` by header alg/kid), `IS_ACTIVE` and realm-URL checks | `LoginActionsService`, `handleActionToken`, `LoginActionsServiceChecks` |
| `/realms/{realm}/broker/{alias}/endpoint`, `/login`, `/link` | anonymous (callback from the external IdP); per-provider validation | `IdentityBrokerService`, `broker/oidc`, `broker/saml/SAMLEndpoint` |
| `/realms/{realm}/broker/{alias}/token` | GET (v1): out of view. POST (v2, feature off): confidential client plus a verified user token whose audience includes the client | `IdentityBrokerService.getTokenV2` |
| `/realms/{realm}/clients-registrations/{provider}` | anonymous create allowed, subject to the realm's **anonymous** registration policies. Defaults from `DefaultClientRegistrationPolicies.addAnonymousPolicies`: Trusted Hosts with an empty list and host-must-match (checks the remote address, `TrustedHostClientRegistrationPolicy.verifyHost`), Consent Required, Full Scope Disabled, Max Clients, allowed mappers/scopes/web origins. Bearer (`manage-clients`/`create-client`), initial access token or registration access token otherwise | `ClientRegistrationAuth.requireCreate` and siblings |
| `/realms/{realm}/clients-managements/(un)register-node` | client authentication | `ClientsManagementService.authorizeClient` |
| `/realms/{realm}/account` (console HTML) | anonymous HTML; JSON goes through the bearer path (A4) | `AccountLoader.getAccountService` |
| `/admin/`, `/admin/{realm}/console/` (index, `messages.json`) | anonymous static console; `whoami` needs a bearer | `AdminRoot`, `AdminConsole` |
| `/lb-check` | anonymous; UP/DOWN only | `LoadBalancerResource` |
| `/realms/{realm}/hostname-debug` | anonymous, only when `hostname-debug` is true (default false) | `@EndpointDisabled` on `DebugHostnameSettingsResource` |
| `…/protocol/docker-v2/*` | feature `DOCKER` off by default; out of view | `protocol/docker` |
| OID4VC issuer endpoints (`OID4VCIssuerEndpoint`: nonce, credential-offer/{nonce}, credential) | preview feature. Offer creation and credential issuance go through `BearerTokenAuthenticator` (`getAuthResult`, `checkClientEnabled`). A code comment (~line 698) says fetching an offer by nonce needs no authenticated session. Per-method access not verified | `protocol/oid4vc/issuance` |
| Management interface, port 9000 (`/health`, `/metrics`) | off unless `health-enabled`/`metrics-enabled` (both default false, `HealthOptions`, `MetricsOptions`); authentication out of view (Quarkus extensions) | `ManagementOptions` |

What A1 targets:
- **OAuth/OIDC flow logic**: redirect_uri matching, PKCE, state/nonce, code reuse, DPoP.
- **SAML**: parsing, signature handling and XML-wrapping.
- **Login flow and action tokens**: flow step skipping, action-token replay.
- **Open redirect** via `/clients/{id}/redirect` and post-logout URIs.
- **XSS** in FreeMarker login and email templates.
- **Host-header influence** when `hostname-strict=false`.
- **Brute force**: off by default (`RealmManager.setupRealmDefaults`: `setBruteForceProtected(false)`).
- **Account enumeration.**
- **Costly unauthenticated requests**: SAML redirect binding is inflated with `maxInflatingSize` (`SamlService`); Quarkus limits are in `quarkus/runtime/src/main/resources/application.properties` (max header size 65535, initial line 32779, form attribute 131072).

### A2 — Malicious or compromised OAuth/SAML client (holds a client_id and possibly a secret, key or SA token)
- **Client authenticators**: `authentication/authenticators/client/` — client secret, signed JWT, client-secret JWT, X.509, federated JWT (`CLIENT_AUTH_FEDERATED`, default on), Kubernetes service-account tokens (`KUBERNETES_SERVICE_ACCOUNTS`, default on), attestation (`CLIENT_AUTH_ABCA`, experimental).
- **X.509 from proxy headers**: header-based certificate lookups (`services/.../x509/*ProxySslClientCertificateLookup`) exist alongside the TLS-session `default` provider.
- **Grants**: `protocol/oidc/grants` — authorization_code, refresh, client_credentials, password (ROPC), token exchange (standard v2 on, v1 preview), JWT authorization grant (on), CIBA, device, UMA permission, pre-authorized code.
- **Server-side fetches a client controls**: `request_uri` (above); `jwks_uri` (client key loaders); pairwise `sector_identifier_uri` (`protocol/oidc/mappers/PairwiseSubMapperHelper`).
- **Outbound client**: `DefaultHttpClientFactory` disables redirects by default (`ALLOW_REDIRECTS` false) and caps response size (`MAX_CONSUMED_RESPONSE_SIZE`). Its options include no destination allow/deny list; destination restriction is left to client policies (Secure Client URIs executors, per `threat/ssrf.adoc`).
- **Code and refresh-token handling** (`grants/AuthorizationCodeGrantType`):
  - Codes are single-use: `OAuth2CodeParser.parseCode` removes them from `session.singleUseObjects()`.
  - `redirect_uri` must equal the saved one.
  - PKCE is verified when a challenge method was stored (`PkceUtils.checkParamsForPkceEnforcedClient`); otherwise `checkParamsForPkceNotEnforcedClient` runs.
  - DPoP `jkt` binding is checked (`DPoPUtil.validateDPoPJkt`).
  - Refresh-token reuse limits apply only when the realm sets `revokeRefreshToken` (`TokenManager`, `getRefreshTokenMaxReuse`).
  - Standard token exchange requires the client attribute checked by `OIDCAdvancedConfigWrapper.isStandardTokenExchangeEnabled` (`StandardTokenExchangeProvider`).
- **What A2 targets**: scope/audience escalation, token exchange to other clients or users, impersonating another client under a shared domain, claim injection through mappers it controls via dynamic registration.

### A3 — Malicious external IdP, SAML IdP, LDAP server or other remote data source
- **Broker callbacks** feed external claims into first-broker-login and account linking.
- **SAML broker signature checks are opt-in per IdP**:
  - `SAMLEndpoint` verifies signatures only when `SAMLIdentityProviderConfig.isValidateSignature()` is true; assertion signatures are required only if `isWantAssertionsSigned()`.
  - Both read `Boolean.valueOf(config.get(...))`, so they are false when the key is absent.
- **OIDC broker signature check is opt-in**: `OIDCIdentityProviderConfig.isValidateSignature` is likewise false when absent.
- **JWT authorization grant and federated client auth** accept IdP-issued JWTs (`JWTAuthorizationGrantType`, `FederatedJWTClientValidator`).
- **IdP metadata import**: `IdentityProvidersResource.importFrom` makes the server fetch an admin-supplied URL. Error detail is limited to the HTTP status.
- **LDAP**:
  - Returned attributes are mapped into users; read-only attributes such as `LDAP_ID` are protected (`DeclarativeUserProfileProviderFactory.DEFAULT_READ_ONLY_ATTRIBUTES`).
  - Referral object factories are ignored when `secure-referral` is true (default, `LDAPStorageProviderFactory.init` → `ObjectFactoryBuilder`).
  - JNDI is enabled (`quarkus.naming.enable-jndi=true`).
- **Kerberos/SPNEGO**: `SpnegoAuthenticator`, `federation/kerberos`.
- **Twitter broker**: Java-deserializes its request token from a server-side auth note, with an allow-list filter (`TwitterIdentityProvider.base64DecodeRequestToken`).

### A4 — Authenticated end user of a realm (browser session or bearer token)
- **Account REST** (`/realms/{realm}/account/…`, `/account/v1…`): `AccountLoader.getAccountRestService` requires a bearer token (`BearerTokenAuthenticator`) whose audience includes the `account` client, and rejects service accounts. Each method then calls `auth.require`/`requireOneOf` for `manage-account`/`view-profile` etc. (`AccountRestService`, several call sites).
  - Exceptions: `supportedLocales` has no role check. `/credentials`, `/verifiable-credentials` and `/issued-verifiable-credentials` delegate role checks to their sub-resources (not verified per method).
- **Profile updates** go through the user profile with built-in read-only attributes for users (`EMAIL_VERIFIED`, `ENABLED`, `LDAP_*`, `KERBEROS_PRINCIPAL`, `saml.persistent.name.id.for.*`, …) in `DeclarativeUserProfileProviderFactory`.
- **Required actions and authenticated login flows**: `authentication/requiredactions` (update email/password/OTP, WebAuthn registration parsing CBOR via webauthn4j).
- **UMA protection API** (`/realms/{realm}/authz/protection/*`): `ProtectionService.createIdentity` requires a bearer and the `uma_protection` client role, unless the caller is the resource server itself.
- **Organizations**: membership and invites (`resources/account/OrganizationsResource`, action token `inviteorg`).

### A5 — Realm-scoped or limited administrator; another tenant (realm)
- **Admin token authentication** (`AdminRoot.authenticateRealmAdminRequest`):
  - The issuer realm is read from the unverified JWT, then the token is fully verified against that realm by `AuthenticationManager.verifyIdentityToken`: signature with realm key by `kid`/alg, issuer URL, expiry, `notBefore`, revocation (`TokenRevocationCheck`), a valid user session, the issuing client passing `isClientValid`, and `TokenManager.isUserValid`.
  - No audience check is applied.
- **CORS on the Admin API**: `AdminRoot.getRealmsAdmin` calls `Cors.builder().checkAllowedOrigins(auth.getToken())`, so allowed origins come from the admin token.
- **Cross-realm gate**: `RealmsAdminResource.getRealmAdmin` forbids a non-master admin from addressing another realm, and the `MgmtPermissions` constructor re-checks this for every evaluator.
- **Role checks** (`MgmtPermissions.hasOneAdminRole`):
  - Use `realm-management` client roles for same-realm admins and `{realm}-realm` roles in master.
  - `KeycloakIdentity(…, ignoreTokenRoles=true)` requires the role in the DB (`user.hasRole`), and also in the token's `resource_access` when the requesting client's scope lacks the role.
  - Fine-grained admin permissions v2 (`fgap/*V2`) are evaluated through Authorization Services.
- **Per-method pattern**: handlers call `auth.realm()/clients()/users()/groups()… .require*` (e.g. `IdentityProvidersResource`, `RealmAdminResource`, `TestLdapConnectionResource` → `requireManageRealm`, `rest/admin-ui-ext/SessionsResource`). Extensions get the same evaluator via `RealmAdminResource.extension`. Not verified for every one of the ~275 admin methods.
- **High-impact admin capabilities**:
  - realm import (`importRealm` needs `create-realm`), partial import, user impersonation (`IMPERSONATION` on);
  - LDAP/IdP/SMTP/test connections to arbitrary hosts (`TestLdapConnectionResource`, `IdentityProvidersResource.importFrom`, `RealmAdminResource.testSMTPConnection`);
  - key providers, component config (returned through `StripSecretsUtils` via `ModelToRepresentation.toRepresentation(…, internal=false)`), workflows, client policies, vault references.
- **Impersonation and workflows**:
  - `UserResource.impersonate` requires `auth.users().requireImpersonate(user)` and rejects service accounts.
  - The `WorkflowsResource` constructor requires `auth.requireRealmAdmin()`. Workflow conditions use an ANTLR expression grammar in `model/jpa/src/main/antlr4`.
- **Scripts cannot be uploaded**: JS authenticators, mappers and policies run only from deployed JARs (`DeployedScript*Factory`). `JSPolicyProviderFactory.throwCanNotUpdatePolicy` throws "Script upload is disabled" unless deployed; the session attribute it consults is never set in production code.
- **SCIM** (`/realms/{realm}/scim/v2/*`, feature on, per-realm opt-in):
  - `ScimRealmResourceFactory` requires a valid bearer, a non-public client, and audience `{frontend}/realms/{realm}/scim/v2`.
  - Authorization goes through `DefaultPermissions` → the same `AdminPermissions` evaluators (`BaseResourceTypeProvider.hasPermission`).
- **Admin API v2** (`/admin/api/{realm}/clients/v2`, preview): `DefaultAdminApi` authenticates, then checks permissions via `ClientResourceTypeProvider` → `DefaultPermissions`.
- **What A5 targets**: reaching another realm or the master realm, raising its own admin roles, IDOR across realms via IDs, reading secrets (client secrets, IdP secrets, LDAP bind credentials, private keys).

### A6 — Machine clients of experimental APIs
- **AuthZEN** (`/realms/{realm}/authzen/…/evaluation(s)`): `AuthZenResource.authenticateClient` requires the bearer to be the client's own service account obtained by client credentials.
- **SSF transmitter** (`/realms/{realm}/ssf/transmitter/*`):
  - `SsfAuthUtil` requires a receiver-configured, enabled client, by default its own service account, an optional required role, and `ssf.read`/`ssf.manage` scopes.
  - Push targets are validated by `SsfPushUrlValidator`: allow-list `ssf.validPushUrls` (bare `*` dropped), https only, DNS-resolved private/loopback/link-local addresses rejected. The https and address checks are skipped when `allow-insecure-push-targets` is set. Whether delivery re-resolves the host is not verified.
- **CIMD** (experimental client policy executor): fetches the client_id URL (`AbstractClientIdMetadataDocumentExecutor`, size-capped).

### A7 — Kubernetes user who can create operator custom resources
- Creating `Keycloak`/`KeycloakRealmImport`/`KeycloakOIDCClient`/`KeycloakSAMLClient` CRs in a watched namespace drives the operator to deploy servers, run realm-import Jobs (placeholders from Secrets, `KeycloakRealmImportSpec.placeholders`), and manage clients.
- Client management goes through Admin API v2, using the `<name>-admin` Secret's client credentials (`KeycloakClientBaseController.getAdminClient`).
- RBAC: `operator/src/main/kubernetes/kubernetes.yml` adds a ClusterRole for OpenShift ingress config; the rest is generated by the Operator SDK (out of view).

### A8 — Network peer inside the cluster/infrastructure
- **JGroups/Infinispan transport**: TLS by default (`CachingOptions.CACHE_EMBEDDED_MTLS_ENABLED` default true; the caching guide says the keys are stored in the DB and rotated).
- **Remote Infinispan**: has `cache-remote-tls-enabled`.
- **Management port 9000** (when enabled) and the database.

### A9 — Local or host-level
- **Who**: the operator or anyone with the server's config, the DB or the `providers/` directory (trusted, see out-of-scope).
- **JDWP debug**: `bin/kc.sh --debug` / `KC_DEBUG` adds JDWP at `address=$DEBUG_ADDRESS` (default `8787`). Off by default.
- **CLI config files**: `kcadm`/`kcreg` write them owner-only (`IoUtil.setUnixPermissions`).

**Left out**: individual routes beyond those above — ≈275 JAX-RS method annotations under `services/.../resources/admin`, 44 under `rest/`, 37 under `resources/account`, 49 under `services/.../authorization`, 30 under `ssf/`, 9 under `model/storage-services`, 9 workflow admin, 3 LDAP admin. All are reached through `AdminRoot`, `AccountLoader`, `RealmsResource.getAuthorizationService` or `RealmsResource.resolveRealmExtension` as described above.

## assets

1. **Token and assertion signing keys and other realm keys**:
   - Generated by key providers in `services/.../keys` and held in component config (DB); admin APIs strip secrets for non-internal representations (`ModelToRepresentation.toRepresentation(…, false)` → `stripSecrets`).
   - Used by `SignatureProvider` for access/ID/action tokens and by `saml-core` `XMLSignatureUtil` for SAML.
   - Forgery or key confusion breaks every relying party.
2. **Client credentials**: secrets, registration access tokens, initial access tokens (`ClientRegistrationAuth`), IdP client secrets (resolvable from the vault, e.g. `TwitterIdentityProvider` uses `session.vault()`).
3. **User credentials and authenticators**:
   - Password hashes: realm policy or the default `PasswordHashProvider`. Factories: Argon2 order 300 in `crypto/default`, PBKDF2-SHA512 order 200, PBKDF2-SHA256 100. Default selection by order is not verified; `threat/password-db-compromised.adoc` says PBKDF2-HMAC-SHA512.
   - OTP secrets, WebAuthn/passkey credentials, recovery codes.
4. **Sessions and cookies**: user/client sessions (Infinispan and DB, `PERSISTENT_USER_SESSIONS` on) and the cookies in `server-spi-private/.../cookie/CookieType`:
   - `KEYCLOAK_IDENTITY`, `AUTH_SESSION_ID`, `KC_RESTART`: `CookieScope.FEDERATION` = SameSite=None, HttpOnly.
   - `KEYCLOAK_SESSION`, `KC_AUTH_SESSION_HASH`: `FEDERATION_JS`, not HttpOnly.
   - `KC_STATE_CHECKER`: `INTERNAL` = SameSite=Strict.
   - `KEYCLOAK_IDENTITY` is a signed token verified by `verifyIdentityToken(isCookie=true)`.
5. **Action tokens and codes**: reset-credential, verify-email, execute-actions, IdP-link, org-invite tokens (`authentication/actiontoken/*`); single-use enforcement through `SingleUseObjectKeyModel`/single-use store (`JpaSingleUseObjectProvider` or Infinispan); authorization codes, device/user codes, CIBA auth_req_ids.
6. **Admin authority and realm isolation**: master-realm admin roles, the `realm-management` client roles, FGAP v2 permissions. Enforced in `RealmsAdminResource.getRealmAdmin`, the `MgmtPermissions` constructor and `hasOneAdminRole`, and `KeycloakIdentity`.
7. **Federated directory credentials and data**: LDAP bind DN/credential (component config, optionally vault), Kerberos keytabs (paths in config), synced PII.
8. **User PII and events**: user attributes, login/admin events (DB), organization membership.
9. **Server configuration secrets**: DB password, keystore/truststore passwords and vault passwords, loaded from CLI/env/`keycloak.conf`/keystore config source (`quarkus/runtime/.../configuration`).
   - `HttpOptions.HTTPS_KEY_STORE_PASSWORD` and `ManagementOptions.HTTPS_MANAGEMENT_KEY_STORE_PASSWORD` carry a hard-coded default value.
   - Vault keys: the default resolver `REALM_UNDERSCORE_KEY` prefixes the realm name (`AbstractVaultProviderFactory.init`); a configured `KEY_ONLY` resolver ignores the realm. Paths are confined to the vault directory (`FilesPlainTextVaultProvider.validate` compares normalized parents).
10. **Bootstrap admin**: on a new install `QuarkusKeycloakApplication.createTemporaryAdmin` creates a temporary master admin user/service account from `bootstrap-admin-*` options or the env vars; `WelcomeResource` allows local-only creation.
11. **Integrity of what is shipped**: server dist and images, operator image/OLM bundle, Maven artifacts, npm `@keycloak/keycloak-admin-client` and `@keycloak/keycloak-ui-shared`. Built by Maven/pnpm; the release pipeline is out of view.
12. **Availability of login/token endpoints**: shared by all realms on one server.

Trust boundaries and where they are enforced:
- **Internet ↔ server**: TLS (`https-*` options), the global path filters (`KeycloakRecorder`), per-realm `sslRequired` (default `EXTERNAL`, `RealmManager.setupRealmDefaults`; checked e.g. in `TokenEndpoint.checkSsl`, `RealmsResource.checkSsl`) and browser security headers. Realm defaults are set in `setupRealmDefaults` from `BrowserSecurityHeaders.realmDefaultHeaders` (X-Frame-Options SAMEORIGIN, CSP, nosniff, HSTS, Referrer-Policy no-referrer) and can be edited by realm admins.
- **Reverse proxy ↔ server**:
  - Forwarded headers are honoured only with `proxy-headers` (`ProxyOptions`); with it set, from **any** address unless `proxy-trusted-addresses` is set.
  - Client IPs feed `WelcomeResource.isLocal`, `TrustedHostClientRegistrationPolicy` and brute-force/event data.
  - Hostname: `hostname-strict` defaults true and `HostnameV2ProviderFactory` refuses to start without `hostname`. With `hostname-strict=false`, URLs derive from request headers.
- **Realm ↔ realm**: realm resolved from the path or the token issuer; admin cross-realm checks as above. Vault keys and key material are per realm.
- **User ↔ admin**: user profile read-only/admin-read-only attribute lists (`DeclarativeUserProfileProviderFactory`).
- **Server ↔ external IdPs/directories**: per-IdP signature flags (default off when unset), LDAP `secure-referral` (default on).
  - LDAP filter values are escaped by `ldap/idm/query/EscapeStrategy.DEFAULT` (via `NamedParameterCondition`); admin-configured custom filters are used as configured.
- **SAML signature semantics** (`saml-core/.../XMLSignatureUtil.validate`):
  - Every `ds:Signature` in the document must validate (key by `KeyName` hint, then every key from the locator).
  - The result is true only if the root is signed, or an `ArtifactResponse`'s single payload is signed, or every `saml:Assertion` is among the signed nodes.
  - Signed nodes are the first node of each reference after `propagateIDAttributeSetup`.
- **Server ↔ outbound URLs**: `DefaultHttpClientFactory` (no redirects, size cap, optional `proxy-mappings`, `disable-trust-manager` default false). Destinations are not filtered except by SSF's `SsfPushUrlValidator` and admin-configured client policies.
- **Templates ↔ user data**: FreeMarker HTML auto-escaping (see facts); `kcSanitize` (OWASP sanitizer, `KeycloakSanitizerMethod`) wherever templates use `?no_esc` (68 occurrences in `themes/src/main/resources`).
- **Server ↔ provider/extension code**: no boundary (same class loader).

## out-of-scope
What follows reports the repositories' own statements and exempts nothing from the audit.


Repository documents concede or require the following.
- **`SECURITY.md`**:
  - Experimental features: "the security team usually does not issue CVEs for experimental features. The preview state marks that the feature is mature enough to start normal security handling."
  - "Raw output from automated security scanners will **not** be accepted", and "We will reject reports based on static scanners or AI without a proof-of-concept."
  - Known CVEs in third-party libraries are reported as public GitHub issues.
  - Supported versions: depending on severity, a fix lands in the current `major.minor`, or for lower severity or hardening in the following `major.minor`.
- **`docs/features.md`**: experimental features are "not supported for production use-cases, only for evaluation purposes"; "A security review is required prior to graduating a feature to preview."
- **`docs/guides/server/configuration-provider.adoc`**: "Do not install untrusted provider JARs! … no built-in sandboxing … Providers can do whatever the server process can which includes direct access to the DB, reading all server configuration (incl. credentials)."
- **`docs/guides/server/reverseproxy.adoc`**:
  - Expose only `/realms/`, `/resources/`, `/.well-known/` and `/lb-check`. `/admin/` and `/realms/master/` "Only internally"; `/`, `/metrics`, `/health` not at all.
  - "You should not proxy port `9000`".
  - With `forwarded`/`xforwarded`, "make sure your reverse proxy properly sets and overwrites" those headers; "Misconfiguration will leave {project_name} exposed".
  - "By default, {project_name} accepts proxy headers from any source", and `proxy-trusted-addresses` is "only weak protection because IP addresses can be spoofed".
  - `--hostname-strict=false` "exposes {project_name} to Host header injection".
  - Header-based X.509 lookup with `trust-proxy-verification=true` without proxy chain verification "will expose {project_name} to a security vulnerability where a forged client certificate can be used".
- **`docs/documentation/server_admin/topics/threat/`**:
  - `admin.adoc`: "Do not expose administrative endpoints externally if external access is not necessary."
  - `brute-force.adoc`: "Brute force detection is disabled by default."
  - `ssrf.adoc`: SSRF via client URI fields (e.g. JWKS URI) by "a malicious administrator, a compromised account or a Dynamic Client Registration" is to be mitigated by admins with the Secure Client URIs (Pattern) client-policy executors.
  - `redirect.adoc`: make redirect URIs specific.
  - `host.adoc`: configure acceptable hostnames when no proxy validates Host.
- **`docs/guides/server/outgoinghttp.adoc`**: `disable-trust-manager` "never in production"; keep `allow-redirects` false to avoid SSRF.
- **`docs/guides/server/caching.adoc`**: "Disabling security is not recommended in production!" for the remote Infinispan connection. TLS is on by default only for TCP-based JGroups stacks; UDP/TCP_NIO2 need manual encryption.
- **`quarkus/runtime/src/main/resources/application.properties`**: the `%dev` profile is "Default, and insecure, and non-production grade" (`http-enabled=true`, `hostname-strict=false`, local cache, `dev-file` DB).
- **`docs/guides/server/bootstrap-admin-recovery.adoc`**: bootstrap admin accounts are *temporary* and "needs to be removed manually".
- **Deployer must**: provide TLS or an edge proxy (HTTP is off by default), set `hostname` (or explicitly `hostname-strict=false`), set `proxy-headers` correctly behind a proxy, enable brute-force protection per realm, and configure client policies against SSRF and redirect URIs.

## production

One line per top-level area of `github.com/cx-benchmark/keycloak`.
- **Server modules** (all bundled into the server via `quarkus/runtime/pom.xml` dependencies):
  - `services/` — production: core server (endpoints, protocols, flows, admin/account APIs, themes engine). Read (entry points and auth paths).
  - `server-spi/` — production: public SPIs and model interfaces (`RealmModel` …). Partly read.
  - `server-spi-private/` — production: internal SPIs, `AdminRoles`, `AccountRoles`, `AdminPermissionsSchema`, cookies, `BrowserSecurityHeaders`, `ModelToRepresentation`. Partly read.
  - `model/` — production: JPA (Liquibase `META-INF/jpa-changelog-master.xml`), Infinispan, storage. Partly read.
  - `saml-core/` — production: SAML parsers, `DocumentUtil`, `StaxParserUtil`, `XMLSignatureUtil`, also used by adapters. Partly read.
  - `saml-core-api/` — production: SAML model/constants. Only listed.
  - `federation/` — production: LDAP, Kerberos, SSSD, IPA-Tuura providers. Partly read.
  - `authz/` — `policy/common` production (policy providers bundled); `client/` is tests only (`keycloak-authz-client-tests`).
  - `scim/` — production except `tests/`. Partly read.
  - `authzen/` — production (experimental feature) except `tests/`. Read.
  - `ssf/` — production (experimental feature) except `tests/`. Partly read.
  - `rest/` — production: `admin-ui-ext` (on with `ADMIN_V2`) and `admin-v2` (preview). Partly read.
  - `themes/` — production: FreeMarker templates, messages, static assets served by `/resources`. Listed and grepped.
  - `crypto/` — production: `default` and `fips1402` are bundled (`quarkus/runtime/pom.xml`). `elytron` is unclassified: no consumer besides the root `pom.xml` was found.
  - `common/` — production: `Profile` features, utilities (`KerberosSerializationUtils`, `SslRequired`). Partly read.
  - `core/` — production: JOSE, `TokenVerifier`, representations, `JsonSerialization`; also used by published clients. Partly read.
- **Runtime and packaging**:
  - `quarkus/` — production: `config-api`, `runtime`, `deployment`, `server`, `dist`, `container`. `tests/` is tests.
  - `distribution/` — release packaging (`jboss-release`/`distribution` profiles): SAML adapter packs, downloads, licences, API docs. Only listed.
  - `boms/` — published Maven BOMs (packaging metadata).
  - `dependencies/` — `server-all`/`server-min` aggregator POMs (packaging metadata).
- **Other shipped code**:
  - `js/` — production: `apps/admin-ui`, `apps/account-ui`, `libs/ui-shared`, `themes-vendor` are bundled into the server (`quarkus/runtime/pom.xml` depends on `keycloak-admin-ui`/`keycloak-account-ui`). `libs/keycloak-admin-client` is published to npm (`publishConfig.access public`). `apps/keycloak-server` (dev server) and `apps/create-keycloak-theme` (scaffolding) are tooling.
  - `integration/` — production: Java admin client libraries, client-registration library, `client-cli` (shipped in the dist).
  - `operator/` — production: operator image, OLM bundle, Helm chart (built under the `operator` profile). `src/test` is tests. Partly read.
  - `adapters/` — production: SAML SP adapters for WildFly/EAP (built under the `adapters` profile). Only listed.
- **Tests and test tooling**:
  - `tests/` — tests (new suite). Not deployed.
  - `testsuite/` — tests (deprecated Arquillian suite, `testsuite/DEPRECATED.md`). Not deployed.
  - `test-framework/` — test tooling. JUnit framework modules (published for extension authors, except `test-framework/tests` with `maven-deploy-plugin skip`); includes server-side test providers (`remote-providers` `RunOnServerRealmResourceProviderFactory`, `TimeOffSetRealmResourceProviderFactory`) that are not in the server bundle.
  - `util/embedded-ldap` — test tooling (used by `testsuite`).
- **Tooling and docs**:
  - `misc/` — tooling: `db-compatibility-verifier` and `theme-verifier` (build-time checks), scripts, log trimmer, rewrite recipes.
  - `docs/` — documentation: guides, server admin manual, release notes. Read where cited.
  - `.github/` — CI workflows, CodeQL/Snyk/Trivy config, issue templates, `copilot-instructions.md`. Tooling.
  - `.mvn/`, `mvnw`, `mvnw.cmd`, `maven-settings.xml`, `pom.xml` — build tooling (root POM defines modules and profiles).
  - `set-version.sh`, `get-version.sh` — release-versioning scripts (tooling).
  - `.trivy/`, `.gitleaks.toml`, `.cveignore.yaml` — scanner configuration (tooling).
  - `.idea/` — IDE settings (tooling).
  - `skills/` and `.claude/` (symlink to `skills`) — AI-agent instruction files for translation review and release notes. Tooling; content decides nothing.
- **Root documents** (README, SECURITY, CONTRIBUTING, GOVERNANCE, RELEASES, …) — documentation.

## facts

Repository `github.com/cx-benchmark/keycloak`:
- **Security policy**: present — `SECURITY.md` (report to the project security mailing list; no bug bounty), plus `SECURITY-INSIGHTS.yml` (`expiration-date` 2025-02-14).
- **Template escaping**:
  - FreeMarker (`services/.../theme/freemarker/DefaultFreeMarkerProvider.getTemplate`): `HTMLOutputFormat` auto-escaping for templates ending `.ftl` (this includes text emails, which are `.ftl` too).
  - `setNewBuiltinClassResolver(ALLOWS_NOTHING_RESOLVER)`; `kcSanitize` is injected into every data map.
  - The admin and account consoles are React (JSX escaping). `dangerouslySetInnerHTML` and `innerHTML` were not found in `js/apps` or `js/libs` sources.
- **Serialization**:
  - **JSON**: Jackson via `core/.../util/JsonSerialization` (no default typing; no `JsonTypeInfo.Id.CLASS` or `activateDefaultTyping` found in production modules).
  - **XML/SAML**: StAX from `StaxParserUtil.getXMLInputFactory` (`SUPPORT_DTD=false`, `IS_SUPPORTING_EXTERNAL_ENTITIES=false`); DOM from `DocumentUtil.getDocumentBuilderFactory` (`disallow-doctype-decl` true, external general/parameter entities false, XInclude off); `TransformerUtil` sets `FEATURE_SECURE_PROCESSING` and empty external DTD/stylesheet access. `AbstractParser`'s own unhardened `XMLInputFactory` is used only for `createFilteredReader` over an already-created reader.
  - **Cache entities**: Infinispan ProtoStream (81 annotated files in `model/infinispan`).
  - **CBOR**: WebAuthn attestation parsed by webauthn4j/jackson-cbor.
  - **Java serialization**: only `TwitterIdentityProvider.base64DecodeRequestToken` and `common/.../KerberosSerializationUtils.deserialize`, both with `DelegatingSerializationFilter` allow-lists. No server-side caller of `deserializeCredential` was found.
  - **YAML**: snakeyaml is a runtime dependency (`quarkus/runtime/pom.xml`); no direct use found in production Java.
- **Authentication and sessions**:
  - Browser SSO: `KEYCLOAK_IDENTITY` cookie (signed JWT) plus user sessions; login state in authentication sessions keyed by `AUTH_SESSION_ID` (`AuthenticationSessionManager`).
  - APIs: bearer access tokens verified by `AuthenticationManager.verifyIdentityToken` (via `AppAuthManager.BearerTokenAuthenticator`, with DPoP binding through `DPoPUtil.withDPoPVerifier`).
  - Clients: `AuthorizeClientUtil.authorizeClient` with pluggable client authenticators.
  - Admin authority: `MgmtPermissions`/`KeycloakIdentity` and FGAP v2.
- **Exposure-changing defaults**:
  - Listener: `http-enabled` false (dev true); HTTPS port 8443, HTTP 8080, management 9000; `https-client-auth` none; TLS 1.3/1.2.
  - Hostname and proxy: `hostname-strict` true; `hostname-debug` false; `proxy-headers` unset; `proxy-trusted-addresses` unset (all trusted once headers are on); `http-accept-non-normalized-paths` false.
  - Off by default: `health-enabled`, `metrics-enabled`, `openapi-enabled`, `openapi-ui-enabled`; `fips-mode` disabled.
  - Cluster: `cache-embedded-mtls-enabled` true.
  - Outbound client: `allow-redirects` false; `disable-trust-manager` false.
  - Realm defaults (`RealmManager.setupRealmDefaults`): brute force off, `sslRequired=EXTERNAL`, login with email allowed, event listener `jboss-logging`.
  - Feature defaults as listed under system.
  - Sources: `quarkus/config-api/.../*Options.java`, `quarkus/runtime/src/main/resources/application.properties`, `DefaultHttpClientFactory`.
- **Build and hardening**:
  - Java/Maven build (`pom.xml`); the server image runs as non-root UID 1000 on `ubi9-micro` with Java 21 (operator Java 25).
  - Optional FIPS via `crypto/fips1402` and `fips-mode`.
  - Quarkus HTTP limits and the `;`-in-path rejection, `use-semicolon-as-query-param-delimiter=false`, `host-validation.require-localhost=false` (`application.properties`).
  - CI scanners: CodeQL (`.github/workflows/codeql-analysis.yml`), Trivy/Snyk/Dependabot (`SECURITY-INSIGHTS.yml`, `.github/workflows/scan-dependencies.yml`).
  - `pull_request_target` workflows (`label.yml`, `translation-notify.yml`) run only on closed/merged PRs, use the default (base) checkout, and scoped tokens (`issues: write`, `pull-requests: write`).
- **Where routes, schemas and permissions are defined**:
  - JAX-RS `@Path` root resources as listed under system.
  - Realm sub-resources via `RealmResourceProviderFactory` and `AdminRealmResourceProviderFactory` service files (`*/src/main/resources/META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory`, `…admin.ext.AdminRealmResourceProviderFactory`); OIDC extensions via `org.keycloak.protocol.oidc.ext.OIDCExtProviderFactory` (PAR, CIBA).
  - Roles in `server-spi-private/.../models/AdminRoles.java` and `AccountRoles.java`; FGAP v2 resource types/scopes in `server-spi-private/.../authorization/fgap/AdminPermissionsSchema.java`.
  - DB schema in `model/jpa/src/main/resources/META-INF/jpa-changelog-*.xml`.
  - CLI options in `quarkus/config-api/src/main/java/org/keycloak/config/`.
  - Feature flags in `common/.../Profile.java`.
- **Languages** (tracked files):
  - Java ≈ 1.28 M lines (≈ 90% of code lines; ≈ 515 k of them under `src/test`).
  - TypeScript/TSX ≈ 126 k (≈ 9%, `js/`).
  - FreeMarker ≈ 6.5 k; JavaScript ≈ 2 k.
  - Also ≈ 129 k lines of `.properties` (mostly message bundles) and 680 AsciiDoc files.
  - Largest code areas: `services` 248 k, `testsuite` 234 k, `tests` 223 k, `js` 127 k, `model` 123 k lines.







<!-- written at these commits:
1d7be35d0764060a8143fc74b0aabf2442743be4 https://github.com/cx-benchmark/keycloak
-->
