# SSF subject subscription state kept in user-editable attributes lets users suppress their own security events

| Field | Value |
|---|---|
| ID | `find_01ByNrTTSpmmPDy1t1m1DcUR` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-642 — External control of critical state |
| Created | 2026-10-27T22:10:13.364960Z |
| Claude Security | https://claude.ai/security/findings/find_01ByNrTTSpmmPDy1t1m1DcUR |

## Description

A logged-in realm user can switch off the security event signals that receivers get about their own account, such as credential changes, session revocations and account disabling. They can also force events to a receiver the operator never subscribed. This works only in a realm whose user profile has `unmanagedAttributePolicy=ENABLED` and that has an SSF receiver stream. The subscription state sits in user-editable attributes `ssf.notify.<receiverClientId>`, which the user profile does not protect.

1. **attacker (realm user or someone holding the user's session)** sends an account update through the Account REST API. The request is `POST /realms/{realm}/account` with `attributes: {"ssf.notify.<receiverClientId>": ["false"]}`. ([`server-spi-private/src/main/java/org/keycloak/userprofile/DefaultAttributes.java:123-131`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/server-spi-private/src/main/java/org/keycloak/userprofile/DefaultAttributes.java#L123-L131))
2. **user profile** accepts the attribute as an unmanaged attribute. The built-in read-only attribute patterns do not cover `ssf.*`, and with `unmanagedAttributePolicy=ENABLED` the account context may edit unmanaged attributes. ([`services/src/main/java/org/keycloak/userprofile/DeclarativeUserProfileProviderFactory.java:103-104`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/services/src/main/java/org/keycloak/userprofile/DeclarativeUserProfileProviderFactory.java#L103-L104))
3. **`SsfNotifyAttributes`** reads the stored attribute as the subscription state. `isUserNotified` and `isUserExcluded` read the raw user attribute value, so whoever wrote it controls the result. ([`ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java:85-93`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java#L85-L93))
4. **`SubjectSubscriptionFilter.evaluateSubjectSubscription`** drops every event about that user for that receiver. A user-level `false` counts as an explicit exclusion and wins over organisation inheritance and `default_subjects`. A `true` forces delivery instead. ([`ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SubjectSubscriptionFilter.java:134-148`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SubjectSubscriptionFilter.java#L134-L148))

## Assessment

The attacker is an authenticated realm user, or someone who has taken over a user's session. The realm's user profile must have `unmanagedAttributePolicy=ENABLED`, and an SSF receiver stream must exist. The attacker writes the attribute on their own account through the Account REST API or the account console. The report also names other routes that can set attributes with matching names: LDAP-synced attributes and IdP attribute mappers that an operator has opened for self-service.

Impact: The user decides whether a receiver is told about events on their own account. Setting `false` silences signals that downstream receivers rely on. Setting `true` makes a receiver get events about them that the operator never subscribed. Other users' data is not exposed and availability is not affected.

## Recommendation

The subscription control state is stored under the user attribute names `ssf.notify.*` and `ssf.notifyRemovedAt.*`. The user profile does not protect these names, so the user whose events are controlled can edit them when unmanaged attributes are user-editable.

Fix criteria: The `ssf.notify.*` and `ssf.notifyRemovedAt.*` state cannot be written from non-admin user profile contexts (account API, account console, registration). Either it is stored outside the user attribute namespace, or those names are read-only internal attributes in every non-admin context whatever the unmanaged-attribute policy. Verify with `unmanagedAttributePolicy=ENABLED`: an account API update carrying `ssf.notify.<clientId>` is rejected or ignored, and the dispatcher's decision for that user is unchanged.

## Evidence

**https://github.com/cx-benchmark/keycloak**

- [`ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java:23-27`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java#L23-L27)
- [`ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java:85-93`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SsfNotifyAttributes.java#L85-L93)
- [`ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SubjectSubscriptionFilter.java:134-148`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/ssf/transmitter/src/main/java/org/keycloak/ssf/transmitter/subject/SubjectSubscriptionFilter.java#L134-L148)
- [`services/src/main/java/org/keycloak/userprofile/DeclarativeUserProfileProviderFactory.java:103-104`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/services/src/main/java/org/keycloak/userprofile/DeclarativeUserProfileProviderFactory.java#L103-L104)
- [`server-spi-private/src/main/java/org/keycloak/userprofile/DefaultAttributes.java:123-131`](https://github.com/cx-benchmark/keycloak/blob/1d7be35d0764060a8143fc74b0aabf2442743be4/server-spi-private/src/main/java/org/keycloak/userprofile/DefaultAttributes.java#L123-L131)

