# Shared organization tenancy

## Status

Accepted

## Context

Verified identities can belong to multiple independent customer organizations. Products need an authoritative active tenant and ownership scope.

## Decision

Use one organization per tenant with distinct UUIDs. Store memberships, invitations, policy and audit state in a shared control-plane database. Resolve tenant membership per request and tag new hosted cases with ownership in their creation transaction.

## Alternatives considered

A tenant per user would prevent collaboration. Database-per-tenant hosting would introduce storage provisioning beyond the current milestone. Inferring tenants from email domains or token claims would delegate authorization to identifiers whose ownership lifecycle is independent of the platform.

## Rationale

A shared tenant boundary supports future products without a separate membership system. Explicit request selection avoids implicit organization changes across browser tabs.

## Trade-offs and consequences

Application checks mediate shared product storage until Task 4.7. Control-plane locking serializes protected requests with revocation. User enrollment at the identity provider precedes invitations. Legacy case ownership remains untouched pending an explicit import process.
