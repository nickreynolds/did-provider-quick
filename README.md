# Veramo did:quick provider

This package contains an implementation of `AbstractIdentifierProvider` for the `did:quick` method.
This enables creation and control of `did:quick` entities.

## Details

This package contains both the Veramo *Provider* and *Resolver* for `did:quick`.

The provider creates DID Method Update credentials and submits them to a specified "relayer".

The resolver constructs DID Documents by interating over all DID Method Update credentials for a given DID.
