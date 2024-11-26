/**
 * Provides `did:quick` {@link did-provider-quick#QuickDIDProvider | identifier provider } for the
 * {@link @veramo/did-manager#DIDManager}
 *
 * @packageDocumentation
 */
export { QuickDIDProvider } from './quick-did-provider.js'
export { getResolver } from './quick-did-resolver.js'
export { resolveDID } from './resolveDID.js'
export { saveDIDQuickUpdate } from './saveDIDQuickUpdate.js'
export { getDIDQuickUpdates } from './getDIDQuickUpdates.js'
export { QuickDIDRelayer } from './quick-did-relayer.js'
export { IQuickDIDRelayer } from './IQuickDIDRelayer.js'