import { DIDResolutionResult, IAgentContext, ICredentialIssuer, ICredentialPlugin, IDataStore, IDataStoreORM, IResolver, TAgent, UniqueVerifiableCredential, VerifiableCredential } from '@veramo/core-types'
import { ICredentialIssuerEIP712 } from '@veramo/credential-eip712'
import { ICredentialIssuerLD } from '@veramo/credential-ld'
import Debug from 'debug'
import { get } from 'http'
import { getDIDQuickUpdates } from './getDIDQuickUpdates.js'
const debug = Debug('veramo:did-provider-quick:saveDIDQuickUpdate')

type IContext = IAgentContext<IResolver & IDataStore & IDataStoreORM & ICredentialPlugin & ICredentialIssuer & ICredentialIssuerEIP712 & ICredentialIssuerLD>

export async function resolveDID(did: string, agent: TAgent<IDataStore & ICredentialPlugin & ICredentialIssuerEIP712 & ICredentialIssuerLD>): Promise<DIDResolutionResult> {
  debug("did-provider-quick resolveDID: ", did)
  if (!did.startsWith('did:quick:')) {
    throw Error('DID not of type did:quick')
  }
  const rootDid = did.replace('did:quick:', '')
  debug("rootDid: ", rootDid)
  const rootDoc = await agent.resolveDid({ didUrl: rootDid })
  debug("rootDoc: ", rootDoc)
  const creds = await getDIDQuickUpdates({ did: rootDid }, agent)
  let keyAgreementKeys: any[] = rootDoc.didDocument.keyAgreement ? [...(rootDoc.didDocument.keyAgreement)] : []
  let authenticationKeys: any[] = rootDoc.didDocument.authentication ? [...(rootDoc.didDocument.authentication)] : []
  let verificationMethods: any[] = [...(rootDoc.didDocument.verificationMethod)]
  let serviceEndpoints: any[] = rootDoc.didDocument.service ? [...(rootDoc.didDocument.service)] : []
  // let numKeys = 0
  for (const cred of creds) {
    const { verifiableCredential } = cred
    // const { addOp } = verifiableCredential.credentialSubject
    // if (addOp) {
    //   if (addOp.keyAgreementKey) {
    //     verificationMethods = [...verificationMethods, addOp.keyAgreementKey]
    //     keyAgreementKeys = [...keyAgreementKeys, addOp.keyAgreementKey.id]
    //   } else if (addOp.authenticationKey) {
    //     verificationMethods = [...verificationMethods, addOp.authenticationKey]
    //     authenticationKeys = [...authenticationKeys, addOp.authenticationKey.id]
    //   } else if (addOp.serviceEndpoint) {
    //     serviceEndpoints = [...serviceEndpoints, ...addOp.serviceEndpoint]
    //   }
    // }
    if (verifiableCredential?.type?.includes('DIDQuickAddKey')) {
      verificationMethods = [...verificationMethods, verifiableCredential.credentialSubject]
      keyAgreementKeys = [...keyAgreementKeys, verifiableCredential.credentialSubject.id]
    }
  }
  const didDocument = {
    ...rootDoc.didDocument,
    id: 'did:quick:' + rootDid,
    verificationMethod: verificationMethods,
    authentication: authenticationKeys,
    assertionMethod: authenticationKeys,
    keyAgreement: keyAgreementKeys,
    service: serviceEndpoints
  }

  return {
    didDocument,
    didDocumentMetadata: {},
    didResolutionMetadata: {}
  }
}