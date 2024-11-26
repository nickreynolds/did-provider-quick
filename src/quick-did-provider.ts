import { IAgentContext, ICredentialPlugin, IDIDManager, IIdentifier, IKey, IKeyManager, IService } from '@veramo/core-types'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import Debug from 'debug'
import { ICredentialIssuerEIP712 } from '@veramo/credential-eip712'
// import { EthrDID } from 'ethr-did'
import { KeyValueStore } from '@veramo/kv-store'

const debug = Debug('veramo:did-provider-quick')

export type IRequiredContext = IAgentContext<IKeyManager & ICredentialIssuerEIP712 & ICredentialPlugin & IDIDManager>

export interface CreateDidQuickOptions {

}

/**
 * {@link @veramo/did-manager#DIDManager} identifier provider for `did:quick` identifiers
 * @public
 */
export class QuickDIDProvider extends AbstractIdentifierProvider {
  private defaultKms: string
  private relayerUrl: string

  constructor(options: {
    defaultKms: string
    relayerUrl: string,

  }) {
    super()
    this.defaultKms = options.defaultKms
    this.relayerUrl = options.relayerUrl
  }

  async createIdentifier(
    { kms, options }: { kms?: string; options?: CreateDidQuickOptions },
    context: IRequiredContext,
  ): Promise<Omit<IIdentifier, 'provider'>> {
    const rootIdentifier = await context.agent.didManagerCreate({
      provider: 'did:key',
      kms: this.defaultKms,
    })
    // console.log("1 CREATED ROOT IDENTIFIER: ", rootIdentifier)
    console.log("1 GET ROOT ID DID: ", rootIdentifier.did)
    const gotRoot = await context.agent.didManagerGet({ did: rootIdentifier.did })
    console.log("2 GOT ROOT IDENTIFIER: ", gotRoot)
    const identifier: Omit<IIdentifier, 'provider'> = {
      did: 'did:quick:' + rootIdentifier.did,
      controllerKeyId: rootIdentifier.keys[0].kid,
      keys: [...(rootIdentifier.keys || [])],
      services: [],
    }
    const gotRoot2 = await context.agent.didManagerGet({ did: rootIdentifier.did })
    console.log("3 GOT ROOT IDENTIFIER: ", gotRoot2)
    return identifier
    // throw new Error('QuickDIDProvider createIdentifier not implemented.')
  }

  async updateIdentifier(
    args: { did: string; kms?: string | undefined; alias?: string | undefined; options?: any },
    context: IAgentContext<IKeyManager>,
  ): Promise<IIdentifier> {
    throw new Error('QuickDIDProvider updateIdentifier not supported yet.')
  }

  async deleteIdentifier(identifier: IIdentifier, context: IRequiredContext): Promise<boolean> {
    for (const { kid } of identifier.keys) {
      // FIXME: keys might be used by multiple DIDs or even independent
      await context.agent.keyManagerDelete({ kid })
    }
    return true
  }

  async addKey(
    { identifier, key, options }: { identifier: IIdentifier; key: IKey; options?: any },
    context: IRequiredContext,
  ): Promise<any> {
    const rootDid = identifier.did.replace('did:quick:', '')
    if (!rootDid.startsWith('did:ethr:')) {
      throw Error('root DID not of type did:ethr')
    }
    console.log("2 GET ROOT ID DID: ", rootDid)
    const rootIdentifier = await context.agent.didManagerGet({ did: rootDid })
    console.log("GOT ROOT IDENTIFIER: ", rootIdentifier)
    const proofFormats = await context.agent.listUsableProofFormats(rootIdentifier)
    console.log("proofFormats: ", proofFormats)
    const addKeyCred = await context.agent.createVerifiableCredential({
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DIDQuickUpdate', 'DIDQuickAddKey'],
        issuer: rootDid,
        issuanceDate: new Date().toISOString(),
        credentialSubject: key,
      },
      proofFormat: proofFormats[0],
    })

    console.log("addKeyCred: ", addKeyCred)

    console.log("relayerUrl: ", this.relayerUrl)
    const res = await fetch(`${this.relayerUrl}/add-did-quick-update`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        type: 'did-quick-update',
        media_type: 'credential+ld+json',
        data: addKeyCred
      })
    })
    if (res.ok) {
      return true
    }
    throw new Error(`Failed to add key: ${res.statusText}`)
  }

  async addService(
    {
      identifier,
      service,
      options,
    }: { identifier: IIdentifier; service: IService; options?: any },
    context: IRequiredContext,
  ): Promise<any> {
    throw new Error('Method not implemented.')
  }

  async removeKey(
    args: { identifier: IIdentifier; kid: string; options?: any },
    context: IRequiredContext,
  ): Promise<any> {
    throw new Error('Method not implemented.')
  }

  async removeService(
    args: { identifier: IIdentifier; id: string; options?: any },
    context: IRequiredContext,
  ): Promise<any> {
    throw new Error('Method not implemented.')
  }


}
