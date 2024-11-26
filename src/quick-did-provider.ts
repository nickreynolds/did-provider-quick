import { IAgentContext, ICredentialPlugin, IDIDManager, IIdentifier, IKey, IKeyManager, IService, TKeyType } from '@veramo/core-types'
import { AbstractIdentifierProvider } from '@veramo/did-manager'
import { ICredentialIssuerEIP712 } from '@veramo/credential-eip712'
// import { EthrDID } from 'ethr-did'
import { bytesToBase58, bytesToMultibase, hexToBytes } from '@veramo/utils'
import { KeyValueStore } from '@veramo/kv-store'
import { VerificationMethod } from 'did-resolver'


export type IRequiredContext = IAgentContext<IKeyManager & ICredentialIssuerEIP712 & ICredentialPlugin & IDIDManager>

export interface CreateDidQuickOptions {

}

const keyMapping: Record<TKeyType, string> = {
  Secp256k1: 'EcdsaSecp256k1VerificationKey2019',
  Secp256r1: 'EcdsaSecp256r1VerificationKey2019',
  Ed25519: 'Ed25519VerificationKey2018',
  X25519: 'X25519KeyAgreementKey2019',
  Bls12381G1: 'Bls12381G1Key2020',
  Bls12381G2: 'Bls12381G2Key2020',
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
    const identifier: Omit<IIdentifier, 'provider'> = {
      did: 'did:quick:' + rootIdentifier.did,
      controllerKeyId: rootIdentifier.keys[0].kid,
      keys: [...(rootIdentifier.keys || [])],
      services: [],
    }
    return identifier
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
    if (!rootDid.startsWith('did:key:')) {
      throw Error('root DID not of type did:key')
    }
    const rootIdentifier = await context.agent.didManagerGet({ did: rootDid })
    const proofFormats = await context.agent.listUsableProofFormats(rootIdentifier)


   const vm: VerificationMethod = {
    id: identifier.did + '#' + key.kid,
    type: "Multikey",
    controller: identifier.did
  }

   switch(key.type) {
    case 'Ed25519':
      vm.publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'base58btc', 'ed25519-pub')
      break;
    case 'Secp256k1':
      vm.publicKeyMultibase = bytesToMultibase(hexToBytes(key.publicKeyHex), 'base58btc', 'secp256k1-pub')      
      break;
   }

   if (!vm.publicKeyMultibase) {
    throw new Error('Unsupported key type')
  }

    const addKeyCred = await context.agent.createVerifiableCredential({
      credential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'DIDQuickUpdate', 'DIDQuickAddKey'],
        issuer: rootDid,
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          ...vm
        },
      },
      proofFormat: proofFormats[0],
    })

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
