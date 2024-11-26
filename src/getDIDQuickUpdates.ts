import { IAgentContext, ICredentialIssuer, ICredentialPlugin, IDataStore, IDataStoreORM, TAgent, UniqueVerifiableCredential, VerifiableCredential } from '@veramo/core-types'
import { ICredentialIssuerEIP712 } from '@veramo/credential-eip712'
import { ICredentialIssuerLD } from '@veramo/credential-ld'

type IContext = IAgentContext<IDataStore & IDataStoreORM & ICredentialPlugin & ICredentialIssuer & ICredentialIssuerEIP712 & ICredentialIssuerLD>

export async function getDIDQuickUpdates(message: any, agent: TAgent<IDataStore & ICredentialPlugin & ICredentialIssuerEIP712 & ICredentialIssuerLD>): Promise<UniqueVerifiableCredential[]> {
  
  if (!message.did) {
    throw Error('DID not found in request')
  }
  const credentials = await agent.dataStoreORMGetVerifiableCredentials(
    { 
      where: [
        {
          column: 'type',
          value: ['VerifiableCredential,DIDQuickUpdate,DIDQuickAddKey'], 
        },
        {
          column: 'issuer',
          value: [message.did]
        }
      ], 
      order: [{ column: 'issuanceDate', direction: 'ASC' }]
    }
  )
  return credentials
}