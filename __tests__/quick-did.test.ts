import { createAgent, ICredentialPlugin, IDataStore, IDataStoreORM, IDIDManager, IIdentifier, IKey, IKeyManager, IResolver, MinimalImportableKey, TAgent } from '@veramo/core'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem, SecretBox } from '@veramo/kms-local'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { QuickDIDProvider } from '../src/quick-did-provider'
// import { createGanacheProvider } from './utils/ganache-providers'
// import { createEthersProvider } from './utils/ethers-provider'
import { EthrDIDProvider } from '@veramo/did-provider-ethr'
import { CredentialIssuerEIP712, ICredentialIssuerEIP712 } from '@veramo/credential-eip712'
import { CredentialPlugin } from '@veramo/credential-w3c'
import { CredentialIssuerLD } from '@veramo/credential-ld'
import {
  ICredentialIssuerLD,
  LdDefaultContexts,
  VeramoEcdsaSecp256k1RecoverySignature2020,
  VeramoEd25519Signature2018,
  VeramoEd25519Signature2020,
  VeramoJsonWebSignature2020,
} from '@veramo/credential-ld'
import { contexts as credential_contexts } from '@transmute/credentials-context'
import express from 'express'
import { resolveDID } from '../src/resolveDID'
import { DataSource } from 'typeorm'
import { DataStore, DataStoreORM, DIDStore, Entities, KeyStore, migrations, PrivateKeyStore } from '@veramo/data-store'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { getDidKeyResolver, KeyDIDProvider } from '@veramo/did-provider-key'
import { getResolver as quickDidResolver } from '../src/quick-did-resolver'
import { Web3KeyManagementSystem } from '@veramo/kms-web3'
import {
  KeyValueStore,
  Entities as KVStoreEntities,
  kvStoreMigrations,
  KeyValueTypeORMStoreAdapter,
  IKeyValueStoreOptions
} from '@veramo/kv-store'
import { QuickDIDRelayer} from "did-relayer-quick"
 
import { afterAll, describe, test, expect, beforeAll } from "vitest"


// const { provider, registry } = await createGanacheProvider()
// const ethersProvider = createEthersProvider()

const quickDIDProvider = new QuickDIDProvider({
  defaultKms: 'local',
  relayerUrl: 'http://localhost:3131',
})

const databaseFile = ':memory:'
const infuraProjectId = '3586660d179141e3801c3895de1c2eba'
const secretKey = '29739248cad1bd1a0fc4d9b75cd4d2990de535baf5caadfdf8d8f86664aa830c'

const dbConnection = new DataSource({
  name: 'test',
  type: 'sqlite',
  database: databaseFile,
  synchronize: false,
  migrations: migrations.concat(kvStoreMigrations),
  migrationsRun: true,
  logging: false,
  entities: (KVStoreEntities as any).concat(Entities),
  // allow shared tests to override connection options
  //   ...options?.context?.dbConnectionOptions,
}).initialize()


let saveToArweaveStore = new KeyValueStore<boolean>({
  namespace: 'save_to_arweave',
  store: new KeyValueTypeORMStoreAdapter({ dbConnection, namespace: 'save_to_arweave' }),
})



let agent: TAgent<
  IDIDManager &
  IKeyManager &
  IDataStore &
  IDataStoreORM &
  IResolver &
  ICredentialPlugin &
  ICredentialIssuerLD &
  ICredentialIssuerEIP712
>

agent = createAgent<
  IDIDManager &
  IKeyManager &
  IDataStore &
  IDataStoreORM &
  IResolver &
  ICredentialPlugin &
  ICredentialIssuerLD &
  ICredentialIssuerEIP712
>({
  plugins: [
    new KeyManager({
      store: new KeyStore(dbConnection),
      kms: {
        local: new KeyManagementSystem(new PrivateKeyStore(dbConnection, new SecretBox(secretKey))),
      },
    }),
    new DIDManager({
      store: new MemoryDIDStore(),
      providers: {
        'did:key': new KeyDIDProvider({ defaultKms: 'local' }),
        'did:quick': quickDIDProvider,
      },
      defaultProvider: 'did:quick',
    }),
    new DIDResolverPlugin({
      ...getDidKeyResolver(),
      ...quickDidResolver({ nodeEndpoint: 'http://localhost:3131/resolveDIDQuick' }),
    }),
    new DataStore(dbConnection),
    new DataStoreORM(dbConnection),
    new CredentialPlugin(),
    new CredentialIssuerEIP712(),
    new CredentialIssuerLD({
      contextMaps: [LdDefaultContexts, credential_contexts as any],
      suites: [
        new VeramoEcdsaSecp256k1RecoverySignature2020(),
        new VeramoEd25519Signature2018(),
        new VeramoJsonWebSignature2020(),
        new VeramoEd25519Signature2020(),
      ],
    }),
    new QuickDIDRelayer({ saveToArweaveStore })
  ],
})

const app = express()
app.use(express.json())
app.use('/add-did-quick-update', async (req, res) => {
  const message = req.body
  const result = await agent.saveCredential(message)
  res.send(result)
})

app.use('/resolveDIDQuick', async (req, res) => {
  const message = req.body
  if (!message.didUrl) {
    throw Error('didUrl not found in request')
  }
  const result = await resolveDID(message.didUrl, agent)
  res.send(result)
})

const listener = app.listen(3131, () => {
  console.log("listening on 3131")
})

afterAll(async () => {
  listener.close()
})

function delay(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

describe('did-provider-quick', () => {
  test('should create identifier', async () => {
    // const options: ICreateIdentifierOpts = createIdentifierOpts
    const identifier: IIdentifier = await agent.didManagerCreate({ provider: 'did:quick' })

    // console.log('identifier quick', identifier)
    expect(identifier).toBeDefined()

    expect(identifier.keys.length).toBe(1)
    expect(identifier.services.length).toBe(0)
  })

  test('should add keys', async () => {
    const identifier: IIdentifier = await agent.didManagerCreate({ provider: 'did:quick' })

    expect(identifier).toBeDefined()

    expect(identifier.keys.length).toBe(1)
    expect(identifier.services.length).toBe(0)

    const rootDID = identifier.did.replace('did:quick:', '')
    const rootIdentifier = await agent.didManagerGet({ did: rootDID })

    const newKey = await agent.keyManagerCreate({ kms: 'local', type: 'Ed25519' })
    const added = await agent.didManagerAddKey({
      did: identifier.did,
      key: newKey,
      options: {},
    })

    const creds = await agent.dataStoreORMGetVerifiableCredentials();

    expect(added).toBeDefined()

    let resolved = await agent.resolveDid({ didUrl: identifier.did })
    expect(resolved?.didDocument?.verificationMethod?.length).toBe(3)
    expect(resolved?.didDocument?.authentication?.length).toBe(2)
    expect(resolved?.didDocument?.assertionMethod?.length).toBe(2)
    expect(resolved?.didDocument?.keyAgreement?.length).toBe(2)

    const secpKey = await agent.keyManagerCreate({ kms: 'local', type: 'Secp256k1' })
    const added2 = await agent.didManagerAddKey({
      did: identifier.did,
      key: secpKey,
      options: {},
    })

    resolved = await agent.resolveDid({ didUrl: identifier.did })
    expect(resolved?.didDocument?.verificationMethod?.length).toBe(4)
    expect(resolved?.didDocument?.authentication?.length).toBe(3)
    expect(resolved?.didDocument?.assertionMethod?.length).toBe(3)
    // Secp256k1 keys are not added to keyAgreement
    expect(resolved?.didDocument?.keyAgreement?.length).toBe(2)

  })

  test('should add service', async () => {

  })
})
