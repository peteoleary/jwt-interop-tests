import {importJWK} from 'jose';

import didJWT from 'did-jwt';

import * as ed from '@noble/ed25519';

import { convertSecretKeyToX25519 } from '@stablelib/ed25519'

export interface Settings {
  keyFile: string
}

// keypair is from didkit
const keyPair = {"kty":"OKP","crv":"Ed25519","x":"MccmZisY6gqIW-FQ13ck6To9afSioMUpE4-UlHvH3JE","d":"E9rC9_DEb99EWXvQk4S5xjSkoUu3Ywa8A77224d5vaA"}

async function testJOSE() {
  const key = await importJWK(keyPair, 'EdDSA')
  console.log(key)
}

// noble/ed25519 is used for DWN verification
async function nobleEd25519Test(messageString: string) {
  
  const privateKey = Buffer.from(keyPair.d, 'base64');
  // const privateKey = ed.utils.randomPrivateKey();
  const publicKey = Buffer.from(keyPair.x, 'base64');
  
  const message = new TextEncoder().encode(messageString);
  // const publicKey = await ed.getPublicKey(privateKey);
  const signature = await ed.sign(message, privateKey);
  const result = await ed.verify(signature, message, publicKey);

  return result
}

async function didJWTTest() {

  const encodedKey = new TextEncoder().encode('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f');

  // TOOD: get the public key from encodedKey

  const signer = didJWT.EdDSASigner(encodedKey)

  const payloadBytes = {descriptorCid: '0123456789ABCDEF'};
  const protectedHeader = { alg: 'Ed25519', kid: 'did:key:0123456789ABCDEF' }; // TODO: make a real key DID from the private key above

  const jws = await didJWT.createJWS(payloadBytes, signer, protectedHeader);

  const whichPubkey = didJWT.verifyJWS(jws, { id:'abcdef', type:'', controller: '', publicKeyJwk: keyPair })

  console.log(jws)
}



async function combinedTest() {
  // create JWT with did-jwt and didkitKey

  const privateKeyBytes = Buffer.from(keyPair.d, 'base64');
  const publicKeyBytes = Buffer.from(keyPair.x, 'base64');

  const payload = { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' }
  const protectedHeader = { alg: 'Ed25519', kid: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74' };

  const protectedHeaderBase64UrlString = Buffer.from(JSON.stringify(protectedHeader)).toString('base64')
  const payloadBase64UrlString = Buffer.from(JSON.stringify(payload)).toString('base64')

  const signingInputBase64urlString = `${protectedHeaderBase64UrlString}.${payloadBase64UrlString}`;
  const signingInputBytes = new TextEncoder().encode(signingInputBase64urlString);

  const signature = await ed.sign(signingInputBytes, privateKeyBytes);


  const verified = await ed.verify(signature, signingInputBytes, publicKeyBytes)

  console.log(verified)

  // verify JWT with noble/ed25519
}

export async function handleCommand (settings: Settings): Promise<{ messageString: string}> {
  let messageString = 'run command with:\n'
  messageString += `  - ${settings.keyFile}`

  // await testJOSE();
  // const isValid = await nobleEd25519Test(messageString);
  // console.log(isValid);
  // await didJWTTest();
  await combinedTest();

  return {
    messageString
  }
}
