import didJWT from 'did-jwt';
import * as ed from '@noble/ed25519';

export interface Settings {
  keyFile: string
}

export async function handleCommand (settings: Settings): Promise<{ messageString: string}> {
  let messageString = 'run command with:\n'
  messageString += `  - ${settings.keyFile}`

  const privateKey = ed.utils.randomPrivateKey();
  const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
  const publicKey = await ed.getPublicKey(privateKey);
  const signature = await ed.sign(message, privateKey);
  const isValid = await ed.verify(signature, message, publicKey);

  return {
    messageString
  }
}
