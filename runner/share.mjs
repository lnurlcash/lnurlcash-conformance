// The grader's own reading of LUD-26 shares and their registration proofs.
//
// A share is S/a'/2/n', exported as its cx1: BIP-32's extended public key,
// bech32m("cx", chaincode || P compressed). It is registered against a
// Lightning Address with a BIP-340 signature by the share's own key p over
// sha256 of a message that binds the SERVICE's domain, the lowercased
// username and, for register and update, the cx1 itself.
//
// Written from 26.md and @noble alone, like everything else in the grader;
// the selfcheck holds it to luds' own 26-vectors.json.

import {bech32m} from '@scure/base'
import {sha256} from '@noble/hashes/sha2.js'
import {schnorr, secp256k1} from '@noble/curves/secp256k1.js'
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js'
import {randomBytes} from 'node:crypto'

const CX1_LIMIT = 200

export const encodeCx1 = (chainCode, compressedPubkey) => {
  if (chainCode.length !== 32 || compressedPubkey.length !== 33) {
    throw new Error('a cx1 is a 32-byte chain code and a 33-byte compressed key')
  }
  const bytes = new Uint8Array(65)
  bytes.set(chainCode, 0)
  bytes.set(compressedPubkey, 32)
  return bech32m.encode('cx', bech32m.toWords(bytes), CX1_LIMIT)
}

// {chainCode, pubkey} out of a cx1, or null. The 64-byte x(P) || chainCode
// shape LUD-26 dropped in luds a6c4652 is not a cx1.
export const decodeCx1 = value => {
  if (typeof value !== 'string') return null
  try {
    const {prefix, words} = bech32m.decode(value.toLowerCase(), CX1_LIMIT)
    if (prefix !== 'cx') return null
    const bytes = bech32m.fromWords(words)
    if (bytes.length !== 65) return null
    const pubkey = bytes.slice(32)
    secp256k1.Point.fromBytes(pubkey)
    return {chainCode: bytes.slice(0, 32), pubkey}
  } catch {
    return null
  }
}

// The three messages a registration proof signs. `cx1` is the one being
// registered, or for update the new one; unregister binds none.
export const registrationMessage = (action, domain, username, cx1 = null) => {
  const base = `LNURLcash:${action}:${domain.toLowerCase()}:${username.toLowerCase()}`
  if (action === 'unregister') return base
  if (action !== 'register' && action !== 'update') throw new Error(`no such registration action: ${action}`)
  return `${base}:${cx1}`
}

// hex BIP-340 signature by `secretKey` over sha256(message). `auxRand`
// defaults to fresh randomness; the selfcheck passes luds' all-zero one to
// reproduce 26-vectors.json byte for byte.
export const signRegistration = (message, secretKey, auxRand = randomBytes(32)) =>
  bytesToHex(schnorr.sign(sha256(utf8ToBytes(message)), secretKey, auxRand))

export const verifyRegistration = (message, sigHex, xOnlyPubkey) => {
  try {
    return schnorr.verify(hexToBytes(sigHex), sha256(utf8ToBytes(message)), xOnlyPubkey)
  } catch {
    return false
  }
}

// A throwaway share for the grader: a random key and chain code. Nothing a
// SERVICE can see tells it apart from a share at S/a'/2/n'.
export const freshShare = ({secretKey = secp256k1.utils.randomSecretKey(), chainCode = randomBytes(32)} = {}) => {
  const pubkey = secp256k1.getPublicKey(secretKey, true)
  return {secretKey, chainCode: Uint8Array.from(chainCode), pubkey, cx1: encodeCx1(chainCode, pubkey)}
}
