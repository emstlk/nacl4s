package com.emstlk.nacl4s.crypto.sign

import com.emstlk.nacl4s.crypto.hash.Sha512
import com.emstlk.nacl4s.crypto.hash.Sha512.State

object Ed25519 {

  val bytes = 64
  val seedBytes = 32
  val publicKeyBytes = 32
  val secretKeyBytes = 64

  def cryptoSignDetached(sig: Array[Byte], m: Array[Byte], mOffset: Int, mLength: Int, sk: Array[Byte]) {
    val az = new Array[Byte](64)
    val nonce = new Array[Byte](64)
    val hram = new Array[Byte](64)

    Sha512.cryptoHash(az, sk, 32)
    az(0) = (az(0) & 248).toByte
    az(31) = ((az(31) & 63) | 64).toByte

    Array.copy(sk, 32, sig, 32, 32)

    val hs = State()
    Sha512.init(hs)
    Sha512.update(hs, az, 32, 32)
    Sha512.update(hs, m, mOffset, mLength)
    Sha512.finish(hs, nonce)

    val r = new P3
    Sc.reduce(nonce)
    Ge.scalarmultBase(r, nonce)
    Ge.p3ToBytes(sig, r)

    Sha512.init(hs)
    Sha512.update(hs, sig, 0, 64)
    Sha512.update(hs, m, mOffset, mLength)
    Sha512.finish(hs, hram)

    Sc.reduce(hram)
    Sc.muladd(sig, 32, hram, az, nonce)
  }

  def cryptoSign(sm: Array[Byte], m: Array[Byte], mLength: Int, sk: Array[Byte]) {
    Array.copy(m, 0, sm, bytes, mLength)
    cryptoSignDetached(sm, sm, bytes, mLength, sk)
  }

}
