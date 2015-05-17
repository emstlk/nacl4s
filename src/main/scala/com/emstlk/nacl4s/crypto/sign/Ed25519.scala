package com.emstlk.nacl4s.crypto.sign

import com.emstlk.nacl4s.crypto.hash.Sha512
import com.emstlk.nacl4s.crypto.hash.Sha512.State

object Ed25519 {

  val bytes = 64
  val seedBytes = 32
  val publicKeyBytes = 32
  val secretKeyBytes = 64

  def cryptoSignDetached(sig: Array[Byte], sigLength: Int, m: Array[Byte], mLength: Int, sk: Array[Byte]) {
    val az = new Array[Byte](64)
    val nonce = new Array[Byte](64)
    val hram = new Array[Byte](64)

    Sha512.cryptoHash(az, sk, 32)
    az(0) = (az(0) & 248).toByte
    az(31) = ((az(31) & 63) | 64).toByte

    Array.copy(sk, 32, sig, 32, 32)

    val st = State()
    Sha512.init(st)
    Sha512.update(st, az, 32, 32)
    Sha512.update(st, m, 0, mLength)
    Sha512.finish(st, nonce)

    val r = new P3
    Sc.reduce(nonce)
    Ge.scalarmultBase(r, nonce)
    // ge_p3_tobytes(sig, &R);


  }

}
