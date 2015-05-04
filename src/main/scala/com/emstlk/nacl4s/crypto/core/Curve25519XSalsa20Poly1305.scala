package com.emstlk.nacl4s.crypto.core

import com.emstlk.nacl4s.crypto.Utils._

object Curve25519XSalsa20Poly1305 {

  val seedBytes = 32
  val publicKeyBytes = 32
  val secretKeyBytes = 32
  val beforenmBytes = 32
  val nonceBytes = 24
  val zeroBytes = 32
  val boxZeroBytes = 16

  def cryptoBoxBeforenm(k: Array[Byte], pk: Array[Byte], sk: Array[Byte]) {
    val s = new Array[Byte](32)
    Curve25519.cryptoScalarmult(s, sk, pk)
    HSalsa20.cryptoCore(k, new Array[Byte](16), s, getSigma)
  }

  def cryptoBoxAfternm(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], k: Array[Byte]) {
    XSalsa20Poly1305.cryptoSecretBox(c, m, mlen, n, k)
  }

  def cryptoBoxOpenAfternm(m: Array[Byte], c: Array[Byte], clen: Int, n: Array[Byte], k: Array[Byte]) {
    XSalsa20Poly1305.cryptoSecretBoxOpen(m, c, clen, n, k)
  }

  def cryptoBox(c: Array[Byte], m: Array[Byte], mlen: Int, n: Array[Byte], pk: Array[Byte], sk: Array[Byte]) {
    val k = new Array[Byte](beforenmBytes)
    cryptoBoxBeforenm(k, pk, sk)
    cryptoBoxAfternm(c, m, mlen, n, k)
  }

  def cryptoBoxOpen(m: Array[Byte], c: Array[Byte], clen: Int, n: Array[Byte], pk: Array[Byte], sk: Array[Byte]) {
    val k = new Array[Byte](beforenmBytes)
    cryptoBoxBeforenm(k, pk, sk)
    cryptoBoxOpenAfternm(m, c, clen, n, k)
  }

  //TODO init crypto_box_seed_keypair

  def cryptoBoxKeypair(pk: Array[Byte], sk: Array[Byte]) {
    random.nextBytes(sk)
    Curve25519.cryptoScalarmultBase(pk, sk)
  }

}
