package com.emstlk.nacl4s.crypto.sign

import com.emstlk.nacl4s.crypto.hash.Sha512
import com.emstlk.nacl4s.crypto.hash.Sha512.State
import com.emstlk.nacl4s.crypto.verify.Verify

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

    Scalar.reduce(nonce)
    val r = new P3
    GroupElement.scalarmultBase(r, nonce)
    GroupElement.p3ToBytes(sig, r)

    Sha512.init(hs)
    Sha512.update(hs, sig, 0, 64)
    Sha512.update(hs, m, mOffset, mLength)
    Sha512.finish(hs, hram)

    Scalar.reduce(hram)
    Scalar.muladd(sig, 32, hram, az, nonce)
  }

  def cryptoSign(sm: Array[Byte], m: Array[Byte], mLength: Int, sk: Array[Byte]) {
    Array.copy(m, 0, sm, bytes, mLength)
    cryptoSignDetached(sm, sm, bytes, mLength, sk)
  }

  def cryptoSignVerifyDetached(sig: Array[Byte], m: Array[Byte], offset: Int, length: Int, pk: Array[Byte]) {
    require((sig(63) & 224) == 0)

    val a = new P3
    GroupElement.fromBytesNegateVartime(a, pk)

    var d: Byte = 0
    var i = 0
    while (i < 32) {
      d = (d | pk(i)).toByte
      i += 1
    }
    require(d != 0)

    val hs = State()
    Sha512.init(hs)
    Sha512.update(hs, sig, 0, 32)
    Sha512.update(hs, pk, 0, 32)
    Sha512.update(hs, m, 0, length)
    val h = new Array[Byte](64)
    Sha512.finish(hs, h)
    Scalar.reduce(h)

    val r = new P2
    GroupElement.doubleScalarmultVartime(r, h, a, sig, 32)
    val rCheck = new Array[Byte](32)
    GroupElement.toBytes(rCheck, r)

    require(Verify.cryptoVerify32(rCheck, 0, sig))
  }

  def cryptoSignOpen(m: Array[Byte], sm: Array[Byte], smLength: Int, pk: Array[Byte]) {
    require(smLength >= 64)

    val mLength = smLength - 64
    cryptoSignVerifyDetached(sm, sm, 64, mLength, pk)
    Array.copy(sm, 64, m, 0, mLength)
  }

}
