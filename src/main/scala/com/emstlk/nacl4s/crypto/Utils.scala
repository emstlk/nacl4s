package com.emstlk.nacl4s.crypto

import java.security.SecureRandom

object Utils {

  private val sigma = "expand 32-byte k".map(_.toByte).toArray

  def getSigma = sigma.clone()

  lazy val random = new SecureRandom

  @inline def checkLength(a: Array[Byte], length: Int) = {
    require(Option(a).exists(_.length == length), s"Wrong length, required $length")
  }

  @inline def loadInt(a: Array[Byte], offset: Int): Int = {
    a(offset) & 0xff |
      (a(offset + 1) & 0xff) << 8 |
      (a(offset + 2) & 0xff) << 16 |
      (a(offset + 3) & 0xff) << 24
  }

  @inline def storeInt(a: Array[Byte], offset: Int, value: Int) = {
    a(offset) = value.toByte
    a(offset + 1) = (value >>> 8).toByte
    a(offset + 2) = (value >>> 16).toByte
    a(offset + 3) = (value >>> 24).toByte
  }

}
