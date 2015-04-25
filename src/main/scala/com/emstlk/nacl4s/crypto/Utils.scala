package com.emstlk.nacl4s.crypto

object Utils {

  private val sigma = "expand 32-byte k".map(_.toByte).toArray

  def getSigma = sigma.clone()

  @inline def loadInt(a: Array[Byte], offset: Int): Int = {
    a(offset) & 0xFF |
      (a(offset + 1) & 0xFF) << 8 |
      (a(offset + 2) & 0xFF) << 16 |
      (a(offset + 3) & 0xFF) << 24
  }

  @inline def storeInt(a: Array[Byte], offset: Int, value: Int) {
    a(offset) = value.toByte
    a(offset + 1) = (value >>> 8).toByte
    a(offset + 2) = (value >>> 16).toByte
    a(offset + 3) = (value >>> 24).toByte
  }

  @inline def loadLong(in: Array[Byte], offset: Int): Long = {
    (in(offset).toLong & 0xff) |
      ((in(offset + 1).toLong & 0xff) << 8) |
      ((in(offset + 2).toLong & 0xff) << 16) |
      ((in(offset + 3).toLong & 0xff) << 24) |
      ((in(offset + 4).toLong & 0xff) << 32) |
      ((in(offset + 5).toLong & 0xff) << 40) |
      ((in(offset + 6).toLong & 0xff) << 48) |
      ((in(offset + 7).toLong & 0xff) << 56)
  }

  @inline def storeLong(out: Array[Byte], offset: Int, in: Long) {
    out(offset) = (in & 0xFF).toByte
    out(offset + 1) = ((in >>> 8) & 0xFF).toByte
    out(offset + 2) = ((in >>> 16) & 0xFF).toByte
    out(offset + 3) = ((in >>> 24) & 0xFF).toByte
    out(offset + 4) = ((in >>> 32) & 0xFF).toByte
    out(offset + 5) = ((in >>> 40) & 0xFF).toByte
    out(offset + 6) = ((in >>> 48) & 0xFF).toByte
    out(offset + 7) = ((in >>> 56) & 0xFF).toByte
  }

}
