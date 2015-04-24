package com.emstlk.nacl4s.crypto

object Utils {

  val sigma = "expand 32-byte k".map(_.toByte).toArray

  def rotate(u: Int, c: Int) = (u << c) | (u >>> (32 - c))

  def loadLittleEndian(a: Array[Byte], offset: Int): Int = {
    a(offset) & 0xFF |
      (a(offset + 1) & 0xFF) << 8 |
      (a(offset + 2) & 0xFF) << 16 |
      (a(offset + 3) & 0xFF) << 24
  }

  def saveLittleEndian(a: Array[Byte], offset: Int, value: Int) {
    a(offset) = value.toByte
    a(offset + 1) = (value >>> 8).toByte
    a(offset + 2) = (value >>> 16).toByte
    a(offset + 3) = (value >>> 24).toByte
  }

}
