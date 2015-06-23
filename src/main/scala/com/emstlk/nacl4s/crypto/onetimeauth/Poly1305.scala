package com.emstlk.nacl4s.crypto.onetimeauth

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.verify.Verify._

object Poly1305 {

  val blockSize = 16

  final case class State(r: Array[Int],
                         h: Array[Int],
                         pad: Array[Int],
                         var leftover: Int,
                         buffer: Array[Byte],
                         var fin: Int)

  def init(st: State, k: Array[Byte]) = {
    st.r(0) = loadInt(k, 0) & 0x3ffffff
    st.r(1) = (loadInt(k, 3) >>> 2) & 0x3ffff03
    st.r(2) = (loadInt(k, 6) >>> 4) & 0x3ffc0ff
    st.r(3) = (loadInt(k, 9) >>> 6) & 0x3f03fff
    st.r(4) = (loadInt(k, 12) >>> 8) & 0x00fffff

    st.pad(0) = loadInt(k, 16)
    st.pad(1) = loadInt(k, 20)
    st.pad(2) = loadInt(k, 24)
    st.pad(3) = loadInt(k, 28)
  }

  def blocks(st: State, m: Array[Byte], offset: Int, length: Int) = {
    val hibit = if (st.fin != 0) 0 else 1 << 24

    val r0 = st.r(0).toLong
    val r1 = st.r(1).toLong
    val r2 = st.r(2).toLong
    val r3 = st.r(3).toLong
    val r4 = st.r(4).toLong

    val s1 = r1 * 5
    val s2 = r2 * 5
    val s3 = r3 * 5
    val s4 = r4 * 5

    var h0 = st.h(0)
    var h1 = st.h(1)
    var h2 = st.h(2)
    var h3 = st.h(3)
    var h4 = st.h(4)

    var d0, d1, d2, d3, d4 = 0L
    var c = 0
    var pos = 0

    while (length - pos >= blockSize) {
      /* h += m[i] */
      h0 += loadInt(m, offset + pos) & 0x3ffffff
      h1 += (loadInt(m, offset + pos + 3) >>> 2) & 0x3ffffff
      h2 += (loadInt(m, offset + pos + 6) >>> 4) & 0x3ffffff
      h3 += (loadInt(m, offset + pos + 9) >>> 6) & 0x3ffffff
      h4 += (loadInt(m, offset + pos + 12) >>> 8) | hibit

      /* h *= r */
      d0 = (h0 * r0) + (h1 * s4) + (h2 * s3) + (h3 * s2) + (h4 * s1)
      d1 = (h0 * r1) + (h1 * r0) + (h2 * s4) + (h3 * s3) + (h4 * s2)
      d2 = (h0 * r2) + (h1 * r1) + (h2 * r0) + (h3 * s4) + (h4 * s3)
      d3 = (h0 * r3) + (h1 * r2) + (h2 * r1) + (h3 * r0) + (h4 * s4)
      d4 = (h0 * r4) + (h1 * r3) + (h2 * r2) + (h3 * r1) + (h4 * r0)

      /* (partial) h %= p */
      c = (d0 >>> 26).toInt
      h0 = d0.toInt & 0x3ffffff

      d1 += c
      c = (d1 >>> 26).toInt
      h1 = d1.toInt & 0x3ffffff

      d2 += c
      c = (d2 >>> 26).toInt
      h2 = d2.toInt & 0x3ffffff

      d3 += c
      c = (d3 >>> 26).toInt
      h3 = d3.toInt & 0x3ffffff

      d4 += c
      c = (d4 >>> 26).toInt
      h4 = d4.toInt & 0x3ffffff

      h0 += c * 5
      c = h0 >>> 26
      h0 &= 0x3ffffff

      h1 += c

      pos += blockSize
    }

    st.h(0) = h0
    st.h(1) = h1
    st.h(2) = h2
    st.h(3) = h3
    st.h(4) = h4
  }

  def finish(st: State, mac: Array[Byte], offset: Int) = {
    if (st.leftover != 0) {
      st.buffer(st.leftover) = 1
      var i = st.leftover + 1
      while (i < blockSize) {
        st.buffer(i) = 0
        i += 1
      }
      st.fin = 1
      blocks(st, st.buffer, 0, blockSize)
    }

    var h0 = st.h(0)
    var h1 = st.h(1)
    var h2 = st.h(2)
    var h3 = st.h(3)
    var h4 = st.h(4)

    var c = h1 >>> 26
    h1 &= 0x3ffffff

    h2 += c
    c = h2 >>> 26
    h2 &= 0x3ffffff

    h3 += c
    c = h3 >>> 26
    h3 &= 0x3ffffff

    h4 += c
    c = h4 >>> 26
    h4 &= 0x3ffffff

    h0 += c * 5
    c = h0 >>> 26
    h0 &= 0x3ffffff

    h1 += c

    /* compute h + -p */
    var g0 = h0 + 5
    c = g0 >>> 26
    g0 &= 0x3ffffff

    var g1 = h1 + c
    c = g1 >>> 26
    g1 &= 0x3ffffff

    var g2 = h2 + c
    c = g2 >>> 26
    g2 &= 0x3ffffff

    var g3 = h3 + c
    c = g3 >>> 26
    g3 &= 0x3ffffff

    var g4 = h4 + c - (1 << 26)

    /* select h if h < p, or h + -p if h >= p */
    var mask = (g4 >>> 31) - 1
    g0 &= mask
    g1 &= mask
    g2 &= mask
    g3 &= mask
    g4 &= mask
    mask = ~mask
    h0 = (h0 & mask) | g0
    h1 = (h1 & mask) | g1
    h2 = (h2 & mask) | g2
    h3 = (h3 & mask) | g3
    h4 = (h4 & mask) | g4

    /* h = h % (2^128) */
    h0 = (h0 | (h1 << 26)) & 0xffffffff
    h1 = ((h1 >>> 6) | (h2 << 20)) & 0xffffffff
    h2 = ((h2 >>> 12) | (h3 << 14)) & 0xffffffff
    h3 = ((h3 >>> 18) | (h4 << 8)) & 0xffffffff

    /* mac = (h + pad) % (2^128) */
    var f = (h0 & 0xffffffffL) + (st.pad(0) & 0xffffffffL)
    h0 = f.toInt
    f = (h1 & 0xffffffffL) + (st.pad(1) & 0xffffffffL) + (f >>> 32)
    h1 = f.toInt
    f = (h2 & 0xffffffffL) + (st.pad(2) & 0xffffffffL) + (f >>> 32)
    h2 = f.toInt
    f = (h3 & 0xffffffffL) + (st.pad(3) & 0xffffffffL) + (f >>> 32)
    h3 = f.toInt

    storeInt(mac, offset, h0)
    storeInt(mac, offset + 4, h1)
    storeInt(mac, offset + 8, h2)
    storeInt(mac, offset + 12, h3)
  }

  def update(st: State, m: Array[Byte], offset: Int, length: Int): Unit = {
    var pos = offset

    if (st.leftover != 0) {
      var want = blockSize - st.leftover
      if (want > length) want = length

      var i = 0
      while (i < want) {
        st.buffer(st.leftover + i) = m(pos + i)
        i += 1
      }

      pos += want
      st.leftover += want

      if (st.leftover < blockSize) return

      blocks(st, st.buffer, 0, blockSize)
      st.leftover = 0
    }

    var rest = length - (pos - offset)
    if (rest >= blockSize) {
      val want = rest & ~(blockSize - 1)
      blocks(st, m, pos, want)
      pos += want
    }

    rest = length - (pos - offset)
    if (rest != 0) {
      var i = 0
      while (i < rest) {
        st.buffer(st.leftover + i) = m(pos + i)
        i += 1
      }
      st.leftover += rest
    }
  }

  def cryptoOneTimeAuth(out: Array[Byte], outOffset: Int, m: Array[Byte], mOffset: Int, mLength: Int, key: Array[Byte]) = {
    val state = State(new Array[Int](5), new Array[Int](5), new Array[Int](4), 0, new Array[Byte](blockSize), 0)
    init(state, key)
    update(state, m, mOffset, mLength)
    finish(state, out, outOffset)
  }

  def cryptoOneTimeAuthVerify(h: Array[Byte], hOffset: Int, in: Array[Byte], inOffset: Int, inLength: Int, key: Array[Byte]) = {
    val correct = new Array[Byte](16)
    cryptoOneTimeAuth(correct, 0, in, inOffset, inLength, key)
    if (!cryptoVerify16(h, hOffset, correct)) sys.error("Decryption failed: ciphertext failed verification")
  }

}
