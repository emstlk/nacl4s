package com.emstlk.nacl4s.crypto.core

object Poly1305 {

  val crypto_onetimeauth_poly1305_BYTES = 16
  val crypto_onetimeauth_poly1305_KEYBYTES = 32

  val blockSize = 16

  val minusp = Array[Int](5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252)

  case class State(buffer: Array[Byte] = new Array[Byte](blockSize),
                   var leftover: Int = 0,
                   h: Array[Int] = new Array[Int](17),
                   r: Array[Int] = new Array[Int](17),
                   pad: Array[Int] = new Array[Int](17),
                   var fin: Byte = 0)

  def cryptoOnetimeauth(out: Array[Byte],
                        outoffset: Int,
                        in: Array[Byte],
                        inoffset: Int,
                        inlen: Int,
                        k: Array[Byte]) {
    val state = State()

    init(state, k)
    update(state, in, inoffset, inlen)
    finish(state, out, outoffset)
  }

  def cryptoOnetimeauthVerify(h: Array[Byte],
                              hoffset: Int,
                              in: Array[Byte],
                              inoffset: Int,
                              inlen: Int,
                              k: Array[Byte]): Int = {
    val correct = new Array[Byte](16)

    cryptoOnetimeauth(correct, 0, in, inoffset, inlen, k)
    Verify16.cryptoVerify(h, hoffset, correct)
  }

  def init(st: State, k: Array[Byte]) {
    st.r(0) = k(0) & 0xFF
    st.r(1) = k(1) & 0xFF
    st.r(2) = k(2) & 0xFF
    st.r(3) = k(3) & 0x0F
    st.r(4) = k(4) & 0xFC
    st.r(5) = k(5) & 0xFF
    st.r(6) = k(6) & 0xFF
    st.r(7) = k(7) & 0x0F
    st.r(8) = k(8) & 0xFC
    st.r(9) = k(9) & 0xFF
    st.r(10) = k(10) & 0xFF
    st.r(11) = k(11) & 0x0F
    st.r(12) = k(12) & 0xFC
    st.r(13) = k(13) & 0xFF
    st.r(14) = k(14) & 0xFF
    st.r(15) = k(15) & 0x0F

    for (i <- 0 until 16) {
      st.pad(i) = k(i + 16) & 0xFF
    }
  }

  def add(h: Array[Int], c: Array[Int]) {
    var u = 0
    for (i <- 0 until 17) {
      u += h(i) + c(i)
      h(i) = u & 0xFF
      u >>>= 8
    }
  }

  def squeeze(h: Array[Int], hr: Array[Int]) {
    var u = 0
    for (i <- 0 until 16) {
      u += hr(i)
      h(i) = u & 0xFF
      u >>>= 8
    }

    u += hr(16)
    h(16) = u & 0x03
    u >>>= 2
    u += (u << 2)

    for (i <- 0 until 16) {
      u += h(i)
      h(i) = u & 0xFF
      u >>>= 8
    }
    h(16) += u
  }

  def freeze(h: Array[Int]) {
    val horig = new Array[Int](17)
    for (i <- 0 until 17) {
      horig(i) = h(i)
    }

    add(h, minusp)

    val negative = -(h(16) >>> 7)
    for (i <- 0 until 17) {
      h(i) = h(i) ^ (negative & (horig(i) ^ h(i)))
    }
  }

  def blocks(st: State, m: Array[Byte], offset: Int, length: Int) {
    val hibit = st.fin ^ 1

    var pos = offset
    while (length - pos >= blockSize) {
      val c = new Array[Int](17)
      for (i <- 0 until 16) {
        c(i) = m(pos + i) & 0xFF
      }
      c(16) = hibit

      add(st.h, c)

      val hr = new Array[Int](17)
      for (i <- 0 until 17) {
        var u = 0
        for (j <- 0 to i) {
          u += st.h(j) * st.r(i - j)
        }
        for (j <- (i + 1) until 17) {
          val v = st.h(j) * st.r(i + 17 - j)
          u += (v << 8) + (v << 6)
        }
        hr(i) = u
      }

      squeeze(st.h, hr)

      pos += blockSize
    }
  }

  def update(st: State, m: Array[Byte], offset: Int, length: Int) {
    var pos = offset

    if (st.leftover != 0) {
      var want = blockSize - st.leftover
      if (want > length) want = length

      for (i <- 0 until want) {
        st.buffer(st.leftover + i) = m(pos + i)
      }

      pos += want
      st.leftover += want

      //TODO
      if (st.leftover < blockSize) return

      blocks(st, st.buffer, 0, blockSize)
      st.leftover = 0
    }

    var restLength = length - (pos - offset)
    if (restLength >= blockSize) {
      val want = restLength & ~(blockSize - 1)
      blocks(st, m, pos, want)
      pos += want
    }

    restLength = length - (pos - offset)
    if (restLength != 0) {
      for (i <- 0 until restLength) {
        st.buffer(st.leftover + i) = m(pos + i)
      }
      st.leftover += restLength
    }
  }

  def finish(st: State, mac: Array[Byte], offset: Int) {
    if (st.leftover != 0) {
      st.buffer(st.leftover) = 1
      for (i <- (st.leftover + 1) until blockSize) {
        st.buffer(i) = 0
      }
      st.fin = 1
      blocks(st, st.buffer, 0, blockSize)
    }

    freeze(st.h)
    add(st.h, st.pad)

    for (i <- 0 until 16) {
      mac(offset + i) = st.h(i).toByte
    }

    for (i <- 0 until 17) {
      st.h(i) = 0
      st.r(i) = 0
      st.pad(i) = 0
    }
  }

}
