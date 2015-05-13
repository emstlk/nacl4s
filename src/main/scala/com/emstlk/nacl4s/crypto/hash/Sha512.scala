package com.emstlk.nacl4s.crypto.hash

object Sha512 {

  val bytes = 64

  final case class State(state: Array[Long], count: Array[Long], buf: Array[Byte])

  @inline def loadLong(in: Array[Byte], offset: Int): Long = {
    (in(offset + 7).toLong & 0xff) |
      ((in(offset + 6).toLong & 0xff) << 8) |
      ((in(offset + 5).toLong & 0xff) << 16) |
      ((in(offset + 4).toLong & 0xff) << 24) |
      ((in(offset + 3).toLong & 0xff) << 32) |
      ((in(offset + 2).toLong & 0xff) << 40) |
      ((in(offset + 1).toLong & 0xff) << 48) |
      ((in(offset).toLong & 0xff) << 56)
  }

  @inline def storeLong(out: Array[Byte], offset: Int, in: Long) {
    out(offset + 7) = (in & 0xff).toByte
    out(offset + 6) = ((in >>> 8) & 0xff).toByte
    out(offset + 5) = ((in >>> 16) & 0xff).toByte
    out(offset + 4) = ((in >>> 24) & 0xff).toByte
    out(offset + 3) = ((in >>> 32) & 0xff).toByte
    out(offset + 2) = ((in >>> 40) & 0xff).toByte
    out(offset + 1) = ((in >>> 48) & 0xff).toByte
    out(offset) = ((in >>> 56) & 0xff).toByte
  }

  @inline def rotr(x: Long, n: Int) = (x >>> n) | (x << (64 - n))

  def S0(x: Long) = rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39)
  def S1(x: Long) = rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41)

  def s0(x: Long) = rotr(x, 1) ^ rotr(x, 8) ^ (x >>> 7)
  def s1(x: Long) = rotr(x, 19) ^ rotr(x, 61) ^ (x >>> 6)

  def sha512Transform(state: Array[Long], block: Array[Byte], offset: Int) {
    val w = new Array[Long](80)
    val s = new Array[Long](8)

    var t0, t1 = 0L

    @inline def rnd(i: Int, k: Long) {
      @inline def doRnd(a: Long, b: Long, c: Long, e: Long, f: Long, g: Long) {
        t0 = s((87 - i) % 8) + S1(e) + ((e & (f ^ g)) ^ g) + w(i) + k
        t1 = S0(a) + ((a & (b | c)) | (b & c))
        s((83 - i) % 8) += t0
        s((87 - i) % 8) = t0 + t1
      }

      doRnd(s((80 - i) % 8), s((81 - i) % 8),
        s((82 - i) % 8), s((84 - i) % 8),
        s((85 - i) % 8), s((86 - i) % 8))
    }

    for (i <- 0 until 16)
      w(i) = loadLong(block, offset + i * 8)

    for (i <- 16 until 80)
      w(i) = s1(w(i - 2)) + w(i - 7) + s0(w(i - 15)) + w(i - 16)

    Array.copy(state, 0, s, 0, 8)

    rnd(0, 0x428a2f98d728ae22L)
    rnd(1, 0x7137449123ef65cdL)
    rnd(2, 0xb5c0fbcfec4d3b2fL)
    rnd(3, 0xe9b5dba58189dbbcL)
    rnd(4, 0x3956c25bf348b538L)
    rnd(5, 0x59f111f1b605d019L)
    rnd(6, 0x923f82a4af194f9bL)
    rnd(7, 0xab1c5ed5da6d8118L)
    rnd(8, 0xd807aa98a3030242L)
    rnd(9, 0x12835b0145706fbeL)
    rnd(10, 0x243185be4ee4b28cL)
    rnd(11, 0x550c7dc3d5ffb4e2L)
    rnd(12, 0x72be5d74f27b896fL)
    rnd(13, 0x80deb1fe3b1696b1L)
    rnd(14, 0x9bdc06a725c71235L)
    rnd(15, 0xc19bf174cf692694L)
    rnd(16, 0xe49b69c19ef14ad2L)
    rnd(17, 0xefbe4786384f25e3L)
    rnd(18, 0x0fc19dc68b8cd5b5L)
    rnd(19, 0x240ca1cc77ac9c65L)
    rnd(20, 0x2de92c6f592b0275L)
    rnd(21, 0x4a7484aa6ea6e483L)
    rnd(22, 0x5cb0a9dcbd41fbd4L)
    rnd(23, 0x76f988da831153b5L)
    rnd(24, 0x983e5152ee66dfabL)
    rnd(25, 0xa831c66d2db43210L)
    rnd(26, 0xb00327c898fb213fL)
    rnd(27, 0xbf597fc7beef0ee4L)
    rnd(28, 0xc6e00bf33da88fc2L)
    rnd(29, 0xd5a79147930aa725L)
    rnd(30, 0x06ca6351e003826fL)
    rnd(31, 0x142929670a0e6e70L)
    rnd(32, 0x27b70a8546d22ffcL)
    rnd(33, 0x2e1b21385c26c926L)
    rnd(34, 0x4d2c6dfc5ac42aedL)
    rnd(35, 0x53380d139d95b3dfL)
    rnd(36, 0x650a73548baf63deL)
    rnd(37, 0x766a0abb3c77b2a8L)
    rnd(38, 0x81c2c92e47edaee6L)
    rnd(39, 0x92722c851482353bL)
    rnd(40, 0xa2bfe8a14cf10364L)
    rnd(41, 0xa81a664bbc423001L)
    rnd(42, 0xc24b8b70d0f89791L)
    rnd(43, 0xc76c51a30654be30L)
    rnd(44, 0xd192e819d6ef5218L)
    rnd(45, 0xd69906245565a910L)
    rnd(46, 0xf40e35855771202aL)
    rnd(47, 0x106aa07032bbd1b8L)
    rnd(48, 0x19a4c116b8d2d0c8L)
    rnd(49, 0x1e376c085141ab53L)
    rnd(50, 0x2748774cdf8eeb99L)
    rnd(51, 0x34b0bcb5e19b48a8L)
    rnd(52, 0x391c0cb3c5c95a63L)
    rnd(53, 0x4ed8aa4ae3418acbL)
    rnd(54, 0x5b9cca4f7763e373L)
    rnd(55, 0x682e6ff3d6b2b8a3L)
    rnd(56, 0x748f82ee5defb2fcL)
    rnd(57, 0x78a5636f43172f60L)
    rnd(58, 0x84c87814a1f0ab72L)
    rnd(59, 0x8cc702081a6439ecL)
    rnd(60, 0x90befffa23631e28L)
    rnd(61, 0xa4506cebde82bde9L)
    rnd(62, 0xbef9a3f7b2c67915L)
    rnd(63, 0xc67178f2e372532bL)
    rnd(64, 0xca273eceea26619cL)
    rnd(65, 0xd186b8c721c0c207L)
    rnd(66, 0xeada7dd6cde0eb1eL)
    rnd(67, 0xf57d4f7fee6ed178L)
    rnd(68, 0x06f067aa72176fbaL)
    rnd(69, 0x0a637dc5a2c898a6L)
    rnd(70, 0x113f9804bef90daeL)
    rnd(71, 0x1b710b35131c471bL)
    rnd(72, 0x28db77f523047d84L)
    rnd(73, 0x32caab7b40c72493L)
    rnd(74, 0x3c9ebe0a15c9bebcL)
    rnd(75, 0x431d67c49c100d4cL)
    rnd(76, 0x4cc5d4becb3e42b6L)
    rnd(77, 0x597f299cfc657e2aL)
    rnd(78, 0x5fcb6fab3ad6faecL)
    rnd(79, 0x6c44198c4a475817L)

    for (i <- 0 until 8) {
      state(i) += s(i)
    }
  }

  private val pad = {
    val p = new Array[Byte](128)
    p(0) = 128.toByte
    p
  }

  def sha512Pad(st: State) {
    val len = new Array[Byte](16)
    storeLong(len, 0, st.count(0))
    storeLong(len, 8, st.count(1))

    val r = (st.count(1) >>> 3) & 0x7f
    val plen = if (r < 112) 112 - r else 240 - r

    update(st, pad, plen)
    update(st, len, 16)
  }

  def init(st: State) {
    st.state(0) = 0x6a09e667f3bcc908L
    st.state(1) = 0xbb67ae8584caa73bL
    st.state(2) = 0x3c6ef372fe94f82bL
    st.state(3) = 0xa54ff53a5f1d36f1L
    st.state(4) = 0x510e527fade682d1L
    st.state(5) = 0x9b05688c2b3e6c1fL
    st.state(6) = 0x1f83d9abfb41bd6bL
    st.state(7) = 0x5be0cd19137e2179L
  }

  def update(st: State, in: Array[Byte], length: Long) {
    val r = (st.count(1) >>> 3) & 0x7f

    val bitLen = new Array[Long](2)
    bitLen(0) = length << 3
    bitLen(1) = length >>> 61

    st.count(1) += bitLen(1)
    if (st.count(1) < bitLen(1)) st.count(0) += 1

    st.count(0) += bitLen(0)

    if (length < 128 - r) Array.copy(in, 0, st.buf, r.toInt, length.toInt)
    else {
      Array.copy(in, 0, st.buf, r.toInt, (128 - r).toInt)
      sha512Transform(st.state, st.buf, 0)

      var pos = (128 - r).toInt
      while (length - pos >= 128) {
        sha512Transform(st.state, in, pos)
        pos += 128
      }
      Array.copy(in, 0, st.buf, 0, (length - pos).toInt)
    }
  }

  def finish(st: State, out: Array[Byte]) {
    sha512Pad(st)
    for (i <- 0 until 8) {
      storeLong(out, i * 8, st.state(i))
    }
  }

  def crypto_hash(out: Array[Byte], in: Array[Byte], length: Long) {
    val st = State(new Array[Long](8), new Array[Long](2), new Array[Byte](128))
    init(st)
    update(st, in, length)
    finish(st, out)
  }

}
