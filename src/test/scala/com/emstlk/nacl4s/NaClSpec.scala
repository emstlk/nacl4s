package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils
import com.emstlk.nacl4s.crypto.core.Curve25519._
import com.emstlk.nacl4s.crypto.core.{Curve25519, Poly1305}
import com.emstlk.nacl4s.crypto.core.Poly1305._
import org.scalatest._

class NaClSpec extends FunSpec with Matchers {

  def toHex(a: Array[Byte]) = a.map("%02x" format _).mkString

  def fromHex(s: String) = s.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)

  describe("Save and load a little-endian number") {
    val arr = new Array[Byte](4)
    val number = Int.MaxValue

    Utils.storeInt(arr, 0, number)
    val loadedNumber = Utils.loadInt(arr, 0)

    loadedNumber shouldBe number
  }

  val rs = Array(
    0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2,
    0xcb, 0x21, 0x4d, 0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23,
    0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80)

  val c = Array(
    0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
    0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
    0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c,
    0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
    0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
    0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
    0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68,
    0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
    0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e,
    0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
    0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5
  )

  val expectedMac = Array(
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
    0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9
  )

  describe("Poly1305 MAC") {
    val mac = new Array[Byte](16)
    cryptoOnetimeauth(mac, 0, c.map(_.toByte), 0, c.length, rs.map(_.toByte))
    mac shouldBe expectedMac.map(_.toByte)

    val check = cryptoOnetimeauthVerify(mac, 0, c.map(_.toByte), 0, c.length, rs.map(_.toByte))
    check shouldBe 0
  }

  describe("Curve25519") {

    it("first case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val alicepk = new Array[Byte](scalarmultBytes)
      cryptoScalarmultBase(alicepk, alicesk)
      toHex(alicepk) shouldBe "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    }

    it("second case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val bobpk = new Array[Byte](scalarmultBytes)
      cryptoScalarmultBase(bobpk, bobsk)
      toHex(bobpk) shouldBe "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    }

    it("third case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val bobpk = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
      val k = new Array[Byte](scalarmultBytes)
      cryptoScalarmult(k, alicesk, bobpk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fourth case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val alicepk = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val k = new Array[Byte](scalarmultBytes)
      cryptoScalarmult(k, bobsk, alicepk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fifth case") {
      val p1 = fromHex("7220f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4eea")
      val p2 = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val out1 = new Array[Byte](scalarmultBytes)
      val out2 = new Array[Byte](scalarmultBytes)
      val scalar = new Array[Byte](scalarmultScalarBytes)
      scalar(0) = 1

      cryptoScalarmult(out1, scalar, p1)
      cryptoScalarmult(out2, scalar, p2)
      toHex(out1) shouldBe "03ad4080c2910b5e0be22f6c5f7c7e08e642462ef0ec93a654c5c34dc95b556d"
      toHex(out2) shouldBe "2108adf6afe8883b77ac565e807159be646f7f35275bb0a9bc4ed29759ee665b"
    }

  }

}
