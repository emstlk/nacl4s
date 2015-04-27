package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.core.{Salsa20, HSalsa20, Curve25519}
import com.emstlk.nacl4s.crypto.core.Curve25519._
import com.emstlk.nacl4s.crypto.core.Poly1305._
import org.scalatest._

class NaClSpec extends FunSpec with Matchers {

  def toHex(a: Array[Byte]) = a.map("%02x" format _).mkString

  def fromHex(s: String) = s.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)

  describe("Utils") {

    it("store and load Int") {
      val arr = new Array[Byte](4)
      storeInt(arr, 0, Int.MinValue)
      loadInt(arr, 0) shouldBe Int.MinValue
    }

    it("store and load Long") {
      val arr = new Array[Byte](8)
      storeLong(arr, 0, Long.MinValue)
      loadLong(arr, 0) shouldBe Long.MinValue
    }

  }

  describe("Salsa20") {

    it("first case") {
      val secondKey = fromHex("dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4")
      val noncesuffix = fromHex("8219e0036b7a0b37")
      val c = fromHex("657870616e642033322d62797465206b")
      val in = new Array[Byte](16)
      val out = new Array[Byte](64)
      val h = new Array[Byte](32)
      val expectedOut = "a763249cfc79b52add4d52000bae41c0b7fa0e72368ae15495a1a50714d5c020" +
        "8c2f5ba72de4cf3ddce7efd71d2aebf22d19b607e6647446f4284fa4b89d5d91"
      Salsa20.encrypt(out, in, secondKey, c)
      toHex(out) shouldBe expectedOut
    }

    it("second case") {
      val k = fromHex("0102030405060708090a0b0c0d0e0f10c9cacbcccdcecfd0d1d2d3d4d5d6d7d8")
      val in = fromHex("65666768696a6b6c6d6e6f7071727374")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](64)
      val expectedOut = "45254427290f6bc1ff8b7a06aae9d9625990b66a1533c841ef31de22d772287e" +
        "68c507e1c5991f02664e4cb054f5f6b8b1a0858206489577c0c384ecea67f64a"
      Salsa20.encrypt(out, in, k, c)
      toHex(out) shouldBe expectedOut
    }

    it("third case") {
      val k = fromHex("ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777")
      val in = fromHex("81918ef2a5e0da9b3e9060521e4bb352")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](64)
      Salsa20.encrypt(out, in, k, c)

      def show(x: Array[Byte], xoffset: Int, y: Array[Byte], yoffset: Int) = {
        var borrow = 0
        (0 until 4).map { i =>
          val xi = x(xoffset + i) & 0xff
          val yi = y(yoffset + i) & 0xff
          val res = "%02x".format((xi - yi - borrow) & 0xff)
          borrow = if (xi < yi + borrow) 1 else 0
          res
        }.mkString
      }

      show(out, 0, c, 0) shouldBe "bc1b30fc"
      show(out, 20, c, 4) shouldBe "072cc140"
      show(out, 40, c, 8) shouldBe "75e4baa7"
      show(out, 60, c, 12) shouldBe "31b5a845"
      show(out, 24, in, 0) shouldBe "ea9b11e9"
      show(out, 28, in, 4) shouldBe "a5191f94"
      show(out, 32, in, 8) shouldBe "e18cba8f"
      show(out, 36, in, 12) shouldBe "d821a7cd"
    }

  }

  describe("HSalsa20") {

    it("first case") {
      val shared = fromHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
      val c = fromHex("657870616e642033322d62797465206b")
      val firstkey = new Array[Byte](32)
      HSalsa20.encrypt(firstkey, new Array[Byte](32), shared, c)
      toHex(firstkey) shouldBe "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389"
    }

    it("second case") {
      val firstKey = fromHex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389")
      val nonceprefix = fromHex("69696ee955b62b73cd62bda875fc73d6")
      val c = fromHex("657870616e642033322d62797465206b")
      val secondKey = new Array[Byte](32)
      HSalsa20.encrypt(secondKey, nonceprefix, firstKey, c)
      toHex(secondKey) shouldBe "dc908dda0b9344a953629b733820778880f3ceb421bb61b91cbd4c3e66256ce4"
    }

    it("third case") {
      val k = fromHex("ee304fca27008d8c126f90027901d80f7f1d8b8dc936cf3b9f819692827e5777")
      val in = fromHex("81918ef2a5e0da9b3e9060521e4bb352")
      val c = fromHex("657870616e642033322d62797465206b")
      val out = new Array[Byte](32)
      HSalsa20.encrypt(out, in, k, c)
      toHex(out) shouldBe "bc1b30fc072cc14075e4baa731b5a845ea9b11e9a5191f94e18cba8fd821a7cd"
    }

  }

  describe("Poly1305") {

    it("first case") {
      val rs = fromHex("eea6a7251c1e72916d11c2cb214d3c252539121d8e234e652d651fa4c8cff880")

      val c = fromHex("8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a" +
        "c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738" +
        "b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da" +
        "99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74" +
        "e355a5")

      val mac = new Array[Byte](16)
      oneTimeAuth(mac, 0, c, 0, c.length, rs)
      toHex(mac) shouldBe "f3ffc7703f9400e52a7dfb4b3d3305d9"

      noException should be thrownBy {
        oneTimeAuthVerify(mac, 0, c, 0, c.length, rs)
      }
    }

  }

  describe("Curve25519") {

    it("first case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val alicepk = new Array[Byte](Curve25519.bytes)
      cryptoScalarmultBase(alicepk, alicesk)
      toHex(alicepk) shouldBe "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    }

    it("second case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val bobpk = new Array[Byte](Curve25519.bytes)
      cryptoScalarmultBase(bobpk, bobsk)
      toHex(bobpk) shouldBe "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    }

    it("third case") {
      val alicesk = fromHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
      val bobpk = fromHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
      val k = new Array[Byte](Curve25519.bytes)
      cryptoScalarmult(k, alicesk, bobpk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fourth case") {
      val bobsk = fromHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
      val alicepk = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val k = new Array[Byte](Curve25519.bytes)
      cryptoScalarmult(k, bobsk, alicepk)
      toHex(k) shouldBe "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    }

    it("fifth case") {
      val p1 = fromHex("7220f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4eea")
      val p2 = fromHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
      val out1 = new Array[Byte](Curve25519.bytes)
      val out2 = new Array[Byte](Curve25519.bytes)
      val scalar = new Array[Byte](scalarBytes)
      scalar(0) = 1

      cryptoScalarmult(out1, scalar, p1)
      cryptoScalarmult(out2, scalar, p2)
      toHex(out1) shouldBe "03ad4080c2910b5e0be22f6c5f7c7e08e642462ef0ec93a654c5c34dc95b556d"
      toHex(out2) shouldBe "2108adf6afe8883b77ac565e807159be646f7f35275bb0a9bc4ed29759ee665b"
    }

  }

}
