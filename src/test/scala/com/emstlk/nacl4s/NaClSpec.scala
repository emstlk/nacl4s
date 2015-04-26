package com.emstlk.nacl4s

import com.emstlk.nacl4s.crypto.Utils._
import com.emstlk.nacl4s.crypto.core.Curve25519
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

  describe("Poly1305") {

    it("one case") {
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
