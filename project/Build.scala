import pl.project13.scala.sbt.JmhPlugin
import sbt.Keys._
import sbt._
import scoverage.ScoverageSbtPlugin.ScoverageKeys._

object Build extends Build {

  lazy val root = Project(
    id = "nacl4s",
    base = file("."),
    settings = Seq(
      organization := "com.github.emstlk",
      version := "1.0.0-SNAPSHOT",
      scalaVersion := "2.11.6",
      crossScalaVersions := Seq("2.10.5", scalaVersion.value),
      scalacOptions ++= Seq(
        "-encoding", "UTF-8",
        "-deprecation",
        "-unchecked",
        "-feature",
        "-Xfatal-warnings",
        "-Xlint",
        "-Xfuture",
        "-Yno-adapted-args",
        "-Ywarn-dead-code",
        "-Ywarn-numeric-widen"
      ) ++ (CrossVersion.partialVersion(scalaVersion.value) match {
        case Some((2, 11)) => Seq("-Ywarn-unused-import")
        case _ => Seq.empty
      }),
      libraryDependencies ++= Seq(
        "org.scalatest" %% "scalatest" % "2.2.4" % "test" withSources(),
        "org.scalacheck" %% "scalacheck" % "1.12.2" % "test" withSources()
      ),
      coverageExcludedPackages := "com\\.emstlk\\.nacl4s\\.crypto\\.sign\\.Const;com\\.emstlk\\.nacl4s\\.benchmark",
      publishMavenStyle := true,
      publishArtifact := true,
      publishTo := {
        val nexus = "https://oss.sonatype.org/"
        if (isSnapshot.value)
          Some("snapshots" at nexus + "content/repositories/snapshots")
        else
          Some("releases" at nexus + "service/local/staging/deploy/maven2")
      },
      publishArtifact in Test := false,
      licenses := Seq("MIT License" -> url("http://opensource.org/licenses/MIT")),
      homepage := Some(url("https://github.com/emstlk/nacl4s")),
      scmInfo := Some(ScmInfo(
        url("https://github.com/emstlk/nacl4s"),
        "scm:git:git@github.com:emstlk/nacl4s.git"
      )),
      pomExtra :=
        <developers>
          <developer>
            <id>emstlk</id>
            <name>eMASTER</name>
            <url>https://github.com/emstlk</url>
          </developer>
        </developers>
    )
  ).enablePlugins(JmhPlugin)

}
