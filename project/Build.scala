import sbt._
import Keys._

object Build extends Build {

  lazy val root = Project(
    id = "nacl4s",
    base = file("."),
    settings = Seq(
      organization := "com.github.emstlk",
      version := "1.0.0",
      scalaVersion := "2.11.6",
      crossScalaVersions := Seq("2.10.5", "2.11.6"),
      scalacOptions ++= Seq("-encoding", "UTF-8", "-deprecation", "-unchecked", "-feature"),
      libraryDependencies ++= Seq(
        "org.scalatest" %% "scalatest" % "2.2.4" % "test" withSources()
      ),
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
  )

}
