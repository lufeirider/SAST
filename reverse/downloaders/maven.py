"""Deprecated alias — use jar_source.JarSourceResolver (JAR-centric)."""

from reverse.downloaders.jar_source import JarSourceResolver, MavenSourceDownloader

__all__ = ["JarSourceResolver", "MavenSourceDownloader"]
