# Provenance

This standalone implementation and test harness were prepared for the YuKat project owner in October 2026. The four-line signed metadata format follows the existing Windows updater's protocol: version, original URL, lowercase SHA-256, and invariant decimal byte length.

The owner has authorized publishing this separate component under MIT. No production UI, downloader, installer, VPN engine, private key, customer data or original repository history is included. The main YuKat application remains a separate private project.

Build projects depend on the .NET SDK/runtime and projects in this repository only; no third-party NuGet packages are required. The CI workflow uses official GitHub checkout and .NET setup actions.
