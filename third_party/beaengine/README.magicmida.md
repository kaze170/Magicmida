# Vendored BeaEngine

Source: https://github.com/Hendi48/beaengine
Commit: `6eaf28674c20e73f094ac0f7aee5a770c6a94b3a`

`src`, `include`, and `headers` are copied without modification. Compile only
`src/BeaEngine.c`: it includes the other C implementation files itself.
Built as C with `BEA_ENGINE_STATIC` for the selected architecture. Do not link
the legacy Delphi `.obj` files into MSVC. License texts: `src/COPYING.txt` and
`src/COPYING.LESSER.txt` (LGPL v3 or later). Retain these and the source when
redistributing the statically linked application.
