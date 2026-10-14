# Vendored BeaEngine

Source: https://github.com/Hendi48/beaengine
Commit: `6eaf28674c20e73f094ac0f7aee5a770c6a94b3a`

The compiled `src` and `include` files retain their upstream contents. Unused
`headers/` language bindings (Delphi, assembler, Python, C#, PureBasic and the
duplicate public header) are omitted from this native-only checkout. Compile only
`src/BeaEngine.c`: it includes the other C implementation files itself.
Built from C source with `BEA_ENGINE_STATIC` for the selected architecture.
No prebuilt object files are used. License texts: `src/COPYING.txt` and
`src/COPYING.LESSER.txt` (LGPL v3 or later). Retain these and the source when
redistributing the statically linked application.
