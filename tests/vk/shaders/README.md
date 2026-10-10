# The test's shaders

`triangle.vert` and `triangle.frag` are the source of the words in
`../triangle-spv.h`. miniBox does not build a shader compiler, so the compiled
form is kept; to make it again after changing a shader:

    glslangValidator -V -S vert -o triangle.vert.spv triangle.vert
    spirv-opt -O triangle.vert.spv -o triangle.vert.opt.spv

and the same for `frag`, then write each `.opt.spv` out as little-endian
32-bit words. The ones here were made with glslang and SPIRV-Tools as the
Xenia core builds them (glslang 16.x, SPIRV-Tools 33e0256).
