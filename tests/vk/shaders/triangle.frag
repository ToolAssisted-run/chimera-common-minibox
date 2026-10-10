#version 450
layout(set = 0, binding = 0) uniform Colour { vec4 colour; } u;
layout(push_constant) uniform Push { vec4 add; } p;
layout(location = 0) out vec4 o;
void main() { o = u.colour + p.add; }
