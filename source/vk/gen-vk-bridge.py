#!/usr/bin/env python3
"""Generates both sides of the Vulkan bridge from the Vulkan registry.

The OpenGL bridge (../gl) passes a call's arguments across untouched, because
everything OpenGL names is a small integer. Vulkan names its objects by
HANDLE, and a driver's handles are pointers into the driver: different in
every process, unreadable by a guest, and - worst - they would land in guest
memory, where they enter savestates and order whatever a renderer keeps in a
hash map. So the guest never sees one. The host keeps a table, the guest holds
counters into it, and every handle that crosses is looked up on the way.

That is what this generator is for. The registry (vk.xml) says, for every
command and every structure, which members are handles and which are arrays
and how long; from it this writes:

  vk-bridge-ops.h      an opcode per command and a struct of its arguments,
                       included by both sides so the layout is one definition
  vk-bridge-guest.c    the wrapper the guest calls: fill the struct, hand its
                       address to the sandbox's callback
  vk-bridge-host.inc   the host's answer: copy what holds handles, translate
                       them, make the real call, hand new handles back as
                       counters

A structure with no handle anywhere inside it is NOT copied: the host is in
the guest's address space and the driver reads it where it lies. Only what
must change is copied, into an arena that lasts one call.

Opcodes are indices into the master list (vk-entry-points.txt), which is
append-only. See README.md.

Usage: gen-vk-bridge.py <vk.xml> <master list> <output dir>
       gen-vk-bridge.py <vk.xml> --survey <feature or extension name>...
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

# Commands whose host side is written by hand in vk-host.c: the ones that
# decide policy (which device, which extensions), the ones that touch mapped
# memory, and the ones the registry cannot describe.
HOST_SPECIAL = {
    "vkCreateInstance", "vkDestroyInstance", "vkEnumerateInstanceExtensionProperties",
    "vkEnumerateInstanceLayerProperties", "vkEnumerateDeviceExtensionProperties",
    "vkEnumerateDeviceLayerProperties", "vkEnumeratePhysicalDevices", "vkCreateDevice",
    "vkDestroyDevice", "vkGetPhysicalDeviceMemoryProperties",
    "vkGetPhysicalDeviceMemoryProperties2", "vkGetPhysicalDeviceMemoryProperties2KHR",
    "vkAllocateMemory", "vkFreeMemory", "vkMapMemory", "vkUnmapMemory",
    "vkFlushMappedMemoryRanges", "vkInvalidateMappedMemoryRanges",
    "vkBeginCommandBuffer", "vkAllocateCommandBuffers", "vkAllocateDescriptorSets",
    "vkDestroyCommandPool", "vkDestroyDescriptorPool", "vkResetDescriptorPool",
}

# Commands the guest half answers itself, or wraps by hand (vk-guest.c): a
# mapping is a buffer on the guest's side, and "which function has this name"
# is a question about the guest's own table.
GUEST_SPECIAL = {"vkMapMemory", "vkUnmapMemory", "vkFreeMemory"}
GUEST_ONLY = {"vkGetInstanceProcAddr", "vkGetDeviceProcAddr"}

# A member the registry marks "noautovalidity" is one whose validity depends
# on something else in the structure, and when it is not valid it may hold
# anything. Each such member that this generator would follow is listed here
# with the condition under which it may be read. None means "the ordinary rule
# is right: a null pointer or a zero count is nothing". A member that is not
# listed stops the generator, so a new one is looked at by a person.
MEMBER_VALID_WHEN = {
    ("VkWriteDescriptorSet", "pImageInfo"): "vkb_desc_uses_image(d->descriptorType)",
    ("VkWriteDescriptorSet", "pBufferInfo"): "vkb_desc_uses_buffer(d->descriptorType)",
    ("VkWriteDescriptorSet", "pTexelBufferView"): "vkb_desc_uses_view(d->descriptorType)",
    ("VkDescriptorSetLayoutBinding", "pImmutableSamplers"):
        "(d->descriptorType == VK_DESCRIPTOR_TYPE_SAMPLER || "
        "d->descriptorType == VK_DESCRIPTOR_TYPE_COMBINED_IMAGE_SAMPLER)",
    ("VkFramebufferCreateInfo", "pAttachments"):
        "!(d->flags & VK_FRAMEBUFFER_CREATE_IMAGELESS_BIT)",
    # vkBeginCommandBuffer is written by hand: it clears this for a primary
    # buffer, whose inheritance info is ignored and may be anything.
    ("VkCommandBufferBeginInfo", "pInheritanceInfo"): None,
    ("VkGraphicsPipelineCreateInfo", "pStages"): None,
    ("VkSubmitInfo", "pWaitSemaphores"): None,
    ("VkRenderingInfo", "pDepthAttachment"): None,
    ("VkRenderingInfo", "pStencilAttachment"): None,
    ("VkPipelineLayoutCreateInfo", "pSetLayouts"): None,
    ("VkBindSparseInfo", "pWaitSemaphores"): None,
    ("VkSubpassDescription2", "pResolveAttachments"): None,
}

# What a structure must have for a driver to be handed it at all, where the
# registry cannot say so: a line of C run after the structure is translated,
# which sets vkb_bad to refuse the call. A descriptor write with a count and
# none of its three arrays is a null pointer the driver will follow.
STRUCT_REFUSED_WHEN = {
    "VkWriteDescriptorSet":
        "d->descriptorCount && !d->pImageInfo && !d->pBufferInfo && !d->pTexelBufferView && !d->pNext",
}

# Structures never followed: a parameter of this type is replaced by NULL.
NULLED_PARAM_TYPES = {"VkAllocationCallbacks"}


def text_of(elem):
    """A member's or parameter's declaration, without its <comment>."""
    out = elem.text or ""
    for child in elem:
        if child.tag != "comment":
            out += "".join(child.itertext())
        out += child.tail or ""
    return " ".join(out.split())


def api_ok(elem):
    api = elem.get("api")
    return api is None or "vulkan" in api.split(",")


class Field:
    """One member of a structure, or one parameter of a command."""

    def __init__(self, elem):
        self.decl = text_of(elem)
        self.type = elem.find("type").text
        self.name = elem.find("name").text
        before = self.decl[: self.decl.rfind(self.name)]
        after = self.decl[self.decl.rfind(self.name) + len(self.name):]
        self.ptr = before.count("*")
        self.const = "const" in before
        m = re.match(r"\s*\[([^\]]+)\]", after)
        self.array = m.group(1) if m else None
        self.bitfield = after.strip().startswith(":")
        self.len = elem.get("altlen") or elem.get("len")
        self.optional = (elem.get("optional") or "").split(",")[0] == "true"
        self.noauto = elem.get("noautovalidity") == "true"
        self.values = elem.get("values")


class Registry:
    def __init__(self, path):
        root = ET.parse(path).getroot()
        self.alias = {}
        self.handles = set()
        self.dispatchable = set()
        self.funcptrs = set()
        self.structs = {}      # name -> [Field]
        self.unions = set()
        self.extends = {}      # name -> [names it may be chained to]
        self.stype = {}        # name -> VK_STRUCTURE_TYPE_...
        for t in root.find("types"):
            if t.tag != "type" or not api_ok(t):
                continue
            cat = t.get("category")
            if t.get("alias"):
                self.alias[t.get("name")] = t.get("alias")
                continue
            if cat == "handle":
                name = t.find("name").text
                self.handles.add(name)
                if t.find("type").text == "VK_DEFINE_HANDLE":
                    self.dispatchable.add(name)
            elif cat == "funcpointer":
                name = t.find("name")
                self.funcptrs.add(name.text if name is not None else t.find("proto/name").text)
            elif cat in ("struct", "union"):
                name = t.get("name")
                fields = [Field(m) for m in t.findall("member") if api_ok(m)]
                self.structs[name] = fields
                if cat == "union":
                    self.unions.add(name)
                if t.get("structextends"):
                    self.extends[name] = t.get("structextends").split(",")
                for f in fields:
                    if f.name == "sType" and f.values:
                        self.stype[name] = f.values.split(",")[0]

        self.commands = {}     # name -> (return type, [Field])
        self.cmd_alias = {}
        for c in root.find("commands"):
            if not api_ok(c):
                continue
            if c.get("alias"):
                self.cmd_alias[c.get("name")] = c.get("alias")
                continue
            proto = c.find("proto")
            self.commands[proto.find("name").text] = (
                proto.find("type").text,
                [Field(p) for p in c.findall("param") if api_ok(p)])

        # What vulkan_core.h does not declare: the window systems' and the
        # provisional extensions' types and commands. A structure of theirs in
        # a chain is a structure this bridge does not know.
        good_t, bad_t, good_c, bad_c = set(), set(), set(), set()
        self.blocks = {}       # feature or extension name -> [command names]
        for f in root.findall("feature"):
            if not api_ok(f):
                continue
            for req in f.findall("require"):
                good_t.update(e.get("name") for e in req.findall("type"))
                cmds = [e.get("name") for e in req.findall("command")]
                good_c.update(cmds)
                self.blocks.setdefault(f.get("name"), []).extend(cmds)
        for x in root.find("extensions"):
            supported = (x.get("supported") or "").split(",")
            bad = (x.get("platform") is not None or x.get("provisional") == "true"
                   or "vulkan" not in supported)
            for req in x.findall("require"):
                if not api_ok(req):
                    continue
                types = [e.get("name") for e in req.findall("type")]
                cmds = [e.get("name") for e in req.findall("command")]
                (bad_t if bad else good_t).update(types)
                (bad_c if bad else good_c).update(cmds)
                if not bad:
                    self.blocks.setdefault(x.get("name"), []).extend(cmds)
        self.absent_types = bad_t - good_t
        # A structure that extends another, and a handle, is declared by
        # vulkan_core.h only if something that header covers requires it by
        # name: the safety-critical profile's are in the registry too.
        self.declared = good_t
        self.absent_cmds = bad_c - good_c
        self._needs = {}

    def canon(self, name):
        while name in self.alias:
            name = self.alias[name]
        return name

    def is_handle(self, name):
        return self.canon(name) in self.handles

    def is_struct(self, name):
        return self.canon(name) in self.structs

    def extensions_of(self, name):
        return [e for e, bases in self.extends.items()
                if name in bases and e in self.declared]

    def needs(self, name):
        """Does a value of this type hold a handle anywhere the host would
        have to translate - in itself, behind a pointer, or in a structure
        that may be chained to it?"""
        name = self.canon(name)
        if name in self._needs:
            return self._needs[name]
        self._needs[name] = False     # cycles (the chain's own base types)
        result = False
        if name in self.handles or name in self.funcptrs:
            result = True
        elif name in self.structs and name not in NULLED_PARAM_TYPES:
            for f in self.structs[name]:
                if f.name == "pNext":
                    continue
                if self.needs(f.type):
                    result = True
            if not result:
                result = any(self.needs(e) for e in self.extensions_of(name))
        self._needs[name] = result
        return result

    def unsupported_reason(self, name, seen=None):
        """Why a structure that needs translating cannot be generated, or
        None. Recursive through what it holds."""
        name = self.canon(name)
        seen = seen or set()
        if name in seen:
            return None
        seen.add(name)
        if name in self.unions:
            return "%s is a union" % name
        for f in self.structs.get(name, []):
            if f.name == "pNext" or not self.needs(f.type):
                continue
            t = self.canon(f.type)
            if t in self.funcptrs:
                return "%s.%s is a function pointer" % (name, f.name)
            if f.ptr > 1:
                return "%s.%s is a pointer to pointers" % (name, f.name)
            if f.ptr == 1 and f.len and not re.fullmatch(r"\w+", f.len):
                return "%s.%s has length '%s'" % (name, f.name, f.len)
            if f.ptr == 1 and f.noauto and (name, f.name) not in MEMBER_VALID_WHEN:
                return "%s.%s is conditionally valid and has no rule" % (name, f.name)
            if t in self.structs:
                why = self.unsupported_reason(t, seen)
                if why:
                    return why
        return None


def kind(reg, type_name):
    return "VKB_K_" + reg.canon(type_name)[2:]


# ---------------------------------------------------------------------------
# The host's translators: one per structure that holds a handle.

def gen_translator(reg, name, out):
    fields = reg.structs[name]
    out.append("VKB_UNUSED static void vkb_x_%s(%s *d)\n{" % (name, name))
    body = []
    for f in fields:
        if f.name == "pNext":
            if any(reg.needs(e) for e in reg.extensions_of(name)):
                body.append("\td->pNext = vkb_chain(d->pNext);")
            continue
        if not reg.needs(f.type):
            continue
        t = reg.canon(f.type)
        look = "vkb_h_soft" if f.noauto else "vkb_h0"
        if f.ptr == 0:
            if t in reg.handles:
                if f.array:
                    body.append("\tfor (uint32_t i = 0; i < %s; i++) d->%s[i] = (%s)%s((uint64_t)d->%s[i], %s);"
                                % (f.array, f.name, f.type, look, f.name, kind(reg, t)))
                else:
                    body.append("\td->%s = (%s)%s((uint64_t)d->%s, %s);"
                                % (f.name, f.type, look, f.name, kind(reg, t)))
            elif f.array:
                body.append("\tfor (uint32_t i = 0; i < %s; i++) vkb_x_%s(&d->%s[i]);" % (f.array, t, f.name))
            else:
                body.append("\tvkb_x_%s(&d->%s);" % (t, f.name))
            continue
        count = "d->%s" % f.len if f.len else "1"
        cond = "d->%s" % f.name
        rule = MEMBER_VALID_WHEN.get((name, f.name))
        if rule:
            cond = "%s && %s" % (rule, cond)
        if t in reg.handles:
            body.append("\tif (%s) d->%s = (const %s *)vkb_h_array(d->%s, %s, %s);\n\telse d->%s = NULL;"
                        % (cond, f.name, f.type, f.name, count, kind(reg, t), f.name))
        else:
            body.append("\tif (%s) {\n\t\t%s *c = vkb_copy(d->%s, (size_t)(%s) * sizeof(%s));\n"
                        "\t\tfor (uint32_t i = 0; c && i < (uint32_t)(%s); i++) vkb_x_%s(&c[i]);\n"
                        "\t\td->%s = c;\n\t} else d->%s = NULL;"
                        % (cond, t, f.name, count, t, count, t, f.name, f.name))
    out.extend(body)
    if name in STRUCT_REFUSED_WHEN:
        out.append("#ifndef VKB_TEST_BREAK_EMPTY_WRITE    /* a test build: nothing is refused here */")
        out.append("\tif (%s) vkb_bad = 1;" % STRUCT_REFUSED_WHEN[name])
        out.append("#endif")
    out.append("}\n")


def translator_order(reg, wanted):
    """Structures in an order where each comes after what it holds."""
    order, state = [], {}

    def visit(name):
        name = reg.canon(name)
        if state.get(name) or name not in reg.structs:
            return
        state[name] = 1
        for f in reg.structs[name]:
            if f.name != "pNext" and reg.needs(f.type) and reg.is_struct(f.type):
                visit(f.type)
        order.append(name)

    for name in sorted(wanted):
        visit(name)
    return order


# ---------------------------------------------------------------------------
# Commands.

def param_decl(p):
    """A parameter as a member of the argument block: an array decays."""
    if p.array:
        return re.sub(r"\s*\[[^\]]+\]", "", p.decl.replace(p.name, "*" + p.name, 1))
    return p.decl


def len_expr(cmd_params, p):
    """The C expression for how many elements a parameter points at, read
    from the guest's own argument block."""
    if not p.len:
        return "1"
    first = p.len.split(",")[0]
    if not re.fullmatch(r"[\w>-]+", first):
        return None
    return "a->" + first


def command_problem(reg, name):
    ret, params = reg.commands[name]
    if name in reg.absent_cmds:
        return "not declared by vulkan_core.h"
    if name in HOST_SPECIAL or name in GUEST_ONLY:
        return None
    if ret not in ("void", "VkResult", "VkBool32", "uint32_t"):
        return "returns %s" % ret
    for p in params:
        t = reg.canon(p.type)
        if t in NULLED_PARAM_TYPES or not reg.needs(t):
            continue
        if p.ptr > 1:
            return "%s is a pointer to pointers" % p.name
        if t in reg.funcptrs:
            return "%s is a function pointer" % p.name
        if p.ptr == 1 and p.len and len_expr(params, p) is None:
            return "%s has length '%s'" % (p.name, p.len)
        if t in reg.structs:
            if p.ptr == 1 and not p.const:
                return "%s returns a structure holding handles" % p.name
            why = reg.unsupported_reason(t)
            if why:
                return why
    return None


def structs_needed(reg, names):
    """Every structure the host must be able to translate for these
    commands: what their parameters hold, and what may be chained to it."""
    todo, seen = [], set()
    for name in names:
        if name in GUEST_ONLY:
            continue
        for p in reg.commands[name][1]:
            t = reg.canon(p.type)
            if t in reg.structs and t not in NULLED_PARAM_TYPES and reg.needs(t):
                todo.append(t)
    while todo:
        t = reg.canon(todo.pop())
        if t in seen or t not in reg.structs:
            continue
        seen.add(t)
        for f in reg.structs[t]:
            if f.name != "pNext" and reg.needs(f.type) and reg.is_struct(f.type):
                todo.append(f.type)
        for e in reg.extensions_of(t):
            if reg.needs(e):
                todo.append(e)
    # a chained structure that cannot be translated is one the chain drops
    return {t for t in seen if not reg.unsupported_reason(t)}, \
           {t for t in seen if reg.unsupported_reason(t)}


def gen_host_command(reg, name, op, out):
    ret, params = reg.commands[name]
    creates = not (name.startswith("vkEnumerate") or name.startswith("vkGet"))
    destroys = name.startswith("vkDestroy") or name.startswith("vkFree")
    pre, args, post = [], [], []
    count_params = {p.name for p in params if p.ptr == 1 and not p.const and p.type == "uint32_t"}
    victim = None
    for p in params:
        t = reg.canon(p.type)
        if t in reg.handles:
            victim = p
    for p in params:
        t = reg.canon(p.type)
        if t in NULLED_PARAM_TYPES:
            args.append("NULL")
        elif t in reg.handles and p.ptr == 0:
            fn = "vkb_h0" if p.optional else "vkb_h"
            args.append("(%s)%s((uint64_t)a->%s, %s)" % (p.type, fn, p.name, kind(reg, t)))
        elif t in reg.handles and p.const:
            args.append("(const %s *)vkb_h_array(a->%s, %s, %s)"
                        % (p.type, p.name, len_expr(params, p), kind(reg, t)))
        elif t in reg.handles:
            n = len_expr(params, p)
            enumerating = p.len and p.len.split(",")[0] in count_params
            how = "vkb_new" if creates else "vkb_intern"
            if enumerating:
                n = "(a->%s ? *a->%s : 0)" % (p.len, p.len)
            pre.append("\t\t%s *o_%s = a->%s ? vkb_alloc((size_t)(%s) * sizeof(%s)) : NULL;"
                       % (p.type, p.name, p.name, n, p.type))
            args.append("o_%s" % p.name)
            post.append("\t\tfor (uint32_t i = 0; ok && o_%s && i < (uint32_t)(%s); i++)\n"
                        "\t\t\ta->%s[i] = (%s)%s(%s, (uint64_t)o_%s[i]);"
                        % (p.name, n, p.name, p.type, how, kind(reg, t), p.name))
        elif t in reg.structs and reg.needs(t) and p.ptr == 1:
            n = len_expr(params, p)
            pre.append("\t\t%s *c_%s = vkb_copy(a->%s, (size_t)(%s) * sizeof(%s));\n"
                       "\t\tfor (uint32_t i = 0; c_%s && i < (uint32_t)(%s); i++) vkb_x_%s(&c_%s[i]);"
                       % (t, p.name, p.name, n, t, p.name, n, t, p.name))
            args.append("c_%s" % p.name)
        else:
            args.append("a->%s" % p.name)

    out.append("\tcase VK_OP_%s: {" % name)
    out.append("\t\tstruct vkb_%s_args *a = (struct vkb_%s_args *)args;" % (name, name))
    out.append("\t\t(void)a;")
    out.extend(pre)
    refused = {"VkResult": "(uint64_t)(int64_t)VK_ERROR_DEVICE_LOST"}.get(ret, "0")
    out.append("\t\tif (vkb_bad || !vkb_fn.%s) return vkb_refuse(op, %s);" % (name, refused))
    call = "vkb_fn.%s(%s)" % (name, ", ".join(args))
    if ret == "void":
        out.append("\t\t%s;" % call)
        out.append("\t\tconst int ok = 1; (void)ok;")
        result = "0"
    elif ret == "VkResult":
        out.append("\t\tconst VkResult r = %s;" % call)
        out.append("\t\tconst int ok = r >= 0; (void)ok;")
        result = "(uint64_t)(int64_t)r"
    else:
        out.append("\t\tconst %s r = %s;" % (ret, call))
        out.append("\t\tconst int ok = 1; (void)ok;")
        result = "(uint64_t)r"
    out.extend(post)
    if destroys and victim is not None:
        t = reg.canon(victim.type)
        if victim.ptr == 0:
            out.append("\t\tvkb_forget((uint64_t)a->%s, %s);" % (victim.name, kind(reg, t)))
        else:
            out.append("\t\tfor (uint32_t i = 0; a->%s && i < (uint32_t)(%s); i++) vkb_forget((uint64_t)a->%s[i], %s);"
                       % (victim.name, len_expr(params, victim), victim.name, kind(reg, t)))
    out.append("\t\treturn %s;" % result)
    out.append("\t}")


def survey(reg, blocks):
    for block in blocks:
        for name in reg.blocks.get(block, []):
            name = reg.cmd_alias.get(name, name) if name not in reg.commands else name
            why = command_problem(reg, name)
            print("%-52s %s" % (name, "ok" if why is None else "NO: " + why))


def main():
    if len(sys.argv) >= 3 and sys.argv[2] == "--survey":
        survey(Registry(sys.argv[1]), sys.argv[3:])
        return 0
    if len(sys.argv) != 4:
        sys.stderr.write(__doc__)
        return 2
    reg = Registry(sys.argv[1])
    master = [line.strip() for line in open(sys.argv[2], encoding="ascii").read().split("\n")]
    while master and not master[-1]:
        master.pop()
    out_dir = sys.argv[3]

    # A name in the list is either a command or an alias of one; an alias has
    # its own opcode (it is its own name to a driver) and its target's shape.
    def shape(name):
        return name if name in reg.commands else reg.cmd_alias.get(name)

    live = []
    for index, name in enumerate(master):
        if not name or name.startswith("-"):
            continue        # a retired opcode: the line stays, nothing answers
        target = shape(name)
        if target is None:
            sys.exit("gen-vk-bridge: %s is not in the registry" % name)
        why = command_problem(reg, target)
        if why:
            sys.exit("gen-vk-bridge: %s cannot be generated: %s" % (name, why))
        live.append((100 + index, name, target))

    wanted, dropped = structs_needed(reg, {t for _, _, t in live})
    order = [s for s in translator_order(reg, wanted) if s in wanted]

    # ---- the shared header ----------------------------------------------------
    h = ["/* Generated by gen-vk-bridge.py from the Vulkan registry. Do not edit. */",
         "#pragma once", "#include <vulkan/vulkan_core.h>", "",
         "#define VKB_LIST_LENGTH %d" % len(master), ""]
    for op, name, target in live:
        h.append("#define VK_OP_%s %d" % (name, op))
    h.append("")
    done = set()
    for op, name, target in live:
        if target in done:
            continue
        done.add(target)
        h.append("struct vkb_%s_args {" % target)
        params = reg.commands[target][1]
        h.extend("\t%s;" % param_decl(p) for p in params)
        if not params:
            h.append("\tint nothing;")
        h.append("};")
    h.append("")
    h.append("enum vkb_kind {\n\tVKB_K_none = 0,")
    for handle in sorted(reg.handles):
        if handle in reg.declared:
            h.append("\tVKB_K_%s," % handle[2:])
    h.append("\tVKB_K_count\n};")
    for op, name, target in live:
        if name != target:
            h.append("#define vkb_%s_args vkb_%s_args" % (name, target))

    # ---- the guest half -------------------------------------------------------
    g = ["/* Generated by gen-vk-bridge.py from the Vulkan registry. Do not edit. */",
         '#include "vk-bridge.h"', '#include "vk-bridge-ops.h"', "#include <string.h>", ""]
    done = set()
    for op, name, target in live:
        if target in GUEST_ONLY or target in GUEST_SPECIAL:
            continue
        # an alias gets a wrapper of its own: it carries its own opcode
        ret, params = reg.commands[target]
        sig = ", ".join(p.decl for p in params) or "void"
        g.append("static VKAPI_ATTR %s VKAPI_CALL vkb_w_%s(%s)\n{" % (ret, name, sig))
        g.append("\tstruct vkb_%s_args a;" % target)
        g.extend("\ta.%s = %s;" % (p.name, p.name) for p in params)
        g.append(("\tchimera_vk_call(VK_OP_%s, &a);" if ret == "void"
                  else "\treturn (" + ret + ")chimera_vk_call(VK_OP_%s, &a);") % name)
        g.append("}\n")
    for target in sorted(GUEST_SPECIAL | GUEST_ONLY):
        ret, params = reg.commands[target]
        g.append("VKAPI_ATTR %s VKAPI_CALL vkb_g_%s(%s);"
                 % (ret, target, ", ".join(p.decl for p in params)))
    g.append("\nstatic const struct { const char *name; void (*fn)(void); } vkb_names[] = {")
    for op, name, target in sorted(live, key=lambda e: e[1]):
        prefix = "vkb_g_" if target in (GUEST_SPECIAL | GUEST_ONLY) else "vkb_w_"
        which = target if prefix == "vkb_g_" else name
        g.append('\t{"%s", (void (*)(void))%s%s},' % (name, prefix, which))
    g.append("};\n")
    g.append("void *chimera_vk_lookup(const char *name)\n{\n"
             "\tsize_t lo = 0, hi = sizeof vkb_names / sizeof vkb_names[0];\n"
             "\twhile (lo < hi) {\n\t\tconst size_t mid = (lo + hi) / 2;\n"
             "\t\tconst int c = strcmp(name, vkb_names[mid].name);\n"
             "\t\tif (c == 0) return (void *)vkb_names[mid].fn;\n"
             "\t\tif (c < 0) hi = mid; else lo = mid + 1;\n\t}\n\treturn NULL;\n}")

    # ---- the host half --------------------------------------------------------
    c = ["/* Generated by gen-vk-bridge.py from the Vulkan registry. Do not edit. */",
         "#define VKB_UNUSED __attribute__((unused))", ""]
    c.append("struct vkb_fns {")
    done = set()
    for op, name, target in live:
        if target in GUEST_ONLY:
            continue
        c.append("\tPFN_%s %s;" % (name, name))
    c.append("};\nstatic struct vkb_fns vkb_fn;\n")
    c.append("static const struct { const char *name; size_t offset; int device; } vkb_fn_names[] = {")
    for op, name, target in live:
        if target in GUEST_ONLY:
            continue
        first = reg.commands[target][1][0].type if reg.commands[target][1] else ""
        device = reg.canon(first) in ("VkDevice", "VkQueue", "VkCommandBuffer")
        c.append('\t{"%s", offsetof(struct vkb_fns, %s), %d},' % (name, name, 1 if device else 0))
    c.append("};\n")
    for s in order:
        c.append("VKB_UNUSED static void vkb_x_%s(%s *d);" % (s, s))
    c.append("")
    for s in order:
        gen_translator(reg, s, c)
    c.append("/* Every structure that may be chained and is known here: its size, and\n"
             " * its translator when it holds a handle. One the registry has and this\n"
             " * table has not is one a chain drops. */")
    c.append("static struct vkb_chain_entry { VkStructureType type; size_t size; void (*x)(void *); } vkb_chain_table[] = {")
    for s in sorted(reg.extends):
        if s not in reg.declared or s not in reg.stype or s in dropped:
            continue
        x = "(void (*)(void *))vkb_x_%s" % s if s in wanted else "NULL"
        c.append("\t{%s, sizeof(%s), %s}," % (reg.stype[s], s, x))
    c.append("};\n")
    for target in sorted(HOST_SPECIAL):
        if any(t == target for _, _, t in live):
            c.append("static uint64_t vkb_special_%s(uint64_t op, struct vkb_%s_args *a);" % (target, target))
    c.append("\nstatic uint64_t vkb_dispatch_generated(uint64_t op, void *args)\n{\n\tswitch (op) {")
    for op, name, target in live:
        if target in GUEST_ONLY:
            continue
        if target in HOST_SPECIAL:
            c.append("\tcase VK_OP_%s: return vkb_special_%s(op, (struct vkb_%s_args *)args);"
                     % (name, target, target))
            continue
        # an alias answers through its own entry in the function table
        body = []
        gen_host_command(reg, target, op, body)
        if name != target:
            body = [line.replace("VK_OP_%s:" % target, "VK_OP_%s:" % name)
                        .replace("vkb_fn.%s" % target, "vkb_fn.%s" % name) for line in body]
        c.extend(body)
    c.append("\tdefault: return vkb_refuse(op, 0);\n\t}\n}")

    os.makedirs(out_dir, exist_ok=True)
    for fname, lines in (("vk-bridge-ops.h", h), ("vk-bridge-guest.c", g), ("vk-bridge-host.inc", c)):
        with open(os.path.join(out_dir, fname), "w", encoding="ascii") as f:
            f.write("\n".join(lines) + "\n")
    sys.stderr.write("gen-vk-bridge: %d commands, %d structures translated, %d chained structures known\n"
                     % (len(live), len(order), sum(1 for s in reg.extends if s in reg.stype and s in reg.declared)))
    if dropped:
        sys.stderr.write("gen-vk-bridge: dropped from chains (cannot be translated): %s\n"
                         % ", ".join(sorted(dropped)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
