#!/usr/bin/env python2.7
import re
import subprocess
import sys
import json

from elftools.dwarf import dwarfinfo
from io import BytesIO

CONFIG = dwarfinfo.DwarfConfig(little_endian=True,
                               machine_arch='x64',
                               default_address_size=8)

SEGMENT_DIVIDER = re.compile(r"Load command \d\s+cmd LC_SEGMENT_64\n")

SECTION_DIVIDER = re.compile(r"Section\n")

DWARF_SEGNAME = "__DWARF"

WANTED_SECTIONS = set([
    "debug_info_sec",
    "debug_abbrev_sec",
    "debug_frame_sec",
    "debug_str_sec",
    "debug_loc_sec",
    "debug_ranges_sec",
    "debug_line_sec",
    "eh_frame_sec"
])

def want_section(name):
    return name in WANTED_SECTIONS

def fix_name(name):
    # Get rid of leading __ in the section name.
    return name[2:] + "_sec"

# TODO actually parse otool output

def get_attribute(s, name):
    name_index = s.index(name)
    newline_index = s.index("\n", name_index)
    return s[name_index + len(name) + 1 : newline_index]

def read_section(string, handle):
    name = fix_name(get_attribute(string, "sectname"))
    size = int(get_attribute(string, "size"), base=16)
    offset = int(get_attribute(string, "offset"))
    handle.seek(offset)
    stream = BytesIO(handle.read(size))
    return dwarfinfo.DebugSectionDescriptor(stream=stream,
                                            name=name,
                                            global_offset=offset,
                                            size=size)

def read_dwarf_sections(filename):
    pipe = subprocess.Popen("otool -l %s" % filename, stdout=subprocess.PIPE, shell=True)
    text = pipe.stdout.read()

    segments = SEGMENT_DIVIDER.split(text)[1:]

    dwarf_segment = None
    for s in segments:
        segname = get_attribute(s, "segname")
        if segname == DWARF_SEGNAME:
            dwarf_segment = s

    if not dwarf_segment:
        raise Exception("Could not find DWARF segment")

    sections = SECTION_DIVIDER.split(dwarf_segment)[1:]
    handle = open(filename, "r")

    descriptors = {}
    for s in sections:
        descriptor = read_section(s, handle)
        if want_section(descriptor.name):
            descriptors[descriptor.name] = descriptor

    for s in WANTED_SECTIONS:
        if s not in descriptors:
            descriptors[s] = None

    return descriptors


# Based on
# https://github.com/eliben/pyelftools/blob/master/examples/dwarf_decode_address.py
#
# TODO: binary search is better
def get_location(dwarf, address):
    # Go over all the line programs in the DWARF information, looking for
    # one that describes the given address.
    for CU in dwarf.iter_CUs():
        # First, look at line programs to find the file/line for the address
        lineprog = dwarf.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None or entry.state.end_sequence:
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                column = prevstate.column
                return {
                    "source": filename,
                    "line": line,
                    "column": column
                }
            prevstate = entry.state
    return None

# TODO: really shouldn't be using linear search
# TODO: send PR upstream
def get_DIE_by_offset(cu, offset):
    for die in cu.iter_DIEs():
        if die.offset == offset + cu.cu_offset:
            return die
    raise ValueError("No die with offset=%r" % offset)

# Visitor API

START_VISITORS = {}
END_VISITORS = {}

def visitor(tag, when="start"):
    """ Decorator to register the decorated function to be called whenever we visit
        an entry of type `tag`.
    """
    def decorator(fn):
        visitors = None
        if when == "start":
            visitors = START_VISITORS
        elif when == "end":
            visitors = END_VISITORS
        else:
            raise Exception("when must be start or end")

        visitors["DW_TAG_%s" % tag] = fn.func_name
        return fn

    return decorator

class DebugInfo(object):
    """ Accumulates the subset of debugging info we care about from DWARF and
        massages it into a format that's easier for us to handle.
    """

    # Public API

    def __init__(self, dwarf):
        self.dwarf = dwarf

        self._types = []
        self._types_by_offset = {}

        global_scope = {
            "name": "Global",
            "bindings": {}
        }
        self._scopes = [global_scope]
        self._current_scope_stack = [global_scope]

    def as_json(self, **kwargs):
        return json.dumps({
            "types": self._types,
            "scopes": self._scopes
        }, **kwargs)

    def visit(self, cu, entry, indent=""):
        """ Traverse the DIE tree and accumulate its information.
        """
        self._call_visitor(entry, START_VISITORS, cu, indent)
        for child in entry.iter_children():
            self.visit(cu, child, indent + "    ")
        self._call_visitor(entry, END_VISITORS, cu, indent)

    # Privates

    def _current_scope(self):
        return self._current_scope_stack[-1]

    def _call_visitor(self, entry, visitors, cu, indent):
        if entry.tag in visitors:
            method_name = visitors[entry.tag]
            method = getattr(self, method_name)
            method(cu, entry, indent)

    def _get_or_create_type(self, cu, type_entry):
        """ Get or create the type object for the given type entry DIE, and return its
            index into our types list.
        """
        # TODO: save size, name, members, etc
        # TODO: don't use linear search

        if type_entry.offset in self._types_by_offset:
            existing_type = self._types_by_offset[type_entry.offset]
            return self._types.index(existing_type)

        new_type = {
            "kind": type_entry.tag.replace("DW_TAG_", "")
        }

        if "DW_AT_type" in type_entry.attributes:
            parent_offset = type_entry.attributes["DW_AT_type"].value
            parent = self._get_or_create_type(cu, get_DIE_by_offset(cu, parent_offset))
            new_type["parent"] = parent

        self._types_by_offset[type_entry.offset] = new_type
        self._types.append(new_type)
        return len(self._types) - 1

    # Visitor Implementations

    @visitor("subprogram")
    @visitor("lexical_block")
    @visitor("try_block")
    @visitor("catch_block")
    def add_scope(self, cu, entry, indent):
        # TODO types of scopes (function vs block, etc). should be part of name?
        # TODO add return type

        low_pc = entry.attributes["DW_AT_low_pc"].value
        start = get_location(self.dwarf, low_pc)

        high_pc = entry.attributes["DW_AT_high_pc"].value
        end = get_location(self.dwarf, high_pc)

        name = None
        if "DW_AT_name" in entry.attributes:
            name = entry.attributes["DW_AT_name"].value

        scope = {
            "start": start,
            "end": end,
            "bindings": {},
            "name": name,
            # TODO: don't use linear search
            "parent": self._scopes.index(self._current_scope())
        }

        self._current_scope_stack.append(scope)
        self._scopes.append(scope)

    @visitor("subprogram", "end")
    @visitor("lexical_block", "end")
    @visitor("try_block", "end")
    @visitor("catch_block", "end")
    def end_scope(self, cu, entry, indent):
        self._current_scope_stack.pop()

    @visitor("variable")
    @visitor("formal_parameter")
    @visitor("constant")
    def add_variable(self, cu, entry, indent):
        # TODO type of variable (constant, parameter, normal, ...)

        name = entry.attributes["DW_AT_name"].value
        location = None
        if "DW_AT_location" in entry.attributes:
            loc_val = entry.attributes["DW_AT_location"].value
            if len(loc_val) == 2 and loc_val[0] == 145:
                location = 128 - loc_val[1]

        type_offset = entry.attributes["DW_AT_type"].value
        type_entry = get_DIE_by_offset(cu, type_offset)
        type_index = self._get_or_create_type(cu, type_entry)

        self._current_scope()["bindings"][name] = {
            "location": location,
            "type": type_index
        }

    @visitor("base_type")
    @visitor("const_type")
    @visitor("structure_type")
    @visitor("class_type")
    @visitor("pointer_type")
    @visitor("enumeration_type")
    @visitor("union_type")
    @visitor("subrange_type")
    @visitor("array_type")
    @visitor("typedef")
    def add_type(self, cu, entry, indent):
        self._get_or_create_type(cu, entry)

def main():
    filename = sys.argv[1]
    sections = read_dwarf_sections(filename)
    dwarf = dwarfinfo.DWARFInfo(CONFIG, **sections)
    dbg_info = DebugInfo(dwarf)

    for cu in dwarf.iter_CUs():
        root = cu.get_top_DIE()
        dbg_info.visit(cu, root)

    print dbg_info.as_json(indent=2)

if __name__ == "__main__":
    main()
