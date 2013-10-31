#!/usr/bin/env python

import csv    # loading reference file
import pprint # debugging
import struct # unpacking binary data
import binascii

# Load opcodes

opcodes = {} # '0a' => { "name" => 'string', arguments => ["1: rawr", "2: blah"], stack => 'string', description => 'string' } 

csvfile = open('opcodes.csv', 'r')

with csvfile:
    opcoderef = csv.reader(csvfile, delimiter=',', quotechar='"')
    opcoderef.next() # skip header
    for row in opcoderef:
        (mnemonic, opcode, arguments, stack, description) = row

        opcode = opcode.zfill(2) # I want leading zeros

        if opcode not in opcodes:
            opcodes[opcode] = { "name" : mnemonic, "arguments" : arguments.split(','), "stack" : stack, "description" : description }

for opcode in opcodes:
    print opcode

def disassemble(bytecode):
    index = 0

    while index < len(bytecode) - 1:
        opcode = binascii.hexlify(bytecode[index])
        name = opcodes[opcode]['name']
        arguments = len(opcodes[opcode]['arguments'])
        opcode_location = index

        if arguments == 0:
            print "[0x%02x] %s %s" % (opcode_location, opcode, name)
        else:
            argument_bytes = []
            for i in range(0, arguments):
                index += 1
                argument_bytes.append(binascii.hexlify(bytecode[index]))
            print "[0x%02x] %s %s | %s %s" % (opcode_location, opcode, " ".join(argument_bytes), name, " ".join(argument_bytes))

        index += 1

# Load file
constant_pool_tag = {
    1 : "CONSTANT_Utf8",
    3 : "CONSTANT_Integer",
    4 : "CONSTANT_Float",
    5 : "CONSTNAT_Long",
    6 : "CONSTANT_Double",
    7 : "CONSTANT_Class",
    8 : "CONSTANT_String",
    9 : "CONSTANT_Fieldref",
    10 : "CONSTANT_Methodref",
    11 : "CONSTANT_InterfaceMethodref",
    12 : "CONSTANT_NameAndType",
    15 : "CONSTANT_MethodHandle",
    16 : "CONSTANT_MethodType",
    18 : "CONSTANT_InvokeDynamic",
}

tag_structure = {
    "CONSTANT_Class" : ('>H',),
    "CONSTANT_Fieldref" :  ('>H', '>H'),
    "CONSTANT_Methodref" : ('>H', '>H'),
    "CONSTANT_InterfaceMethodref" : ('>H', '>H'),
    "CONSTANT_String" : ('>H',),
    "CONSTANT_Integer" : ('>I',),
    "CONSTANT_Float" : ('>f',), 
    "CONSTNAT_Long" : ('>I', '>I'), # 8 bytes
    "CONSTANT_Double" : ('>I','>I'), # 8 bytes
    "CONSTANT_NameAndType" : ('>H', '>H'),
    "CONSTANT_Utf8" : ('>H', 's'),
    "CONSTANT_MethodHandle" : ('B', '>H'),
    "CONSTANT_MethodType" : ('>H',),
    "CONSTANT_InvokeDynamic" :  ('>H', '>H'),
}

constant_pool = []
classfile = open('NLicenseManager.class', 'rb')

def Utf8Dereference(index):
    # Not a string, but a reference to one
    if len(constant_pool[index]) < 3:
        return constant_pool[constant_pool[index][1]][2]
    # A direct string
    else:
        return constant_pool[index][2]

def GetBytes(data_format):
    return struct.unpack(data_format, classfile.read(struct.calcsize(data_format)))[0]

magic = classfile.read(4)
if magic != chr(0xCA) + chr(0xFE) + chr(0xBA) + chr(0xBE):
    print "This is not a class file. Exiting."
    exit()

print "This is a class file."
minor_version = GetBytes('>H')
major_version = GetBytes('>H')

# The number of entries in the constant_pool plus one
constant_pool_count = GetBytes('>H')

print "Version: %d.%d" % (major_version, minor_version)
print "We have %d entries to extract from the constant_pool table (minus one)" % constant_pool_count

pool_entries_processed = 0

constant_pool.append("Null entry to harmonize our index with Java class index convention.")

while pool_entries_processed < constant_pool_count - 1:
    tag = GetBytes('B')
    entry = [tag]

    if tag == 1: # Utf8, contains variable-length strings
        length = GetBytes('>H')
        string = classfile.read(length)

        entry.append(length)
        entry.append(string)

    else:
        for packet in tag_structure[constant_pool_tag[tag]]:
            data = GetBytes(packet)
            entry.append(data)

    constant_pool.append(entry)
    pool_entries_processed += 1

class_access_flags = GetBytes('>H')
print "Access flags: %04X" % class_access_flags

this_class = GetBytes('>H')
print "This class is '%s'" % Utf8Dereference(this_class)

super_class = GetBytes('>H')
print "This class has a superclass '%s'" % Utf8Dereference(super_class)
#    print "This class has a super class represented by index %d in the pool." % super_class
#    print constant_pool[constant_pool[super_class][1]][2]

interfaces_count = GetBytes('>H')
print "Direct superinterfaces of this class: %d" % interfaces_count

counted_interfaces = 0
while counted_interfaces < interfaces_count:
    GetBytes('>H')
    counted_interfaces += 1

fields_count = GetBytes('>H')
print "There are %d fields." % fields_count

counted_fields = 0
while counted_fields < fields_count:
    access_flags = GetBytes('>H')
    name_index = GetBytes('>H')
    descriptor_index = GetBytes('>H')
    attributes_count = GetBytes('>H')
    
    counted_attributes = 0
    while counted_attributes < attributes_count:
        attribute_name_index = GetBytes('>H')
        attribute_length = GetBytes('>I')

        attribute_content = classfile.read(attribute_length)

        counted_attributes += 1

    counted_fields += 1

methods_count = GetBytes('>H')
print "There are %d methods." % methods_count

counted_methods = 0
while counted_methods < methods_count:
    access_flags = GetBytes('>H')
    name_index = GetBytes('>H')
    descriptor_index = GetBytes('>H')
    attributes_count = GetBytes('>H')

    print "-- %s() has %d attributes." % (Utf8Dereference(name_index), attributes_count)
    
    counted_attributes = 0
    while counted_attributes < attributes_count:
        attribute_name_index = GetBytes('>H')
        attribute_length = GetBytes('>I')
        print "----" + Utf8Dereference(attribute_name_index) + " (%d bytes)" %  attribute_length
        
        if Utf8Dereference(attribute_name_index) == "Code":
            max_stack = GetBytes(">H")
            max_locals = GetBytes(">H")
            code_length = GetBytes(">I")

            print "Max stack: %d\nMax locals: %d" % (max_stack, max_locals)
            print "Code length: %d" % code_length

            code_content = classfile.read(code_length)
            disassemble(code_content)

            exception_table_length = GetBytes(">H")

            print "Method has %d exceptions" % exception_table_length

            for i in range(0, exception_table_length):
                start_pc = GetBytes(">H")
                end_pc = GetBytes(">H")
                handler_pc = GetBytes(">H")
                catch_type = GetBytes(">H")

            attributes_count = GetBytes(">H")

            print "Method has %d attributes" % attributes_count

            for i in range(0, attributes_count):
                attribute_name_index = GetBytes(">H")
                attribute_length = GetBytes(">I")
                attributes = classfile.read(attribute_length)

        else:
            attribute_content = classfile.read(attribute_length)

        counted_attributes += 1

    counted_methods += 1
