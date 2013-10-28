#!/usr/bin/env python

import csv    # loading reference file
import pprint # debugging
import struct # unpacking binary data

# Load opcodes

opcodes = {} # '0a' => { "name" => 'string', arguments => ["1: rawr", "2: blah"], stack => 'string', description => 'string' } 

csvfile = open('opcodes.csv', 'r')

with csvfile:
    opcoderef = csv.reader(csvfile, delimiter=',', quotechar='"')
    opcoderef.next() # skip header
    for row in opcoderef:
        (mnemonic, opcode, arguments, stack, description) = row

        if opcode not in opcodes:
            opcodes[opcode] = { "name" : mnemonic, "arguments" : arguments.split(','), "stack" : stack, "description" : description }

def disassemble(bytecode):
    index = 0
    while index < len(bytecode):
        opcode = bytecode[index]
        print "[0x%02x] %02x" % (index, ord(opcode))
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

with open('NLicenseManager.class', 'rb') as classfile:
    file_address = 0
    magic = classfile.read(4)
    if magic != chr(0xCA) + chr(0xFE) + chr(0xBA) + chr(0xBE):
        print "This is not a class file. Exiting."
        exit()

    print "This is a class file."
    minor_version = struct.unpack('>H',classfile.read(struct.calcsize('>H')))[0]
    major_version = struct.unpack('>H',classfile.read(struct.calcsize('>H')))[0]

    # The number of entries in the constant_pool plus one
    constant_pool_count = struct.unpack('>H',classfile.read(struct.calcsize('>H')))[0]
    
    print "Version: %d.%d" % (major_version, minor_version)
    print "We have %d entries to extract from the constant_pool table (minus one)" % constant_pool_count

    pool_entries_processed = 0

    constant_pool.append("Null entry to harmonize our index with Java class index convention.")

    while pool_entries_processed < constant_pool_count - 1:
        tag = struct.unpack('B', classfile.read(1))[0]
        entry = [tag]

        if tag == 1: # Utf8, contains variable-length strings
            length = struct.unpack('>H', classfile.read(struct.calcsize('>H')))[0]
            string = classfile.read(length)

            entry.append(length)
            entry.append(string)

        else:
            for packet in tag_structure[constant_pool_tag[tag]]:
                size = struct.calcsize(packet)
                data = struct.unpack(packet, classfile.read(size))

                entry.extend(data)

        constant_pool.append(entry)
        pool_entries_processed += 1

    class_access_flags = struct.unpack('>H', classfile.read(2))[0]
    print "Access flags: %x" % class_access_flags

    this_class = struct.unpack('>H', classfile.read(2))[0]
    print "This class is '%s'" % constant_pool[constant_pool[this_class][1]][2]

    super_class = struct.unpack('>H', classfile.read(2))[0]
    print "This class has a superclass '%s'" % constant_pool[constant_pool[super_class][1]][2]
#    print "This class has a super class represented by index %d in the pool." % super_class
#    print constant_pool[constant_pool[super_class][1]][2]

    interfaces_count = struct.unpack('>H', classfile.read(2))[0]
    print "Direct superinterfaces of this class: %d" % interfaces_count

    counted_interfaces = 0
    while counted_interfaces < interfaces_count:
        struct.unpack('>H', classfile.read(2))[0]
        counted_interfaces += 1

    fields_count = struct.unpack('>H', classfile.read(2))[0]
    print "There are %d fields." % fields_count

    counted_fields = 0
    while counted_fields < fields_count:
        access_flags = struct.unpack('>H', classfile.read(2))[0]
        name_index = struct.unpack('>H', classfile.read(2))[0]
        descriptor_index = struct.unpack('>H', classfile.read(2))[0]
        attributes_count = struct.unpack('>H', classfile.read(2))[0]
        
        counted_attributes = 0
        while counted_attributes < attributes_count:
            attribute_name_index = struct.unpack('>H', classfile.read(2))[0]
            attribute_length = struct.unpack('>I', classfile.read(4))[0] # bytes

            attribute_content = classfile.read(attribute_length)

            counted_attributes += 1

        counted_fields += 1

    methods_count = struct.unpack('>H', classfile.read(2))[0]
    print "There are %d methods." % methods_count

    counted_methods = 0
    while counted_methods < methods_count:
        access_flags = struct.unpack('>H', classfile.read(2))[0]
        name_index = struct.unpack('>H', classfile.read(2))[0]
        descriptor_index = struct.unpack('>H', classfile.read(2))[0]
        attributes_count = struct.unpack('>H', classfile.read(2))[0]

        print "-- %s() has %d attributes." % (constant_pool[name_index][2], attributes_count)
        
        counted_attributes = 0
        while counted_attributes < attributes_count:
            attribute_name_index = struct.unpack('>H', classfile.read(2))[0]
            attribute_length = struct.unpack('>I', classfile.read(4))[0] # bytes
            print "----" + constant_pool[attribute_name_index][2] + " (%d bytes)" %  attribute_length

            attribute_content = classfile.read(attribute_length)
            disassemble(attribute_content)

            counted_attributes += 1

        counted_methods += 1
