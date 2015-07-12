#!/usr/bin/env python

# This application takes a given .class JAVA file and outputs all of the 
# metadata associated with it and - most importantly - the instructions
# that make up all of the methods in the class. 

# This was created by Matthew Scheffel <matt@weeoak.com> and is released
# under the GNU General Public License version 2.0

import csv         # loading reference file
import pprint      # debugging
import struct      # unpacking binary data
import binascii    # converting 0x30 to "30"
import prettytable # nice output for code disassembly
import argparse    # interpret command line arguments

parser = argparse.ArgumentParser(description='Disassemble a class file')
parser.add_argument('--class', help='class file to disassemble', dest="classfile", required=True)
parser.add_argument('--debug', help='enable verbose debugging information (True or False)', dest="debug", default=False)
args = parser.parse_args()

if args.debug != False and args.debug != True:
    print "Argument to --debug is invalid, assuming False."
    args.debug = False

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

def disassemble(bytecode, address):
    index = 0

    table = prettytable.PrettyTable(["Address", "Opcode", "Arguments", "Instruction", "Description"])
    while index < len(bytecode) - 1:
        opcode = binascii.hexlify(bytecode[index])
        name = opcodes[opcode]['name']

        arguments = len(opcodes[opcode]['arguments'])
        if opcodes[opcode]['arguments'] == [""]:
            arguments = 0

        description = opcodes[opcode]['description']
        opcode_location = address + index

        if arguments == 0:
            table.add_row(["[0x%04x]" % opcode_location, opcode, "", name, description])
        else:
            argument_bytes = []
            for i in range(0, arguments):
                index += 1
                argument_bytes.append(binascii.hexlify(bytecode[index]))
            table.add_row(["[0x%04x]" % opcode_location, opcode, " ".join(argument_bytes), name, description])

        index += 1

    print table

# Not using these two dictionaries yet!
constant_pool_tag = {
    1 : "CONSTANT_Utf8",
    3 : "CONSTANT_Integer",
    4 : "CONSTANT_Float",
    5 : "CONSTANT_Long",
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
    "CONSTANT_Class" : ('>H',),                     # reference to name_index
    "CONSTANT_Fieldref" :  ('>H', '>H'),            # class index, name and type index
    "CONSTANT_Methodref" : ('>H', '>H'),            
    "CONSTANT_InterfaceMethodref" : ('>H', '>H'),
    "CONSTANT_String" : ('>H',),
    "CONSTANT_Integer" : ('>I',),
    "CONSTANT_Float" : ('>f',), 
    "CONSTANT_Long" : ('>I', '>I'), # 8 bytes
    "CONSTANT_Double" : ('>I','>I'), # 8 bytes
    "CONSTANT_NameAndType" : ('>H', '>H'),
    "CONSTANT_Utf8" : ('>H', 's'),                  # length, length bytes
    "CONSTANT_MethodHandle" : ('B', '>H'),
    "CONSTANT_MethodType" : ('>H',),
    "CONSTANT_InvokeDynamic" :  ('>H', '>H'),
}

def ProcessConstantPoolTable(number_of_items):
    constant_pool = []
    pool_entries_processed = 1

    # The constant pool table is indexed from 1 to constant_pool_count - 1
    # Python arrays are indexed from 0 to N
    constant_pool.append("Unused entry to harmonize our index with Java class index convention.")

    while pool_entries_processed < constant_pool_count:
        tag = GetBytes('B')
        entry = [tag]

        if tag == 1: # Utf8, contains variable-length strings
            length = GetBytes('>H')
            string = classfile.read(length) # FIXME: the string is encoded in a modified UTF8

            entry.append(length) # don't really need to store the length...
            entry.append(string)

        else:
            if tag not in constant_pool_tag:
                print "Constant pool error - tag '%x' is not known" % tag
                exit(1)

            for packet in tag_structure[constant_pool_tag[tag]]:
                data = GetBytes(packet)
                entry.append(data)

        constant_pool.append(entry)
        pool_entries_processed += 1

    return constant_pool

def Utf8Dereference(index):
    # Not a string, but a reference to one
    if len(constant_pool[index]) < 3:
        return constant_pool[constant_pool[index][1]][2]

    # A direct string
    else:
        return constant_pool[index][2]

def GetBytes(data_format):
    size_of_format = struct.calcsize(data_format)
    packed_content = classfile.read(size_of_format)
    # print "GetBytes - File now at 0x%x" % classfile.tell()
    return struct.unpack(data_format, packed_content)[0]

# Attributes are used in ClassFile, field_info, method_info, and Code_attribute
# structures.
def ProcessAttributes(count):
    counted_attributes = 0
    while counted_attributes < count:
        print "counted: %d, total_count: %d" % (counted_attributes, count)
        print "current position in file: 0x%x" % classfile.tell()
        attribute_name_index = GetBytes(">H")
        attribute_length = GetBytes(">I")
        print "----" + Utf8Dereference(attribute_name_index) + " (%d bytes)" %  attribute_length
        
        if Utf8Dereference(attribute_name_index) == "Code":
            max_stack = GetBytes(">H")
            max_locals = GetBytes(">H")
            code_length = GetBytes(">I")

            print "Max stack: %d\nMax locals: %d" % (max_stack, max_locals)
            print "Code length: %d" % code_length

            code_location = classfile.tell()
            code_content = classfile.read(code_length)
            disassemble(code_content, code_location)

            exception_table_length = GetBytes(">H")

            print"%s()'s code has %d exceptions" % (Utf8Dereference(name_index), exception_table_length)

            for i in range(0, exception_table_length):
                start_pc = GetBytes(">H")
                end_pc = GetBytes(">H")
                handler_pc = GetBytes(">H")
                catch_type = GetBytes(">H")

            attributes_count = GetBytes(">H")

            print "%s()'s code has %d attributes" % (Utf8Dereference(name_index), attributes_count)
            ProcessAttributes(attributes_count)

        else:
            attribute_content = classfile.read(attribute_length)

        counted_attributes += 1

try:
    classfile = open(args.classfile, 'rb')
except IOError as e:
    print "Failed to open class file: %s" % e
else:
    classfile.seek(0, 2)                # seek to end of file
    final_position = classfile.tell()   # report where that is
    classfile.seek(0)                   # return to the start

    print "The final position in the class file is at 0x%x" % final_position

    magic = classfile.read(4)
    if magic != chr(0xCA) + chr(0xFE) + chr(0xBA) + chr(0xBE):
        print "This is not a class file. Exiting."
        exit()
    print "This is a class file."

    minor_version = GetBytes('>H')
    major_version = GetBytes('>H')

    # The number of entries in the constant_pool plus one
    constant_pool_count = GetBytes('>H')
    constant_pool_count -= 1
    
    print "Version: %d.%d" % (major_version, minor_version)
    print "We have %d entries to extract from the constant_pool table" % (constant_pool_count)

    constant_pool = ProcessConstantPoolTable(constant_pool_count)

    print "%d entries extracted from the constant_pool table." % len(constant_pool)

    class_access_flags = GetBytes('>H')
    print "Access flags: %04X" % class_access_flags

    this_class = GetBytes('>H')
    super_class = GetBytes('>H')

    print this_class
    print super_class

    print "This class is '%s'" % Utf8Dereference(this_class)
    
    if super_class > 0:
        print "Superclass of '%s'" % Utf8Dereference(super_class)
    else:
        print "Superclass of 'Object'"

    interfaces_count = GetBytes('>H')
    print "%d direct superinterfaces of this class." % interfaces_count 

    counted_interfaces = 0
    while counted_interfaces < interfaces_count:
        interface = GetBytes('>H')
        print " #%d: %s" % (counted_interfaces+1, Utf8Dereference(interface))
        counted_interfaces += 1

    fields_count = GetBytes('>H')
    print "%d class fields." % fields_count 

    counted_fields = 0
    while counted_fields < fields_count:
        access_flags = GetBytes('>H')
        name_index = GetBytes('>H')
        name_string = Utf8Dereference(name_index)
        descriptor_index = GetBytes('>H')
        attributes_count = GetBytes('>H')

        print " #%d: %s (%d attributes)" % (counted_fields+1, name_string, attributes_count)
        ProcessAttributes(attributes_count)

        counted_fields += 1

    methods_count = GetBytes('>H')
    print "There are %d methods." % methods_count

    counted_methods = 0
    while counted_methods < methods_count:
        access_flags = GetBytes('>H')
        name_index = GetBytes('>H')
        descriptor_index = GetBytes('>H')
        attributes_count = GetBytes('>H')

        if attributes_count > 0:
            print "-- %s() has %d attributes." % (Utf8Dereference(name_index), attributes_count)
    
        ProcessAttributes(attributes_count)

        counted_methods += 1
        #print "Last byte processed is at: %s" % hex(classfile.tell())

    print "%d methods processed." % counted_methods

    attributes_count = GetBytes('>H')
    print "There are %d attributes." % attributes_count

    counted_attributes = 0
    while counted_attributes < attributes_count:
        ProcessAttributes(attributes_count)
        counted_attributes += 1
    
    #print "%d attributes processed." % counted_attributes
    print "Last byte processed is at: %s - true EOF is at 0x%x" % (hex(classfile.tell()), final_position)

