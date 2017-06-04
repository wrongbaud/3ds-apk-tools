#!/usr/bin/python 
import shutil
import zlib
import time
import os
import sys
import logging
import struct

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
hdlr = logging.FileHandler('guntanked.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 

class apk_hdr:

    def __init__(self):
        self.offset = 0
        self.desc = ''
        self.length = 0
        self.unknown_val_1 = 0
        self.data = []

class pack_hdr:

    def __init__(self):
        self.offset = 0
        self.desc = ''
        self.length = 0
        self.first_file_offset = 0
        self.unknown_vals = []
        self.checksum_vals = []

class packtoc_hdr:
    
    def __init__(self):
        self.offset = 0
        self.desc = ''
        self.object_size = 0
        self.length = 0
        self.object_count = 0
        self.unknown = []
        self.entries = []

class packtoc_entry:

    def __init__(self):
        self.offset = 0
        self.id = 0
        self.count = 0
        self.unknown = []
        self.file_offset = 0
        self.decompressed_len = 0
        self.compressed_len = 0
        self.name = ""
        self.unknown_element = 0

    def __str__(self):
        return "ID: 0x%x Count: 0x%x File Offset = 0x%x Decompressed Len: 0x%x Compressed Len: 0x%x Unknown: 0x%x" % (self.id,self.count,self.file_offset,self.decompressed_len,self.compressed_len,self.unknown_element)

class packfsls_hdr:

    def __init__(self):
        self.offset = 0
        self.desc = ''
        self.length = 0
        self.unknown = []

class genestr_hdr:

    def __init__(self):
        self.offset = 0
        self.desc = ''
        self.length = 0 
        self.unknown = []
        self.str_table_offset = 0
        self.length_2 = 0
        self.object_count = 0
        self.str_offsets_loc = 0
        self.str_offsets = []
        self.entries = []

class apk_file:

    def __init__(self,filepath):
        self.filepath = filepath
        self.apk = open(filepath,'rb')
        self.genestr_hdr = None      #This section holds the strings and table of offsets into the string table for naming files
        self.packfsls_hdr = None     #This section is empty for most of the archives, assuming it means filessystem something
        self.apk_hdr = None             #This section seems to be at the beginning of each file
        self.pack_hdr = None            #This section is the generic header for the "PACK" sections (I think)
        self.packtoc_hdr = None         #This secrion describes the PACK Table of Contents which defines all file entries
        self.packtoc_entries = []       #This is a list of objects representing the PACKTOC entries

    #Check the APK initial header, bail if not ENDILTLE
    def _check_apk_hdr(self,offset=None):
        if offset != None:
            self.apk.seek(offset)
        else:
            self.apk.seek(0)
        endiltle = self.apk.read(8)
        if endiltle.decode("utf-8") != 'ENDILTLE':
            logger.info("First header ENDILTLE not found, exiting!")
            self.apk.close()
            return 0
        else:
            self.apk_hdr = apk_hdr()
            self.apk_hdr.offset = 0
            self.apk_hdr.desc = endiltle.decode("utf-8")
            self.apk_hdr.length = int(struct.unpack("I",self.apk.read(4))[0])
            logger.info("Found ENDILTLE header for file: %s at offset 0x%x" % (self.filepath,self.apk_hdr.offset))
            return 1

    #Check the PACKHEDR portion
    def _check_pack_hdr(self,offset=None):
        self.apk.seek(0)
        if offset == None:
            offset = 0x10 #Note: This may not always be true, it's just what I've observed!
        self.apk.seek(offset)
        self.pack_hdr = pack_hdr()
        self.pack_hdr.desc = self.apk.read(8).decode("utf-8")
        if self.pack_hdr.desc != "PACKHEDR":
            logger.info("PACKHEDR not found in file: %s exiting now" % self.filename)
            return 0
        else:
            self.pack_hdr.offset = offset
            self.pack_hdr.length = int(struct.unpack("I",self.apk.read(4))[0])
            for x in range(0,3):
                self.pack_hdr.unknown_vals.append(struct.unpack("I",self.apk.read(4))[0])
            self.pack_hdr.first_file_offset = int(struct.unpack("I",self.apk.read(4))[0])
            self.pack_hdr.unknown_vals.append(struct.unpack("I",self.apk.read(4)))
            for x in range(0,4):
                self.pack_hdr.checksum_vals.append(struct.unpack("I",self.apk.read(4))[0])
            logger.info("Found PACKHEDR Section for file: %s at offset 0x%x" % (self.filepath,self.pack_hdr.offset))
            return 1

    def _check_packtoc_hdr(self,offset=None):
        self.apk.seek(0)
        if offset == None:
            offset = 0x40
        self.apk.seek(offset)
        self.packtoc_hdr = packtoc_hdr()
        self.packtoc_hdr.offset = offset
        self.packtoc_hdr.desc = self.apk.read(8).decode("utf-8")
        if self.packtoc_hdr.desc != "PACKTOC ":
            logger.info("PACKTOC not found in file: %s, exiting now" % self.filename)
            return 0
        else:
            self.packtoc_hdr.length = int(struct.unpack("I",self.apk.read(4))[0])
            self.packtoc_hdr.unknown.append(struct.unpack("I",self.apk.read(4)))
            self.packtoc_hdr.object_size = int(struct.unpack("I",self.apk.read(4))[0])
            self.packtoc_hdr.object_count = int(struct.unpack("I",self.apk.read(4))[0])
            self.packtoc_hdr.unknown.append(int(struct.unpack("I",self.apk.read(4))[0]))
            self.packtoc_hdr.unknown.append(int(struct.unpack("I",self.apk.read(4))[0]))
            logger.info("Found PACTOC Section for file: %s at offset 0x%x" % (self.filepath,self.packtoc_hdr.offset))
            logger.info("\tPACKTOC Object Count: 0x%x" % self.packtoc_hdr.object_count)
            logger.info("\tPACKTOC Object Size: 0x%x" % self.packtoc_hdr.object_size)
            return 1

    def _build_packtoc_objects(self,offset=None):
        self.apk.seek(0)
        if offset == None:
            offset = 0x60   #Again, this is just what I have seen, could certainly be different in other files
        self.apk.seek(offset)
        for x in range(0,self.packtoc_hdr.object_count):
            obj = packtoc_entry()
            obj.offset = self.apk.tell()
            obj.id = int(struct.unpack("I",self.apk.read(4))[0])
            obj.count = int(struct.unpack("I",self.apk.read(4))[0])
            obj.unknown.append(struct.unpack("I",self.apk.read(4)))
            obj.unknown.append(struct.unpack("I",self.apk.read(4)))
            obj.file_offset = int(struct.unpack("I",self.apk.read(4))[0])
            obj.unknown.append(struct.unpack("I",self.apk.read(4)))
            obj.decompressed_len = int(struct.unpack("I",self.apk.read(4))[0])
            obj.unknown.append(struct.unpack("I",self.apk.read(4)))
            obj.compressed_len = int(struct.unpack("I",self.apk.read(4))[0])
            obj.unknown.append(struct.unpack("I",self.apk.read(4)))
            self.packtoc_hdr.entries.append(obj)
        logger.info("\tPACKTOC Objects Parsed: 0x%x" % len(self.packtoc_hdr.entries))
    
    #Don't really know much about this structure to confirm anything...    
    def _check_packfsls_hdr(self,offset=None):
        self.apk.seek(0)
        if offset == None:
            offset = self.packtoc_hdr.offset + self.packtoc_hdr.length + 0x10
            #Make sure that it's 0x10 byte alligned...
            while offset % 0x10 != 0:
                offset += 1
        self.apk.seek(offset)
        self.packfsls_hdr = packfsls_hdr()
        self.packfsls_hdr.offset = offset
        self.packfsls_hdr.desc = self.apk.read(8).decode("utf-8")
        if self.packfsls_hdr.desc != "PACKFSLS":
            logger.info("PACKFSLS not found in file %s at offset 0x%x, exiting now" % (self.filepath,offset)) 
            return 0
        else:
            self.packfsls_hdr.length = int(struct.unpack("I",self.apk.read(4))[0])
            logger.info("Found PACKFSLS Section for file %s at offset 0x%x" % (self.filepath,self.packfsls_hdr.offset))
            return 1

    def _check_genestr_hdr(self,offset=None):
        self.apk.seek(0)
        if offset == None:
            offset = self.packfsls_hdr.offset + self.packfsls_hdr.length + 0x10
            while offset % 0x10 != 0:
                offset += 1
        self.apk.seek(offset)
        self.genestr_hdr = genestr_hdr()
        self.genestr_hdr.offset = offset
        self.genestr_hdr.desc = self.apk.read(8).decode("utf-8")
        self.genestr_hdr.str_offset_loc = 0x10  #Not entire sure about this, will need to see more files first...
        if self.genestr_hdr.desc != "GENESTRT":
            logger.info("GENESTRT not found in file %s at offset 0x%x" % (self.filepath,self.genestr_hdr.offset))
            return 0
        else:
            self.genestr_hdr.length = int(struct.unpack("I",self.apk.read(4))[0])
            self.genestr_hdr.unknown.append(struct.unpack("I",self.apk.read(4)))
            self.genestr_hdr.object_count = int(struct.unpack("I",self.apk.read(4))[0])
            self.genestr_hdr.unknown.append(struct.unpack("I",self.apk.read(4)))
            self.genestr_hdr.str_table_offset = int(struct.unpack("I",self.apk.read(4))[0])
            self.genestr_hdr.length_2 = int(struct.unpack("I",self.apk.read(4))[0])
            for x in range(0,self.genestr_hdr.object_count):
                self.genestr_hdr.str_offsets.append(int(struct.unpack("I",self.apk.read(4))[0]))
            logger.info("Found GENESTRT Section for file %s at offset 0x%x" % (self.filepath, self.genestr_hdr.offset))
            logger.info("\tGENESTRT offsets parsed: 0x%x" % len(self.genestr_hdr.str_offsets))

    def _apply_names_to_objects(self):
        for obj in self.packtoc_hdr.entries:
            obj.name = self.genestr_hdr.entries[obj.count]

    def _build_genestrt_objects(self,offset=None):
            self.apk.seek(0)
            if offset == None:
                offset = self.genestr_hdr.offset + self.genestr_hdr.str_table_offset + 0x10
            logger.info("Attempting to read GENESTRT objects at offset 0x%x" % offset) 
            self.apk.seek(offset)
            total_bytes = self.genestr_hdr.length
            str_count = self.genestr_hdr.object_count
            while str_count > 0:
                val = self.apk.read(1)
                new_str = ''
                while val != b"\x00":
                    new_str += val.decode("utf-8")
                    val = self.apk.read(1)
                str_count -=1
                if new_str == "GENEEOF ":
                    logger.info("\tFinished parsing filename strings!")
                    break
                self.genestr_hdr.entries.append(new_str)
 
    def _export_apk(self,output_dir):
        logger.info("Attempting to export %s to directory %s" % (self.filepath,output_dir))
        output_dir += '/'
        for obj in self.packtoc_hdr.entries:
            self.apk.seek(0)
            if obj.id == 0x200:
                start_addr = obj.file_offset
                length = obj.compressed_len
                self.apk.seek(start_addr)
                buf = self.apk.read(length)
                new_file = zlib.decompress(buf)
                try:
                    out = open(output_dir + self.genestr_hdr.entries[obj.count],'wb+')
                    out.write(new_file)
                    out.close()
                except IsADirectoryError as e:
                    out = open(output_dir+"UNKNOWN-%f" % time.time(),'wb+')
                    out.write(new_file)
                    out.close()
                except FileNotFoundError as e:
                    logger.info("Error attempting to export data, file not found -- does the specified output directory exist?")
                    return 0
        logger.info("Finished exporting APK Files")

    ###NOTE: NOT TESTED
    ### THIS ASSUMES THAT THE NEW FILE HAS THE SAME OR LESS COMPRESSED SIZE!
    def _import_apk(self,current_file,new_file):
        if self.apk != None:
            self.apk.close()
        logger.info("Making modified copy of %s please wait..." % self.filepath)
        os.copy(self.filename,'modded'+self.filepath)
        self.apk = open('modded'+self.filepath,'rb+')
        #Import and compress our new texture
        updated_file = open(new_file,'rb').read()
        d_updated_size = len(updated_file)
        z_updated_file = zlib.compress(updated_file)
        z_updated_size = len(z_updated_file)
        #Get info on old texture
        target_element == None
        for element in self.packtoc_entries:
            if element.name == current_file:
                logger.info("Found target element %s in PACKTOC entries!")
                logger.info("\t%s" % element)
                target_element = element
        #Update attributes based on our new texture...
        if z_updated_size != target_element.compressed_len:
            target_element.compressed_len = z_updated_size
        if d_updated_size != target_element.decompressed_len:
            target_element.compressed_len = d_updated_size
        logger.info("New Element:\n")
        logger.info("\t%s" % target_element)
        #Write our new data
        #TODO: IF WE ARE LARGER THAN THE ORIGINAL WE NEED TO MODIFY ALL OF THE TABLE OFFSET AFTER THIS ONE
        self.apk.seek(target_element.file_offset)
        self.apk.write(z_updated_file)
        #Modify the table entry
        self.apk.seek(0)
        self.apk.seek(target_element.offset + 24)
        self.apk.write(struct.pack("I",d_updated_size))
        self.apk.seek(4)
        self.apk.write(struct.pack("I",z_updated_size))
        self.apk.close()
 
if __name__ == "__main__":
    test_ap = apk_file(sys.argv[1])
    test_ap._check_apk_hdr()
    test_ap._check_pack_hdr()
    test_ap._check_packtoc_hdr()
    test_ap._build_packtoc_objects()
    test_ap._check_packfsls_hdr()
    test_ap._check_genestr_hdr()
    test_ap._build_genestrt_objects()
    test_ap._apply_names_to_objects()
    test_ap._import_apk("d_04.bctex","d_04.bctex")
    #test_ap._export_apk(sys.argv[2])
    
