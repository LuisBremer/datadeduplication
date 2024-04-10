#!/usr/bin/env python3 
#https://stackoverflow.com/questions/27494758/how-do-i-make-a-python-script-executable

import os #https://www.geeksforgeeks.org/os-module-python-examples/
import zipfile #https://docs.python.org/3/library/zipfile.html

source_dir = '/users/luisbremer/datadeduplication/files'
destination_dir = '/users/luisbremer/datadeduplication/compressedfiles'

#walk through all files in the source directory
for foldername, subfolders, filenames in os.walk(source_dir):
    for filename in filenames:
        file_to_compress = os.path.join(foldername, filename)
        
        # Create a zip file in the destination directory
        compressed_file = os.path.join(destination_dir, filename + '.zip')
        
        with zipfile.ZipFile(compressed_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(file_to_compress, os.path.basename(file_to_compress))
        
        print(f"Compressed and moved {filename} to {compressed_file}")


