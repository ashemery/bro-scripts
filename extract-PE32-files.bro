# A working version of PE files extraction
# Adds file extension to the extracted files
# Calcs the HASH values of the files too

global ext_map: table[string] of string = {
    ["application/x-dosexec"] = "exe",
    ["text/plain"] = "txt",
    ["image/jpeg"] = "jpg",
    ["image/png"] = "png",
    ["text/html"] = "html",
} &default ="";

event file_sniff(f: fa_file, meta: fa_metadata)
{
	        local ext = "";
	
	if ( meta?$mime_type && meta$mime_type == "application/x-dosexec" )
	{
	        ext = ext_map[meta$mime_type];
		      #print "New file created with ID =", f$id;
		      Files::add_analyzer(f, Files::ANALYZER_MD5);
		      local fname = fmt("%s-%s.%s", f$source, f$id, ext);
    		  Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=fname]);
	}
}

event file_hash(f: fa_file, kind: string, hash: string)
{
      print "file", f$id, kind, hash;
}
