# Will extract all Windows PE files detected by BRO

event file_new(f: fa_file)
{
	if (f$mime_type && f$mime_type == "application/x-dosexec")
	{
		Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
	}
}
