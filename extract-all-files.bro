# will extract all files detected by BRO

event file_new(f: fa_file)
{
	Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
}
