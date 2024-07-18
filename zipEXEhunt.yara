rule ExampleRule {
	meta:
		author = "EJM"
		description = "test rule to flag zip files"
	strings:
		$zip_ext = ".zip" wide ascii
	condition:
		$zip_ext at 0
}
