rule ExampleRule {
	meta:
		author = "EJM"
		description = "test rule to flag executabl zip files"
	strings:
		$zip_magic = ".zip"
	condition:
		$zip_magic
}
