rule ExampleRule {
	meta:
		author = "EJM"
		description = "test rule to flag hotmail forwards"
	strings:
		$string = "Return-Path: <ejakemcleod88@gmail.com>"
	condition:
		all of them
}
