rule flag_forwards_from hotmail {
    meta:
        author = "Ernest-Exo"
        date = "2024-07-17"
        description = "flag mail in sublime for forwards from my hotmail"
    strings:
        $return_path = "Return-Path: <ejmcleod88@hotmail.com>"

    condition:
        $return_path
}
