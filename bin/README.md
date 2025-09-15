Helper scripts to remember what the fuck I'm sposed to do

* aquire-local: use certbot to aquire a certificate via the dns challenge
* rotate-ds: generate the DS entry for DNSSEC, and notify bind9 that the record has been entered.
	* If you're dns server is public (not the case for local.evan-brass.net) then hopefully CDS / CDNSKEY records will mean you don't need to do this more than once.
