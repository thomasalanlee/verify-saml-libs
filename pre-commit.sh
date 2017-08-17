#!/bin/sh

./gradlew --daemon --parallel clean build test

tput setaf 3
printf "\nOnce you publish a new version of saml-metadata-bindings "
tput bold
printf "PLEASE DON'T FORGET "
tput sgr0
tput setaf 3
printf "to update the following dependent projects:\n"

printf "\n ida-hub"
printf "\n ida-compliance-tool"
printf "\n ida-sample-rp"
printf "\n ida-stub-idp"
printf "\n ida-msa\n"

tput bold
printf "\nThank you! :)\n\n"
tput sgr0
