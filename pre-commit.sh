#!/bin/sh

./gradlew --daemon --parallel clean build

tput setaf 3
printf "\nOnce you publish a new version of saml-security "
tput bold
printf "PLEASE DON'T FORGET "
tput sgr0
tput setaf 3
printf "to update the following dependent projects:\n"

printf "\n saml-utils"
printf "\n stub-idp-saml"
printf "\n ida-stub-idp"
printf "\n ida-compliance-tool"
printf "\n ida-hub"
printf "\n ida-msa"
printf "\n ida-sample-rp"
printf "\n verify-service-provider"

tput bold
printf "\n\nThank you! :)\n\n"
tput sgr0
