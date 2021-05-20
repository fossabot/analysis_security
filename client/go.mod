module github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/client

replace github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common => ./../common

require (
	github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common v0.0.0-00010101000000-000000000000
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
)
