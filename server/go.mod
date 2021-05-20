module github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/server

replace github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common => ./../common


go 1.16

require (
	github.com/BorysekOndrej/PV204_Noise_Protocol_and_TPM/common v0.0.0-00010101000000-000000000000
	github.com/dchest/uniuri v0.0.0-20200228104902-7aecb25e1fe5 // indirect
	github.com/google/go-tpm v0.3.2
	gorm.io/driver/sqlite v1.1.4
	gorm.io/gorm v1.21.6
)
