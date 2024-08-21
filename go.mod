module github.com/go-acme/lego/v4

go 1.21

toolchain go1.22.5

// github.com/exoscale/egoscale v1.19.0 => It is an error, please don't use it.
// github.com/linode/linodego v1.0.0 => It is an error, please don't use it.
require (
	cloud.google.com/go v0.54.0
	github.com/Azure/azure-sdk-for-go v32.4.0+incompatible
	github.com/Azure/go-autorest/autorest v0.9.0
	github.com/Azure/go-autorest/autorest/azure/auth v0.1.0
	github.com/Azure/go-autorest/autorest/to v0.2.0
	github.com/Azure/go-autorest/autorest/validation v0.1.0 // indirect
	github.com/BurntSushi/toml v0.3.1
	github.com/OpenDNS/vegadns2client v0.0.0-20180418235048-a3fa4a771d87
	github.com/akamai/AkamaiOPEN-edgegrid-golang v1.1.0
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.976
	github.com/aws/aws-sdk-go v1.37.27
	github.com/cenkalti/backoff/v4 v4.1.2
	github.com/cloudflare/cloudflare-go v0.14.0
	github.com/cpu/goacmedns v0.1.1
	github.com/dnsimple/dnsimple-go v0.63.0
	github.com/exoscale/egoscale v0.46.0
	github.com/google/go-querystring v1.0.0
	github.com/gophercloud/gophercloud v0.16.0
	github.com/gophercloud/utils v0.0.0-20210216074907-f6de111f2eae
	github.com/iij/doapi v0.0.0-20190504054126-0bbf12d6d7df
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/labbsr0x/bindman-dns-webhook v1.0.2
	github.com/linode/linodego v0.25.3
	github.com/liquidweb/liquidweb-go v1.6.3
	github.com/miekg/dns v1.1.59
	github.com/namedotcom/go v0.0.0-20180403034216-08470befbe04
	github.com/nrdcg/auroradns v1.0.1
	github.com/nrdcg/desec v0.5.0
	github.com/nrdcg/dnspod-go v0.4.0
	github.com/nrdcg/goinwx v0.8.1
	github.com/nrdcg/namesilo v0.2.1
	github.com/oracle/oci-go-sdk v24.3.0+incompatible
	github.com/ovh/go-ovh v1.1.0
	github.com/pquerna/otp v1.3.0
	github.com/rainycape/memcache v0.0.0-20150622160815-1031fa0ce2f2
	github.com/sacloud/libsacloud v1.36.2
	github.com/stretchr/testify v1.9.0
	github.com/transip/gotransip/v6 v6.2.0
	github.com/urfave/cli v1.22.4
	github.com/vinyldns/go-vinyldns v0.0.0-20200917153823-148a5f6b8f14
	github.com/vultr/govultr/v2 v2.0.0
	golang.org/x/crypto v0.25.0
	golang.org/x/net v0.25.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	google.golang.org/api v0.20.0
	gopkg.in/ns1/ns1-go.v2 v2.4.4
	gopkg.in/yaml.v2 v2.4.0
)

require github.com/go-jose/go-jose/v4 v4.0.4

require (
	github.com/Azure/go-autorest/autorest/adal v0.5.0 // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.1.0 // indirect
	github.com/Azure/go-autorest/autorest/date v0.1.0 // indirect
	github.com/Azure/go-autorest/logger v0.1.0 // indirect
	github.com/Azure/go-autorest/tracing v0.5.0 // indirect
	github.com/boombuler/barcode v1.0.1-0.20190219062509-6c824513bacc // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/deepmap/oapi-codegen v1.3.11 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/dimchansky/utfbom v1.1.0 // indirect
	github.com/fatih/structs v1.1.0 // indirect
	github.com/go-errors/errors v1.0.1 // indirect
	github.com/go-resty/resty/v2 v2.1.1-0.20191201195748-d7b97669fe48 // indirect
	github.com/gofrs/uuid v3.2.0+incompatible // indirect
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.3.4 // indirect
	github.com/google/uuid v1.1.1 // indirect
	github.com/googleapis/gax-go/v2 v2.0.5 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.6.6 // indirect
	github.com/jarcoal/httpmock v1.0.6 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/json-iterator/go v1.1.7 // indirect
	github.com/k0kubun/go-ansi v0.0.0-20180517002512-3bf9e2903213 // indirect
	github.com/kolo/xmlrpc v0.0.0-20200310150728-e0350524596b // indirect
	github.com/labbsr0x/goh v1.0.1 // indirect
	github.com/liquidweb/go-lwApi v0.0.5 // indirect
	github.com/liquidweb/liquidweb-cli v0.6.9 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.3.3 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/sirupsen/logrus v1.4.2 // indirect
	github.com/smartystreets/go-aws-auth v0.0.0-20180515143844-0c1422d1fdb9 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	go.opencensus.io v0.22.3 // indirect
	go.uber.org/ratelimit v0.0.0-20180316092928-c15da0234277 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.7.0 // indirect
	golang.org/x/sys v0.22.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	golang.org/x/time v0.0.0-20201208040808-7e3f01d25324 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20200305110556-506484158171 // indirect
	google.golang.org/grpc v1.27.1 // indirect
	gopkg.in/ini.v1 v1.62.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
