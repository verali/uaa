Spring Metering Filter Integration Test Guide
=============================================
Set your environment variables

```
export NUREGO_API_KEY=l4d7f4be-6812-44bd-b95e-9d415210fe14
export NUREGO_API_URL=https://am-staging.nurego.com
export METER_BASE_DOMAIN=localhost
export ORG_ID=ff85feb9-be02-4a73-9b13-9e1970abf09c
export PLAN_ID=pla_b77c-e9fd-434d-afad-c80e45f712fd
export NUREGO_BATCH_INTERVAL_SECONDS=1
export NUREGO_BATCH_MAX_MAP_SIZE=1
```

Then run the test

```
gradle -DintegrationTest.single=SpringMeteringFilterIT integrationTest -x javadoc --info
```

Tested with gradle 2.2.1
